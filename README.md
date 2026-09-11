# Parameter Store

A small, self-hosted parameter/value panel for use on a trusted local network,
with values encrypted at rest in SQLite.

> **Security boundary.** Values are encrypted at rest with a key stored outside
> the database and Docker image. The service still uses plain HTTP and has no
> authentication by design, so use it only on a trusted network or place it
> behind HTTPS and an authentication layer before storing sensitive values.

## Features

- Browser panel at `/` for listing, searching, saving, editing, copying, and deleting values
- REST API for parameter/value CRUD operations
- SQLite persistence on the host with AES-GCM-encrypted value blobs
- External, read-only encryption key file mounted into the container
- Parameter-name validation and value-size limits
- Safe browser rendering using DOM text nodes rather than injected HTML
- Python `cryptography` dependency for authenticated encryption
- Docker image runs as non-root UID/GID `1000:1000`

## Requirements

- Docker Engine
- Docker Compose v2 (`docker compose`)

## Quick start

From the project directory:

```bash
if [ ! -e parameter-store.key ]; then
  umask 077
  openssl rand -base64 -out parameter-store.key 32
  chmod 400 parameter-store.key
  sudo chown 1000:1000 parameter-store.key
fi
docker compose up -d --build
```

Generate the key once before the first start. The guarded command refuses to
overwrite an existing key. If the host user already has UID/GID `1000`, the
`chown` command may not be needed. Do not regenerate the key while an existing
database is in use: changing or losing it makes the encrypted values
unrecoverable.

Check the service:

```bash
docker compose ps
curl http://localhost:8080/healthz
```

Open the web panel locally:

```text
http://localhost:8080/
```

From another device on the LAN, use the host's LAN address. On the original
NanoPi host this is:

```text
http://192.168.4.153:8080/
```

The Compose configuration publishes `0.0.0.0:8080:8080`, so both local and LAN
access work. The service has no authentication and responses are sent over
plain HTTP; do not expose it to the public Internet. For sensitive values, use
HTTPS and authentication at a trusted reverse proxy or use a purpose-built
secret manager.

## Data and permissions

The SQLite database is stored at:

```text
./data/parameters.db
```

The `data/` directory is bind-mounted into the container and is excluded from
Git. The container runs as UID/GID `1000:1000`, so the host directory must be
writable by that UID/GID when deploying on another machine:

```bash
mkdir -p data
sudo chown 1000:1000 data
chmod 700 data
```

If the host user already has UID/GID `1000`, ownership may already be correct.

The encryption key is stored separately at:

```text
./parameter-store.key
```

Compose mounts this file read-only at
`/run/secrets/parameter-store.key`. It contains a base64-encoded random 32-byte
key. The file is ignored by both Git and the Docker build context; protect it
with restrictive permissions and back it up separately from the database. The
application refuses to start if the key is missing or invalid and never creates
a replacement automatically.

On startup, any legacy plaintext values from an older database are encrypted
transactionally with the configured key. A failed migration is rolled back.
Fresh values are stored as authenticated encrypted BLOBs in
`./data/parameters.db`.

Stop the container without deleting the database:

```bash
docker compose down
```

View logs:

```bash
docker compose logs -f parameter-store
```

## REST API

All request bodies are JSON objects. Values must be strings. Values are
encrypted before they are written to SQLite and decrypted when returned by the
API.

### List parameters

```bash
curl http://localhost:8080/api/parameters
```

Filter parameter names with `q`:

```bash
curl 'http://localhost:8080/api/parameters?q=region'
```

### Create or replace a parameter

```bash
curl -X POST http://localhost:8080/api/parameters \
  -H 'Content-Type: application/json' \
  -d '{"parameter":"region","value":"eu-west-2"}'
```

Returns `201 Created` when the value is saved.

### Read one parameter

```bash
curl http://localhost:8080/api/parameters/region
```

### Update a parameter

```bash
curl -X PUT http://localhost:8080/api/parameters/region \
  -H 'Content-Type: application/json' \
  -d '{"value":"eu-west-1"}'
```

### Delete a parameter

```bash
curl -X DELETE http://localhost:8080/api/parameters/region
```

### Health check

```bash
curl http://localhost:8080/healthz
```

A healthy service returns:

```json
{"status": "ok"}
```

## Validation limits

- Parameter names are at most 128 characters.
- Names must start with a letter or number.
- The remaining name characters may be letters, numbers, `.`, `_`, `:`, or `-`.
- Values must be strings no larger than 64 KiB when encoded as UTF-8.
- JSON request bodies are limited to 64 KiB.
- Invalid JSON, incomplete bodies, malformed request targets, unavailable
  storage, and ciphertext-integrity failures return controlled error responses.
- Missing or invalid encryption-key files prevent application startup.

## Development

The application declares its encryption dependency in `requirements.txt`. Run
the tests with:

```bash
make test
```

Equivalent command:

```bash
PYTHONPATH=. python3 -W error -m unittest discover -v
```

Validate the Compose configuration without starting the service:

```bash
make compose-config
```

Useful Make targets:

```text
make test            Run the test suite
make compose-config  Validate Docker Compose configuration
make up              Build and start the service
make down            Stop the service
make logs            Follow container logs
```

## Git safety

Runtime databases, SQLite sidecar files, the encryption key, environment files,
and Python cache files are ignored by Git. The key is also excluded from the
Docker build context. Review staged changes before committing, and never commit
a populated database, key file, `.env` file, or confidential data.

This project provides encryption at rest, but not authentication, authorization,
HTTPS, audit logging, or key rotation. Add those controls or use a purpose-built
secret manager when the threat model requires them.
