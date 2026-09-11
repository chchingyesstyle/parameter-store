# Parameter Store

A small, self-hosted parameter/value panel for use by applications running on
the Pi, with values encrypted at rest in SQLite.

> **Security boundary.** Values are encrypted at rest with a key stored outside
> the database and Docker image. Parameter API requests require a separate API
> key. This deployment assumes callers run on the Pi and uses plain HTTP; do
> not expose the published port beyond that trusted scope.

## Features

- Browser panel at `/` for listing, searching, saving, editing, copying, and deleting values
- REST API for parameter/value CRUD operations
- SQLite persistence on the host with AES-GCM-encrypted value blobs
- External, read-only encryption key file mounted into the container
- Separate, external, read-only API key required for REST API access
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
for key_file in parameter-store.key parameter-store-api.key; do
  if [ ! -e "$key_file" ]; then
    umask 077
    openssl rand -base64 -out "$key_file" 32
    chmod 400 "$key_file"
    sudo chown 1000:1000 "$key_file"
  fi
done
docker compose up -d --build
```

Generate both keys once before the first start. The guarded commands refuse to
overwrite existing keys. If the host user already has UID/GID `1000`, the
`chown` command may not be needed. Do not regenerate `parameter-store.key`
while an existing database is in use: changing or losing it makes the
encrypted values unrecoverable. The API key can be rotated separately, but
clients and the web panel must then use the new file contents.

Check the service:

```bash
docker compose ps
curl http://localhost:8080/healthz
```

Open the web panel locally:

```text
http://localhost:8080/
```

The Compose configuration publishes `0.0.0.0:8080:8080`, so local and LAN
connections are technically possible. The intended deployment for this
configuration keeps callers on the Pi; the API key is a bearer credential and
the current service does not provide transport encryption.

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

The API bearer key is stored separately at:

```text
./parameter-store-api.key
```

Compose mounts it read-only at
`/run/secrets/parameter-store-api.key`. It contains a base64-encoded random
32-byte API key. Applications send the file contents in the
`Authorization: Bearer ...` header, and the web panel asks for the same
contents on its unlock screen. Never give applications or browser users the
encryption key, and never store either key in SQLite, Git, or the Docker
image. Both files must be backed up separately from the database.

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
API. Every `/api/parameters` request requires a valid API key. Load the key
into a shell variable without printing it:

```bash
API_KEY="$(tr -d '\n' < parameter-store-api.key)"
```

The browser panel uses the same key: open `/`, paste the contents of
`parameter-store-api.key` into the unlock box, and click **Unlock**. The
parameter table and edit controls remain hidden until the authenticated list
request succeeds. Refreshing the page requires unlocking again.

### List parameters

```bash
curl -H "Authorization: Bearer ${API_KEY}" \
  http://localhost:8080/api/parameters
```

Filter parameter names with `q`:

```bash
curl -H "Authorization: Bearer ${API_KEY}" \
  'http://localhost:8080/api/parameters?q=region'
```

### Create or replace a parameter

```bash
curl -X POST http://localhost:8080/api/parameters \
  -H "Authorization: Bearer ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"parameter":"region","value":"eu-west-2"}'
```

Returns `201 Created` when the value is saved.

### Read one parameter

```bash
curl -H "Authorization: Bearer ${API_KEY}" \
  http://localhost:8080/api/parameters/region
```

### Update a parameter

```bash
curl -X PUT http://localhost:8080/api/parameters/region \
  -H "Authorization: Bearer ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"value":"eu-west-1"}'
```

### Delete a parameter

```bash
curl -X DELETE http://localhost:8080/api/parameters/region \
  -H "Authorization: Bearer ${API_KEY}"
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
- Missing or invalid encryption-key or API-key files prevent application
  startup.
- Missing, malformed, or incorrect API credentials return `401 Unauthorized`
  with a generic error body.

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

Runtime databases, SQLite sidecar files, both key files, environment files, and
Python cache files are ignored by Git. Both keys are also excluded from the
Docker build context. Review staged changes before committing, and never
commit a populated database, key file, `.env` file, or confidential data.

This project provides encryption at rest and API-key authentication for
parameter routes, but not authorization, HTTPS, audit logging, or automatic
key rotation. Add those controls or use a purpose-built secret manager if the
threat model changes.
