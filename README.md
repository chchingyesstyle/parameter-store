# Parameter Store

A small, self-hosted parameter/value panel for use on a trusted local network.

> **Non-secret tool only.** Do not enter or store passwords, API keys, tokens,
> connection strings, personal data, or any other confidential information.
> This service uses plain HTTP and has no authentication by design.

## Features

- Browser panel at `/` for listing, searching, saving, editing, copying, and deleting values
- REST API for parameter/value CRUD operations
- SQLite persistence on the host
- Parameter-name validation and value-size limits
- Safe browser rendering using DOM text nodes rather than injected HTML
- No third-party Python dependencies
- Docker image runs as non-root UID/GID `1000:1000`

## Requirements

- Docker Engine
- Docker Compose v2 (`docker compose`)

## Quick start

From the project directory:

```bash
docker compose up -d --build
```

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
access work. Do not expose this service to the public Internet.

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

Stop the container without deleting the database:

```bash
docker compose down
```

View logs:

```bash
docker compose logs -f parameter-store
```

## REST API

All request bodies are JSON objects. Values must be strings.

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
- Invalid JSON, incomplete bodies, malformed request targets, and unavailable storage return controlled error responses.

## Development

The application has no third-party Python dependencies. Run the tests with:

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

Runtime databases, SQLite sidecar files, environment files, and Python cache
files are ignored by Git. Review staged changes before committing, and never
commit a populated database or confidential data.

This project is intentionally a simple non-secret LAN tool. If authentication,
encryption, audit logging, or secret storage is required, use a purpose-built
system instead of this application.
