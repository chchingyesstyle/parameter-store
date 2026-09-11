# Parameter Store

A small, self-hosted parameter/value panel for a trusted LAN.

> **Non-secret tool only.** Do not enter passwords, API keys, tokens, connection
> strings, personal data, or any other confidential value. This service uses
> plain HTTP and has no authentication by design.

## Run with Docker Compose

```bash
cd /u01/docker/parameter-store
docker compose up -d --build
```

Open the panel from the NanoPi itself at:

```text
http://localhost:8080
```

Other machines on the LAN can use:

```text
http://192.168.4.153:8080
```

The application listens on `0.0.0.0:8080` so both access paths work. Its data
is stored in `./data/parameters.db` and is deliberately excluded from Git. The
image runs as UID/GID `1000`; keep the host `data/` directory writable by that
UID/GID when deploying on another machine.

## API

Create or replace a parameter:

```bash
curl -X POST http://localhost:8080/api/parameters \
  -H 'Content-Type: application/json' \
  -d '{"parameter":"region","value":"eu-west-2"}'
```

Read one parameter:

```bash
curl http://localhost:8080/api/parameters/region
```

List parameters, optionally filtering names:

```bash
curl 'http://localhost:8080/api/parameters?q=reg'
```

Update or delete:

```bash
curl -X PUT http://localhost:8080/api/parameters/region \
  -H 'Content-Type: application/json' \
  -d '{"value":"eu-west-1"}'

curl -X DELETE http://localhost:8080/api/parameters/region
```

Health check:

```bash
curl http://localhost:8080/healthz
```

## Development

The application has no third-party Python dependencies.

```bash
PYTHONPATH=. python3 -W error -m unittest discover -v
```

The test suite uses temporary SQLite databases and does not touch `data/`.

## Git safety

Runtime data, environment files, Python caches, and SQLite sidecar files are
ignored. Review `git diff --cached` before committing. Never commit real
credentials or a populated database.
