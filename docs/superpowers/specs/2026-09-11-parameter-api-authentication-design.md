# Parameter API Authentication Design

## Context

The parameter store now encrypts values in SQLite with
`parameter-store.key`. Applications running on the Pi also need a way to
read and update parameters through the REST API. The existing REST API has no
authentication, so any process that can reach port 8080 can use it.

The API credential must not be the SQLite encryption key. The encryption key
must remain private to the service because anyone who obtains it can decrypt
the database. A separate bearer credential provides API access without
exposing the database key to application clients.

The deployment assumption for this change is that callers and the service are
inside the same Pi. HTTPS is therefore outside this change's scope. The API
key file and the encryption key file must still be protected from unrelated
local processes and must never be committed.

## Goals

- Require a separate API key for every `/api/parameters` request.
- Keep `parameter-store.key` exclusively for SQLite encryption.
- Mount `parameter-store-api.key` read-only into the container.
- Preserve unauthenticated Docker health checks at `/healthz`.
- Keep the browser panel reachable at `/`, with the API key held only in
  browser memory.
- Return generic authentication failures without revealing which part of the
  credential was wrong.
- Document setup and authenticated API calls without including a real key.

## Non-goals

- HTTPS or certificate management.
- User accounts, roles, sessions, key rotation, or a key-management service.
- Storing the API key in SQLite, browser storage, cookies, or the Docker image.
- Reusing or deriving the API key from the encryption key.
- Changing the existing parameter validation or encrypted storage format.

## Proposed design

### Secret files and configuration

Create a host-side `parameter-store-api.key` containing a base64-encoded
random 32-byte value. The file is generated only when absent, has restrictive
permissions, and is ignored by both Git and Docker build context rules.

Compose will provide:

- `PARAMETER_STORE_API_KEY_FILE=/run/secrets/parameter-store-api.key`
- a read-only bind mount from `./parameter-store-api.key` to that path

`PARAMETER_STORE_KEY_FILE` and `parameter-store.key` remain unchanged and are
used only by the encryption layer.

At startup, the application reads and validates the API key file. Missing,
invalid, or incorrectly sized key files fail startup rather than silently
creating a replacement or running without authentication.

### HTTP authentication boundary

The following routes remain unauthenticated:

- `/healthz`, for Docker and local liveness checks
- `/`, so the web panel can load its HTML shell

All API routes under `/api/parameters` require:

```text
Authorization: Bearer <base64-api-key>
```

The server decodes the presented base64 value and compares its bytes with the
configured API key using a constant-time comparison. Missing, malformed, and
incorrect credentials all return the same response:

- status `401 Unauthorized`
- `WWW-Authenticate: Bearer`
- JSON body `{"error":"unauthorized"}`

Authentication is checked before request-body parsing or database access.

### Browser panel

Add a password-style API-key field to the page. The browser includes its
value as a Bearer token on API requests. The key is not written to
`localStorage`, cookies, or any other persistent browser storage. Users can
refresh after entering a key; an empty or invalid key displays the normal
unauthorized error message.

### Compatibility and failure behavior

- Existing authorized CRUD behavior and response bodies remain unchanged.
- `/healthz` continues to return `{"status":"ok"}` without a key.
- The encryption key remains required and is loaded independently.
- API-key startup errors are controlled and do not print the key value.
- Existing storage-integrity and SQLite error handling is unchanged.

Unknown routes continue to return `404`; authentication is only applied to
the existing parameter API surface.

## Testing strategy

- Unit-test valid, missing, malformed, and wrong-length API-key files.
- Test missing and invalid Authorization headers return `401`, the generic
  JSON error, and `WWW-Authenticate`.
- Test a valid Authorization header preserves list/create/read/update/delete
  behavior.
- Test `/healthz` and `/` remain available without authentication.
- Test the browser HTML contains the API-key input and does not use persistent
  browser storage for it.
- Run the full test suite with warnings treated as errors.
- Build the Docker image and run a disposable-container smoke test with both
  secret files mounted.

## Operational notes

The API key is a bearer credential. It must be supplied to applications from
their own secret configuration and must not be placed in the parameter store
itself. Back up the API key separately from the database. Losing the API key
requires an intentional credential rotation; losing the encryption key makes
the encrypted values unrecoverable.

