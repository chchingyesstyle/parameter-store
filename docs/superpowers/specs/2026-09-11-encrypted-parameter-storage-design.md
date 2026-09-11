# Encrypted Parameter Storage Design

**Date:** 2026-09-11
**Status:** Approved for implementation

## Context

The application currently stores parameter values directly in SQLite and serves
them through a small unauthenticated HTTP API. The requested change is to make
the application suitable for storing passwords, API keys, and tokens by
encrypting values at rest in SQLite.

Encryption at rest does not provide transport security or user authentication.
The service will therefore remain suitable only for a trusted LAN unless the
operator places it behind HTTPS and an authentication layer.

## Goals

- Encrypt every value stored in SQLite using authenticated encryption.
- Keep the encryption key outside the database and Docker image.
- Mount the host key file read-only into the container.
- Preserve the existing REST API and browser behavior.
- Preserve and encrypt any existing legacy plaintext rows transactionally.
- Fail closed when the key is missing, malformed, or unable to decrypt data.
- Detect ciphertext tampering without exposing secret material in errors.
- Keep the key file and runtime secrets out of Git.

## Non-goals

- Adding authentication, authorization, or HTTPS.
- Encrypting HTTP responses or browser memory.
- Automatic key generation during application startup.
- Key rotation or multiple active encryption keys.
- Replacing SQLite with a dedicated secret manager.

## Encryption architecture

Use the `cryptography` package's `AESGCM` implementation with a 256-bit key.
The application loads and validates the key once during startup, then keeps it
only in process memory while serving requests.

Each value is encoded as UTF-8 and encrypted with a fresh 12-byte random nonce.
The stored SQLite BLOB format is:

```text
version byte (0x01) || nonce (12 bytes) || AES-GCM ciphertext and tag
```

The parameter name is supplied as AES-GCM associated authenticated data with a
context prefix. This binds a ciphertext to its parameter name, so moving a
ciphertext to another parameter causes decryption to fail. The nonce is never
stored separately and is not secret.

The existing `parameters.value` column remains the logical value column, but
new values are stored as SQLite BLOBs. Fresh databases declare it as `BLOB`;
SQLite's dynamic typing allows the migration to update the existing column
without changing the public schema.

## Key file and Docker wiring

The host key file will be:

```text
./parameter-store.key
```

It contains a base64-encoded 32-byte random key and is ignored by Git. Docker
Compose will mount it read-only as:

```text
/run/secrets/parameter-store.key
```

The container receives the path through
`PARAMETER_STORE_KEY_FILE=/run/secrets/parameter-store.key`. The application
will reject missing files, invalid base64, decoded keys of any length other
than 32 bytes, and files that cannot be read. It will not silently generate a
replacement key because that would make existing data unrecoverable after a
restart.

The setup documentation will show how to generate the key, apply permissions
compatible with container UID/GID `1000:1000`, back it up securely, and avoid
committing it.

## Startup migration

On `ParameterStore` initialization, the application will open a transaction and
inspect existing values:

- Legacy SQLite text values are encrypted with the configured key and updated
  in place.
- Existing versioned BLOB values are retained after validation on read.
- If migration fails, the transaction rolls back and startup fails rather than
  leaving a partially migrated database.

This preserves current non-secret parameters while ensuring that after a
successful startup no legacy plaintext value remains in the table.

Changing or losing the key makes encrypted values unreadable. Key rotation is
out of scope for this change and will be documented as an operational warning.

## Runtime behavior and errors

- `POST` and `PUT` validate and encrypt values before writing them.
- `GET` and list operations decrypt values before producing their existing JSON
  responses.
- `DELETE` removes rows without needing to decrypt them.
- A malformed payload, unsupported encryption version, authentication-tag
  failure, or wrong key is treated as a controlled storage failure; the API
  returns the existing generic `500 storage unavailable` response and does not
  return cryptographic details or plaintext.
- Missing or invalid key configuration prevents startup with a clear operator
  error.

The API contract, parameter validation, value-size limit, and browser UI remain
otherwise unchanged.

## Files to change

- `app.py`: key loading, encryption/decryption, legacy migration, and storage
  error handling.
- `tests/test_store.py`: encryption, persistence, tamper detection, key
  validation, and migration coverage.
- `tests/test_http.py`: inject a test key and retain API/error coverage.
- `Dockerfile`: install the cryptography dependency.
- `requirements.txt`: declare the dependency.
- `compose.yml`: configure the key-file path and read-only bind mount.
- `.gitignore`: ignore the host key file.
- `.dockerignore`: exclude the host key from the Docker build context.
- `README.md`: document encrypted-at-rest behavior, key setup/backup, and the
  remaining HTTP/authentication limitations.
- `parameter-store.key`: generate locally as an ignored runtime secret; never
  commit or print its contents.

## Verification

Tests will prove that:

- A stored value round-trips through the store and across new store instances
  with the same key.
- The raw SQLite value is a BLOB and does not contain the plaintext.
- Writing the same plaintext twice produces different ciphertexts.
- A wrong key and tampered ciphertext are rejected.
- Legacy plaintext rows are migrated and no longer stored as text.
- Missing and malformed key files are rejected.
- Existing HTTP CRUD and controlled storage-error behavior remain correct.
- The Compose configuration validates successfully.
