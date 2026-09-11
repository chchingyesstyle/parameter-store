# Encrypted Parameter Storage Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Encrypt parameter values in SQLite with AES-256-GCM using a host-mounted key file while preserving the current API and safely migrating legacy text rows.

**Architecture:** Add a small encryption boundary inside app.py. Startup loads a base64-encoded 32-byte key from a host file, ParameterStore encrypts values into versioned SQLite BLOBs, and legacy text values are converted inside one transaction. Docker mounts ./parameter-store.key read-only, while the API continues decrypting values for existing UI and REST responses.

**Tech Stack:** Python 3.13 standard library, cryptography AESGCM, SQLite, Docker Compose, unittest.

**Spec:** docs/superpowers/specs/2026-09-11-encrypted-parameter-storage-design.md

## Global Constraints

- Use authenticated AES-GCM with a 256-bit key and a fresh 12-byte nonce for every value.
- Store version byte 0x01, nonce (12 bytes), and AES-GCM ciphertext plus tag as a SQLite BLOB.
- Keep the key outside SQLite and the Docker image at ./parameter-store.key; mount it read-only as /run/secrets/parameter-store.key.
- Reject missing, unreadable, malformed, or incorrectly sized key files; never auto-generate a replacement key at startup.
- Encrypt legacy SQLite text rows transactionally before serving requests.
- Preserve the existing REST API, browser behavior, parameter validation, and 64 KiB limits.
- Treat wrong-key and ciphertext-integrity failures as generic 500 storage unavailable responses.
- Keep parameter-store.key, .env, and runtime database files out of Git.

---

## File Map

- Modify app.py: key loading, AES-GCM value codec, startup migration, encrypted CRUD, and controlled integrity errors.
- Modify tests/test_store.py: key helpers, encrypted storage, persistence, migration, tampering, and key-file validation tests.
- Modify tests/test_http.py: pass a deterministic test key to the server and test generic responses for decryption failures.
- Create requirements.txt: declare the cryptography runtime dependency.
- Modify Dockerfile: install requirements.txt before copying/running the app.
- Modify compose.yml: pass PARAMETER_STORE_KEY_FILE and mount the host key read-only.
- Modify .gitignore: ignore the host key explicitly.
- Modify .dockerignore: exclude the host key from the Docker build context.
- Modify README.md: document key generation, permissions, backups, encrypted-at-rest limits, and Docker startup.
- Create ignored parameter-store.key: generate one local base64 key and never print or commit it.

## Task 1: Add key loading and authenticated value codec

**Files:**
- Modify app.py near the imports and constants
- Test tests/test_store.py

**Interfaces:**
- Produce EncryptionKeyError(ValueError) for invalid key files or key bytes.
- Produce StorageIntegrityError(RuntimeError) for malformed or unauthenticated ciphertext.
- Produce load_encryption_key(key_path: Path | str) -> bytes.
- Produce ValueCipher(key: bytes) with encrypt(parameter: str, value: str) -> bytes and decrypt(parameter: str, payload: bytes) -> str.

- [ ] Step 1: Write failing tests for key validation and codec behavior.

Add base64 to the test imports and import EncryptionKeyError, StorageIntegrityError, ValueCipher, and load_encryption_key from app. Add an EncryptionTests unittest class with these behaviors:

    test_loads_exactly_32_decoded_key_bytes:
        create a temporary parameter-store.key containing base64 of 32 k bytes and a trailing newline
        assert load_encryption_key(path) equals 32 k bytes

    test_rejects_missing_or_invalid_key_file:
        assert missing and non-base64 files each raise EncryptionKeyError

    test_encrypts_and_decrypts_with_authenticated_parameter_name:
        encrypt api.token and secret-value with ValueCipher(32 k bytes)
        assert ciphertext does not contain secret-value
        assert decrypting with api.token returns secret-value
        assert decrypting the same payload with other raises StorageIntegrityError

    test_encrypting_same_value_twice_uses_different_nonces:
        encrypt the same token value twice and assert the byte payloads differ

- [ ] Step 2: Run the focused tests to verify the expected missing-symbol failure.

Run:

    PYTHONPATH=. python3 -m unittest tests.test_store.EncryptionTests -v

Expected: FAIL because the new encryption symbols do not exist yet.

- [ ] Step 3: Implement the minimal key loader and codec.

Add KEY_LENGTH = 32, NONCE_LENGTH = 12, GCM_TAG_LENGTH = 16, ENCRYPTION_VERSION = b"\x01", and AAD_PREFIX = b"parameter-store:v1:".

Use base64.b64decode(encoded, validate=True) after reading and stripping the key file. Convert read errors, invalid base64, and decoded lengths other than 32 bytes into EncryptionKeyError without including key contents.

ValueCipher must validate a 32-byte key, use AESGCM, create a fresh os.urandom(12) nonce per encryption, and authenticate AAD_PREFIX plus the UTF-8 parameter name. Store version byte plus nonce plus AES-GCM output. On decryption, reject unsupported versions, short payloads, invalid tags, and invalid UTF-8 as StorageIntegrityError with a generic message that contains no secret material.

- [ ] Step 4: Run the focused tests and confirm they pass.

Run the same focused unittest command. Expected: all EncryptionTests pass with no warnings.

## Task 2: Encrypt ParameterStore and migrate legacy rows

**Files:**
- Modify app.py in ParameterStore
- Test tests/test_store.py

**Interfaces:**
- Change ParameterStore.__init__ to accept encryption_key: bytes and construct a ValueCipher.
- Store new rows as encrypted bytes and decrypt rows for get() and list().
- Keep put, get, list, and delete public behavior unchanged.

- [ ] Step 1: Write failing tests for raw ciphertext, persistence, wrong keys, and migration.

Import sqlite3, StorageIntegrityError, and ParameterStore. Define TEST_KEY = b"k" * 32 and a make_store(database_path) helper returning ParameterStore(database_path, TEST_KEY). Add tests with these exact assertions:

    test_store_value_is_a_ciphertext_blob:
        make_store(...).put("password", "correct horse battery staple")
        select value from SQLite
        assert the raw result is bytes
        assert the raw result does not contain the plaintext bytes

    test_value_round_trips_across_store_instances:
        put token/secret with one store
        assert a second store with the same key returns secret

    test_wrong_key_is_rejected:
        put token/secret with TEST_KEY
        assert ParameterStore(database_path, b"w" * 32).get("token") raises StorageIntegrityError

    test_legacy_text_rows_are_encrypted_during_startup:
        create the old parameters table with value TEXT
        insert legacy/old-value
        create a store with TEST_KEY
        assert get("legacy") returns old-value
        select value directly and assert it is bytes and does not contain old-value

Update the existing store tests to use make_store.

- [ ] Step 2: Run the focused store tests and verify they fail for missing encryption behavior.

Run:

    PYTHONPATH=. python3 -m unittest tests.test_store -v

Expected: the new tests fail because the constructor and SQL still use plaintext values.

- [ ] Step 3: Implement encrypted storage and one-transaction migration.

In ParameterStore.__init__, validate the supplied key by constructing ValueCipher, create fresh tables with value BLOB NOT NULL, and call _migrate_legacy_values inside the same SQLite connection transaction.

For each existing row whose SQLite value is str, validate its parameter and value, encrypt it, and update it in place. Leave valid versioned BLOBs for authenticated decryption on read. Reject other SQLite value types as StorageIntegrityError. If any migration operation fails, let the transaction roll back and fail startup.

Change put to validate as before, encrypt before binding the SQL parameter, and store bytes. Change get and list to decrypt values using the row's parameter name while preserving updated_at and the existing dictionaries. Do not include plaintext, keys, or ciphertext in integrity errors.

- [ ] Step 4: Run all store tests and confirm green.

Run:

    PYTHONPATH=. python3 -m unittest tests.test_store -v

Expected: all existing and new store tests pass.

## Task 3: Wire key loading into the server and HTTP error handling

**Files:**
- Modify app.py in create_server, request handlers, and run
- Modify tests/test_http.py

**Interfaces:**
- Change create_server(host: str, port: int, database_path: Path | str, encryption_key: bytes) to pass the key to ParameterStore.
- run() reads PARAMETER_STORE_KEY_FILE, defaulting to /run/secrets/parameter-store.key, and calls load_encryption_key before opening the server.

- [ ] Step 1: Update HTTP test setup and add a tampering regression test.

Add TEST_KEY = b"k" * 32 to tests/test_http.py and pass it as the fourth argument to create_server. Add a test that creates token/secret, updates the SQLite value to b"not-a-valid-ciphertext", requests /api/parameters/token, and asserts status 500 with exactly {"error": "storage unavailable"}.

- [ ] Step 2: Run HTTP tests and verify the new setup/tamper test fails.

Run:

    PYTHONPATH=. python3 -m unittest tests.test_http -v

Expected: setup fails until create_server accepts and forwards the key, and the tampering test fails until StorageIntegrityError is mapped to HTTP 500.

- [ ] Step 3: Implement server key wiring and controlled storage failures.

Pass the key through create_server. In run, read os.environ.get("PARAMETER_STORE_KEY_FILE", "/run/secrets/parameter-store.key"), load the key, and call create_server with it before serve_forever. Missing or invalid keys must stop startup.

In do_GET, catch StorageIntegrityError alongside sqlite3.Error for list and single-value reads and call _send_storage_unavailable. Keep validation errors as 400 and never return decryption exception details. Writes and deletes retain their current behavior.

- [ ] Step 4: Run all HTTP tests and confirm green.

Run the same HTTP unittest command. Expected: all API, timeout, malformed JSON, storage, and tampering tests pass.

## Task 4: Add dependency, Docker key mount, ignore rules, and documentation

**Files:**
- Create requirements.txt
- Modify Dockerfile
- Modify compose.yml
- Modify .gitignore
- Modify .dockerignore
- Modify README.md

- [ ] Step 1: Add dependency and configuration changes.

Create requirements.txt with:

    cryptography>=43,<50

Install it in Dockerfile before copying the application:

    COPY requirements.txt /app/requirements.txt
    RUN pip install --no-cache-dir -r /app/requirements.txt
    COPY app.py /app/app.py

Add PARAMETER_STORE_KEY_FILE: "/run/secrets/parameter-store.key" to the service environment and add this read-only bind mount:

    - ./parameter-store.key:/run/secrets/parameter-store.key:ro

Keep the exact parameter-store.key ignore rule and the existing .env, .env.*, and !.env.example rules.

Also exclude parameter-store.key from .dockerignore so it is not sent to the Docker daemon as build context.

- [ ] Step 2: Update README operational guidance.

Document that values are encrypted at rest in SQLite but decrypted in application memory and returned over the existing unauthenticated HTTP API. Add setup before docker compose up:

    umask 077
    openssl rand -base64 32 > parameter-store.key
    sudo chown 1000:1000 parameter-store.key
    chmod 400 parameter-store.key
    docker compose up -d --build

Explain that the key must be backed up separately, never committed or placed in SQLite, and that changing or losing it makes encrypted values unrecoverable. Warn that HTTPS and authentication are required before exposure beyond a trusted LAN. Document startup failure for missing keys and transactional migration of legacy rows.

- [ ] Step 3: Validate configuration and ignored-secret behavior.

Run:

    git check-ignore -v parameter-store.key .env
    make compose-config

Expected: both secret paths are ignored and Compose validates successfully.

## Task 5: Generate the local key, run full verification, and commit if permitted

**Files:**
- Create ignored runtime secret: parameter-store.key

- [ ] Step 1: Generate the key without printing it.

If parameter-store.key does not exist, use openssl rand -base64 -out parameter-store.key 32 to create it; never overwrite an existing key. Set owner UID/GID 1000:1000 and mode 0400, and verify only metadata and decoded length without displaying key contents.

- [ ] Step 2: Run the complete test suite and build checks.

Run:

    make test
    make compose-config
    docker compose build

Expected: all tests pass, Compose validates, and the image builds with the cryptography dependency.

- [ ] Step 3: Inspect the final diff for secret leakage.

Run:

    git status --short
    git diff --check
    git diff -- . ':!docs/superpowers/specs/*' ':!docs/superpowers/plans/*'

Confirm no key bytes, PAT, .env contents, database contents, or unrelated changes appear in the diff.

- [ ] Step 4: Commit the implementation if .git is writable.

Run:

    git add .gitignore Dockerfile Makefile README.md app.py compose.yml requirements.txt tests docs/superpowers
    git commit -m "feat: encrypt parameter values at rest"

If the managed workspace still reports a read-only .git directory, preserve all verified working-tree changes and report that the implementation is ready but the commit must be created from a writable checkout.
