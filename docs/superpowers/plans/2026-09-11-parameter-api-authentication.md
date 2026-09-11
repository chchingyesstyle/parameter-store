# Parameter API Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Protect every parameter REST API operation with a separate API key while keeping the web panel locked until that key authenticates successfully.

**Architecture:** Keep parameter-store.key as the AES-GCM database-encryption key and add a separate base64-encoded 32-byte parameter-store-api.key bearer credential. The HTTP handler will authenticate /api/parameters requests before parsing bodies or opening storage operations; /healthz and the HTML shell remain public. The browser will hold the pasted API-key text in JavaScript memory only and reveal the parameter panel after a successful authenticated list request.

**Tech Stack:** Python 3.13 standard-library http.server, sqlite3, base64, and secrets; existing cryptography dependency; browser Fetch API; Docker Compose.

**Spec:** docs/superpowers/specs/2026-09-11-parameter-api-authentication-design.md

## Global Constraints

- parameter-store.key remains exclusively the SQLite encryption key.
- parameter-store-api.key is a separate base64-encoded random 32-byte API credential.
- Both secret files are ignored by Git and Docker build context rules and mounted read-only.
- Missing or invalid secret files fail application startup without printing secret contents.
- Every /api/parameters request requires Authorization: Bearer <base64-api-key>.
- Missing, malformed, and incorrect API credentials return the same 401 JSON response with WWW-Authenticate: Bearer.
- /healthz and / remain unauthenticated; HTTPS is outside this Pi-local deployment change.
- The browser never stores the API key in localStorage, sessionStorage, cookies, URLs, or other persistent storage.
- Existing encrypted storage format, parameter validation, response bodies, and error handling remain unchanged except for authentication failures.
- Never print, commit, or include the contents of either key file in test output, documentation, image layers, or source code.

---

### Task 1: Add independent API-key file loading

**Files:**
- Modify: app.py near EncryptionKeyError and load_encryption_key
- Test: tests/test_store.py near EncryptionTests

**Interfaces:**
- Produces APIKeyError(ValueError) for API-key file failures.
- Produces load_api_key(key_path: Path | str) -> bytes, returning exactly 32 decoded key bytes.
- Consumes the existing KEY_LENGTH, _base64, _binascii, and Path definitions.

- [ ] **Step 1: Write failing API-key loader tests**

Add APIKeyError and load_api_key to the from app import (...) list and add these methods to EncryptionTests:

~~~python
    def test_loads_exactly_32_decoded_api_key_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "parameter-store-api.key"
            path.write_bytes(base64.b64encode(b"a" * 32) + b"\n")

            self.assertEqual(load_api_key(path), b"a" * 32)

    def test_rejects_missing_invalid_and_wrong_length_api_key_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.key"
            invalid = Path(tmp) / "invalid.key"
            wrong_length = Path(tmp) / "wrong-length.key"
            invalid.write_bytes(b"not-base64")
            wrong_length.write_bytes(base64.b64encode(b"short"))

            for path in (missing, invalid, wrong_length):
                with self.subTest(path=path.name):
                    with self.assertRaises(APIKeyError):
                        load_api_key(path)
~~~

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

~~~bash
docker compose run --rm --no-deps -v "$PWD:/workspace" -w /workspace \
  --entrypoint python parameter-store \
  -W error -m unittest tests.test_store.EncryptionTests.test_loads_exactly_32_decoded_api_key_bytes \
  tests.test_store.EncryptionTests.test_rejects_missing_invalid_and_wrong_length_api_key_files
~~~

Expected: FAIL because APIKeyError and load_api_key do not yet exist.

- [ ] **Step 3: Implement the loader without exposing secret values**

Add the exception and function immediately after EncryptionKeyError and load_encryption_key using the same validation rules as the encryption-key loader, but a separate exception type:

~~~python
class APIKeyError(ValueError):
    """Raised when the configured API key cannot be used."""


def load_api_key(key_path: Path | str) -> bytes:
    try:
        encoded = Path(key_path).read_bytes().strip()
    except OSError as exc:
        raise APIKeyError("unable to read API key file") from exc
    try:
        key = _base64.b64decode(encoded, validate=True)
    except (_binascii.Error, ValueError) as exc:
        raise APIKeyError("API key must be valid base64") from exc
    if len(key) != KEY_LENGTH:
        raise APIKeyError("API key must decode to exactly 32 bytes")
    return key
~~~

- [ ] **Step 4: Run the focused and existing storage tests**

Run the two focused tests again, then run:

~~~bash
docker compose run --rm --no-deps -v "$PWD:/workspace" -w /workspace \
  --entrypoint python parameter-store \
  -W error -m unittest tests.test_store
~~~

Expected: all storage tests pass with zero warnings.

- [ ] **Step 5: Commit the key-loader unit**

~~~bash
git add app.py tests/test_store.py
git commit -m "feat: load separate parameter API key"
~~~

### Task 2: Authenticate parameter HTTP routes

**Files:**
- Modify: app.py in ParameterRequestHandler, ParameterHTTPServer, create_server, and run
- Test: tests/test_http.py request helpers, server setup, and HTTP tests

**Interfaces:**
- ParameterHTTPServer(..., store: ParameterStore, api_key: bytes) exposes the configured decoded API key to its handler.
- create_server(host: str, port: int, database_path: Path | str, encryption_key: bytes, api_key: bytes) -> ParameterHTTPServer requires both independent keys.
- load_api_key from Task 1 supplies the API key in run().
- ParameterRequestHandler._require_api_key() -> bool sends the generic 401 response and returns False on failure.

- [ ] **Step 1: Add authenticated test credentials and request-helper support**

In tests/test_http.py, add base64 to the imports, define a second test key and its wire representation, and pass both keys to create_server:

~~~python
TEST_API_KEY = b"a" * 32
TEST_API_TOKEN = base64.b64encode(TEST_API_KEY).decode("ascii")
AUTHORIZATION = f"Bearer {TEST_API_TOKEN}"
~~~

Change request_json, request_raw, and request_json_allow_error so valid authentication is the default and callers can explicitly omit or replace it. The helper must add Authorization: AUTHORIZATION when authorization == "valid", add a supplied header string for any other non-None value, and add no Authorization header when authorization is None.

Add an error helper that preserves response headers for authentication assertions:

~~~python
    def request_json_error(self, path, method="GET", payload=None, authorization=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if authorization == "valid":
            headers["Authorization"] = AUTHORIZATION
        elif authorization is not None:
            headers["Authorization"] = authorization
        request = Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8")), response.headers
        except HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8")), error.headers
~~~

Update the manually constructed valid POST wires in the incomplete-body and short-body tests to include an Authorization header with the test token. The malformed-target test remains unauthenticated because it tests request-target parsing before route dispatch.

- [ ] **Step 2: Write failing authentication tests**

Add these methods to HttpApiTests:

~~~python
    def test_parameter_api_rejects_missing_and_invalid_credentials(self):
        for authorization in (None, "Basic not-a-bearer-token", "Bearer not-the-key"):
            with self.subTest(authorization=authorization):
                status, result, headers = self.request_json_error(
                    "/api/parameters", authorization=authorization
                )

                self.assertEqual(status, 401)
                self.assertEqual(result, {"error": "unauthorized"})
                self.assertEqual(headers.get("WWW-Authenticate"), "Bearer")

    def test_parameter_api_authenticates_before_body_parsing(self):
        status, result = self.request_json_allow_error(
            "/api/parameters", "POST", {"not": "valid for this test"}, authorization=None
        )

        self.assertEqual(status, 401)
        self.assertEqual(result, {"error": "unauthorized"})

    def test_root_and_health_remain_public(self):
        status, headers, body = self.request_text("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get_content_type())
        self.assertIn("Parameter Store", body)

        status, result = self.request_json("/healthz", authorization=None)
        self.assertEqual(status, 200)
        self.assertEqual(result, {"status": "ok"})

~~~

- [ ] **Step 3: Run the new HTTP tests and verify they fail for the intended reason**

Run:

~~~bash
docker compose run --rm --no-deps -v "$PWD:/workspace" -w /workspace \
  --entrypoint python parameter-store \
  -W error -m unittest \
  tests.test_http.HttpApiTests.test_parameter_api_rejects_missing_and_invalid_credentials \
  tests.test_http.HttpApiTests.test_parameter_api_authenticates_before_body_parsing \
  tests.test_http.HttpApiTests.test_root_and_health_remain_public
~~~

Expected: FAIL because the server does not yet accept an API key or authenticate parameter routes.

- [ ] **Step 4: Implement constant-time bearer authentication**

Import the standard-library secrets module as _secrets. Add an optional headers: dict[str, str] | None = None argument to _send_json; emit those headers before end_headers. Add:

~~~python
    @property
    def api_key(self) -> bytes:
        return self.server.api_key  # type: ignore[attr-defined]

    def _send_unauthorized(self) -> None:
        self._send_json(
            401,
            {"error": "unauthorized"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _require_api_key(self) -> bool:
        authorization = self.headers.get("Authorization", "")
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            self._send_unauthorized()
            return False
        try:
            presented = _base64.b64decode(parts[1].encode("ascii"), validate=True)
        except (UnicodeEncodeError, _binascii.Error, ValueError):
            self._send_unauthorized()
            return False
        if not _secrets.compare_digest(presented, self.api_key):
            self._send_unauthorized()
            return False
        return True
~~~

Do not include the presented or configured key in exceptions or logs.

- [ ] **Step 5: Apply authentication before API work**

In do_GET, preserve the existing / and /healthz branches, then call _require_api_key() before parse_qs, store.list, _parameter_from_path, or store.get for the exact list route and parameter subroutes. In do_POST, do_PUT, and do_DELETE, retain the existing route-shape 404 checks, then call _require_api_key() and return immediately when it is false, before _read_json, _parameter_from_path, or storage calls.

The resulting route order must be:

~~~python
if parsed.path == "/api/parameters":
    if not self._require_api_key():
        return
    # existing list or POST behavior
~~~

and, for parameter subpaths:

~~~python
if parsed.path.startswith("/api/parameters/"):
    if not self._require_api_key():
        return
    # existing path parsing and storage behavior
~~~

- [ ] **Step 6: Thread the key through the server and process configuration**

Change the server and factory signatures exactly as follows:

~~~python
class ParameterHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], store: ParameterStore, api_key: bytes):
        self.store = store
        self.api_key = api_key
        super().__init__(server_address, ParameterRequestHandler)


def create_server(
    host: str,
    port: int,
    database_path: Path | str,
    encryption_key: bytes,
    api_key: bytes,
) -> ParameterHTTPServer:
    return ParameterHTTPServer(
        (host, port), ParameterStore(database_path, encryption_key), api_key
    )
~~~

In run(), read PARAMETER_STORE_API_KEY_FILE with default /run/secrets/parameter-store-api.key, call load_api_key, and pass the decoded bytes to create_server alongside the encryption key.

- [ ] **Step 7: Run all HTTP tests and commit the authenticated API**

Run:

~~~bash
docker compose run --rm --no-deps -v "$PWD:/workspace" -w /workspace \
  --entrypoint python parameter-store \
  -W error -m unittest tests.test_http
~~~

Expected: all HTTP tests pass with zero warnings, including the existing authorized CRUD, malformed-request, storage-error, and tamper tests.

Commit:

~~~bash
git add app.py tests/test_http.py
git commit -m "feat: require API key for parameter routes"
~~~

### Task 3: Add the locked web unlock screen

**Files:**
- Modify: app.py in FRONTEND_HTML
- Test: tests/test_http.py::HttpApiTests.test_web_panel_starts_locked_and_does_not_persist_api_key

**Interfaces:**
- The HTML exposes #unlock-panel, #unlock-form, #api-key, and #parameter-panel.
- JavaScript stores the current credential only in an in-memory accessToken variable.
- request(url, options) adds Authorization: Bearer <accessToken> only when unlocked.

- [ ] **Step 1: Add the locked markup**

The page must contain this structure before the parameter controls:

~~~html
  <section id="unlock-panel">
    <h2>Unlock</h2>
    <form id="unlock-form">
      <label for="api-key">API key</label>
      <input id="api-key" type="password" autocomplete="off" required>
      <button type="submit">Unlock</button>
    </form>
    <p id="unlock-message" role="status"></p>
  </section>
  <section id="parameter-panel" hidden>
    <form id="add-form">
      <input name="parameter" placeholder="parameter" maxlength="128" required pattern="[A-Za-z0-9][A-Za-z0-9_.:-]*">
      <input name="value" placeholder="value" maxlength="65536" required>
      <button type="submit">Save</button>
    </form>
    <div class="toolbar">
      <input id="search" placeholder="Search parameters" autocomplete="off">
      <button id="refresh" type="button">Refresh</button>
    </div>
    <p id="message" role="status"></p>
    <table>
      <thead><tr><th>Parameter</th><th>Value</th><th>Updated</th><th>Actions</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </section>
~~~

Keep the existing controls inside #parameter-panel rather than duplicating them. The initial hidden attribute is the security-relevant UI gate.

Add this test before the markup change so it fails until the structure and client-side storage rules are present:

~~~python
    def test_web_panel_starts_locked_and_does_not_persist_api_key(self):
        _, _, body = self.request_text("/")
        self.assertIn('id="unlock-panel"', body)
        self.assertIn('id="api-key"', body)
        self.assertIn('id="parameter-panel"', body)
        self.assertIn('id="parameter-panel" hidden', body)
        self.assertNotIn("localStorage", body)
        self.assertNotIn("sessionStorage", body)
~~~

- [ ] **Step 2: Implement in-memory unlock state and authenticated Fetch requests**

Add these references and state near the existing frontend constants:

~~~javascript
const unlockPanel = document.querySelector('#unlock-panel');
const unlockForm = document.querySelector('#unlock-form');
const apiKeyInput = document.querySelector('#api-key');
const unlockMessage = document.querySelector('#unlock-message');
const parameterPanel = document.querySelector('#parameter-panel');
let accessToken = '';
~~~

Add functions with this behavior:

~~~javascript
function showUnlockMessage(text, isError = false) {
  unlockMessage.textContent = text;
  unlockMessage.style.color = isError ? '#dc2626' : '';
}

function lockPanel() {
  accessToken = '';
  apiKeyInput.value = '';
  parameterPanel.hidden = true;
  unlockPanel.hidden = false;
  showUnlockMessage('Enter API key to unlock', true);
  apiKeyInput.focus();
}

function unlockPanelAfterAuthentication() {
  unlockPanel.hidden = true;
  parameterPanel.hidden = false;
  showUnlockMessage('');
}

async function request(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');
  if (accessToken) headers.set('Authorization', 'Bearer ' + accessToken);
  const response = await fetch(url, {...options, headers});
  const data = await response.json();
  if (response.status === 401) {
    lockPanel();
    throw new Error('unauthorized');
  }
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
~~~

Change load() so it returns the request('/api/parameters') result or throws; its callers continue to display errors. Remove the unconditional initial load() call and add:

~~~javascript
unlockForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const candidate = apiKeyInput.value.trim();
  if (!candidate) {
    showUnlockMessage('Enter API key', true);
    return;
  }
  accessToken = candidate;
  try {
    await load();
    apiKeyInput.value = '';
    unlockPanelAfterAuthentication();
    showMessage('Unlocked');
  } catch (error) {
    showUnlockMessage(error.message, true);
  }
});

lockPanel();
~~~

The existing save, edit, delete, search, refresh, and render logic stays inside the parameter panel and uses request, so it automatically sends the in-memory token. Do not add localStorage, sessionStorage, cookies, URL parameters, or an API key in HTML attributes.

- [ ] **Step 3: Run the web-panel test and the full HTTP suite**

Run:

~~~bash
docker compose run --rm --no-deps -v "$PWD:/workspace" -w /workspace \
  --entrypoint python parameter-store \
  -W error -m unittest tests.test_http.HttpApiTests.test_web_panel_starts_locked_and_does_not_persist_api_key
docker compose run --rm --no-deps -v "$PWD:/workspace" -w /workspace \
  --entrypoint python parameter-store \
  -W error -m unittest tests.test_http
~~~

Expected: both commands pass with zero warnings.

- [ ] **Step 4: Commit the locked web panel**

~~~bash
git add app.py tests/test_http.py
git commit -m "feat: lock web panel behind API key"
~~~

### Task 4: Configure the separate secret in Docker and ignore rules

**Files:**
- Modify: compose.yml
- Modify: .gitignore
- Modify: .dockerignore
- Create locally, untracked: parameter-store-api.key

**Interfaces:**
- The container receives PARAMETER_STORE_API_KEY_FILE=/run/secrets/parameter-store-api.key.
- The host file is mounted read-only at that path.
- Git and Docker never include the host API-key file.

- [ ] **Step 1: Add ignore rules before generating the secret**

Add parameter-store-api.key to .dockerignore and add this .gitignore entry beside the encryption-key rule:

~~~gitignore
# Local API bearer key; never commit this file.
parameter-store-api.key
~~~

- [ ] **Step 2: Add Compose environment and read-only mount**

Extend the service environment and volumes with:

~~~yaml
      PARAMETER_STORE_API_KEY_FILE: "/run/secrets/parameter-store-api.key"
~~~

~~~yaml
      - ./parameter-store-api.key:/run/secrets/parameter-store-api.key:ro
~~~

Do not change the existing encryption-key path or mount.

- [ ] **Step 3: Generate the API key only if it is absent**

Run from the repository directory; this must not overwrite an existing key:

~~~bash
if [ ! -e parameter-store-api.key ]; then
  umask 077
  openssl rand -base64 -out parameter-store-api.key 32
  chmod 400 parameter-store-api.key
  sudo chown 1000:1000 parameter-store-api.key
fi
~~~

Verify only non-secret metadata and ignore behavior:

~~~bash
stat -c 'mode=%a uid=%u gid=%g size=%s' parameter-store-api.key
git check-ignore -v parameter-store-api.key
docker compose config --quiet
~~~

Do not run cat, echo, or any command that prints the key contents.

- [ ] **Step 4: Commit the Docker configuration**

~~~bash
git add compose.yml .gitignore .dockerignore
git commit -m "chore: mount separate parameter API key"
~~~

The generated key remains untracked and ignored.

### Task 5: Document API-key setup and usage

**Files:**
- Modify: README.md

**Interfaces:**
- Documentation names both key files and clearly separates encryption from API authentication.
- Every parameter API example includes the Bearer header without embedding a real secret.
- Health-check and root examples remain header-free.

- [ ] **Step 1: Update the security boundary and feature list**

Replace the no-auth description with the actual boundary: values are encrypted with parameter-store.key, parameter API routes require the separate API key, /healthz and / are public, and this deployment assumes callers stay on the Pi over HTTP. Add the separate API key to the feature list.

- [ ] **Step 2: Update quick start to generate both keys safely**

Document guarded generation for parameter-store.key and parameter-store-api.key, preserving existing files and restrictive ownership/mode. Explain that the API key file contents are what applications and the web unlock field use, while the encryption key must never be shared with clients.

- [ ] **Step 3: Add API authentication documentation and update examples**

At the start of the REST API section, document:

~~~bash
API_KEY="$(tr -d '\n' < parameter-store-api.key)"
~~~

Then add -H "Authorization: Bearer ${API_KEY}" to list, filter, create, read, update, and delete examples. Keep the health-check example unchanged and state that the browser asks for the same file contents on its unlock screen. Do not include a real key, a key path as a token, or the encryption-key file in API examples.

- [ ] **Step 4: Update validation, operations, and development notes**

Document 401 Unauthorized for missing/invalid API credentials, startup failure for a missing/invalid API-key file, the browser refresh behavior, and the fact that both secret files are ignored and mounted read-only.

- [ ] **Step 5: Review documentation for secret leakage and commit**

Run:

~~~bash
git diff --check
rg -n "parameter-store-api\\.key|Authorization|localStorage|sessionStorage|no authentication|no auth" README.md
~~~

Confirm the search output contains only filenames, placeholders, and instructions—not key contents—then commit:

~~~bash
git add README.md
git commit -m "docs: document parameter API authentication"
~~~

### Task 6: Full verification and deployment smoke test

**Files:**
- No source changes expected; inspect git status and generated runtime state.

**Interfaces:**
- The final image starts only when both secret files are mounted.
- The health check works without an API key.
- Parameter CRUD works with the API key and rejects unauthenticated requests.
- SQLite still contains encrypted BLOB values, not plaintext.

- [ ] **Step 1: Run the complete test suite with warnings treated as errors**

Run:

~~~bash
docker compose run --rm --no-deps -v "$PWD:/workspace" -w /workspace \
  --entrypoint python parameter-store \
  -W error -m unittest discover -v
~~~

Expected: every test passes and no warnings are emitted.

- [ ] **Step 2: Build and validate Compose**

Run:

~~~bash
docker compose build
docker compose config --quiet
~~~

Expected: the image builds successfully and Compose validates with exit code 0.

- [ ] **Step 3: Recreate the service and verify public routes**

Run:

~~~bash
docker compose up -d --force-recreate
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/api/parameters
~~~

Expected: health and root return 200; the API request returns 401, WWW-Authenticate: Bearer, and {"error":"unauthorized"}. Do not put a real API key in command output or shell history.

- [ ] **Step 4: Verify authenticated CRUD and encrypted SQLite storage without printing secrets**

Use a shell variable loaded from the ignored API-key file and make a temporary parameter value that is safe for the test. Capture only status codes/JSON structure, then inspect SQLite with a script that prints the SQLite type and whether the known test value occurs, never the stored blob or key:

~~~bash
API_KEY="$(tr -d '\n' < parameter-store-api.key)"
curl --fail -H "Authorization: Bearer ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"parameter":"verification","value":"container-test-value"}' \
  http://127.0.0.1:8080/api/parameters
curl --fail -H "Authorization: Bearer ${API_KEY}" \
  http://127.0.0.1:8080/api/parameters/verification
~~~

Verify the response value is returned only for the authenticated request, then delete the temporary parameter with the same header. Query SQLite using a one-off read-only inspection that prints typeof(value) and a boolean plaintext check, not the value itself.

- [ ] **Step 5: Confirm final repository and runtime state**

Run:

~~~bash
git status --short
git log --oneline -8
docker compose ps
~~~

Expected: only the ignored runtime key/data files are outside Git, the service is healthy, and all feature commits are present. Do not clean volumes or remove the active image unless explicitly requested; preserve the running deployment and database.
