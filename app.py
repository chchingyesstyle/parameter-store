#!/usr/bin/env python3
"""Small encrypted parameter/value store for a trusted LAN."""

from __future__ import annotations

import base64 as _base64
import binascii as _binascii
import json as _json
import os
import re
import secrets as _secrets
import socket
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from types import SimpleNamespace

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


json = SimpleNamespace(
    dumps=_json.dumps,
    loads=_json.loads,
    JSONDecodeError=_json.JSONDecodeError,
)


MAX_PARAMETER_LENGTH = 128
MAX_VALUE_LENGTH = 64 * 1024
KEY_LENGTH = 32
NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16
ENCRYPTION_VERSION = b"\x01"
AAD_PREFIX = b"parameter-store:v1:"
REQUEST_HEADER_READ_TIMEOUT = 1.0
REQUEST_BODY_READ_TIMEOUT = 1.0
PARAMETER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class ParameterError(ValueError):
    """Raised when a parameter name or value is invalid."""


class EncryptionKeyError(ValueError):
    """Raised when the configured encryption key cannot be used."""


class APIKeyError(ValueError):
    """Raised when the configured API key cannot be used."""


class StorageIntegrityError(RuntimeError):
    """Raised when an encrypted database value cannot be authenticated."""


def load_encryption_key(key_path: Path | str) -> bytes:
    try:
        encoded = Path(key_path).read_bytes().strip()
    except OSError as exc:
        raise EncryptionKeyError("unable to read encryption key file") from exc
    try:
        key = _base64.b64decode(encoded, validate=True)
    except (_binascii.Error, ValueError) as exc:
        raise EncryptionKeyError("encryption key must be valid base64") from exc
    if len(key) != KEY_LENGTH:
        raise EncryptionKeyError("encryption key must decode to exactly 32 bytes")
    return key


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


class ValueCipher:
    """Encrypt and authenticate one parameter value at rest."""

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
            raise EncryptionKeyError("encryption key must be exactly 32 bytes")
        self._cipher = AESGCM(key)

    @staticmethod
    def _associated_data(parameter: str) -> bytes:
        return AAD_PREFIX + parameter.encode("utf-8")

    def encrypt(self, parameter: str, value: str) -> bytes:
        nonce = os.urandom(NONCE_LENGTH)
        ciphertext = self._cipher.encrypt(
            nonce,
            value.encode("utf-8"),
            self._associated_data(parameter),
        )
        return ENCRYPTION_VERSION + nonce + ciphertext

    def decrypt(self, parameter: str, payload: bytes) -> str:
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise StorageIntegrityError("encrypted value failed authentication")
        payload = bytes(payload)
        minimum_length = len(ENCRYPTION_VERSION) + NONCE_LENGTH + GCM_TAG_LENGTH
        if len(payload) < minimum_length or payload[:1] != ENCRYPTION_VERSION:
            raise StorageIntegrityError("encrypted value failed authentication")
        nonce = payload[1 : 1 + NONCE_LENGTH]
        ciphertext = payload[1 + NONCE_LENGTH :]
        try:
            plaintext = self._cipher.decrypt(
                nonce,
                ciphertext,
                self._associated_data(parameter),
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError, ValueError) as exc:
            raise StorageIntegrityError("encrypted value failed authentication") from exc


class ParameterStore:
    """SQLite-backed storage for encrypted text parameters."""

    def __init__(self, database_path: Path | str, encryption_key: bytes):
        self.database_path = Path(database_path)
        self._cipher = ValueCipher(encryption_key)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS parameters (
                    parameter TEXT PRIMARY KEY,
                    value BLOB NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._migrate_legacy_values(connection)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _validate_parameter(parameter: str) -> str:
        if not isinstance(parameter, str):
            raise ParameterError("parameter must be a string")
        if not PARAMETER_PATTERN.fullmatch(parameter):
            raise ParameterError(
                "parameter must start with a letter or number and contain only "
                "letters, numbers, '.', '_', ':' or '-'; maximum 128 characters"
            )
        return parameter

    @staticmethod
    def _validate_value(value: str) -> str:
        if not isinstance(value, str):
            raise ParameterError("value must be a string")
        if len(value.encode("utf-8")) > MAX_VALUE_LENGTH:
            raise ParameterError("value is too large; maximum size is 64 KiB")
        return value

    def _migrate_legacy_values(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute("SELECT parameter, value FROM parameters").fetchall()
        for row in rows:
            raw_value = row["value"]
            if isinstance(raw_value, str):
                parameter = self._validate_parameter(row["parameter"])
                value = self._validate_value(raw_value)
                connection.execute(
                    "UPDATE parameters SET value = ? WHERE parameter = ?",
                    (self._cipher.encrypt(parameter, value), parameter),
                )
            elif not isinstance(raw_value, (bytes, bytearray, memoryview)):
                raise StorageIntegrityError("encrypted value failed authentication")

    def _decrypt_value(self, parameter: str, raw_value: Any) -> str:
        if not isinstance(parameter, str):
            raise StorageIntegrityError("encrypted value failed authentication")
        return self._cipher.decrypt(parameter, raw_value)

    def put(self, parameter: str, value: str) -> None:
        parameter = self._validate_parameter(parameter)
        value = self._validate_value(value)
        encrypted_value = self._cipher.encrypt(parameter, value)
        updated_at = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO parameters(parameter, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(parameter) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (parameter, encrypted_value, updated_at),
            )

    def get(self, parameter: str) -> str | None:
        parameter = self._validate_parameter(parameter)
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT value FROM parameters WHERE parameter = ?", (parameter,)
            ).fetchone()
        return None if row is None else self._decrypt_value(parameter, row["value"])

    def list(self, query: str = "") -> list[dict[str, str]]:
        if not isinstance(query, str):
            raise ParameterError("query must be a string")
        query = query[:MAX_PARAMETER_LENGTH]
        with closing(self._connect()) as connection, connection:
            if query:
                escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                rows = connection.execute(
                    """
                    SELECT parameter, value, updated_at
                    FROM parameters
                    WHERE parameter LIKE ? ESCAPE '\\'
                    ORDER BY parameter COLLATE NOCASE
                    """,
                    (f"%{escaped}%",),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT parameter, value, updated_at
                    FROM parameters
                    ORDER BY parameter COLLATE NOCASE
                    """
                ).fetchall()
        return [
            {
                "parameter": row["parameter"],
                "value": self._decrypt_value(row["parameter"], row["value"]),
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def delete(self, parameter: str) -> bool:
        parameter = self._validate_parameter(parameter)
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                "DELETE FROM parameters WHERE parameter = ?", (parameter,)
            )
        return result.rowcount == 1


class ParameterRequestHandler(BaseHTTPRequestHandler):
    server_version = "ParameterStore/0.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_HEADER_READ_TIMEOUT)

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    @property
    def store(self) -> ParameterStore:
        return self.server.store  # type: ignore[attr-defined]

    @property
    def api_key(self) -> bytes:
        return self.server.api_key  # type: ignore[attr-defined]

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

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

    def _send_html(self) -> None:
        body = FRONTEND_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_request_target(self):
        try:
            return urlparse(self.path)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return None

    def _send_storage_unavailable(self) -> None:
        self._send_json(500, {"error": "storage unavailable"})

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length < 0 or length > 65536:
            raise ValueError("request body is too large")
        previous_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(REQUEST_BODY_READ_TIMEOUT)
            body = self.rfile.read(length)
        except (socket.timeout, TimeoutError) as exc:
            raise ValueError("request body read timed out") from exc
        finally:
            self.connection.settimeout(previous_timeout)
        if len(body) != length:
            raise ValueError("request body is incomplete")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    @staticmethod
    def _parameter_from_path(path: str) -> str:
        parts = path.rstrip("/").split("/")
        if len(parts) != 4 or parts[:3] != ["", "api", "parameters"]:
            raise ValueError("invalid parameter path")
        return unquote(parts[3])

    def do_GET(self) -> None:  # noqa: N802
        parsed = self._parse_request_target()
        if parsed is None:
            return
        if parsed.path == "/":
            self._send_html()
            return
        if parsed.path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        if parsed.path == "/api/parameters":
            if not self._require_api_key():
                return
            query = parse_qs(parsed.query).get("q", [""])[0]
            try:
                items = self.store.list(query)
            except (sqlite3.Error, StorageIntegrityError):
                self._send_storage_unavailable()
                return
            except ParameterError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(200, {"items": items})
            return
        if parsed.path.startswith("/api/parameters/"):
            if not self._require_api_key():
                return
            try:
                parameter = self._parameter_from_path(parsed.path)
                value = self.store.get(parameter)
            except (sqlite3.Error, StorageIntegrityError):
                self._send_storage_unavailable()
                return
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            if value is None:
                self._send_json(404, {"error": "parameter not found"})
            else:
                self._send_json(200, {"parameter": parameter, "value": value})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = self._parse_request_target()
        if parsed is None:
            return
        if parsed.path != "/api/parameters":
            self._send_json(404, {"error": "not found"})
            return
        if not self._require_api_key():
            return
        try:
            payload = self._read_json()
            self.store.put(payload["parameter"], payload["value"])
        except sqlite3.Error:
            self._send_storage_unavailable()
            return
        except (KeyError, TypeError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(201, {"status": "saved"})

    def do_PUT(self) -> None:  # noqa: N802
        parsed = self._parse_request_target()
        if parsed is None:
            return
        if not parsed.path.startswith("/api/parameters/"):
            self._send_json(404, {"error": "not found"})
            return
        if not self._require_api_key():
            return
        try:
            parameter = self._parameter_from_path(parsed.path)
            payload = self._read_json()
            self.store.put(parameter, payload["value"])
        except sqlite3.Error:
            self._send_storage_unavailable()
            return
        except (KeyError, TypeError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, {"status": "saved"})

    def do_DELETE(self) -> None:  # noqa: N802
        parsed = self._parse_request_target()
        if parsed is None:
            return
        if not parsed.path.startswith("/api/parameters/"):
            self._send_json(404, {"error": "not found"})
            return
        if not self._require_api_key():
            return
        try:
            parameter = self._parameter_from_path(parsed.path)
            deleted = self.store.delete(parameter)
        except sqlite3.Error:
            self._send_storage_unavailable()
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        if not deleted:
            self._send_json(404, {"error": "parameter not found"})
            return
        self._send_json(200, {"status": "deleted"})


class ParameterHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(
        self, server_address: tuple[str, int], store: ParameterStore, api_key: bytes
    ):
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


FRONTEND_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Parameter Store</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
    h1 { margin-bottom: .25rem; }
    .warning { border: 1px solid #d97706; border-radius: .5rem; padding: .75rem; }
    #unlock-panel { max-width: 32rem; }
    form, .toolbar { display: flex; gap: .5rem; flex-wrap: wrap; margin: 1rem 0; }
    input, button { font: inherit; padding: .55rem; }
    input[name=parameter] { min-width: 14rem; }
    input[name=value] { flex: 1; min-width: 18rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { text-align: left; border-bottom: 1px solid #8885; padding: .55rem; vertical-align: top; }
    td.value { white-space: pre-wrap; overflow-wrap: anywhere; }
    button { cursor: pointer; }
    #message { min-height: 1.5rem; }
  </style>
</head>
<body>
  <h1>Parameter Store</h1>
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
<script>
const unlockPanel = document.querySelector('#unlock-panel');
const unlockForm = document.querySelector('#unlock-form');
const apiKeyInput = document.querySelector('#api-key');
const unlockMessage = document.querySelector('#unlock-message');
const parameterPanel = document.querySelector('#parameter-panel');
const form = document.querySelector('#add-form');
const search = document.querySelector('#search');
const rows = document.querySelector('#rows');
const message = document.querySelector('#message');
let accessToken = '';

function showUnlockMessage(text, isError = false) {
  unlockMessage.textContent = text;
  unlockMessage.style.color = isError ? '#dc2626' : '';
}

function lockPanel() {
  accessToken = '';
  apiKeyInput.value = '';
  parameterPanel.hidden = true;
  unlockPanel.hidden = false;
  showUnlockMessage('Enter API key to unlock');
  apiKeyInput.focus();
}

function unlockPanelAfterAuthentication() {
  unlockPanel.hidden = true;
  parameterPanel.hidden = false;
  showUnlockMessage('');
}

function showMessage(text, isError = false) {
  message.textContent = text;
  message.style.color = isError ? '#dc2626' : '';
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

async function copyValue(value) {
  try {
    await navigator.clipboard.writeText(value);
    showMessage('Copied');
  } catch (_error) {
    window.prompt('Copy value', value);
  }
}

function render(items) {
  rows.replaceChildren();
  for (const item of items) {
    const row = document.createElement('tr');
    const name = document.createElement('td');
    name.textContent = item.parameter;
    const value = document.createElement('td');
    value.className = 'value';
    value.textContent = item.value;
    const updated = document.createElement('td');
    updated.textContent = item.updated_at;
    const actions = document.createElement('td');
    const copy = document.createElement('button');
    copy.type = 'button'; copy.textContent = 'Copy';
    copy.onclick = () => copyValue(item.value);
    const edit = document.createElement('button');
    edit.type = 'button'; edit.textContent = 'Edit';
    edit.onclick = async () => {
      const next = window.prompt('New value for ' + item.parameter, item.value);
      if (next === null) return;
      try {
        await request('/api/parameters/' + encodeURIComponent(item.parameter), {method: 'PUT', body: JSON.stringify({value: next})});
        await load(); showMessage('Saved');
      } catch (error) { showMessage(error.message, true); }
    };
    const remove = document.createElement('button');
    remove.type = 'button'; remove.textContent = 'Delete';
    remove.onclick = async () => {
      if (!window.confirm('Delete ' + item.parameter + '?')) return;
      try {
        await request('/api/parameters/' + encodeURIComponent(item.parameter), {method: 'DELETE'});
        await load(); showMessage('Deleted');
      } catch (error) { showMessage(error.message, true); }
    };
    actions.append(copy, document.createTextNode(' '), edit, document.createTextNode(' '), remove);
    row.append(name, value, updated, actions);
    rows.append(row);
  }
}

async function load() {
  const result = await request('/api/parameters');
  const query = search.value.toLowerCase();
  render(result.items.filter(item => item.parameter.toLowerCase().includes(query)));
}

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

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(form);
  try {
    await request('/api/parameters', {method: 'POST', body: JSON.stringify({parameter: formData.get('parameter'), value: formData.get('value')})});
    form.reset(); await load(); showMessage('Saved');
  } catch (error) { showMessage(error.message, true); }
});
search.addEventListener('input', () => {
  load().catch(error => showMessage(error.message, true));
});
document.querySelector('#refresh').addEventListener('click', () => {
  load().catch(error => showMessage(error.message, true));
});
lockPanel();
</script>
</body>
</html>
"""


def run() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    data_dir = Path(os.environ.get("DATA_DIR", "./data"))
    key_path = Path(
        os.environ.get("PARAMETER_STORE_KEY_FILE", "/run/secrets/parameter-store.key")
    )
    api_key_path = Path(
        os.environ.get(
            "PARAMETER_STORE_API_KEY_FILE", "/run/secrets/parameter-store-api.key"
        )
    )
    encryption_key = load_encryption_key(key_path)
    api_key = load_api_key(api_key_path)
    server = create_server(
        host, port, data_dir / "parameters.db", encryption_key, api_key
    )
    print(f"Parameter store listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
