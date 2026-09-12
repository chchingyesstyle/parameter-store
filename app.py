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
import threading
import time
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
MAX_TAG_LENGTH = 64
MAX_TAGS = 32
MAX_ENV_LENGTH = 64
MAX_JSON_NESTING = 64
KEY_LENGTH = 32
WEB_SESSION_COOKIE = "parameter_store_session"
WEB_SESSION_TTL = 8 * 60 * 60
NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16
ENCRYPTION_VERSION = b"\x01"
AAD_PREFIX = b"parameter-store:v1:"
REQUEST_HEADER_READ_TIMEOUT = 1.0
REQUEST_BODY_READ_TIMEOUT = 1.0
PARAMETER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class ParameterError(ValueError):
    """Raised when a parameter name or value is invalid."""


class ParameterConflictError(ParameterError):
    """Raised when an edit would rename a parameter to an existing name."""


class ParameterNotFoundError(ParameterError):
    """Raised when an edit targets a parameter that does not exist."""


class EncryptionKeyError(ValueError):
    """Raised when the configured encryption key cannot be used."""


class APIKeyError(ValueError):
    """Raised when the configured API key cannot be used."""


class StorageIntegrityError(RuntimeError):
    """Raised when an encrypted database value cannot be authenticated."""


def _json_exceeds_nesting_limit(raw_value: Any) -> bool:
    if isinstance(raw_value, str):
        opening = "[{"
        closing = "]}"
        quote = '"'
        escape = "\\"
    elif isinstance(raw_value, (bytes, bytearray, memoryview)):
        raw_value = bytes(raw_value)
        opening = (ord("["), ord("{"))
        closing = (ord("]"), ord("}"))
        quote = ord('"')
        escape = ord("\\")
    else:
        return False

    depth = 0
    in_string = False
    escaped = False
    for character in raw_value:
        if in_string:
            if escaped:
                escaped = False
            elif character == escape:
                escaped = True
            elif character == quote:
                in_string = False
        elif character == quote:
            in_string = True
        elif character in opening:
            depth += 1
            if depth > MAX_JSON_NESTING:
                return True
        elif character in closing and depth:
            depth -= 1
    return False


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
                    updated_at TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '[]',
                    env TEXT NOT NULL DEFAULT ''
                )
                """
            )
            self._migrate_metadata_columns(connection)
            self._migrate_legacy_values(connection)

    @staticmethod
    def _migrate_metadata_columns(connection: sqlite3.Connection) -> None:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(parameters)")}
        if "tags" not in columns:
            connection.execute("ALTER TABLE parameters ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'")
        if "env" not in columns:
            connection.execute("ALTER TABLE parameters ADD COLUMN env TEXT NOT NULL DEFAULT ''")

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

    @staticmethod
    def _validate_metadata(tags: list[str], env: str) -> tuple[list[str], str]:
        if not isinstance(tags, list):
            raise ParameterError("tags must be a list of strings")
        normalized_tags = []
        for tag in tags:
            if not isinstance(tag, str) or not tag.strip() or len(tag) > MAX_TAG_LENGTH:
                raise ParameterError("tags must contain non-empty strings of at most 64 characters")
            tag = tag.strip()
            try:
                tag.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ParameterError("tags must contain valid Unicode strings") from exc
            if tag in normalized_tags:
                raise ParameterError("tags must not contain duplicate values")
            normalized_tags.append(tag)
        if len(normalized_tags) > MAX_TAGS:
            raise ParameterError("tags cannot contain more than 32 values")
        if not isinstance(env, str) or len(env) > MAX_ENV_LENGTH:
            raise ParameterError("env must be a string of at most 64 characters")
        try:
            env = env.strip()
            env.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ParameterError("env must contain valid Unicode characters") from exc
        return normalized_tags, env

    @classmethod
    def _decode_tags(cls, raw_tags: Any) -> list[str]:
        if _json_exceeds_nesting_limit(raw_tags):
            raise StorageIntegrityError("stored metadata is invalid")
        try:
            tags = _json.loads(raw_tags)
        except (TypeError, ValueError, RecursionError) as exc:
            raise StorageIntegrityError("stored metadata is invalid") from exc
        try:
            tags, _ = cls._validate_metadata(tags, "")
        except ParameterError as exc:
            raise StorageIntegrityError("stored metadata is invalid") from exc
        return tags

    @staticmethod
    def _decode_env(raw_env: Any) -> str:
        if not isinstance(raw_env, str) or len(raw_env) > MAX_ENV_LENGTH:
            raise StorageIntegrityError("stored metadata is invalid")
        try:
            raw_env.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise StorageIntegrityError("stored metadata is invalid") from exc
        return raw_env

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

    def put_with_metadata(
        self, parameter: str, value: str, tags: list[str], env: str
    ) -> None:
        parameter = self._validate_parameter(parameter)
        value = self._validate_value(value)
        tags, env = self._validate_metadata(tags, env)
        encrypted_value = self._cipher.encrypt(parameter, value)
        updated_at = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO parameters(parameter, value, updated_at, tags, env)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(parameter) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at,
                    tags = excluded.tags,
                    env = excluded.env
                """,
                (parameter, encrypted_value, updated_at, _json.dumps(tags), env),
            )

    def update_with_metadata(
        self,
        source_parameter: str,
        parameter: str,
        value: str,
        tags: list[str],
        env: str,
    ) -> None:
        source_parameter = self._validate_parameter(source_parameter)
        parameter = self._validate_parameter(parameter)
        value = self._validate_value(value)
        tags, env = self._validate_metadata(tags, env)
        encrypted_value = self._cipher.encrypt(parameter, value)
        updated_at = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            source_exists = connection.execute(
                "SELECT 1 FROM parameters WHERE parameter = ?", (source_parameter,)
            ).fetchone()
            if source_exists is None:
                raise ParameterNotFoundError("parameter not found")
            if source_parameter != parameter:
                target_exists = connection.execute(
                    "SELECT 1 FROM parameters WHERE parameter = ?", (parameter,)
                ).fetchone()
                if target_exists is not None:
                    raise ParameterConflictError("parameter already exists")
            try:
                result = connection.execute(
                    """
                    UPDATE parameters
                    SET parameter = ?, value = ?, updated_at = ?, tags = ?, env = ?
                    WHERE parameter = ?
                    """,
                    (parameter, encrypted_value, updated_at, _json.dumps(tags), env, source_parameter),
                )
            except sqlite3.IntegrityError as exc:
                raise ParameterConflictError("parameter already exists") from exc
            if result.rowcount != 1:
                raise ParameterNotFoundError("parameter not found")

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

    def list_metadata(
        self, query: str = "", tag: str = "", env: str = ""
    ) -> list[dict[str, Any]]:
        if not isinstance(query, str) or not isinstance(tag, str) or not isinstance(env, str):
            raise ParameterError("metadata filters must be strings")
        query = query[:MAX_PARAMETER_LENGTH]
        tag = tag.strip()[:MAX_TAG_LENGTH]
        env = env.strip()[:MAX_ENV_LENGTH]
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT parameter, value, updated_at, tags, env FROM parameters ORDER BY parameter COLLATE NOCASE"
            ).fetchall()
        items = []
        for row in rows:
            tags = self._decode_tags(row["tags"])
            row_env = self._decode_env(row["env"])
            haystack = " ".join([row["parameter"], *tags, row_env]).casefold()
            if query.casefold() not in haystack:
                continue
            if tag and tag.casefold() not in {item.casefold() for item in tags}:
                continue
            if env and env.casefold() != row_env.casefold():
                continue
            items.append(
                {
                    "parameter": row["parameter"],
                    "value": self._decrypt_value(row["parameter"], row["value"]),
                    "updated_at": row["updated_at"],
                    "tags": tags,
                    "env": row_env,
                }
            )
        return items

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
        response_headers = {"Cache-Control": "no-store"}
        response_headers.update(headers or {})
        if "Vary" not in response_headers and "Set-Cookie" not in response_headers:
            response_headers["Vary"] = "Cookie"
        for name, value in response_headers.items():
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
            body_text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("request body must be valid JSON") from exc
        if _json_exceeds_nesting_limit(body_text):
            raise ValueError("request body is too deeply nested")
        try:
            payload = json.loads(body_text)
        except (json.JSONDecodeError, RecursionError) as exc:
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

    def _web_session_token(self) -> str | None:
        prefix = WEB_SESSION_COOKIE + "="
        for cookie in self.headers.get("Cookie", "").split(";"):
            cookie = cookie.strip()
            if cookie.startswith(prefix):
                return cookie[len(prefix) :]
        return None

    def _require_web_session(self) -> bool:
        token = self._web_session_token()
        if token is None or not self.server.has_web_session(token):  # type: ignore[attr-defined]
            self._send_json(401, {"error": "unauthorized"})
            return False
        return True

    def _web_parameter_from_path(self, path: str) -> str:
        parts = path.rstrip("/").split("/")
        if len(parts) != 4 or parts[:3] != ["", "web", "parameters"]:
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
        if parsed.path == "/web/parameters":
            if not self._require_web_session():
                return
            filters = parse_qs(parsed.query)
            try:
                items = self.store.list_metadata(
                    filters.get("q", [""])[0],
                    filters.get("tag", [""])[0],
                    filters.get("env", [""])[0],
                )
            except (sqlite3.Error, StorageIntegrityError):
                self._send_storage_unavailable()
                return
            self._send_json(
                200,
                {"items": items},
                headers={"Cache-Control": "no-store", "Vary": "Cookie"},
            )
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
        if parsed.path == "/web/logout":
            token = self._web_session_token()
            if token:
                self.server.revoke_web_session(token)  # type: ignore[attr-defined]
            self._send_json(
                200,
                {"status": "logged_out"},
                headers={
                    "Set-Cookie": f"{WEB_SESSION_COOKIE}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"
                },
            )
            return
        if parsed.path == "/web/login":
            try:
                payload = self._read_json()
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            username = payload.get("username")
            password = payload.get("password")
            configured_username = self.server.web_username  # type: ignore[attr-defined]
            configured_password = self.server.web_password  # type: ignore[attr-defined]
            if not isinstance(username, str) or not isinstance(password, str):
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                username_bytes = username.encode("utf-8")
                password_bytes = password.encode("utf-8")
                configured_username_bytes = configured_username.encode("utf-8")
                configured_password_bytes = configured_password.encode("utf-8")
            except UnicodeEncodeError:
                self._send_json(401, {"error": "unauthorized"})
                return
            if not (
                _secrets.compare_digest(username_bytes, configured_username_bytes)
                and _secrets.compare_digest(password_bytes, configured_password_bytes)
            ):
                self._send_json(401, {"error": "unauthorized"})
                return
            token = self.server.create_web_session()  # type: ignore[attr-defined]
            self._send_json(
                200,
                {"status": "ok"},
                headers={
                    "Set-Cookie": f"{WEB_SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"
                },
            )
            return
        if parsed.path == "/web/parameters":
            if not self._require_web_session():
                return
            try:
                payload = self._read_json()
                self.store.put_with_metadata(
                    payload["parameter"],
                    payload["value"],
                    payload.get("tags", []),
                    payload.get("env", ""),
                )
            except sqlite3.Error:
                self._send_storage_unavailable()
                return
            except (KeyError, TypeError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(201, {"status": "saved"})
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
        if parsed.path.startswith("/web/parameters/"):
            if not self._require_web_session():
                return
            try:
                source_parameter = self._web_parameter_from_path(parsed.path)
                payload = self._read_json()
                self.store.update_with_metadata(
                    source_parameter,
                    payload.get("parameter", source_parameter),
                    payload["value"],
                    payload.get("tags", []),
                    payload.get("env", ""),
                )
            except sqlite3.Error:
                self._send_storage_unavailable()
                return
            except ParameterConflictError as exc:
                self._send_json(409, {"error": str(exc)})
                return
            except ParameterNotFoundError as exc:
                self._send_json(404, {"error": str(exc)})
                return
            except (KeyError, TypeError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(200, {"status": "saved"})
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
        if parsed.path.startswith("/web/parameters/"):
            if not self._require_web_session():
                return
            try:
                parameter = self._web_parameter_from_path(parsed.path)
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
        self,
        server_address: tuple[str, int],
        store: ParameterStore,
        api_key: bytes,
        web_username: str = "admin",
        web_password: str = "Abc12345",
    ):
        self.store = store
        self.api_key = api_key
        self.web_username = web_username
        self.web_password = web_password
        self.web_sessions: dict[str, float] = {}
        self.web_sessions_lock = threading.Lock()
        super().__init__(server_address, ParameterRequestHandler)

    def create_web_session(self) -> str:
        token = _secrets.token_urlsafe(32)
        now = time.monotonic()
        with self.web_sessions_lock:
            self.web_sessions = {
                session: expiry
                for session, expiry in self.web_sessions.items()
                if expiry > now
            }
            self.web_sessions[token] = now + WEB_SESSION_TTL
        return token

    def revoke_web_session(self, token: str) -> None:
        with self.web_sessions_lock:
            self.web_sessions.pop(token, None)

    def has_web_session(self, token: str) -> bool:
        with self.web_sessions_lock:
            expiry = self.web_sessions.get(token)
            if expiry is None:
                return False
            if expiry <= time.monotonic():
                del self.web_sessions[token]
                return False
            return True


def create_server(
    host: str,
    port: int,
    database_path: Path | str,
    encryption_key: bytes,
    api_key: bytes,
    web_username: str = "admin",
    web_password: str = "Abc12345",
) -> ParameterHTTPServer:
    return ParameterHTTPServer(
        (host, port),
        ParameterStore(database_path, encryption_key),
        api_key,
        web_username,
        web_password,
    )


FRONTEND_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Parameter Store</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { max-width: 1180px; margin: 2rem auto; padding: 0 1rem; }
    h1 { margin-bottom: .25rem; }
    .subtitle { color: #888; margin-top: 0; }
    .warning { border: 1px solid #d97706; border-radius: .5rem; padding: .75rem; }
    #unlock-panel { max-width: 32rem; }
    form, .toolbar { display: flex; gap: .5rem; flex-wrap: wrap; margin: 1rem 0; }
    #unlock-form { display: grid; gap: .5rem; }
    .login-field { display: grid; grid-template-columns: 7rem minmax(0, 1fr); align-items: center; gap: .5rem; }
    #unlock-form button { justify-self: start; }
    input, button { font: inherit; padding: .55rem; }
    input[name=parameter] { min-width: 14rem; }
    input[name=value] { flex: 1; min-width: 18rem; }
    input[name=tags] { min-width: 18rem; }
    input[name=env] { width: 9rem; }
    dialog { border: 1px solid #8885; border-radius: .75rem; color: inherit; background: Canvas; max-width: min(40rem, calc(100vw - 2rem)); width: 100%; }
    dialog::backdrop { background: #0008; }
    #edit-form { display: grid; gap: .75rem; margin: 0; }
    .edit-field { display: grid; gap: .25rem; }
    .edit-field input, .edit-field textarea { width: 100%; box-sizing: border-box; }
    .edit-field textarea { min-height: 8rem; resize: vertical; }
    .edit-actions { display: flex; gap: .5rem; justify-content: flex-end; }
    table { border-collapse: collapse; width: 100%; }
    th, td { text-align: left; border-bottom: 1px solid #8885; padding: .55rem; vertical-align: top; }
    th { white-space: nowrap; }
    td.value { white-space: pre-wrap; overflow-wrap: anywhere; max-width: 30rem; }
    td.actions { white-space: nowrap; }
    .tag { display: inline-block; border-radius: 999px; padding: .15rem .5rem; margin: .1rem .15rem .1rem 0; background: #dbeafe; color: #1e3a8a; font-size: .8rem; }
    .env { font-weight: 600; }
    button { cursor: pointer; }
    #message, #unlock-message { min-height: 1.5rem; }
    @media (max-width: 760px) {
      .login-field { grid-template-columns: 1fr; }
      table { font-size: .88rem; }
      th, td { padding: .4rem; }
      .updated { display: none; }
    }
  </style>
</head>
<body>
  <h1>Parameter Store</h1>
  <section id="unlock-panel">
    <h2>Unlock</h2>
    <form id="unlock-form">
      <div class="login-field">
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required>
      </div>
      <div class="login-field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit">Unlock</button>
    </form>
    <p id="unlock-message" role="status"></p>
  </section>
  <section id="parameter-panel" hidden>
    <p class="subtitle">Encrypted parameters · dense table view</p>
    <form id="add-form">
      <input name="parameter" placeholder="parameter" maxlength="128" required pattern="[A-Za-z0-9][A-Za-z0-9_.:-]*">
      <input name="value" placeholder="value" maxlength="65536" required>
      <input name="tags" placeholder="tags, comma-separated" maxlength="2048">
      <input name="env" placeholder="Env" maxlength="64">
      <button type="submit">+ Add parameter</button>
    </form>
    <div class="toolbar">
      <input id="search" placeholder="Search name, tag, env" autocomplete="off">
      <input id="tag-filter" placeholder="Filter tag" autocomplete="off">
      <input id="env-filter" placeholder="Filter Env" autocomplete="off">
      <button id="refresh" type="button">Refresh</button>
      <button id="lock" type="button">Lock</button>
    </div>
    <p id="message" role="status"></p>
    <table>
      <thead><tr><th>Parameter</th><th>Tags</th><th>Env</th><th>Value</th><th class="updated">Updated</th><th>Actions</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </section>
  <dialog id="edit-dialog" aria-labelledby="edit-title">
    <form id="edit-form">
      <h2 id="edit-title">Edit parameter</h2>
      <div class="edit-field">
        <label for="edit-parameter">Parameter</label>
        <input id="edit-parameter" name="parameter" maxlength="128" required pattern="[A-Za-z0-9][A-Za-z0-9_.:-]*">
      </div>
      <div class="edit-field">
        <label for="edit-value">Value</label>
        <textarea id="edit-value" name="value" maxlength="65536" required></textarea>
      </div>
      <div class="edit-field">
        <label for="edit-tags">Tags</label>
        <input id="edit-tags" name="tags" placeholder="tags, comma-separated" maxlength="2048">
      </div>
      <div class="edit-field">
        <label for="edit-env">Env</label>
        <input id="edit-env" name="env" maxlength="64">
      </div>
      <div class="edit-actions">
        <button id="edit-cancel" type="button">Cancel</button>
        <button type="submit">Save changes</button>
      </div>
    </form>
  </dialog>
<script>
const unlockPanel = document.querySelector('#unlock-panel');
const unlockForm = document.querySelector('#unlock-form');
const usernameInput = document.querySelector('#username');
const passwordInput = document.querySelector('#password');
const unlockMessage = document.querySelector('#unlock-message');
const parameterPanel = document.querySelector('#parameter-panel');
const form = document.querySelector('#add-form');
const search = document.querySelector('#search');
const tagFilter = document.querySelector('#tag-filter');
const envFilter = document.querySelector('#env-filter');
const rows = document.querySelector('#rows');
const message = document.querySelector('#message');
const editDialog = document.querySelector('#edit-dialog');
const editForm = document.querySelector('#edit-form');
const editParameter = document.querySelector('#edit-parameter');
const editValue = document.querySelector('#edit-value');
const editTags = document.querySelector('#edit-tags');
const editEnv = document.querySelector('#edit-env');
let editSourceParameter = '';
let loadSequence = 0;

function showUnlockMessage(text, isError = false) {
  unlockMessage.textContent = text;
  unlockMessage.style.color = isError ? '#dc2626' : '';
}

async function lockPanel() {
  loadSequence++;
  try { await request('/web/logout', {method: 'POST'}); } catch (_error) {}
  usernameInput.value = '';
  passwordInput.value = '';
  form.reset();
  editForm.reset();
  editSourceParameter = '';
  if (editDialog.open) editDialog.close();
  rows.replaceChildren();
  parameterPanel.hidden = true;
  unlockPanel.hidden = false;
  showUnlockMessage('Enter username and password to unlock');
  usernameInput.focus();
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

function openEditDialog(item) {
  editSourceParameter = item.parameter;
  editParameter.value = item.parameter;
  editValue.value = item.value;
  editTags.value = item.tags.join(', ');
  editEnv.value = item.env;
  editDialog.showModal();
  editParameter.focus();
}

function render(items) {
  rows.replaceChildren();
  for (const item of items) {
    const row = document.createElement('tr');
    const name = document.createElement('td');
    name.textContent = item.parameter;
    const tags = document.createElement('td');
    for (const tag of item.tags) { const pill = document.createElement('span'); pill.className = 'tag'; pill.textContent = tag; tags.append(pill); }
    const env = document.createElement('td');
    env.className = 'env'; env.textContent = item.env || '—';
    const value = document.createElement('td');
    value.className = 'value'; value.textContent = item.value;
    const updated = document.createElement('td');
    updated.className = 'updated'; updated.textContent = item.updated_at;
    const actions = document.createElement('td'); actions.className = 'actions';
    const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = 'Copy'; copy.onclick = () => copyValue(item.value);
    const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = 'Edit'; edit.onclick = () => openEditDialog(item);
    const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Delete';
    remove.onclick = async () => {
      if (!window.confirm('Delete ' + item.parameter + '?')) return;
      try { await request('/web/parameters/' + encodeURIComponent(item.parameter), {method: 'DELETE'}); await load(); showMessage('Deleted'); }
      catch (error) { showMessage(error.message, true); }
    };
    actions.append(copy, document.createTextNode(' '), edit, document.createTextNode(' '), remove);
    row.append(name, tags, env, value, updated, actions); rows.append(row);
  }
}

async function load() {
  const requestId = ++loadSequence;
  const params = new URLSearchParams({q: search.value, tag: tagFilter.value, env: envFilter.value});
  const result = await request('/web/parameters?' + params);
  if (requestId !== loadSequence) return;
  render(result.items);
}

editForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(editForm);
  try {
    const tags = String(formData.get('tags') || '').split(',').map(value => value.trim()).filter(Boolean);
    await request('/web/parameters/' + encodeURIComponent(editSourceParameter), {
      method: 'PUT',
      body: JSON.stringify({
        parameter: String(formData.get('parameter') || ''),
        value: String(formData.get('value') || ''),
        tags,
        env: String(formData.get('env') || '').trim()
      })
    });
    editDialog.close();
    editSourceParameter = '';
    await load();
    showMessage('Saved');
  } catch (error) { showMessage(error.message, true); }
});
document.querySelector('#edit-cancel').addEventListener('click', () => editDialog.close());

unlockForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!usernameInput.value.trim() || !passwordInput.value) { showUnlockMessage('Enter username and password', true); return; }
  try {
    await request('/web/login', {method: 'POST', body: JSON.stringify({username: usernameInput.value, password: passwordInput.value})});
    passwordInput.value = ''; await load(); unlockPanelAfterAuthentication(); showMessage('Unlocked');
  } catch (error) { showUnlockMessage(error.message, true); }
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(form);
  try {
    const tags = String(formData.get('tags') || '').split(',').map(value => value.trim()).filter(Boolean);
    await request('/web/parameters', {method: 'POST', body: JSON.stringify({parameter: formData.get('parameter'), value: formData.get('value'), tags, env: formData.get('env') || ''})});
    form.reset(); await load(); showMessage('Saved');
  } catch (error) { showMessage(error.message, true); }
});
for (const filter of [search, tagFilter, envFilter]) filter.addEventListener('input', () => load().catch(error => showMessage(error.message, true)));
document.querySelector('#refresh').addEventListener('click', () => load().catch(error => showMessage(error.message, true)));
document.querySelector('#lock').addEventListener('click', lockPanel);
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
    web_username = os.environ.get("WEB_USERNAME", "admin")
    web_password = os.environ.get("WEB_PASSWORD", "Abc12345")
    if not web_username or not web_password:
        raise ValueError("WEB_USERNAME and WEB_PASSWORD must not be empty")
    server = create_server(
        host,
        port,
        data_dir / "parameters.db",
        encryption_key,
        api_key,
        web_username,
        web_password,
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
