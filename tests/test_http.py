import base64
import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app import create_server


TEST_KEY = b"k" * 32
TEST_API_KEY = b"a" * 32
TEST_API_TOKEN = base64.b64encode(TEST_API_KEY).decode("ascii")
AUTHORIZATION = f"Bearer {TEST_API_TOKEN}"
AUTHORIZATION_HEADER = f"Authorization: {AUTHORIZATION}\r\n".encode("ascii")


class HttpApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = create_server(
            "127.0.0.1",
            0,
            Path(self.tmp.name) / "parameters.db",
            TEST_KEY,
            TEST_API_KEY,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    @staticmethod
    def request_headers(authorization="valid"):
        headers = {"Content-Type": "application/json"}
        if authorization == "valid":
            headers["Authorization"] = AUTHORIZATION
        elif authorization is not None:
            headers["Authorization"] = authorization
        return headers

    def request_json(self, path, method="GET", payload=None, authorization="valid"):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=data,
            method=method,
            headers=self.request_headers(authorization),
        )
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def request_text(self, path):
        request = Request(self.base_url + path, method="GET")
        with urlopen(request, timeout=5) as response:
            return response.status, response.headers, response.read().decode("utf-8")

    def request_json_allow_error(
        self, path, method="GET", payload=None, authorization="valid"
    ):
        try:
            return self.request_json(path, method, payload, authorization)
        except HTTPError as error:
            body = json.loads(error.read().decode("utf-8"))
            return error.code, body

    def request_web_json(self, path, method="GET", payload=None, cookie=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        request = Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with urlopen(request, timeout=5) as response:
                return (
                    response.status,
                    json.loads(response.read().decode("utf-8")),
                    response.headers,
                )
        except HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8")), error.headers

    def request_json_error(
        self, path, method="GET", payload=None, authorization=None
    ):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=data,
            method=method,
            headers=self.request_headers(authorization),
        )
        try:
            with urlopen(request, timeout=5) as response:
                return (
                    response.status,
                    json.loads(response.read().decode("utf-8")),
                    response.headers,
                )
        except HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8")), error.headers

    def request_raw(self, path, body, method="POST", authorization="valid"):
        request = Request(
            self.base_url + path,
            data=body,
            method=method,
            headers=self.request_headers(authorization),
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    def request_wire(self, wire):
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            try:
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except (ConnectionResetError, socket.timeout):
                pass
        return b"".join(chunks)

    def test_post_creates_and_get_returns_parameter(self):
        status, saved = self.request_json(
            "/api/parameters", "POST", {"parameter": "region", "value": "eu-west-2"}
        )

        self.assertEqual(status, 201)
        self.assertEqual(saved, {"status": "saved"})

        status, result = self.request_json("/api/parameters/region")

        self.assertEqual(status, 200)
        self.assertEqual(result["parameter"], "region")
        self.assertEqual(result["value"], "eu-west-2")

    def test_get_list_returns_saved_parameters(self):
        self.request_json(
            "/api/parameters", "POST", {"parameter": "region", "value": "eu-west-2"}
        )

        status, result = self.request_json("/api/parameters")

        self.assertEqual(status, 200)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["parameter"], "region")
        self.assertEqual(result["items"][0]["value"], "eu-west-2")

    def test_get_list_query_filters_parameter_names(self):
        self.request_json(
            "/api/parameters", "POST", {"parameter": "region", "value": "eu-west-2"}
        )
        self.request_json(
            "/api/parameters", "POST", {"parameter": "zone", "value": "2a"}
        )

        status, result = self.request_json("/api/parameters?q=reg")

        self.assertEqual(status, 200)
        self.assertEqual([item["parameter"] for item in result["items"]], ["region"])

    def test_put_updates_parameter(self):
        self.request_json(
            "/api/parameters", "POST", {"parameter": "region", "value": "eu-west-2"}
        )

        status, saved = self.request_json(
            "/api/parameters/region", "PUT", {"value": "eu-west-1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(saved, {"status": "saved"})

        _, result = self.request_json("/api/parameters/region")
        self.assertEqual(result["value"], "eu-west-1")

    def test_delete_removes_parameter(self):
        self.request_json(
            "/api/parameters", "POST", {"parameter": "temporary", "value": "value"}
        )

        status, deleted = self.request_json("/api/parameters/temporary", "DELETE")
        self.assertEqual(status, 200)
        self.assertEqual(deleted, {"status": "deleted"})

        _, result = self.request_json("/api/parameters")
        self.assertEqual(result["items"], [])

    def test_root_and_health_remain_public(self):
        status, headers, body = self.request_text("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get_content_type())
        self.assertIn("Parameter Store", body)

        status, result = self.request_json("/healthz", authorization=None)
        self.assertEqual(status, 200)
        self.assertEqual(result, {"status": "ok"})

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
            "/api/parameters",
            "POST",
            {"not": "valid for this test"},
            authorization=None,
        )

        self.assertEqual(status, 401)
        self.assertEqual(result, {"error": "unauthorized"})

    def test_web_panel_starts_locked_and_uses_username_password_login(self):
        _, _, body = self.request_text("/")
        self.assertIn('id="unlock-panel"', body)
        self.assertIn('id="username"', body)
        self.assertIn('id="password"', body)
        self.assertIn('id="parameter-panel" hidden', body)
        self.assertNotIn('id="api-key"', body)
        self.assertNotIn("localStorage", body)
        self.assertNotIn("sessionStorage", body)

    def test_web_panel_uses_dense_metadata_controls_and_latest_filter_result(self):
        _, _, body = self.request_text("/")
        for element_id in ("tag-filter", "env-filter", "rows"):
            self.assertIn(f'id="{element_id}"', body)
        self.assertIn("let loadSequence = 0", body)
        self.assertIn("if (requestId !== loadSequence) return", body)

    def test_web_login_fields_stay_grouped_in_responsive_layout(self):
        _, _, body = self.request_text("/")
        self.assertEqual(body.count('class="login-field"'), 2)
        self.assertRegex(body, r'class="login-field">\s*<label for="username">Username</label>')
        self.assertRegex(body, r'class="login-field">\s*<label for="password">Password</label>')
        self.assertIn("#unlock-form { display: grid;", body)
        self.assertIn("grid-template-columns: 7rem minmax(0, 1fr)", body)
        self.assertIn("@media (max-width: 760px)", body)
        self.assertIn(".login-field { grid-template-columns: 1fr; }", body)

    def test_web_login_returns_session_cookie_and_lists_metadata(self):
        self.request_json("/api/parameters", "POST", {"parameter": "db", "value": "secret"})
        status, result, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )

        self.assertEqual(status, 200)
        self.assertEqual(result, {"status": "ok"})
        cookie = headers.get("Set-Cookie")
        self.assertTrue(cookie.startswith("parameter_store_session="))

        status, result, _ = self.request_web_json("/web/parameters", cookie=cookie.split(";", 1)[0])
        self.assertEqual(status, 200)
        self.assertEqual(result["items"][0]["parameter"], "db")
        self.assertEqual(result["items"][0]["tags"], [])
        self.assertEqual(result["items"][0]["env"], "")

    def test_authenticated_web_parameter_listing_is_not_cacheable(self):
        _, _, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )
        cookie = headers.get("Set-Cookie").split(";", 1)[0]

        status, _, response_headers = self.request_web_json(
            "/web/parameters", cookie=cookie
        )

        self.assertEqual(status, 200)
        self.assertEqual(response_headers.get("Cache-Control"), "no-store")
        self.assertEqual(response_headers.get("Vary"), "Cookie")

    def test_authenticated_api_responses_are_not_cacheable(self):
        status, _, response_headers = self.request_json_error(
            "/api/parameters", authorization=AUTHORIZATION
        )

        self.assertEqual(status, 200)
        self.assertEqual(response_headers.get("Cache-Control"), "no-store")

    def test_web_save_rejects_unencodable_unicode_tag(self):
        status, _, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie").split(";", 1)[0]

        status, result, _ = self.request_web_json(
            "/web/parameters",
            "POST",
            {"parameter": "bad.tag", "value": "value", "tags": ["bad\ud800"]},
            cookie,
        )

        self.assertEqual(status, 400)
        self.assertIn("error", result)

    def test_web_listing_returns_storage_error_for_deeply_nested_stored_tags(self):
        status, _, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        self.request_web_json(
            "/web/parameters",
            "POST",
            {"parameter": "corrupt.tags", "value": "value"},
            cookie,
        )
        deeply_nested_tags = "[" * 20000 + "0" + "]" * 20000
        with closing(sqlite3.connect(Path(self.tmp.name) / "parameters.db")) as connection, connection:
            connection.execute(
                "UPDATE parameters SET tags = ? WHERE parameter = ?",
                (deeply_nested_tags, "corrupt.tags"),
            )

        status, result, _ = self.request_web_json("/web/parameters", cookie=cookie)

        self.assertEqual(status, 500)
        self.assertEqual(result, {"error": "storage unavailable"})

    def test_web_listing_returns_storage_error_for_unencodable_stored_tag(self):
        status, _, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        self.request_web_json(
            "/web/parameters",
            "POST",
            {"parameter": "corrupt.unicode", "value": "value"},
            cookie,
        )
        with closing(sqlite3.connect(Path(self.tmp.name) / "parameters.db")) as connection, connection:
            connection.execute(
                "UPDATE parameters SET tags = ? WHERE parameter = ?",
                ('["\\ud800"]', "corrupt.unicode"),
            )

        status, result, _ = self.request_web_json("/web/parameters", cookie=cookie)

        self.assertEqual(status, 500)
        self.assertEqual(result, {"error": "storage unavailable"})

    def test_web_login_rejects_excessive_json_nesting(self):
        depth = 65
        nested = b"[" * depth + b"0" + b"]" * depth
        body = b'{"username":' + nested + b',"password":"wrong"}'

        status, result = self.request_raw("/web/login", body)

        self.assertEqual(status, 400)
        self.assertEqual(result, {"error": "request body is too deeply nested"})

    def test_web_login_rejects_malformed_unicode_credentials_without_connection_error(self):
        body = b'{"username":"\\ud800","password":"wrong"}'
        wire = (
            b"POST /web/login HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )

        response = self.request_wire(wire)

        self.assertIn(b" 401 ", response.split(b"\r\n", 1)[0])
        self.assertIn(b'{"error": "unauthorized"}', response)

    def test_web_login_accepts_non_ascii_configured_credentials(self):
        self.server.web_username = "管理員"
        self.server.web_password = "密碼é"

        status, result, _ = self.request_web_json(
            "/web/login", "POST", {"username": "管理員", "password": "密碼é"}
        )

        self.assertEqual(status, 200)
        self.assertEqual(result, {"status": "ok"})

    def test_web_login_rejects_non_ascii_invalid_credentials_without_connection_error(self):
        status, result, _ = self.request_web_json(
            "/web/login", "POST", {"username": "é", "password": "錯誤"}
        )

        self.assertEqual(status, 401)
        self.assertEqual(result, {"error": "unauthorized"})

    def test_web_login_rejects_invalid_credentials(self):
        status, result, _ = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "wrong"}
        )
        self.assertEqual(status, 401)
        self.assertEqual(result, {"error": "unauthorized"})

    def test_web_edit_updates_parameter_value_tags_and_environment(self):
        status, _, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        self.request_web_json(
            "/web/parameters",
            "POST",
            {"parameter": "old.name", "value": "old", "tags": ["old"], "env": "dev"},
            cookie,
        )

        status, result, _ = self.request_web_json(
            "/web/parameters/old.name",
            "PUT",
            {
                "parameter": "new.name",
                "value": "new",
                "tags": ["new", "rotated"],
                "env": "prod",
            },
            cookie,
        )

        self.assertEqual(status, 200)
        self.assertEqual(result, {"status": "saved"})
        _, result, _ = self.request_web_json("/web/parameters", cookie=cookie)
        self.assertEqual(
            result["items"],
            [
                {
                    "parameter": "new.name",
                    "value": "new",
                    "updated_at": result["items"][0]["updated_at"],
                    "tags": ["new", "rotated"],
                    "env": "prod",
                }
            ],
        )

    def test_web_edit_rejects_an_existing_parameter_name(self):
        status, _, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        for parameter, value in (("source", "source-value"), ("target", "target-value")):
            self.request_web_json(
                "/web/parameters",
                "POST",
                {"parameter": parameter, "value": value},
                cookie,
            )

        status, result, _ = self.request_web_json(
            "/web/parameters/source",
            "PUT",
            {"parameter": "target", "value": "replacement", "tags": [], "env": ""},
            cookie,
        )

        self.assertEqual(status, 409)
        self.assertEqual(result, {"error": "parameter already exists"})
        _, result, _ = self.request_web_json("/web/parameters", cookie=cookie)
        values = {item["parameter"]: item["value"] for item in result["items"]}
        self.assertEqual(values, {"source": "source-value", "target": "target-value"})

    def test_web_edit_form_exposes_all_editable_fields(self):
        _, _, body = self.request_text("/")
        self.assertIn('id="edit-dialog"', body)
        self.assertIn('id="edit-form"', body)
        for field in ("edit-parameter", "edit-value", "edit-tags", "edit-env"):
            self.assertIn(f'id="{field}"', body)
        self.assertIn("Save changes", body)
        self.assertIn("Cancel", body)
        self.assertNotIn("New value for ' + item.parameter", body)

    def test_web_metadata_save_updates_value_tags_and_environment(self):
        status, _, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie").split(";", 1)[0]

        status, result, _ = self.request_web_json(
            "/web/parameters",
            "POST",
            {
                "parameter": "api.url",
                "value": "https://api",
                "tags": ["service", "public"],
                "env": "staging",
            },
            cookie,
        )
        self.assertEqual(status, 201)
        self.assertEqual(result, {"status": "saved"})

        _, result, _ = self.request_web_json("/web/parameters?q=service&env=staging", cookie=cookie)
        item = result["items"][0]
        self.assertEqual(item["tags"], ["service", "public"])
        self.assertEqual(item["env"], "staging")

    def test_web_routes_require_session_cookie(self):
        status, result, _ = self.request_web_json("/web/parameters")
        self.assertEqual(status, 401)
        self.assertEqual(result, {"error": "unauthorized"})

    def test_web_logout_revokes_session_and_expires_cookie(self):
        _, _, headers = self.request_web_json(
            "/web/login", "POST", {"username": "admin", "password": "Abc12345"}
        )
        cookie = headers.get("Set-Cookie").split(";", 1)[0]

        status, _, logout_headers = self.request_web_json("/web/logout", "POST", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", logout_headers.get("Set-Cookie"))

        status, result, _ = self.request_web_json("/web/parameters", cookie=cookie)
        self.assertEqual(status, 401)
        self.assertEqual(result, {"error": "unauthorized"})

    def test_web_session_creation_prunes_expired_sessions(self):
        self.server.web_sessions["expired"] = time.monotonic() - 1
        token = self.server.create_web_session()

        self.assertNotIn("expired", self.server.web_sessions)
        self.assertIn(token, self.server.web_sessions)

    def test_deeply_nested_json_returns_bad_request(self):
        nested = b"[" * 2000 + b"0" + b"]" * 2000
        body = b'{"parameter":"nested","value":' + nested + b"}"

        status, result = self.request_raw("/api/parameters", body)

        self.assertEqual(status, 400)
        self.assertIn("error", result)

    def test_json_recursion_error_returns_bad_request(self):
        with patch("app.json.loads", side_effect=RecursionError("too deep")):
            status, result = self.request_raw(
                "/api/parameters", b'{"parameter":"x","value":"y"}'
            )

        self.assertEqual(status, 400)
        self.assertIn("error", result)

    def test_incomplete_body_is_rejected_after_read_timeout(self):
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(
                b"POST /api/parameters HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                + AUTHORIZATION_HEADER
                + b"Content-Type: application/json\r\n"
                + b"Content-Length: 100\r\n"
                + b"Connection: close\r\n\r\n"
                + b"{}"
            )
            response = client.recv(4096)

        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])

    def test_incomplete_request_line_is_closed_after_header_timeout(self):
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3) as client:
            client.settimeout(2)
            client.sendall(b"G")
            started = time.monotonic()
            try:
                response = client.recv(1)
            except (ConnectionResetError, socket.timeout):
                response = b""
            elapsed = time.monotonic() - started

        self.assertEqual(response, b"")
        self.assertLess(elapsed, 1.8)

    def test_short_body_returns_bad_request(self):
        body = b'{"parameter":"short","value":"x"}'
        wire = (
            b"POST /api/parameters HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + AUTHORIZATION_HEADER
            + b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body) + 5}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )

        response = self.request_wire(wire)

        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])

    def test_malformed_request_target_returns_bad_request(self):
        response = self.request_wire(
            b"GET http://[::1 HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n\r\n"
        )

        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])

    def test_storage_failure_returns_internal_server_error(self):
        with patch.object(self.server.store, "put", side_effect=sqlite3.OperationalError("offline")):
            status, result = self.request_json_allow_error(
                "/api/parameters", "POST", {"parameter": "x", "value": "y"}
            )

        self.assertEqual(status, 500)
        self.assertEqual(result, {"error": "storage unavailable"})

    def test_tampered_value_returns_generic_storage_error(self):
        self.request_json(
            "/api/parameters", "POST", {"parameter": "token", "value": "secret"}
        )
        with closing(sqlite3.connect(Path(self.tmp.name) / "parameters.db")) as connection, connection:
            connection.execute(
                "UPDATE parameters SET value = ? WHERE parameter = ?",
                (b"not-a-valid-ciphertext", "token"),
            )

        status, result = self.request_json_allow_error("/api/parameters/token")

        self.assertEqual(status, 500)
        self.assertEqual(result, {"error": "storage unavailable"})


if __name__ == "__main__":
    unittest.main()
