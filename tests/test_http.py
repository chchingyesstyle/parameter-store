import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app import create_server


class HttpApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = create_server("127.0.0.1", 0, Path(self.tmp.name) / "parameters.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def request_json(self, path, method="GET", payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def request_text(self, path):
        request = Request(self.base_url + path, method="GET")
        with urlopen(request, timeout=5) as response:
            return response.status, response.headers, response.read().decode("utf-8")

    def request_json_allow_error(self, path, method="GET", payload=None):
        try:
            return self.request_json(path, method, payload)
        except HTTPError as error:
            body = json.loads(error.read().decode("utf-8"))
            return error.code, body

    def request_raw(self, path, body, method="POST"):
        request = Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json"},
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

    def test_root_serves_panel_and_health_endpoint_is_ok(self):
        status, headers, body = self.request_text("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get_content_type())
        self.assertIn("Parameter Store", body)

        status, result = self.request_json("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(result, {"status": "ok"})

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
                b"Content-Type: application/json\r\n"
                b"Content-Length: 100\r\n"
                b"Connection: close\r\n\r\n"
                b"{}"
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
            b"Content-Type: application/json\r\n"
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


if __name__ == "__main__":
    unittest.main()
