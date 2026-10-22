"""Shared fixtures for Vanzik Python SDK tests."""

import json
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import pytest


class MockVanzikHandler(BaseHTTPRequestHandler):
    """Configurable mock for the Vanzik /v1/* endpoints.

    Class-level attributes control the response for each endpoint.
    Override them via the ``mock_server`` fixture's ``handler_class`` before
    the request arrives.

    Requests are served in parallel, so ``last_request_body`` and
    ``last_request_headers`` reflect whichever request wrote last: assert
    on them only after a single call.
    """

    # Default responses (overridden per-test via class attributes)
    check_response = {
        "decision": "ALLOW",
        "reason": "test policy",
        "matched_rule": "allow:test",
    }
    status_response = {"id": "ap_123", "status": "pending"}

    # Sequenced responses. When non-empty, each /v1/check (resp. each
    # /v1/status/*) pops the next item instead of using the static response
    # above. ``status_raw_queue`` items are (code, content_type, body_bytes)
    # so a test can serve a non-JSON poll body. ``request_log`` records every
    # request as {"method", "path", "body"} in arrival order.
    check_response_queue: list = []
    status_response_queue: list = []
    status_raw_queue: list = []
    request_log: list = []

    last_request_body = None
    last_request_headers = None

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        MockVanzikHandler.last_request_body = body
        MockVanzikHandler.last_request_headers = dict(self.headers)
        MockVanzikHandler.request_log.append(
            {"method": "POST", "path": self.path, "body": body}
        )

        if self.path == "/v1/check":
            if MockVanzikHandler.check_response_queue:
                self._json_response(200, MockVanzikHandler.check_response_queue.pop(0))
            else:
                self._json_response(200, self.check_response)
        elif self.path.startswith("/v1/approve/"):
            aid = self.path.split("/")[-1]
            self._json_response(200, {"status": "approved", "id": aid})
        elif self.path.startswith("/v1/deny/"):
            aid = self.path.split("/")[-1]
            self._json_response(200, {"status": "denied", "id": aid})
        else:
            self._json_response(404, {"error": "not found"})

    def do_GET(self):
        MockVanzikHandler.request_log.append(
            {"method": "GET", "path": self.path, "body": b""}
        )
        if self.path.startswith("/v1/status/"):
            if MockVanzikHandler.status_raw_queue:
                code, ctype, raw = MockVanzikHandler.status_raw_queue.pop(0)
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.end_headers()
                self.wfile.write(raw)
            elif MockVanzikHandler.status_response_queue:
                self._json_response(200, MockVanzikHandler.status_response_queue.pop(0))
            else:
                self._json_response(200, self.status_response)
        else:
            self._json_response(404, {"error": "not found"})

    def _json_response(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        pass  # suppress noisy output during tests


class _DeepBacklogHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a larger listen backlog.

    socketserver.TCPServer's default request_queue_size of 5 makes the
    kernel RST overflow connections from the 32-thread burst in
    test_concurrent_tool_calls on CI Linux runners. 128 absorbs it (the
    host's net.core.somaxconn caps the effective value).
    """
    request_queue_size = 128


@pytest.fixture()
def mock_server():
    """Start a mock Vanzik HTTP server on an OS-assigned port.

    Yields the base URL (e.g. ``http://127.0.0.1:54321``).
    Resets class-level response overrides after each test.
    """
    # Threaded: a single-threaded HTTPServer drops concurrent requests with
    # ConnectionResetError under load.
    server = _DeepBacklogHTTPServer(("127.0.0.1", 0), MockVanzikHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()

    # Reset class-level overrides so the next test gets clean defaults
    MockVanzikHandler.check_response = {
        "decision": "ALLOW",
        "reason": "test policy",
        "matched_rule": "allow:test",
    }
    MockVanzikHandler.status_response = {"id": "ap_123", "status": "pending"}
    MockVanzikHandler.check_response_queue = []
    MockVanzikHandler.status_response_queue = []
    MockVanzikHandler.status_raw_queue = []
    MockVanzikHandler.request_log = []
    MockVanzikHandler.last_request_body = None
    MockVanzikHandler.last_request_headers = None
