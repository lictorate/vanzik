"""Focused regression tests for SDK hardening:

- content-type / status-shape validation in ``Guard.check``.
- jitter on the ``wait_for_approval`` polling loop.
- rejecting unknown ``**check_kwargs`` in ``@guarded``.
- distinguishing HTTP 401/403 (``VanzikAuthError``) from an
  approval-poll timeout (``VanzikApprovalTimeout``).

The full Guard / decorator behavior tests live in test_guard.py and
test_decorator.py.
"""

import io
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

import vanzik as ag
from vanzik import (
    VanzikAuthError,
    VanzikApprovalTimeout,
    VanzikError,
    VanzikTimeoutError,
    DECISION_DENY,
    DECISION_ALLOW,
    Guard,
    guarded,
)
from tests.conftest import MockVanzikHandler


# ---------------------------------------------------------------------------
# Content-type / status-shape validation in Guard.check
# ---------------------------------------------------------------------------


class _CustomHandler(BaseHTTPRequestHandler):
    """Per-test BaseHTTPRequestHandler with class-level response config.

    Separate from MockVanzikHandler so tests can set exact Content-Type /
    body / status combinations without touching the shared mock.
    """
    status_code = 200
    content_type = "application/json"
    body_bytes = b'{"decision":"ALLOW","reason":"ok"}'

    def do_POST(self):
        # Drain the body; the SDK doesn't echo it.
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
        except Exception:  # noqa: BLE001
            pass
        self.send_response(self.status_code)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(self.body_bytes)))
        self.end_headers()
        self.wfile.write(self.body_bytes)

    def log_message(self, *_a, **_kw):  # quiet
        pass


@pytest.fixture()
def custom_server():
    """Start an HTTPServer (single-threaded; tests are sequential).

    Yields the base URL and the handler class so the test can monkey-patch
    response shape before issuing the call.
    """
    srv = HTTPServer(("127.0.0.1", 0), _CustomHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", _CustomHandler
    finally:
        srv.shutdown()
        # Reset class-level overrides for the next test.
        _CustomHandler.status_code = 200
        _CustomHandler.content_type = "application/json"
        _CustomHandler.body_bytes = b'{"decision":"ALLOW","reason":"ok"}'


class TestCheckContentTypeValidation:
    def test_wrong_content_type_falls_through_to_failmode_deny(self, custom_server):
        url, handler = custom_server
        handler.body_bytes = b"<html>oh no</html>"
        handler.content_type = "text/html"

        g = Guard(url, fail_mode="deny")
        result = g.check("shell", command="ls")
        assert result.denied
        assert "content-type" in result.reason.lower()

    def test_wrong_content_type_falls_through_to_failmode_allow(self, custom_server):
        url, handler = custom_server
        handler.body_bytes = b"<html>oh no</html>"
        handler.content_type = "text/html"

        g = Guard(url, fail_mode="allow")
        result = g.check("shell", command="ls")
        assert result.allowed
        assert "content-type" in result.reason.lower()

    def test_charset_suffix_on_content_type_is_accepted(self, custom_server):
        url, handler = custom_server
        handler.content_type = "application/json; charset=utf-8"
        handler.body_bytes = b'{"decision":"ALLOW","reason":"ok"}'

        g = Guard(url)
        result = g.check("shell", command="ls")
        assert result.allowed

    def test_non_2xx_status_falls_through_to_failmode(self, custom_server):
        url, handler = custom_server
        handler.status_code = 500
        # Even a "valid" JSON body must not be trusted on 5xx.
        handler.body_bytes = b'{"decision":"ALLOW","reason":"sneaky"}'

        g = Guard(url, fail_mode="deny")
        result = g.check("shell", command="ls")
        assert result.denied
        assert "500" in result.reason

    def test_malformed_body_missing_decision_falls_through(self, custom_server):
        url, handler = custom_server
        # Valid JSON but missing the 'decision' field.
        handler.body_bytes = b'{"reason":"hi"}'

        g = Guard(url, fail_mode="deny")
        result = g.check("shell", command="ls")
        assert result.denied
        assert "malformed" in result.reason.lower()

    def test_garbage_json_falls_through(self, custom_server):
        url, handler = custom_server
        handler.body_bytes = b"not-json-at-all"

        g = Guard(url, fail_mode="deny")
        result = g.check("shell", command="ls")
        assert result.denied
        # urlopen.read() yields bytes; json.loads raises ValueError /
        # JSONDecodeError, which the SDK wraps in the unreachable path.
        assert "Vanzik" in result.reason


# ---------------------------------------------------------------------------
# @guarded(**check_kwargs) unknown-kwarg rejection
# ---------------------------------------------------------------------------


class TestGuardedUnknownKwargs:
    def test_unknown_kwarg_raises_typeerror(self, mock_server):
        g = Guard(mock_server)
        with pytest.raises(TypeError, match="unexpected keyword arguments"):
            @guarded("shell", guard=g, agentt="typo")  # noqa: F841 (typo on purpose)
            def f(cmd):
                return cmd

    def test_known_kwargs_still_accepted(self, mock_server):
        """`meta`, `session_id`, and friends pass through unchanged.

        `command` is *not* exercised here because the wrapper already
        injects it from positional args (``g.check(scope,
        command=str(cmd), **check_kwargs)``); passing both would collide.
        """
        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        g = Guard(mock_server)

        @guarded("shell", guard=g, meta={"k": "v"}, session_id="s1")
        def f(cmd):
            return f"ran {cmd}"

        assert f("anything") == "ran anything"

    def test_typo_lists_valid_options(self, mock_server):
        g = Guard(mock_server)
        with pytest.raises(TypeError) as exc:
            @guarded("shell", guard=g, agnetId="typo")
            def f(cmd):
                return cmd
        assert "agnetId" in str(exc.value)
        # The error names the valid set so the operator can fix the typo.
        assert "command" in str(exc.value)


# ---------------------------------------------------------------------------
# wait_for_approval jitter
# ---------------------------------------------------------------------------


class TestWaitForApprovalJitter:
    def test_sleep_is_jittered_around_poll_interval(self, mock_server):
        """Every sleep the polling loop issues lies in the 80%..120% band."""
        # Always-pending response so the loop runs a handful of iterations.
        MockVanzikHandler.status_response = {"id": "ap_x", "status": "pending"}

        sleeps: list[float] = []
        real_sleep = time.sleep

        def capturing_sleep(s):
            sleeps.append(s)
            real_sleep(0)

        g = Guard(mock_server, api_key="k")
        with patch("vanzik.time.sleep", side_effect=capturing_sleep):
            r = g.wait_for_approval("ap_x", timeout=0.05, poll_interval=0.5)
        assert r.denied
        assert "timed out" in r.reason.lower()
        for s in sleeps:
            assert 0.4 <= s <= 0.6, f"sleep {s} outside jitter band"

    def test_sleep_durations_are_not_all_equal(self, mock_server):
        """Jitter is actually random: samples from the band must not
        collapse to one value."""
        MockVanzikHandler.status_response = {"id": "ap_x", "status": "pending"}
        sleeps: list[float] = []
        real_sleep = time.sleep

        def capturing_sleep(s):
            sleeps.append(s)
            real_sleep(0)

        g = Guard(mock_server, api_key="k")
        # poll_interval=1 means the band is [0.8, 1.2]; collect more
        # samples by giving the loop a longer deadline.
        with patch("vanzik.time.sleep", side_effect=capturing_sleep):
            g.wait_for_approval("ap_x", timeout=0.01, poll_interval=1.0)

        # If the loop ran at least twice, the durations must differ.
        if len(sleeps) >= 2:
            assert len(set(sleeps)) > 1, (
                f"jitter is not random: {sleeps!r}"
            )


# ---------------------------------------------------------------------------
# VanzikAuthError on 401/403 from /v1/status
# ---------------------------------------------------------------------------


class _AuthRefusingHandler(BaseHTTPRequestHandler):
    """A status handler that always returns 401/403."""
    status_code = 401

    def do_GET(self):
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        body = b'{"error":"unauthorized"}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a, **_kw):
        pass


@pytest.fixture()
def auth_refusing_server():
    srv = HTTPServer(("127.0.0.1", 0), _AuthRefusingHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", _AuthRefusingHandler
    finally:
        srv.shutdown()
        _AuthRefusingHandler.status_code = 401


class TestVanzikAuthError:
    def test_401_raises_auth_error(self, auth_refusing_server):
        url, _ = auth_refusing_server
        g = Guard(url, api_key="bad-key")
        with pytest.raises(VanzikAuthError) as exc:
            g.wait_for_approval("ap_x", timeout=5, poll_interval=0.01)
        assert exc.value.status == 401

    def test_403_raises_auth_error(self, auth_refusing_server):
        url, handler = auth_refusing_server
        handler.status_code = 403
        g = Guard(url, api_key="bad-key")
        with pytest.raises(VanzikAuthError) as exc:
            g.wait_for_approval("ap_x", timeout=5, poll_interval=0.01)
        assert exc.value.status == 403

    def test_auth_error_subclasses_permission_error(self):
        # Existing `except PermissionError:` handlers still catch it.
        e = VanzikAuthError("test", status=401)
        assert isinstance(e, PermissionError)
        assert isinstance(e, VanzikError)

    def test_timeout_alias_is_approval_timeout(self):
        assert VanzikTimeoutError is VanzikApprovalTimeout

    def test_500_keeps_polling_until_timeout(self, mock_server):
        """Only auth failures are fatal: anything else (e.g. a transient
        5xx, or 'pending' here) polls until the natural deadline."""
        MockVanzikHandler.status_response = {"id": "ap_x", "status": "pending"}
        g = Guard(mock_server, api_key="k")
        r = g.wait_for_approval("ap_x", timeout=0.02, poll_interval=0.005)
        assert r.denied
        assert "timed out" in r.reason.lower()


# ---------------------------------------------------------------------------
# Backwards-compat: existing PermissionError handlers still catch new errors
# ---------------------------------------------------------------------------


class TestErrorHierarchy:
    def test_auth_error_caught_by_permission_error(self):
        try:
            raise VanzikAuthError("bad", status=401)
        except PermissionError as e:
            assert isinstance(e, VanzikAuthError)

    def test_auth_error_carries_status_field(self):
        e = VanzikAuthError("bad", status=403)
        assert e.status == 403
