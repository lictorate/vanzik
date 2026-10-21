"""The Anthropic SDK's ``messages.stream()`` against the real LLM proxy.

Drives the real ``anthropic`` SDK through the real ``vanzik-llm-proxy``
binary, gated by the real ``vanzik`` server, with a scripted Anthropic
upstream that always answers with one ``bash`` tool_use. It pins two
things the Go tests cannot see from inside the proxy:

* the SDK's stream accumulator consumes every synthetic refusal (DENY and
  REQUIRE_APPROVAL) without raising: the synthetic ``message_delta``
  carries ``usage``, which the SDK reads unconditionally;
* an approval resumes through the proxy: approve the id from the refusal
  text, retry with the ``X-Vanzik-Approval-ID`` header, and the tool_use
  reaches the client. The approval is one-shot, so a second retry with
  the same id is paused again.

Needs ``anthropic`` (not a CI extra), the ``vanzik`` binary at the repo
root and the proxy binary (``VANZIK_LLM_PROXY_BIN`` or the repo root).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import textwrap
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

import pytest

anthropic = pytest.importorskip("anthropic")

from vanzik import Guard  # noqa: E402

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[4]
APPROVAL_HEADER = "X-Vanzik-Approval-ID"

POLICY = textwrap.dedent("""
    version: "1"
    name: "anthropic-refusal-stream"
    rules:
      - scope: shell
        allow:
          - pattern: "ls *"
        deny:
          - pattern: "dd *"
            message: "raw disk writes are blocked"
        require_approval:
          - pattern: "sudo *"
""")


def _binary(env_var: Optional[str], name: str) -> Optional[str]:
    if env_var:
        path = os.environ.get(env_var)
        if path and os.path.isfile(path):
            return path
    candidate = REPO_ROOT / name
    if candidate.is_file():
        return str(candidate)
    return shutil.which(name)


VANZIK_BIN = _binary(None, "vanzik")
PROXY_BIN = _binary("VANZIK_LLM_PROXY_BIN", "vanzik-llm-proxy")

if VANZIK_BIN is None or PROXY_BIN is None:
    pytest.skip(
        "needs the vanzik and vanzik-llm-proxy binaries "
        "(go build -o vanzik ./cmd/vanzik; set VANZIK_LLM_PROXY_BIN)",
        allow_module_level=True,
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(url: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.1)
    return False


def _start(argv: list) -> subprocess.Popen:
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def _drain():
        for _ in iter(proc.stdout.readline, b""):
            pass

    threading.Thread(target=_drain, daemon=True).start()
    return proc


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------------------
# Scripted Anthropic upstream: every /v1/messages call streams one bash
# tool_use whose command the test sets.
# ---------------------------------------------------------------------------


def _sse(event: str, data: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


class _UpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        srv = self.server  # type: ignore[attr-defined]
        srv.headers_seen.append(dict(self.headers))
        command = srv.command
        body = b"".join([
            _sse("message_start", {"type": "message_start", "message": {
                "id": "msg_test", "type": "message", "role": "assistant",
                "model": "claude-test", "content": [], "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 1},
            }}),
            _sse("content_block_start", {"type": "content_block_start", "index": 0,
                 "content_block": {"type": "tool_use", "id": "toolu_test",
                                   "name": "bash", "input": {}}}),
            _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "input_json_delta",
                           "partial_json": json.dumps({"command": command})}}),
            _sse("content_block_stop", {"type": "content_block_stop", "index": 0}),
            _sse("message_delta", {"type": "message_delta",
                 "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                 "usage": {"output_tokens": 12}}),
            _sse("message_stop", {"type": "message_stop"}),
        ])
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Stack:
    def __init__(self, upstream, server_url: str, api_key: str, proxy_url: str):
        self.upstream = upstream
        self.server_url = server_url
        self.api_key = api_key
        self.client = anthropic.Anthropic(base_url=proxy_url, api_key="sk-ant-test", max_retries=0)

    def stream(self, command: str, approval_id: Optional[str] = None):
        """Run one messages.stream() turn; return the final message."""
        self.upstream.command = command
        extra = {APPROVAL_HEADER: approval_id} if approval_id else None
        with self.client.messages.stream(
            model="claude-test",
            max_tokens=256,
            messages=[{"role": "user", "content": "run it"}],
            extra_headers=extra,
        ) as stream:
            for _ in stream:
                pass
            return stream.get_final_message()


@pytest.fixture()
def stack(tmp_path):
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    upstream.command = "ls -la"
    upstream.headers_seen = []
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY)
    api_key = "anthropic-refusal-stream-secret"
    server_port = _free_port()
    server = _start([
        VANZIK_BIN, "serve",
        "--policy", str(policy),
        "--port", str(server_port),
        "--api-key", api_key,
        "--audit-log", str(tmp_path / "audit.jsonl"),
        "--data-dir", str(tmp_path),
        "--dashboard",
    ])
    server_url = f"http://127.0.0.1:{server_port}"

    proxy_port = _free_port()
    proxy = _start([
        PROXY_BIN,
        "--listen", f"127.0.0.1:{proxy_port}",
        "--guard-url", server_url,
        "--api-key", api_key,
        "--upstream-anthropic", f"http://127.0.0.1:{upstream.server_address[1]}",
        "--fail-mode", "deny",
    ])
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    try:
        assert _wait_for(f"{server_url}/health"), "vanzik server did not start"
        assert _wait_for(f"{proxy_url}/healthz"), "llm proxy did not start"
        yield _Stack(upstream, server_url, api_key, proxy_url)
    finally:
        _stop(proxy)
        _stop(server)
        upstream.shutdown()
        upstream.server_close()


def _text(message) -> str:
    return "".join(b.text for b in message.content if b.type == "text")


def _tool_uses(message) -> list:
    return [b for b in message.content if b.type == "tool_use"]


def _approval_id(message) -> str:
    m = re.search(r"Approval ID: (ap_[0-9a-f]+)", _text(message))
    assert m, f"no approval id in refusal: {_text(message)!r}"
    return m.group(1)


class TestAnthropicRefusalStream:
    def test_allow_passes_the_tool_use_through(self, stack):
        final = stack.stream("ls -la")
        assert final.stop_reason == "tool_use"
        assert [b.input for b in _tool_uses(final)] == [{"command": "ls -la"}]

    def test_deny_refusal_streams_cleanly(self, stack):
        final = stack.stream("dd if=/dev/zero of=/dev/sda")
        assert final.stop_reason == "end_turn"
        assert not _tool_uses(final)
        assert "Vanzik denied this action." in _text(final)
        assert final.usage.output_tokens == 0

    def test_approval_refusal_streams_cleanly_and_names_the_header(self, stack):
        final = stack.stream("sudo reboot")
        assert final.stop_reason == "end_turn"
        assert not _tool_uses(final)
        text = _text(final)
        assert "Vanzik paused this action pending human approval." in text
        assert APPROVAL_HEADER in text
        _approval_id(final)


class TestApprovalResumesThroughProxy:
    def test_approve_then_retry_with_header_allows_once(self, stack):
        paused = stack.stream("sudo reboot")
        approval_id = _approval_id(paused)

        # Retrying without the header asks again: nothing resumes on its own.
        again = stack.stream("sudo reboot")
        assert not _tool_uses(again)

        guard = Guard(stack.server_url, api_key=stack.api_key)
        assert guard.approve(approval_id) is True

        resumed = stack.stream("sudo reboot", approval_id=approval_id)
        assert resumed.stop_reason == "tool_use", _text(resumed)
        assert [b.input for b in _tool_uses(resumed)] == [{"command": "sudo reboot"}]

        # The header is for /v1/check only; the upstream never sees it.
        assert all(
            APPROVAL_HEADER.lower() not in {k.lower() for k in h}
            for h in stack.upstream.headers_seen
        )

        # One-shot: the same id does not approve a second run.
        replay = stack.stream("sudo reboot", approval_id=approval_id)
        assert not _tool_uses(replay)
        assert "pending human approval" in _text(replay)

    def test_approval_id_does_not_unlock_a_different_command(self, stack):
        approval_id = _approval_id(stack.stream("sudo reboot"))
        guard = Guard(stack.server_url, api_key=stack.api_key)
        assert guard.approve(approval_id) is True

        other = stack.stream("sudo rm -rf /var", approval_id=approval_id)
        assert not _tool_uses(other)
        assert "pending human approval" in _text(other)
