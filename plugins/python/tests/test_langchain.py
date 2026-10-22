"""Real-LangChain adapter tests.

Every Tool/Runnable here is a real ``langchain_core`` object; only the
Vanzik HTTP server is mocked (``mock_server``) to steer decisions. Without
``langchain_core`` the module is skipped. Do **not** mock LangChain to
make these tests run: their point is validating against the real
upstream API.
"""

import asyncio
import json

import pytest

from vanzik import Guard
from tests.conftest import MockVanzikHandler


# Skip the entire module if langchain_core is not importable. Tests that
# explicitly want langchain (legacy package) skip via importorskip too.
langchain_core = pytest.importorskip("langchain_core", minversion="0.1")
from langchain_core.tools import Tool  # noqa: E402  (after importorskip)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_real_tool(name: str = "echo", description: str = "echoes input"):
    """Build a real langchain_core Tool around a tracked function.

    Returns ``(tool, calls)``; the function appends each input to
    ``calls``.
    """
    calls: list = []

    def _func(text: str) -> str:
        calls.append(text)
        return f"echo:{text}"

    return Tool.from_function(name=name, description=description, func=_func), calls


# ---------------------------------------------------------------------------
# Modern Runnable API: invoke / ainvoke
# ---------------------------------------------------------------------------

class TestInvoke:
    def test_guardedtool_invoke_allow_passes_through(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.invoke("hello")

        assert out == "echo:hello"
        assert calls == ["hello"]

    def test_guardedtool_invoke_deny_raises(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.invoke("rm -rf /")

        assert "denied" in str(ei.value).lower()
        assert calls == []

    def test_guardedtool_invoke_approval_raises(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_url": "http://approve/ap_1",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.invoke("sudo reboot")

        msg = str(ei.value).lower()
        assert "approval" in msg
        assert "http://approve/ap_1" in str(ei.value)
        assert calls == []

    def test_guardedtool_ainvoke_allow_passes_through(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = asyncio.run(gt.ainvoke("hi"))

        assert out == "echo:hi"
        assert calls == ["hi"]

    def test_guardedtool_ainvoke_deny_raises(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError):
            asyncio.run(gt.ainvoke("dangerous"))
        assert calls == []


# ---------------------------------------------------------------------------
# Stream / astream
# ---------------------------------------------------------------------------

class TestStream:
    def test_guardedtool_stream_gates_input_once(self, mock_server):
        """The gate fires once at stream open, not once per chunk."""
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        chunks = list(gt.stream("hello"))

        assert calls == ["hello"]
        # langchain_core Tool.stream yields the function output directly.
        assert chunks == ["echo:hello"]

    def test_guardedtool_stream_deny_raises(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError):
            list(gt.stream("dangerous"))
        assert calls == []

    def test_guardedtool_astream_gates_input_once(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        async def collect():
            chunks = []
            async for c in gt.astream("hi"):
                chunks.append(c)
            return chunks

        chunks = asyncio.run(collect())
        assert calls == ["hi"]
        assert chunks == ["echo:hi"]

    def test_guardedtool_astream_deny_raises(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {"decision": "DENY", "reason": "no"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        async def collect():
            async for _ in gt.astream("nope"):
                pass

        with pytest.raises(PermissionError):
            asyncio.run(collect())
        assert calls == []


# ---------------------------------------------------------------------------
# Batch / abatch
# ---------------------------------------------------------------------------

class _IndexedDecisionHandler(MockVanzikHandler):
    """Mock handler that returns DENY for the Nth call and ALLOW otherwise.

    Configure via class attribute ``deny_at_index``. The counter is reset by
    the fixture between tests.
    """

    deny_at_index = 0
    _call_count = 0

    def do_POST(self):
        if self.path == "/v1/check":
            idx = _IndexedDecisionHandler._call_count
            _IndexedDecisionHandler._call_count += 1
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length else b""
            MockVanzikHandler.last_request_body = body
            if idx == _IndexedDecisionHandler.deny_at_index:
                self._json_response(
                    200, {"decision": "DENY", "reason": f"deny-at-{idx}"}
                )
            else:
                self._json_response(
                    200, {"decision": "ALLOW", "reason": f"allow-at-{idx}"}
                )
            return
        super().do_POST()


@pytest.fixture()
def mock_server_indexed():
    """Variant of mock_server with the IndexedDecisionHandler.

    Spins a real HTTP server because tests hit it via the SDK's urllib
    client. Resets the call counter and the deny index between tests.
    """
    import threading
    from http.server import ThreadingHTTPServer

    _IndexedDecisionHandler._call_count = 0
    _IndexedDecisionHandler.deny_at_index = 0

    server = ThreadingHTTPServer(("127.0.0.1", 0), _IndexedDecisionHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    _IndexedDecisionHandler._call_count = 0
    _IndexedDecisionHandler.deny_at_index = 0


class TestBatch:
    def test_guardedtool_batch_all_allowed(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.batch(["a", "b", "c"])

        # `out` keeps input order, but `calls` records execution order,
        # which concurrent batch makes nondeterministic: compare sorted.
        assert out == ["echo:a", "echo:b", "echo:c"]
        assert sorted(calls) == ["a", "b", "c"]

    def test_guardedtool_batch_denies_first(self, mock_server_indexed):
        """First entry DENY → batch raises with index 0 in the message,
        underlying function never runs (whole-batch-fails-on-first-deny)."""
        from vanzik.adapters.langchain import GuardedTool

        _IndexedDecisionHandler.deny_at_index = 0
        guard = Guard(mock_server_indexed)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.batch(["bad", "ok1", "ok2"])

        msg = str(ei.value)
        assert "batch entry 0" in msg
        assert "denied" in msg.lower()
        assert calls == []

    def test_guardedtool_batch_denies_second(self, mock_server_indexed):
        """Second entry DENY → batch raises with index 1 in the message."""
        from vanzik.adapters.langchain import GuardedTool

        _IndexedDecisionHandler.deny_at_index = 1
        guard = Guard(mock_server_indexed)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.batch(["ok0", "bad1", "ok2"])

        assert "batch entry 1" in str(ei.value)
        # Entries before the deny may have run: the contract is that the
        # batch doesn't return, not a rollback.
        assert "bad1" not in calls

    def test_guardedtool_abatch_denies_first(self, mock_server_indexed):
        from vanzik.adapters.langchain import GuardedTool

        _IndexedDecisionHandler.deny_at_index = 0
        guard = Guard(mock_server_indexed)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            asyncio.run(gt.abatch(["bad", "ok1"]))

        assert "batch entry 0" in str(ei.value)
        assert calls == []


# ---------------------------------------------------------------------------
# Defense contract: GuardedTool subclasses langchain_core's BaseTool, so
# isinstance(thing, Runnable) holds at framework boundaries (langgraph 1.0 /
# langchain_core 1.x), and every gated dispatch path is defined on the
# class, not inherited. The canary integration tests catch new upstream
# dispatch paths.
# ---------------------------------------------------------------------------

class TestDefenseContract:
    def test_subclass_passes_runnable_isinstance(self, mock_server):
        """The langgraph / langchain runtime checks ``isinstance(thing,
        Runnable)``; GuardedTool must satisfy it.
        """
        try:
            from langchain_core.runnables import Runnable
            from langchain_core.tools import BaseTool as LCBase
        except ImportError:
            pytest.skip("langchain_core not installed")
        from vanzik.adapters.langchain import _build_guarded_tool_class

        cls = _build_guarded_tool_class()
        guard = Guard(mock_server)
        tool, _ = _make_real_tool()
        gt = cls(tool, guard, scope="shell")
        assert isinstance(gt, Runnable), (
            "GuardedTool must be an instance of Runnable so langgraph's "
            "create_react_agent / langchain's create_agent accept it"
        )
        assert isinstance(gt, LCBase), (
            "GuardedTool must subclass BaseTool so framework-side "
            "BaseTool isinstance checks (e.g. tool registries) accept it"
        )

    def test_run_dispatch_paths_are_overridden(self, mock_server):
        """Every gated method must be defined on GuardedTool itself: an
        inherited one runs the parent's un-gated code.
        """
        from vanzik.adapters.langchain import _build_guarded_tool_class

        cls = _build_guarded_tool_class()
        for method_name in (
            "_run",
            "_arun",
            "invoke",
            "ainvoke",
            "stream",
            "astream",
            "batch",
            "abatch",
            "run",
            "arun",
        ):
            assert method_name in cls.__dict__, (
                f"{method_name!r} must be defined on GuardedTool, not "
                "inherited from BaseTool. If you removed the override, the "
                "policy gate no longer fires on that dispatch path."
            )

    def test_private_attrs_not_in_model_dump(self, mock_server):
        """``_tool`` / ``_guard`` / ``_scope`` must NOT appear in
        ``model_dump()`` output.
        """
        from vanzik.adapters.langchain import GuardedTool

        guard = Guard(mock_server)
        tool, _ = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        try:
            dumped = gt.model_dump()
        except Exception as e:  # pragma: no cover
            pytest.fail(f"model_dump should succeed on a subclassed BaseTool: {e}")

        for forbidden in ("_tool", "_guard", "_scope"):
            assert forbidden not in dumped, (
                f"{forbidden!r} leaked through model_dump(): {dumped!r}"
            )

    def test_arbitrary_internal_blocked(self, mock_server):
        """An undeclared attribute like ``_internal_thing`` raises
        AttributeError (pydantic validates field names), while ``name`` /
        ``description`` / ``args_schema`` introspection works.
        """
        from vanzik.adapters.langchain import GuardedTool

        guard = Guard(mock_server)
        tool, _calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(AttributeError):
            _ = gt._GuardedTool__nonexistent

    def test_allowed_passthrough(self, mock_server):
        """Metadata attributes are pydantic fields on the wrapper itself."""
        from vanzik.adapters.langchain import GuardedTool

        guard = Guard(mock_server)
        tool, _calls = _make_real_tool(name="my_tool", description="does things")
        gt = GuardedTool(tool, guard, scope="shell")

        assert gt.name == "my_tool"
        assert gt.description == "does things"
        # args_schema may be None on a Tool.from_function with no schema, but
        # the attribute must exist (no AttributeError):
        _ = gt.args_schema
        _ = gt.return_direct
        _ = gt.metadata
        _ = gt.tags


# ---------------------------------------------------------------------------
# End-to-end through real LangChain runtime
# ---------------------------------------------------------------------------

class TestRealLangChainRuntime:
    def test_real_invoke_round_trip_through_real_langchain_runtime(self, mock_server):
        """A tiny LCEL chain (no LLM needed) piping ``tool.invoke`` into a
        lambda Runnable: the gate fires and the composition stays intact.
        """
        from vanzik.adapters.langchain import GuardedTool

        try:
            from langchain_core.runnables import RunnableLambda
        except ImportError:  # pragma: no cover - sanity guard
            pytest.skip("RunnableLambda not available in this langchain_core version")

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        chain = RunnableLambda(lambda x: gt.invoke(x)) | RunnableLambda(
            lambda r: r.upper()
        )

        out = chain.invoke("ping")

        assert out == "ECHO:PING"
        assert calls == ["ping"]
        body = json.loads(MockVanzikHandler.last_request_body)
        assert body["scope"] == "shell"
        assert body["command"] == "ping"

    def test_real_chain_deny_propagates_through_lcel(self, mock_server):
        """If the gate denies, the PermissionError must propagate through
        the LCEL chain (not be swallowed by the runtime)."""
        from vanzik.adapters.langchain import GuardedTool

        try:
            from langchain_core.runnables import RunnableLambda
        except ImportError:  # pragma: no cover
            pytest.skip("RunnableLambda not available")

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked at chain",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        chain = RunnableLambda(lambda x: gt.invoke(x))

        with pytest.raises(PermissionError) as ei:
            chain.invoke("rm -rf /")
        assert "denied" in str(ei.value).lower()
        assert calls == []


# ---------------------------------------------------------------------------
# Legacy run/arun: string on deny
# ---------------------------------------------------------------------------

class TestLegacyRunArun:
    """The legacy run()/arun() entries return string messages on
    DENY/REQUIRE_APPROVAL; only the modern entries raise."""

    def test_run_allow(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.run("hello")
        assert out == "echo:hello"
        assert calls == ["hello"]

    def test_run_deny_returns_string(self, mock_server):
        from vanzik.adapters.langchain import GuardedTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.run("rm -rf /")
        assert isinstance(out, str)
        assert "denied" in out.lower()
        assert calls == []


class TestStreamRegating:
    """stream()/astream() gate at open and re-validate periodically so a
    mid-stream policy revocation cuts the stream off."""

    class _FlippingGuard:
        """Allows the first N checks, denies afterwards."""

        def __init__(self, allow_first: int):
            self.allow_first = allow_first
            self.calls = 0

        def check(self, scope, **params):
            from vanzik import CheckResult, DECISION_ALLOW, DECISION_DENY
            self.calls += 1
            if self.calls <= self.allow_first:
                return CheckResult(decision=DECISION_ALLOW, reason="ok")
            return CheckResult(decision=DECISION_DENY, reason="revoked mid-stream")

    class _StreamingTool:
        name = "streaming_tool"
        description = "yields three chunks"

        def stream(self, input, config=None, **kwargs):  # noqa: A002
            yield "chunk-1"
            yield "chunk-2"
            yield "chunk-3"

        async def astream(self, input, config=None, **kwargs):  # noqa: A002
            for c in ("chunk-1", "chunk-2", "chunk-3"):
                yield c

        def _run(self, *a, **k):
            return "done"

    def test_stream_cut_off_on_mid_stream_revocation(self, monkeypatch):
        from vanzik.adapters import langchain as lc_mod
        from vanzik.adapters.langchain import GuardedTool

        # Re-validate on every chunk so the revocation lands deterministically.
        monkeypatch.setattr(lc_mod, "STREAM_REGATE_SECONDS", 0.0)

        guard = self._FlippingGuard(allow_first=1)  # open-gate passes, first re-check denies
        gt = GuardedTool(self._StreamingTool(), guard, scope="shell")

        it = gt.stream("run")
        with pytest.raises(PermissionError, match="revoked mid-stream"):
            list(it)
        assert guard.calls >= 2  # open gate + at least one re-check

    def test_stream_completes_when_policy_stays_allowed(self, monkeypatch):
        from vanzik.adapters import langchain as lc_mod
        from vanzik.adapters.langchain import GuardedTool

        monkeypatch.setattr(lc_mod, "STREAM_REGATE_SECONDS", 0.0)
        guard = self._FlippingGuard(allow_first=10**9)
        gt = GuardedTool(self._StreamingTool(), guard, scope="shell")

        assert list(gt.stream("run")) == ["chunk-1", "chunk-2", "chunk-3"]
        assert guard.calls >= 4  # open gate + one re-check per chunk

    def test_astream_cut_off_on_mid_stream_revocation(self, monkeypatch):
        import asyncio

        from vanzik.adapters import langchain as lc_mod
        from vanzik.adapters.langchain import GuardedTool

        monkeypatch.setattr(lc_mod, "STREAM_REGATE_SECONDS", 0.0)
        guard = self._FlippingGuard(allow_first=1)
        gt = GuardedTool(self._StreamingTool(), guard, scope="shell")

        async def consume():
            chunks = []
            async for c in gt.astream("run"):
                chunks.append(c)
            return chunks

        with pytest.raises(PermissionError, match="revoked mid-stream"):
            asyncio.run(consume())

    def test_default_interval_does_not_recheck_fast_streams(self):
        from vanzik.adapters.langchain import GuardedTool

        guard = self._FlippingGuard(allow_first=1)  # any re-check would deny
        gt = GuardedTool(self._StreamingTool(), guard, scope="shell")

        # With the default 10s interval a sub-second stream never re-gates,
        # so the hot path costs exactly one check.
        assert list(gt.stream("run")) == ["chunk-1", "chunk-2", "chunk-3"]
        assert guard.calls == 1
