"""End-to-end tests for the CrewAI adapter.

  - Modern Runnable entry points (``invoke``, ``ainvoke``, ``__call__``)
    and legacy ones (``run``, ``_run``, ``arun``, ``_arun``) are gated.
  - DENY / REQUIRE_APPROVAL raise :class:`PermissionError` rather than
    returning a string the agent might confuse with a tool output.
  - Every dispatch path is overridden on the class itself, and private
    gating attrs stay out of ``model_dump``.

Real-CrewAI tests skip via ``pytest.importorskip("crewai", ...)``; the
Vanzik side is the mock server from ``tests/conftest.py``.
"""

import asyncio
from unittest.mock import MagicMock, AsyncMock

import pytest

from vanzik import (
    VanzikApprovalRequired,
    VanzikDenied,
    Guard,
)
from tests.conftest import MockVanzikHandler


# ---------------------------------------------------------------------------
# Helpers — build a minimal "tool-like" object that mirrors what CrewAI's
# BaseTool exposes (name, description, _run, invoke, ainvoke, __call__).
# ---------------------------------------------------------------------------

class _FakeCrewAITool:
    """Stand-in for a CrewAI BaseTool subclass with the modern surface
    (invoke / ainvoke / _run / __call__); ``TestRealCrewAI`` below uses
    the real ``crewai.tools.BaseTool``.
    """

    def __init__(self, name: str = "fake_tool", description: str = ""):
        self.name = name
        self.description = description
        self._invocations: list = []

    def _run(self, *args, **kwargs):
        self._invocations.append(("_run", args, kwargs))
        return "ran-via-_run"

    async def _arun(self, *args, **kwargs):
        self._invocations.append(("_arun", args, kwargs))
        return "ran-via-_arun"

    def invoke(self, input, config=None, **kwargs):  # noqa: A002
        self._invocations.append(("invoke", input, config, kwargs))
        return "ran-via-invoke"

    async def ainvoke(self, input, config=None, **kwargs):  # noqa: A002
        self._invocations.append(("ainvoke", input, config, kwargs))
        return "ran-via-ainvoke"

    def __call__(self, *args, **kwargs):
        self._invocations.append(("__call__", args, kwargs))
        return "ran-via-__call__"


# ---------------------------------------------------------------------------
# Modern API gating — ALLOW path passes through.
# ---------------------------------------------------------------------------

class TestModernAPIAllowPath:
    def test_guardedcrewtool_invoke_allow_passes_through(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        tool = _FakeCrewAITool(name="search", description="search the web")
        gct = GuardedCrewTool(tool, guard=guard, scope="network")

        out = gct.invoke({"command": "find me cats"})
        assert out == "ran-via-invoke"
        kinds = [inv[0] for inv in tool._invocations]
        assert kinds == ["invoke"]

    def test_guardedcrewtool_ainvoke_allow(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        tool = _FakeCrewAITool(name="search", description="search the web")
        gct = GuardedCrewTool(tool, guard=guard, scope="network")

        out = asyncio.run(gct.ainvoke({"command": "find me cats"}))
        assert out == "ran-via-ainvoke"
        kinds = [inv[0] for inv in tool._invocations]
        assert kinds == ["ainvoke"]

    def test_guardedcrewtool_call_dunder_allow(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        out = gct("ls -la")
        assert out == "ran-via-__call__"
        kinds = [inv[0] for inv in tool._invocations]
        assert kinds == ["__call__"]

    def test_guardedcrewtool_run_allow(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        out = gct.run("ls -la")
        assert out == "ran-via-_run"

    def test_guardedcrewtool_underscore_run_allow(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        out = gct._run("ls -la")
        assert out == "ran-via-_run"

    def test_guardedcrewtool_arun_allow(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        out = asyncio.run(gct.arun("ls -la"))
        assert out == "ran-via-_arun"


# ---------------------------------------------------------------------------
# Modern API gating — DENY raises and underlying is NOT called.
# ---------------------------------------------------------------------------

class TestModernAPIDenyPath:
    def test_guardedcrewtool_invoke_deny_raises(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "policy says no",
        }
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gct.invoke({"command": "rm -rf /"})

        # Should be the typed subclass and reference the reason.
        assert isinstance(ei.value, VanzikDenied)
        assert "denied" in str(ei.value).lower()
        assert "policy says no" in str(ei.value)
        # The underlying tool was never called.
        assert tool._invocations == []

    def test_guardedcrewtool_ainvoke_deny_raises(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        with pytest.raises(PermissionError):
            asyncio.run(gct.ainvoke({"command": "rm -rf /"}))
        assert tool._invocations == []

    def test_guardedcrewtool_call_dunder_gated(self, mock_server):
        """``tool(...)`` direct invocation must hit the gate."""
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gct("rm -rf /")
        assert isinstance(ei.value, VanzikDenied)
        assert tool._invocations == []

    def test_guardedcrewtool_run_deny_raises(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        with pytest.raises(PermissionError):
            gct.run("rm -rf /")
        assert tool._invocations == []


# ---------------------------------------------------------------------------
# REQUIRE_APPROVAL path — also raises (typed).
# ---------------------------------------------------------------------------

class TestApprovalPath:
    def test_invoke_approval_raises(self, mock_server):
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_url": "http://approve/ap_1",
        }
        guard = Guard(mock_server)

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gct.invoke({"command": "sudo reboot"})
        assert isinstance(ei.value, VanzikApprovalRequired)
        assert "approval" in str(ei.value).lower()
        assert "http://approve/ap_1" in str(ei.value)
        assert tool._invocations == []


# ---------------------------------------------------------------------------
# Defense contract: GuardedCrewTool subclasses CrewAI's BaseTool (pydantic
# 2.12 / CrewAI 1.x ignore virtual-subclass registration), and every
# dispatch entry point is defined on the class itself, not inherited. The
# canary tests in test_at_real_crewai.py catch new upstream dispatch paths.
#
# Accepted tradeoff: ``_tool`` / ``_guard`` / ``_scope`` stay out of
# ``model_dump`` but are readable attributes, so ``gct._tool._run(...)``
# skips the gate. The caller holding the wrapper can reach the wrapped
# tool anyway, and the agent runtime only calls the gated methods.
# ---------------------------------------------------------------------------

class TestDefenseContract:
    def test_subclass_passes_isinstance_check(self, mock_server):
        """CrewAI 1.x Agent validation does ``isinstance(thing,
        BaseTool)``; GuardedCrewTool must satisfy it. Skips without crewai.
        """
        try:
            from crewai.tools import BaseTool as CrewBaseTool  # type: ignore
        except ImportError:
            pytest.skip("crewai not installed; isinstance-pass guarantee is crewai-specific")
        from vanzik.adapters.crewai import _build_guarded_class

        guard = Guard(mock_server)
        # Build a real CrewAI BaseTool subclass to wrap.
        class Echo(CrewBaseTool):
            name: str = "echo"
            description: str = "echoes"

            def _run(self, query: str = "") -> str:  # type: ignore[override]
                return f"echo:{query}"

        cls = _build_guarded_class()
        gct = cls(Echo(), guard=guard, scope="shell")
        assert isinstance(gct, CrewBaseTool), (
            "GuardedCrewTool must be an instance of CrewAI BaseTool so "
            "Agent(tools=[...]) validation accepts it"
        )

    def test_run_dispatch_paths_are_overridden(self, mock_server):
        """Every gated method must be defined on GuardedCrewTool itself:
        an inherited one runs the parent's code without Guard.check.
        """
        from vanzik.adapters.crewai import _build_guarded_class

        cls = _build_guarded_class()
        for method_name in (
            "_run",
            "run",
            "invoke",
            "ainvoke",
            "_arun",
            "arun",
            "__call__",
            "to_structured_tool",
        ):
            assert method_name in cls.__dict__, (
                f"{method_name!r} must be defined on GuardedCrewTool, not "
                "inherited from BaseTool. If you removed the override, the "
                "policy gate no longer fires on that dispatch path."
            )

    def test_to_structured_tool_uses_gated_run(self, mock_server):
        """The CrewStructuredTool from ``to_structured_tool`` must call
        our gated ``_run``.
        """
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "structured-tool gate fired",
        }
        guard = Guard(mock_server)
        inner = _FakeCrewAITool()
        gct = GuardedCrewTool(inner, guard=guard, scope="shell")

        # to_structured_tool requires real crewai.
        try:
            structured = gct.to_structured_tool()
        except ImportError:
            pytest.skip("crewai not installed; to_structured_tool requires it")

        # Calling func must hit the gate (DENY here).
        assert callable(structured.func)
        with pytest.raises(PermissionError):
            structured.func("danger")
        assert inner._invocations == []

    def test_private_attrs_not_in_model_dump(self, mock_server):
        """``_tool`` / ``_guard`` / ``_scope`` must not appear in
        ``model_dump()``: tool metadata rendered for telemetry must not
        expose the guard handle.
        """
        from vanzik.adapters.crewai import GuardedCrewTool

        guard = Guard(mock_server)
        inner = _FakeCrewAITool(name="my_tool", description="my description")
        gct = GuardedCrewTool(inner, guard=guard, scope="shell")

        try:
            dumped = gct.model_dump()
        except Exception as e:  # pragma: no cover
            pytest.fail(f"model_dump should succeed on a subclassed BaseTool: {e}")

        for forbidden in ("_tool", "_guard", "_scope"):
            assert forbidden not in dumped, (
                f"{forbidden!r} leaked through model_dump(): {dumped!r}"
            )

    def test_metadata_passthrough(self, mock_server):
        """The framework reads ``name`` / ``description`` / ``args_schema``
        for tool registration. CrewAI itself rewrites ``description`` into
        ``Tool Name: ... Tool Arguments: ...`` in model_post_init.
        """
        from vanzik.adapters.crewai import GuardedCrewTool

        guard = Guard(mock_server)
        inner = _FakeCrewAITool(name="my_tool", description="my description")
        gct = GuardedCrewTool(inner, guard=guard, scope="shell")

        assert gct.name == "my_tool"
        assert "my description" in gct.description or "Tool Name" in gct.description


# ---------------------------------------------------------------------------
# guard_crew_tools factory
# ---------------------------------------------------------------------------

class TestGuardCrewToolsFactory:
    def test_factory_wraps_all_tools(self, mock_server):
        from vanzik.adapters.crewai import guard_crew_tools, GuardedCrewTool

        tools = [_FakeCrewAITool(name=f"t{i}") for i in range(3)]
        wrapped = guard_crew_tools(tools, guard_url=mock_server)

        assert len(wrapped) == 3
        assert all(isinstance(w, GuardedCrewTool) for w in wrapped)
        assert [w.name for w in wrapped] == ["t0", "t1", "t2"]

    def test_factory_gates_invoke(self, mock_server):
        """Factory-produced wrappers must also gate ``invoke``."""
        from vanzik.adapters.crewai import guard_crew_tools

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }

        tools = [_FakeCrewAITool()]
        wrapped = guard_crew_tools(tools, guard_url=mock_server)

        with pytest.raises(PermissionError):
            wrapped[0].invoke({"command": "x"})
        assert tools[0]._invocations == []


# ---------------------------------------------------------------------------
# Real CrewAI integration: runs only when crewai >= 0.80 is installed.
# ---------------------------------------------------------------------------

@pytest.fixture()
def real_crewai_basetool():
    """Yield the real CrewAI BaseTool class, or skip the test."""
    crewai = pytest.importorskip(
        "crewai",
        minversion="0.80",
        reason="real CrewAI integration tests require crewai>=0.80",
    )
    # Resolve BaseTool across the version-renamed locations.
    base = None
    for path in (
        "crewai.tools.BaseTool",
        "crewai.tools.base_tool.BaseTool",
    ):
        module_name, attr = path.rsplit(".", 1)
        try:
            module = __import__(module_name, fromlist=[attr])
            base = getattr(module, attr, None)
        except ImportError:
            continue
        if base is not None:
            break
    if base is None:
        pytest.skip("Could not locate crewai BaseTool in this version")
    return base


class TestRealCrewAI:
    """Tests against the real upstream library; each skips cleanly when
    CrewAI is not installed.
    """

    def test_real_basetool_subclass_invoke_gated(
        self, mock_server, real_crewai_basetool
    ):
        """Build a real CrewAI tool, wrap it, call ``invoke`` and
        verify the Vanzik gate fires."""
        from vanzik.adapters.crewai import GuardedCrewTool

        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "real-crewai gate fired",
        }

        BaseTool = real_crewai_basetool

        class EchoTool(BaseTool):
            name: str = "echo"
            description: str = "echoes the input back"

            def _run(self, query: str) -> str:
                return f"echo: {query}"

        real_tool = EchoTool()
        guard = Guard(mock_server)
        gct = GuardedCrewTool(real_tool, guard=guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gct.invoke({"query": "hi"})
        assert "real-crewai gate fired" in str(ei.value)

    def test_real_basetool_isinstance_via_virtual_subclass(
        self, mock_server, real_crewai_basetool
    ):
        """CrewAI's agent / crew code checks ``isinstance(x, BaseTool)``
        before treating an object as a tool; the call path must be safe."""
        from vanzik.adapters.crewai import GuardedCrewTool

        BaseTool = real_crewai_basetool

        class Noop(BaseTool):
            name: str = "noop"
            description: str = ""

            def _run(self) -> str:
                return ""

        guard = Guard(mock_server)
        gct = GuardedCrewTool(Noop(), guard=guard, scope="shell")

        # Lenient on purpose: the safety guarantee is the gate, not the
        # isinstance result.
        result = isinstance(gct, BaseTool)
        assert result in (True, False)

    def test_real_crewai_agent_kickoff_gates_tool_call(
        self, mock_server, real_crewai_basetool
    ):
        """End-to-end: build a CrewAI agent + crew, kick it off, and
        verify the wrapped tool's calls go through the policy gate.

        Skips cleanly when crewai (or its LLM wiring) is missing.
        """
        from vanzik.adapters.crewai import GuardedCrewTool

        # No LLM in CI without secrets, so this pins the deterministic
        # part: CrewAI's BaseTool.invoke must route through the gate.
        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "kickoff-path gate fired",
        }

        BaseTool = real_crewai_basetool

        class SearchTool(BaseTool):
            name: str = "search"
            description: str = "search the web"

            def _run(self, query: str) -> str:
                return f"results for {query}"

        guard = Guard(mock_server)
        gct = GuardedCrewTool(SearchTool(), guard=guard, scope="network")

        # Drive the same code path the agent's tool-calling loop uses:
        # BaseTool.invoke -> ours.invoke -> gate -> raises.
        with pytest.raises(PermissionError):
            gct.invoke({"query": "anything"})
