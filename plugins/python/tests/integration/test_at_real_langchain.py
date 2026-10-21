"""LangChain agent-loop E2E tests.

``test_real_langchain.py`` covers direct ``GuardedTool`` calls; this file
covers the **agent loop**: a model decides to call a tool, the agent
runtime dispatches, and the gate fires during that dispatch.

The repo's policy is "no API keys in tests", so a fake chat model emits a
pre-canned sequence of ``AIMessage`` objects (some carrying
``tool_calls``).

langgraph's ``create_react_agent`` / langchain's ``create_agent`` register
tools through ``coerce_to_runnable``, which checks ``isinstance(thing,
Runnable)``. ``GuardedTool`` subclasses ``BaseTool``, so these tests
register it directly; if a LangChain release breaks that relationship,
they trip on the ``coerce_to_runnable`` ValueError (an intentional
canary).
"""

from __future__ import annotations

import json

import pytest


# No minversion: pyproject's extras enforce the floor, and importorskip's
# `__version__` parsing stumbled on langchain 1.x's version layout in CI.
langchain_core = pytest.importorskip("langchain_core")
langgraph = pytest.importorskip("langgraph")

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, BaseMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from langchain_core.tools import Tool  # noqa: E402

from vanzik import Guard  # noqa: E402
from vanzik.adapters.langchain import GuardedTool  # noqa: E402

from .conftest import allow, deny  # noqa: E402


# ---------------------------------------------------------------------------
# A fake chat model that supports bind_tools — required by the langgraph
# / langchain agent runtimes. The stock FakeMessagesListChatModel does not
# override bind_tools and inherits the BaseChatModel raise-NotImplementedError
# stub, so we provide a minimal subclass tailored for tool-calling agent loops.
# ---------------------------------------------------------------------------


class _ToolCallingFakeChatModel(BaseChatModel):
    """Emit a pre-canned sequence of ``AIMessage`` objects."""

    responses: list

    @property
    def _llm_type(self) -> str:
        return "tool_calling_fake_chat"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):  # noqa: ANN001
        if not self.responses:
            msg = AIMessage(content="(no more canned responses)")
        else:
            msg = self.responses.pop(0)
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools, **kwargs):  # noqa: ARG002
        # The canned responses already carry tool_calls.
        return self


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_gated_tool(guard, name: str = "echo", scope: str = "shell"):
    """Build a GuardedTool that the agent runtime registers directly.

    Returns ``(agent_tool, calls)``; the underlying function appends each
    input to ``calls``.
    """
    calls: list = []

    def _underlying(text: str) -> str:
        calls.append(text)
        return f"echo:{text}"

    underlying = Tool.from_function(
        name=name, description="echoes input through the Vanzik gate",
        func=_underlying,
    )
    gt = GuardedTool(underlying, guard, scope=scope)
    return gt, calls


# ---------------------------------------------------------------------------
# Agent-loop E2E
# ---------------------------------------------------------------------------


class TestAgentLoopGate:
    def test_agent_runtime_calls_guarded_tool_gate_fires(self, integration_mock):
        """A fake LLM emits a tool_call; when the agent runtime dispatches
        it, the gate MUST fire exactly once, with the expected
        ``/v1/check`` body.
        """
        # langgraph's prebuilt helper: langchain 1.x removed AgentExecutor,
        # so this is the route real users hit.
        try:
            from langgraph.prebuilt import create_react_agent
        except ImportError:
            pytest.skip("langgraph.prebuilt.create_react_agent unavailable")

        integration_mock.set_default_check(allow())

        guard = Guard(integration_mock.base_url, agent_id="lc-agent-loop")
        agent_tool, calls = _make_gated_tool(guard, name="echo")

        # One tool_call message, then a final answer. tool_call ids must be
        # unique: the runtime matches them to ToolMessage results.
        tool_call_msg = AIMessage(
            content="",
            tool_calls=[
                {"name": "echo", "args": {"text": "hello"}, "id": "tc_1"},
            ],
        )
        final_answer = AIMessage(content="echo:hello")
        fake_llm = _ToolCallingFakeChatModel(responses=[tool_call_msg, final_answer])

        agent = create_react_agent(fake_llm, tools=[agent_tool])
        result = agent.invoke({"messages": [("user", "say hi")]})

        assert calls == ["hello"], f"calls={calls!r} result={result!r}"

        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 1, f"expected 1 gate call, got {len(bodies)}: {bodies!r}"
        assert bodies[0]["scope"] == "shell"
        assert bodies[0]["agent_id"] == "lc-agent-loop"
        assert bodies[0]["command"] == "hello"

    def test_agent_runtime_deny_propagates_through_loop(self, integration_mock):
        """A DENY decision raises through the agent runtime — the agent
        does NOT swallow ``PermissionError`` and continue."""
        try:
            from langgraph.prebuilt import create_react_agent
        except ImportError:
            pytest.skip("langgraph.prebuilt.create_react_agent unavailable")

        integration_mock.set_default_check(deny(reason="rule:no-shell"))

        guard = Guard(integration_mock.base_url, agent_id="lc-agent-deny")
        agent_tool, calls = _make_gated_tool(guard, name="echo")

        tool_call_msg = AIMessage(
            content="",
            tool_calls=[{"name": "echo", "args": {"text": "rm -rf /"}, "id": "tc_2"}],
        )
        # A final answer in case the runtime recovers from the tool error.
        final_answer = AIMessage(content="failed")
        fake_llm = _ToolCallingFakeChatModel(responses=[tool_call_msg, final_answer])

        agent = create_react_agent(fake_llm, tools=[agent_tool])

        # Acceptable: the agent raises PermissionError, or it surfaces a
        # ToolMessage with `status="error"`. Either way the wrapped function
        # never ran and the gate fired.
        try:
            result = agent.invoke({"messages": [("user", "be evil")]})
            assert calls == [], f"tool ran despite DENY: {calls!r}"
            messages = result.get("messages", [])
            error_text_seen = any(
                ("denied" in str(getattr(m, "content", "")).lower())
                or (getattr(m, "status", None) == "error")
                for m in messages
            )
            assert error_text_seen, (
                f"no error ToolMessage in trajectory: {messages!r}"
            )
        except PermissionError:
            assert calls == []

        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 1, f"expected 1 gate call, got {len(bodies)}"
        assert bodies[0]["command"] == "rm -rf /"

    def test_two_tool_calls_two_gate_checks(self, integration_mock):
        """Two tool_calls in one AIMessage: the gate fires once per
        tool_call, not once per AIMessage.
        """
        try:
            from langgraph.prebuilt import create_react_agent
        except ImportError:
            pytest.skip("langgraph.prebuilt.create_react_agent unavailable")

        integration_mock.set_default_check(allow())

        guard = Guard(integration_mock.base_url, agent_id="lc-agent-parallel")
        agent_tool, calls = _make_gated_tool(guard, name="echo")

        msg = AIMessage(
            content="",
            tool_calls=[
                {"name": "echo", "args": {"text": "first"}, "id": "tc_1"},
                {"name": "echo", "args": {"text": "second"}, "id": "tc_2"},
            ],
        )
        final = AIMessage(content="done")
        fake_llm = _ToolCallingFakeChatModel(responses=[msg, final])

        agent = create_react_agent(fake_llm, tools=[agent_tool])
        agent.invoke({"messages": [("user", "two calls")]})

        # Parallel tool_calls run concurrently; completion order is
        # scheduler-dependent, so compare sorted.
        assert sorted(calls) == ["first", "second"]
        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 2, f"expected 2 gate calls, got {len(bodies)}: {bodies!r}"
        commands = sorted(b["command"] for b in bodies)
        assert commands == ["first", "second"]
