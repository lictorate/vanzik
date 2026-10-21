"""CrewAI agent-loop E2E tests.

``test_real_crewai.py`` calls ``GuardedCrewTool`` directly; this file
builds a real ``Agent`` + ``Task`` + ``Crew``, runs ``crew.kickoff(...)``
and asserts the gate fires when the agent calls the tool.

An offline LLM (a ``BaseLLM`` subclass) asks for the tool call, so no
API key is needed. If CrewAI's LLM bridge rejects the stub (its API has
shifted across releases), the test skips with a clear message. Scope is
deliberately narrow: one agent, one tool, one task, one tool call.
"""

from __future__ import annotations

import json

import pytest


crewai = pytest.importorskip("crewai")  # floor enforced by pyproject extras
try:
    from crewai import Agent, Task, Crew  # type: ignore[attr-defined]
    from crewai.tools import BaseTool  # type: ignore[attr-defined]
    from crewai.llms.base_llm import BaseLLM  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - layout shifts across versions
    pytest.skip(
        "crewai installed but Agent / Task / Crew / BaseTool / BaseLLM "
        "layout not at the expected import path. Real-CrewAI integration "
        "tests are skipped on this layout. Re-pin in pyproject.toml when "
        "the upstream layout settles.",
        allow_module_level=True,
    )

from vanzik import (  # noqa: E402
    VanzikDenied,
    Guard,
)
from vanzik.adapters.crewai import GuardedCrewTool  # noqa: E402

from .conftest import allow, deny  # noqa: E402


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Real CrewAI BaseTool subclass — mirrors what a real user writes.
# ---------------------------------------------------------------------------


class _EchoTool(BaseTool):
    name: str = "echo"
    description: str = "Echo a message. Call this when the user says hello."

    def _run(self, message: str) -> str:  # type: ignore[override]
        return f"crew-echo: {message}"


# ---------------------------------------------------------------------------
# Offline fake LLM via CrewAI's public BaseLLM extension point. Dumb on
# purpose: it calls ``echo`` once, then gives a final answer. The code
# under test is the agent's tool dispatch, not the LLM.
# ---------------------------------------------------------------------------


class _OfflineEchoLLM(BaseLLM):
    """Drive a CrewAI agent loop offline by emitting a tool-call list
    and then a final-answer string.

    CrewAI's native function-calling executor (``_invoke_loop_native``)
    dispatches a return value that matches ``_is_tool_call_list`` via
    ``available_functions[name](**args)``; a string ends the loop.
    """

    llm_type: str = "offline_echo"
    model: str = "offline/echo-fake"

    def supports_function_calling(self) -> bool:
        """Use CrewAI's native function-calling path, the one under test."""
        return True

    def call(  # type: ignore[override]
        self,
        messages,
        tools=None,
        callbacks=None,
        available_functions=None,
        from_task=None,
        from_agent=None,
        response_model=None,
    ):
        # Track turn count via __dict__ (pydantic ``__setattr__`` falls
        # through to ``object.__setattr__`` for non-field names).
        turn = self.__dict__.get("_offline_turn", 0)
        self.__dict__["_offline_turn"] = turn + 1
        if turn == 0:
            # ``{"name", "input"}`` items satisfy ``_is_tool_call_list`` and
            # ``_parse_native_tool_call``; ``available_functions["echo"]``
            # is bound to GuardedCrewTool.run, which gates.
            return [
                {"name": "echo", "input": {"message": "hello"}, "id": "call_offline_1"},
            ]
        # After the tool result: a string becomes AgentFinish.
        return "Final Answer: done"


# ---------------------------------------------------------------------------
# Full kickoff loop. CrewAI's pluggable LLM interface keeps shifting, so a
# kickoff error mentioning OpenAI, an API key or LiteLLM skips the test;
# it only passes when the gate actually fired.
# ---------------------------------------------------------------------------


class TestRealCrewKickoffGatesTool:
    def test_kickoff_runs_tool_and_gate_fires(self, integration_mock):
        """Run ``crew.kickoff`` end-to-end: at least one ``/v1/check``
        with the right scope. Not exactly one: some CrewAI versions'
        planner calls the tool several times per kickoff.
        """
        integration_mock.set_default_check(allow())

        guard = Guard(integration_mock.base_url, agent_id="crew-at-kickoff")
        wrapped = GuardedCrewTool(_EchoTool(), guard=guard, scope="shell")
        fake_llm = _OfflineEchoLLM(model="offline/echo-fake")

        # Agent() accepts GuardedCrewTool because it subclasses BaseTool. A
        # framework change that breaks this surfaces here unmasked, not
        # under a skip.
        try:
            agent = Agent(
                role="echoer",
                goal="echo back any message the user sends",
                backstory="you only ever call the echo tool",
                tools=[wrapped],
                allow_delegation=False,
                verbose=False,
                llm=fake_llm,
            )
            task = Task(
                description="The user said 'hello'. Call the echo tool with 'hello'.",
                expected_output="The string 'crew-echo: hello'.",
                agent=agent,
            )
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            crew.kickoff()
        except Exception as e:  # noqa: BLE001
            # CrewAI rejected the offline LLM (e.g. an unstubbed bridge
            # field): skip with a clear reason. A tools-field
            # ValidationError would already have surfaced in Agent().
            msg = str(e).lower()
            if any(k in msg for k in ("openai", "api key", "litellm", "no llm", "key", "auth")):
                pytest.skip(f"CrewAI LLM bridge rejected offline LLM: {e}")
            raise

        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) >= 1, (
            "CrewAI kickoff completed without any /v1/check call — "
            "the GuardedCrewTool did not gate the agent's tool dispatch"
        )
        for b in bodies:
            assert b["scope"] == "shell"
            assert b["agent_id"] == "crew-at-kickoff"


class TestRealCrewKickoffDenyHaltsTool:
    def test_kickoff_with_deny_does_not_run_underlying(self, integration_mock):
        """On DENY the underlying ``_run`` never executes, whatever else
        CrewAI's run loop does.
        """
        integration_mock.set_default_check(deny(reason="rule:no-shell"))

        guard = Guard(integration_mock.base_url, agent_id="crew-at-deny")
        underlying = _EchoTool()
        runs_observed: list[str] = []
        original_run = underlying._run

        def _record(message: str) -> str:
            runs_observed.append(message)
            return original_run(message)

        # Shadowed on the instance, not the class, so other tests are
        # unaffected.
        underlying._run = _record  # type: ignore[assignment]
        wrapped = GuardedCrewTool(underlying, guard=guard, scope="shell")
        fake_llm = _OfflineEchoLLM(model="offline/echo-fake")

        try:
            agent = Agent(
                role="echoer",
                goal="echo back any message the user sends",
                backstory="you only call the echo tool",
                tools=[wrapped],
                allow_delegation=False,
                verbose=False,
                llm=fake_llm,
            )
            task = Task(
                description="Call echo tool with 'denied'",
                expected_output="some result",
                agent=agent,
            )
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            crew.kickoff()
        except VanzikDenied:
            pass
        except Exception as e:  # noqa: BLE001
            msg = str(e).lower()
            if any(k in msg for k in ("openai", "api key", "litellm", "no llm", "auth")):
                pytest.skip(f"CrewAI LLM bridge rejected offline LLM: {e}")
            raise

        assert runs_observed == [], (
            f"underlying tool ran despite DENY: invocations={runs_observed!r}"
        )
        assert len(integration_mock.requests_to("/v1/check")) >= 1
