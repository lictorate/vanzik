"""Real-LangChain integration tests.

These tests exercise full Runnable pipelines against the actual
``langchain_core`` and ``langchain`` packages — never a mock of the
framework. Only the Vanzik HTTP server is mocked (``integration_mock``
fixture). They are the real-framework canary for end-to-end gate
enforcement under modern LangChain.

These tests are gated by ``@pytest.mark.integration`` so the regular
``pytest -m "not integration"`` run skips them. The CI integration-tests
job and weekly cron run them with the framework extras installed.
"""

from __future__ import annotations

import asyncio
import json

import pytest

# No minversion: the pyproject langchain extra enforces the floor at install
# time, and importorskip's `__version__` parsing spuriously skipped
# langchain 1.x on CI.
langchain_core = pytest.importorskip("langchain_core")
langchain = pytest.importorskip("langchain")

from langchain_core.tools import Tool  # noqa: E402

from vanzik import Guard  # noqa: E402
from vanzik.adapters.langchain import GuardedTool, GuardedToolkit  # noqa: E402

from .conftest import allow, deny, require_approval  # noqa: E402


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_real_tool(name: str = "echo", description: str = "echoes input"):
    """Build a real ``langchain_core`` Tool around a tracked function."""
    calls: list = []

    def _fn(text: str) -> str:
        calls.append(text)
        return f"echo:{text}"

    tool = Tool.from_function(name=name, description=description, func=_fn)
    return tool, calls


# ---------------------------------------------------------------------------
# Full agent / chain loops
# ---------------------------------------------------------------------------


class TestRealLangChainInvoke:
    """End-to-end ``tool.invoke(input)`` (what agent runtimes call) against
    the actual langchain_core runtime."""

    def test_real_langchain_invoke_allow(self, integration_mock):
        """A real langchain_core ``Tool`` wrapped by GuardedTool runs through invoke().

        What this catches: a regression where LangChain changes how
        ``BaseTool.invoke`` dispatches and bypasses our explicit override.
        """
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.invoke("hello")

        assert out == "echo:hello"
        assert calls == ["hello"]
        assert len(integration_mock.requests_to("/v1/check")) == 1

    def test_real_langchain_invoke_deny_raises(self, integration_mock):
        integration_mock.set_default_check(deny(reason="rule:rm-rf"))
        guard = Guard(integration_mock.base_url, agent_id="lc-int")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.invoke("rm -rf /")

        assert "denied" in str(ei.value).lower()
        assert calls == []

    def test_real_langchain_invoke_approval_raises(self, integration_mock):
        """REQUIRE_APPROVAL also surfaces as PermissionError for invoke()."""
        integration_mock.set_default_check(require_approval(approval_id="ap_lc1"))
        guard = Guard(integration_mock.base_url, agent_id="lc-int")
        tool, _ = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.invoke("anything")
        assert "approval" in str(ei.value).lower()

    def test_real_langchain_underlying_tool_invoke(self, integration_mock):
        """GuardedTool.invoke forwards to the real Tool's invoke(), not
        just ``.func``."""
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int")
        tool, calls = _make_real_tool(name="counter", description="counts")
        gt = GuardedTool(tool, guard, scope="shell")

        # Invoke via dict input (Tool.from_function accepts string or dict
        # depending on the args_schema).
        gt.invoke("first")
        gt.invoke("second")

        assert calls == ["first", "second"]
        assert len(integration_mock.requests_to("/v1/check")) == 2


class TestRealLangChainAsync:
    def test_chain_ainvoke_allow(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-async")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        async def _drive():
            return await gt.ainvoke("async-hi")

        out = asyncio.run(_drive())
        assert out == "echo:async-hi"
        assert calls == ["async-hi"]


class TestRealLangChainBatch:
    """Runnable.batch over multiple inputs with mixed decisions."""

    def test_batch_all_allow(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-batch")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.batch(["a", "b", "c"])

        # `out` keeps input order, but `calls` records completion order on
        # Runnable.batch's thread pool: compare sorted.
        assert out == ["echo:a", "echo:b", "echo:c"]
        assert sorted(calls) == ["a", "b", "c"]
        assert len(integration_mock.requests_to("/v1/check")) == 3

    def test_batch_partial_deny_raises_with_index(self, integration_mock):
        """Mock denies the second entry; the whole batch must fail with index 1."""
        integration_mock.enqueue_check(allow(), deny(reason="bad-2"), allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-batch")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.batch(["a", "b", "c"])

        msg = str(ei.value)
        assert "batch entry 1" in msg
        assert "denied" in msg.lower()
        # The first DENY fails the whole batch before anything runs.
        assert calls == []


class TestRealLangChainAttributeIntrospection:
    """LangChain runtime introspects ``args_schema``, ``name``, ``description``.

    That path must stay open while ``func`` stays unavailable.
    """

    def test_metadata_passthrough_works(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-meta")
        tool, _ = _make_real_tool(name="echo_v2", description="real LC tool")
        gt = GuardedTool(tool, guard, scope="shell")

        # These three reads happen during real LangChain agent construction
        # (see langchain.agents.create_react_agent's tool registration).
        assert gt.name == "echo_v2"
        assert gt.description == "real LC tool"
        assert gt.args_schema is None or hasattr(gt.args_schema, "__name__")

    def test_bypass_attribute_blocked(self, integration_mock):
        """``gt.func`` must not return a callable that skips the gate (the
        AttributeError comes from pydantic's "no such field" path)."""
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-meta")
        tool, _ = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(AttributeError):
            _ = gt.func


class TestRealLangChainToolkit:
    """Toolkit factory wraps a list of real Tools and infers scopes."""

    def test_toolkit_wraps_real_tools_and_routes_scopes(self, integration_mock):
        integration_mock.set_default_check(allow())

        net_tool = Tool.from_function(
            name="http_get",
            description="Fetch a URL via HTTP",
            func=lambda url: f"GET {url}",
        )
        fs_tool = Tool.from_function(
            name="file_read",
            description="Read a file from disk",
            func=lambda path: f"READ {path}",
        )

        toolkit = GuardedToolkit(
            tools=[net_tool, fs_tool],
            guard_url=integration_mock.base_url,
            agent_id="lc-int-toolkit",
        )

        assert all(isinstance(t, GuardedTool) for t in toolkit.tools)

        toolkit.tools[0].invoke("https://example.com")
        toolkit.tools[1].invoke("/tmp/x.txt")

        bodies = [
            json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 2
        assert bodies[0]["scope"] == "network"
        # File-tool gets static-inferred scope=filesystem from name keywords.
        assert bodies[1]["scope"] == "filesystem"
