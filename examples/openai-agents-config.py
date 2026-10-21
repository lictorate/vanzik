"""
Vanzik OpenAI Agents SDK adapter example.

An OpenAI Agents SDK agent whose function tool is gated with
``guard_tools``: each call is checked against the Vanzik server's
``/v1/check`` before the tool body runs, and a DENY or REQUIRE_APPROVAL
raises to this script.

Setup:
  pip install 'vanzik[openai-agents]'
  export OPENAI_API_KEY=sk-...
  export VANZIK_API_KEY="$(openssl rand -hex 32)"   # same key as the server

Run the Vanzik server (one terminal):

  vanzik server \
      --policy configs/default.yaml \
      --dashboard \
      --watch \
      --api-key "$VANZIK_API_KEY"

Then run this script:
  python examples/openai-agents-config.py "list the files in /tmp"
  python examples/openai-agents-config.py "delete /tmp/vanzik-demo recursively"

With configs/default.yaml the first runs the tool and the second raises
VanzikApprovalRequired. Verified versions, expected behaviour and
gotchas: examples/openai-agents-config.md.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from typing import Any, Optional

try:
    from agents import Agent, Runner, function_tool
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "openai-agents-config.py: the 'openai-agents' package is not installed.\n"
        "Install with:  pip install 'vanzik[openai-agents]'\n"
    )
    sys.exit(2)

from vanzik import VanzikApprovalRequired, VanzikDenied, Guard
from vanzik.adapters.openai_agents import guard_tools


@function_tool
def run_shell(command: str) -> str:
    """Run a shell command on this host and return its output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout or result.stderr or "(no output)"
    except Exception as exc:  # pragma: no cover - host-dependent
        return f"error: {exc}"


def build_agent(guard: Guard, model: Optional[Any] = None) -> Any:
    """The agent, with its tools gated by ``guard``.

    ``model`` defaults to the SDK's default OpenAI model; pass an
    ``agents.Model`` to run without an API key.
    """
    kwargs = {"model": model} if model is not None else {}
    return Agent(
        name="ops",
        instructions=(
            "You operate a Linux host. Use the run_shell tool for anything "
            "that needs the filesystem; do not answer from memory."
        ),
        # guard_tools returns gated copies; run_shell itself stays ungated.
        tools=guard_tools([run_shell], guard),
        **kwargs,
    )


async def run(prompt: str, guard: Guard, model: Optional[Any] = None) -> int:
    agent = build_agent(guard, model)
    try:
        result = await Runner.run(agent, prompt)
    except VanzikApprovalRequired as e:
        print(f"[vanzik] approval required: {e.result.reason}")
        print(f"[vanzik] approve at: {e.approval_url}")
        return 3
    except VanzikDenied as e:
        print(f"[vanzik] denied: {e.result.reason}")
        return 1
    print(result.final_output)
    return 0


def main() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        sys.stderr.write(
            "openai-agents-config.py: OPENAI_API_KEY is not set.\n"
            "The agent's model runs on OpenAI; Vanzik only gates the tools.\n"
        )
        sys.exit(2)

    prompt = " ".join(sys.argv[1:]) or "List the files in /tmp."
    guard = Guard(
        os.environ.get("VANZIK_URL", "http://localhost:8080"),
        agent_id="openai-agents-example",
    )
    print(f"[user] {prompt}\n")
    sys.exit(asyncio.run(run(prompt, guard)))


if __name__ == "__main__":
    main()
