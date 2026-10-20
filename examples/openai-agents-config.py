"""
Vanzik OpenAI Agents SDK adapter example.

Runs a real OpenAI Agents SDK agent (PyPI ``openai-agents``, import name
``agents``) whose function tool is gated by Vanzik with
``guard_tools``. Every tool call is checked against the central
Vanzik server's ``/v1/check`` before the tool body runs; a DENY or
REQUIRE_APPROVAL stops the run and raises to this script.

Verified against:
  - openai-agents 0.23.x (supported range: >=0.3.3,<1.0, the pin in
    plugins/python/pyproject.toml). Source:
    https://openai.github.io/openai-agents-python/tools/ (verified
    2026-10-14).

Setup:
  pip install 'vanzik[openai-agents]'
  export OPENAI_API_KEY=sk-...
  export VANZIK_API_KEY="$(openssl rand -hex 32)"   # same key as the server

Run the Vanzik server (one terminal):

  vanzik server \\
      --policy configs/default.yaml \\
      --dashboard \\
      --watch \\
      --api-key "$VANZIK_API_KEY"

Then run this script:
  python examples/openai-agents-config.py "list the files in /tmp"
  python examples/openai-agents-config.py "delete /tmp/vanzik-demo recursively"

Expected behaviour with configs/default.yaml:
  - ``ls /tmp`` matches ``allow: ls *`` in the shell scope: the tool
    runs and the agent answers with the listing.
  - ``rm -rf /tmp/vanzik-demo`` matches ``require_approval: rm -rf *``:
    the tool does not run, and Runner.run raises
    VanzikApprovalRequired carrying the approval id and URL.
  - Anything the policy denies raises VanzikDenied; the tool does
    not run and the model never sees a result.
  The dashboard (http://localhost:8080/dashboard) shows each decision.
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
