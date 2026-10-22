"""
Vanzik LLM API Proxy — LangChain (langchain-openai) example.

Setup:
  pip install "langchain>=0.3,<2.0" "langchain-openai>=0.2"
  export OPENAI_API_KEY=sk-...
  export OPENAI_BASE_URL=http://127.0.0.1:8081/v1   # optional; we also
                                                    # pass base_url= below

Run Vanzik side (two terminals):

  # Terminal 1
  vanzik server \
      --policy configs/default.yaml \
      --dashboard \
      --watch \
      --api-key "$VANZIK_API_KEY"

  # Terminal 2
  vanzik-llm-proxy \
      --listen 127.0.0.1:8081 \
      --policy configs/default.yaml \
      --guard-url http://127.0.0.1:8080 \
      --api-key "$VANZIK_API_KEY"

Then run this script:
  python examples/langchain-agent-config.py

The `list_tmp_files` tool needs a `tool_scope_map` entry and an allow
rule first; without them it reaches the engine as scope `unmapped` and is
denied. That policy snippet, verified versions, expected behaviour and
gotchas: examples/langchain-agent-config.md.
"""

from __future__ import annotations

import os
import subprocess
import sys

# Both langchain_openai and the underlying openai SDK honor
# OPENAI_BASE_URL; we set it as a belt-and-braces in case the operator
# didn't export it explicitly.
os.environ.setdefault("OPENAI_BASE_URL", "http://127.0.0.1:8081/v1")

try:
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_core.tools import tool
    from langchain_openai import ChatOpenAI
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "langchain-agent-config.py: required packages not installed.\n"
        "Install with:  pip install 'langchain>=0.3,<2.0' 'langchain-openai>=0.2'\n"
    )
    sys.exit(2)


@tool
def list_tmp_files(_query: str = "") -> str:
    """List files in /tmp. Argument is ignored — kept for tool-call signature."""
    try:
        result = subprocess.run(
            ["ls", "-la", "/tmp"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout or result.stderr or "(no output)"
    except Exception as exc:  # pragma: no cover - host-dependent
        return f"error: {exc}"


def main() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        sys.stderr.write(
            "langchain-agent-config.py: OPENAI_API_KEY is not set.\n"
            "Export your real OpenAI key — the proxy forwards it verbatim.\n"
        )
        sys.exit(2)

    base_url = os.environ["OPENAI_BASE_URL"]
    print(f"[langchain] ChatOpenAI(base_url={base_url!r})")

    # The langchain-openai 1.x signature accepts `base_url=` directly.
    # The constructor falls back to OPENAI_BASE_URL when base_url is
    # not provided, so passing it explicitly is a safety belt only.
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        base_url=base_url,
        # Streaming surfaces the proxy's pause/resume mechanism — set
        # to False to exercise the non-streaming path through the proxy
        # (which buffers the entire response and gates tool_calls before
        # forwarding the body).
        streaming=True,
        temperature=0,
    )

    tools = [list_tmp_files]
    llm_with_tools = llm.bind_tools(tools)

    messages = [
        SystemMessage(
            content=(
                "You are a helpful assistant. When the user asks about "
                "files, call the list_tmp_files tool — do not answer from "
                "memory."
            )
        ),
        HumanMessage(content="What files are in /tmp right now?"),
    ]

    print(f"[user] {messages[-1].content}\n")

    # First turn — model returns either text or a tool_call. The proxy
    # gates the tool_call before the SDK sees the deltas; on DENY the
    # model's "response" is an assistant text starting with
    # `Vanzik denied this action.`
    response = llm_with_tools.invoke(messages)

    if response.tool_calls:
        print(f"[assistant requested {len(response.tool_calls)} tool call(s)]")
        for tc in response.tool_calls:
            print(f"  - {tc['name']}({tc['args']})")
            # Execute the tool locally only because the proxy ALLOWed
            # the call. If the proxy had DENIED, we'd never have
            # received a tool_calls list — we'd have received a plain
            # assistant text refusal instead.
            tool_result = list_tmp_files.invoke(tc["args"])
            print(f"  result:\n{tool_result}")
    else:
        # Either pure text from the model, OR a synthetic refusal that
        # Vanzik injected. Both arrive as `response.content`.
        print(f"[assistant text]\n{response.content}")


if __name__ == "__main__":
    main()
