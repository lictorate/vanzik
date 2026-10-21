"""
Vanzik LLM API Proxy — LangChain (langchain-openai) example.

Drives a real LangChain agent through the Vanzik LLM API Proxy.
The agent is plain `langchain_openai.ChatOpenAI` bound to a Python tool;
nothing about the agent code changes when going through the proxy —
only the `base_url=` argument moves from "https://api.openai.com/v1"
(implicit) to the proxy's `/v1` URL.

Verified against:
  - langchain-openai 1.x — `from langchain_openai import ChatOpenAI`,
    constructor parameter `base_url=...`. Source:
    https://docs.langchain.com/oss/python/integrations/chat/openai
    (verified 2026-05-05). The legacy `openai_api_base=` parameter is
    still accepted by langchain-openai 1.x but `base_url=` is the
    documented form going forward.
  - langchain-core 1.3.x for the `bind_tools` API on chat models.
  - openai==2.35.1 underneath — the same `OPENAI_BASE_URL` env var
    works as a fallback if you prefer not to pass `base_url=`
    explicitly.

Setup:
  pip install "langchain>=0.3,<2.0" "langchain-openai>=0.2"
  export OPENAI_API_KEY=sk-...
  export OPENAI_BASE_URL=http://127.0.0.1:8081/v1   # optional; we also
                                                    # pass base_url= below

Run Vanzik side (two terminals):

  # Terminal 1
  vanzik server \\
      --policy configs/default.yaml \\
      --dashboard \\
      --watch \\
      --api-key "$VANZIK_API_KEY"

  # Terminal 2
  vanzik-llm-proxy \\
      --listen 127.0.0.1:8081 \\
      --policy configs/default.yaml \\
      --guard-url http://127.0.0.1:8080 \\
      --api-key "$VANZIK_API_KEY"

Then run this script:
  python examples/langchain-agent-config.py

Expected behaviour:
  - The model decides to call `list_tmp_files`. Vanzik's default
    LLM tool-scope map routes the tool name → scope `unmapped` (it's
    not a built-in name like `bash`/`read_file`). Map it to a scope in
    your policy, and allow it there (`tool_scope_map` is a list):

        tool_scope_map:
          - pattern: "list_tmp_files"
            scope: shell

        rules:
          - scope: shell
            allow:
              - pattern: "list_tmp_files"

    For a tool mapped to `shell` the proxy checks the tool's `command`
    argument; this tool has none, so the check runs with the tool name
    as the command, which is why the allow rule names it. The mapping
    alone still gets the shell scope's default DENY. Without the
    mapping, the central engine's default-deny on the unmapped scope
    kicks in (as designed — see docs/POLICY_REFERENCE.md § "LLM API
    Proxy tool scope mapping"). In configs/default.yaml, add both lines
    to the existing `tool_scope_map:` list and `shell` block instead
    of a second block; see examples/langchain-agent-config.md.
  - The dashboard shows the decision live, transport chip
    `llm_api_proxy`.
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
