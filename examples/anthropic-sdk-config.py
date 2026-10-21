"""
Vanzik LLM API Proxy — Anthropic Python SDK example.

Setup (Anthropic's base URL has no /v1 suffix: the SDK appends
/v1/messages itself):
  pip install "anthropic>=0.40"
  export ANTHROPIC_API_KEY=sk-ant-...              # your real Anthropic key
  export ANTHROPIC_BASE_URL=http://127.0.0.1:8081  # the proxy — NO /v1

Run Vanzik side (two terminals):

  # Terminal 1
  vanzik server \
      --policy configs/default.yaml \
      --dashboard \
      --watch \
      --api-key "$VANZIK_API_KEY"

  # Terminal 2 — the same proxy speaks /v1/chat/completions (OpenAI)
  # and /v1/messages (Anthropic).
  vanzik-llm-proxy \
      --listen 127.0.0.1:8081 \
      --policy configs/default.yaml \
      --guard-url http://127.0.0.1:8080 \
      --api-key "$VANZIK_API_KEY"

Then run this script:
  python examples/anthropic-sdk-config.py

Verified SDK versions, expected ALLOW / DENY / REQUIRE_APPROVAL behaviour
and gotchas: examples/anthropic-sdk-config.md.
"""

from __future__ import annotations

import os
import sys

# Anthropic SDK reads ANTHROPIC_BASE_URL automatically. Set a default
# in case the operator forgot to export it before running.
os.environ.setdefault("ANTHROPIC_BASE_URL", "http://127.0.0.1:8081")

try:
    from anthropic import Anthropic
except ImportError:  # pragma: no cover - guidance only
    sys.stderr.write(
        "anthropic-sdk-config.py: the 'anthropic' package is not installed.\n"
        "Install it with:  pip install 'anthropic>=0.40'\n"
    )
    sys.exit(2)


def main() -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        sys.stderr.write(
            "anthropic-sdk-config.py: ANTHROPIC_API_KEY is not set.\n"
            "Export your real Anthropic key — the proxy forwards x-api-key "
            "verbatim to api.anthropic.com.\n"
        )
        sys.exit(2)

    base_url = os.environ["ANTHROPIC_BASE_URL"]
    print(f"[client] base_url={base_url}  (note: no /v1 suffix)")

    client = Anthropic(base_url=base_url, api_key=api_key)

    # Same shell tool as the OpenAI example, but in the Anthropic
    # `tools` shape (no `function` wrapper). The default LLM tool-scope
    # map (pkg/llmproxy/scope_map.go) maps `bash` → `shell`.
    tools = [
        {
            "name": "bash",
            "description": "Execute a shell command on the local host.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The exact shell command to run.",
                    },
                },
                "required": ["command"],
            },
        },
    ]

    user_prompt = "List the files in /tmp by calling the bash tool."
    print(f"[user]   {user_prompt}\n")

    # `messages.stream(...)` is the canonical streaming call. Iterating
    # the context manager yields raw events; `.text_stream` is the
    # convenience iterator over text deltas only. We use the raw event
    # stream so we can also surface tool-input deltas as they arrive.
    print("[assistant stream]")
    with client.messages.stream(
        model="claude-haiku-5-5",  # any Claude model — proxy is model-agnostic
        max_tokens=512,
        tools=tools,
        messages=[{"role": "user", "content": user_prompt}],
    ) as stream:
        for event in stream:
            etype = getattr(event, "type", "")
            # Streaming text deltas (the `text` content block path —
            # also where Vanzik's synthetic refusal lands when a
            # tool_use block was DENIED).
            if etype == "content_block_delta":
                delta = getattr(event, "delta", None)
                if getattr(delta, "type", "") == "text_delta":
                    print(delta.text, end="", flush=True)
                # Tool-input fragments (the `input_json_delta` path).
                elif getattr(delta, "type", "") == "input_json_delta":
                    print(delta.partial_json, end="", flush=True)
            elif etype == "content_block_start":
                block = getattr(event, "content_block", None)
                if getattr(block, "type", "") == "tool_use":
                    print(f"\n[tool_use.name={block.name}]", flush=True)
            elif etype == "message_stop":
                # `message_delta` carries the stop_reason that the proxy
                # rewrites to `end_turn` on a DENY (so the SDK doesn't
                # wait for a tool result that won't come).
                pass
    print()


if __name__ == "__main__":
    main()
