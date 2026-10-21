# Integration Examples

Copy-paste working configs for Vanzik's integration paths. Every
example was last verified against the upstream client docs on **2026-05-05**;
each `<client>-config.md` file cites the source URL and the verification
date.

## MCP Gateway

The gateway binary is `vanzik-mcp-gateway` (Go 1.26+,
`go install lictorate.com/vanzik/v2/cmd/vanzik-mcp-gateway@latest`).
It sits between an MCP client and one or more downstream MCP servers,
gating every `tools/call` against the central Vanzik server's
`/v1/check`. See [`docs/MCP_GATEWAY.md`](../docs/MCP_GATEWAY.md) for the
wire-format design and [`docs/QUICKSTART_MCP.md`](../docs/QUICKSTART_MCP.md)
for the 90-second walkthrough.

| Client | Config file | Where it lives |
|---|---|---|
| Claude Desktop | [`claude-desktop-config.json`](claude-desktop-config.json) | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | [`cursor-config.json`](cursor-config.json) | global `~/.cursor/mcp.json` or per-project `<workspace>/.cursor/mcp.json` |
| Cline (VS Code) | [`cline-config.json`](cline-config.json) | inside VS Code's `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` (use the in-app "Configure MCP Servers" button) |
| Continue.dev | [`continue-config.json`](continue-config.json) (legacy) or YAML in [`continue-config.md`](continue-config.md) | `~/.continue/config.json` or `<workspace>/.continue/mcpServers/*.yaml` |
| Zed | [`zed-config.json`](zed-config.json) | `~/.config/zed/settings.json` (key: `context_servers`, not `mcpServers`) |

Each `<client>-config.json` has a sibling `<client>-config.md` with the
authoritative file path, OS-specific gotchas, the source-doc URL +
verification date, and concrete verification steps. The guides share the
setup below and note only what their client does differently.

### Downstream servers

The configs start three downstream MCP servers, each with its own
launcher:

| Upstream | Launcher | Install |
|---|---|---|
| `fs` — filesystem server | `npx` | [Node.js](https://nodejs.org/) 20+ |
| `fetch` — fetch server | `uvx` | [uv](https://docs.astral.sh/uv/getting-started/installation/) |
| `github` — [GitHub's MCP server](https://github.com/github/github-mcp-server) | `docker` | [Docker](https://docs.docker.com/get-started/get-docker/) |

Install the launchers for the upstreams you keep and delete the
`--upstream` entries you don't need; each one is a subprocess the gateway
starts with it. More servers: <https://github.com/modelcontextprotocol/servers>.
A missing launcher disables only that namespace: the gateway logs
`info mcpgw: startup: upstream "fetch" failed to spawn: …` and serves the
others. The GitHub server reads `GITHUB_PERSONAL_ACCESS_TOKEN` from the
config's `env` block; the gateway passes its environment to every
upstream, and `docker run -e GITHUB_PERSONAL_ACCESS_TOKEN` forwards it
into the container.

### Policy file

The configs point `--policy` at `/etc/vanzik/default.yaml`, the starter
policy a root install of the [one-line installer](../docs/SETUP.md#1-install)
writes; start the central server with the same file. After a user install
the starter is `~/.config/vanzik/default.yaml`: put its absolute path (for
example `/home/you/.config/vanzik/default.yaml`) in the config, since
nothing expands `~` there. Installed with `go install`? Copy
`configs/default.yaml` from this repo into place:

```bash
sudo mkdir -p /etc/vanzik
sudo cp configs/default.yaml /etc/vanzik/default.yaml
```

With `--policy-mode strict` the gateway exits 1 when the file is missing.

### API key handling

Do **not** pass `--api-key "$VANZIK_API_KEY"` as an `args` entry. None of
the clients shell-expands `$VAR` inside `args`, so the gateway would
receive the literal string `$VANZIK_API_KEY` and send it as the key. Put
the key in the config's `env` block (filled from your shell or a secret
store, not pasted raw) and omit `--api-key`: the gateway reads
`VANZIK_API_KEY` from its environment when the flag is absent. Writing
the literal key into `args` also works, but bakes a secret into the
config file.

Today the gateway calls only `/v1/check`, which the server leaves open,
so a missing or literal key doesn't stop it working. The key is still the
bearer it sends on every call, so set the real one.

### Tenant ID

`--tenant-id` picks the tenant whose policy evaluates the gateway's
calls (they go to `/v1/t/<tenant>/check`). Keep `local` — the policy
the server loads with `--policy` — unless you've registered another
tenant on the central server with
`vanzik tenant put <id> --policy <file.yaml>`. A tenant the server
doesn't know answers `404`, which the gateway
treats like an unreachable server: `--fail-mode` decides, so with `deny`
every call is refused.

## LLM API Proxy

The proxy binary is `vanzik-llm-proxy` (Go 1.26+,
`go install lictorate.com/vanzik/v2/cmd/vanzik-llm-proxy@latest`).
It speaks the OpenAI Chat Completions and Anthropic Messages wire
formats, forwards traffic to the real upstream, and gates tool calls
inside the response stream against the central Vanzik server's
`/v1/check`. Existing code that already uses the OpenAI / Anthropic
SDKs works unchanged after setting one environment variable. See
[`docs/LLM_API_PROXY.md`](../docs/LLM_API_PROXY.md) for the wire-format
design and [`docs/QUICKSTART_LLM_PROXY.md`](../docs/QUICKSTART_LLM_PROXY.md)
for the 90-second walkthrough.

| SDK | Example | Path convention |
|---|---|---|
| OpenAI Python | [`openai-sdk-config.py`](openai-sdk-config.py) + [`openai-sdk-config.md`](openai-sdk-config.md) | `OPENAI_BASE_URL=http://127.0.0.1:8081/v1` (with `/v1`) |
| Anthropic Python | [`anthropic-sdk-config.py`](anthropic-sdk-config.py) + [`anthropic-sdk-config.md`](anthropic-sdk-config.md) | `ANTHROPIC_BASE_URL=http://127.0.0.1:8081` (no `/v1`) |
| LangChain | [`langchain-agent-config.py`](langchain-agent-config.py) + [`langchain-agent-config.md`](langchain-agent-config.md) | `ChatOpenAI(base_url="http://127.0.0.1:8081/v1")` |
| CrewAI | [`crewai-agent-config.py`](crewai-agent-config.py) + [`crewai-agent-config.md`](crewai-agent-config.md) | `LLM(base_url="http://127.0.0.1:8081/v1", ...)` |

Each example is runnable end-to-end (`python <file>.py` after `pip
install`), refusals included: a DENY or REQUIRE_APPROVAL arrives as
ordinary assistant text, also through Anthropic's `messages.stream()`.
The paired `.md` walks through the two-binary setup, expected ALLOW /
DENY / REQUIRE_APPROVAL behaviour with the bundled default policy
(`dd if=/dev/zero of=/dev/sda` is denied; `sudo …` and `rm -rf …` need
approval; the LangChain and CrewAI tools first need a `tool_scope_map`
entry and an allow rule), how to resume an approved call with the
`X-Vanzik-Approval-ID` header, and SDK-specific gotchas. Quickstart:
[`docs/QUICKSTART_LLM_PROXY.md`](../docs/QUICKSTART_LLM_PROXY.md).

## Other integration paths

- **OpenAI Agents SDK adapter.**
  [`openai-agents-config.py`](openai-agents-config.py) +
  [`openai-agents-config.md`](openai-agents-config.md) — an OpenAI
  Agents SDK agent whose function tools are gated in-process with
  `guard_tools`. The LLM API Proxy speaks Chat Completions, not the
  Responses API the Agents SDK uses by default; the guide shows how to
  stack the two.
- **SDK (compatibility tier).** [`quickstart.py`](quickstart.py) — the
  Python SDK example: explicit `Guard.check(...)` calls in agent code.
  The SDK is documented in [`docs/SDK_PYTHON.md`](../docs/SDK_PYTHON.md).
  Use it when the proxy isn't practical (offline scripts, custom
  transports), and pair it with the proxy whenever both are available.
