# Continue.dev — Vanzik MCP Gateway

Drop-in MCP config that routes Continue's agent-mode tool calls through
the Vanzik gateway.

> Source: <https://docs.continue.dev/customize/deep-dives/mcp> (verified
> 2026-05-05). Continue accepts either a YAML block file under
> `.continue/mcpServers/` (preferred) **or** an `mcpServers` block in the
> legacy `~/.continue/config.json`. Both shapes are documented below.
>
> The docs note: "MCP can only be used in **agent** mode" — slash-command
> and chat modes do not invoke tools.

## Option A — YAML block file (preferred, current docs)

Save the following to `<workspace>/.continue/mcpServers/vanzik.yaml`:

```yaml
name: Vanzik MCP Gateway
version: 0.0.1
schema: v1
mcpServers:
  - name: vanzik
    type: stdio
    command: vanzik-mcp-gateway
    args:
      - "--upstream"
      - "fs:npx -y @modelcontextprotocol/server-filesystem /tmp"
      - "--upstream"
      - "fetch:uvx mcp-server-fetch"
      - "--upstream"
      - "github:docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server"
      - "--guard-url"
      - "http://127.0.0.1:8080"
      - "--policy"
      - "/etc/vanzik/default.yaml"
      - "--tenant-id"
      - "local"
      - "--policy-mode"
      - "strict"
      - "--fail-mode"
      - "deny"
      - "--log-level"
      - "info"
    env:
      VANZIK_API_KEY: set-from-shell-or-secret-store
      GITHUB_PERSONAL_ACCESS_TOKEN: set-from-shell-or-secret-store
```

> Don't add `--api-key "$VANZIK_API_KEY"` to `args`; the `env:` block is
> enough. See "API key handling" below.

The file is auto-detected — no Continue restart needed for the YAML path
(restart the chat panel to be safe).

## Option B — JSON in `~/.continue/config.json`

If you're on a Continue release that still uses `config.json`, paste the
contents of `continue-config.json` into the top-level object (merge with
your existing `mcpServers` block if you have one).

| OS | Path |
|----|------|
| macOS / Linux | `~/.continue/config.json` |
| Windows | `%USERPROFILE%\.continue\config.json` |

## What this config does

```
Continue (agent mode) ──stdio──► vanzik-mcp-gateway ──► fs / fetch / github
                                       │
                                       └─HTTP──► http://127.0.0.1:8080/v1/check
                                                 (policy + audit + dashboard)
```

## Setup

Install the launchers (`npx`, `uvx`, `docker`) for the upstreams you keep;
see [Downstream servers](README.md#downstream-servers).

1. **Install binaries** (Go 1.26+):

   ```bash
   go install lictorate.com/vanzik/v2/cmd/vanzik@latest
   go install lictorate.com/vanzik/v2/cmd/vanzik-mcp-gateway@latest
   ```

2. **Pick a policy.** The config points `--policy` at
   `/etc/vanzik/default.yaml`; for a user install or a `go install`
   setup, see [Policy file](README.md#policy-file).

3. **Export the API key** in the shell that launches your editor:

   ```bash
   export VANZIK_API_KEY="$(openssl rand -hex 32)"
   ```

4. **Start the central Vanzik server:**

   ```bash
   vanzik server --policy /etc/vanzik/default.yaml --dashboard --watch --api-key "$VANZIK_API_KEY"
   ```

5. **Save the YAML / JSON.** Switch Continue into agent mode and try a
   tool-using prompt.

## Verification

In Continue's agent-mode chat:

- "Read `/tmp/notes.txt`" → ALLOW (default policy), dashboard shows event.
- "Fetch `https://example.com`" → REQUIRE_APPROVAL under the default
  policy (`fetch:*`). Even after approval it is denied, because
  `example.com` isn't on the default `network` allow-list — add it under
  `scope: network` to let it through (see the [approval flow](../docs/MCP_GATEWAY.md#6-approval-flow)).
- "Read `/etc/passwd`" → DENY, dashboard shows event.

## API key handling

Continue does not shell-expand `$VAR` inside JSON or YAML `args`: put
the key in the `env` block and omit `--api-key`. See
[API key handling](README.md#api-key-handling).

## Tenant ID

Keep `--tenant-id local` unless you've registered another tenant; see
[Tenant ID](README.md#tenant-id).

## Notes

- Continue's docs explicitly say JSON configs from Claude Desktop and
  Cursor can be dropped under `.continue/mcpServers/` — so
  `claude-desktop-config.json` from this directory works too.
- If you don't see tools in chat, switch the mode dropdown to **Agent**.
