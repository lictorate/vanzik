# Cline — Vanzik MCP Gateway

Drop-in `cline_mcp_settings.json` that routes Cline's MCP tool calls
through the Vanzik gateway. Cline (formerly Claude Dev) is a VS Code
extension that exposes an autonomous agent in the editor; this config
gates every tool call against your policy.

> Source: <https://docs.cline.bot/mcp/configuring-mcp-servers> (verified
> 2026-05-05). Cline's schema mirrors Claude Desktop's `mcpServers` shape
> and adds `disabled` and `alwaysAllow` keys per entry.

## Config file path

Cline stores its MCP config inside VS Code's extension `globalStorage`
directory. The fastest way to open the file is from inside VS Code:

1. Open the Cline panel.
2. Click the **MCP Servers** tab.
3. Click **Configure MCP Servers** — VS Code opens
   `cline_mcp_settings.json` in an editor tab.

Concrete paths (subject to change between Cline releases — verify with the
Configure-MCP-Servers button):

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Windows | `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json` |
| Linux | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |

The extension publisher slug (`saoudrizwan.claude-dev`) may have changed if
you installed Cline under a different publisher; in that case use the
**Configure MCP Servers** button to find the actual path. Cursor / Codium
forks of VS Code use a different parent directory (e.g.
`~/.config/Cursor/User/...`).

## What this config does

```
VS Code (Cline panel) ──stdio──► vanzik-mcp-gateway ──► fs / fetch / github upstreams
                                          │
                                          └─HTTP──► http://127.0.0.1:8080/v1/check
                                                    (policy / audit / dashboard)
```

The Cline-specific keys:

- `disabled: false` — leave the server enabled. Set `true` to skip without
  removing the entry.
- `alwaysAllow: []` — names of tools Cline will auto-approve in its own UI.
  Leave empty so Cline's per-action prompts still fire **and** Vanzik's
  policy is the authoritative gate. Adding tool names here only suppresses
  Cline's prompt; it does **not** bypass the Vanzik policy.

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

3. **Export the API key** in the shell that launches VS Code:

   ```bash
   export VANZIK_API_KEY="$(openssl rand -hex 32)"
   ```

   On macOS, VS Code launched from Finder/Spotlight may not see your
   `~/.zshrc` exports. Either launch VS Code from a terminal (`code .`) or
   put `VANZIK_API_KEY` in your VS Code `terminal.integrated.env.*`
   settings, then mirror it into the `env` block of the config above.

4. **Start the central Vanzik server:**

   ```bash
   vanzik server \
     --policy /etc/vanzik/default.yaml \
     --dashboard \
     --watch \
     --api-key "$VANZIK_API_KEY"
   ```

5. **Save the JSON.** Cline picks up MCP-config changes immediately — the
   server panel shows `vanzik` once the file parses cleanly.

## Verification

Open the Cline chat in VS Code and ask:

- "Read `/tmp/test.txt`" — Cline calls `fs:read_text_file` through the
  gateway, Vanzik's default policy ALLOWs it, dashboard shows the
  event.
- "List recent issues from `<your repo>`" — gateway routes via `github:`;
  the default policy requires approval for every `github:*` call, so the
  tool returns an approval request and the dashboard lists it (see the
  [approval flow](../docs/MCP_GATEWAY.md#6-approval-flow)).
- "Read `/etc/passwd`" — DENY, dashboard shows the deny event.

## API key handling

Cline does not shell-expand `$VAR` inside JSON `args`: put the key in
the `env` block and omit `--api-key`. See
[API key handling](README.md#api-key-handling).

## Tenant ID

Keep `--tenant-id local` unless you've registered another tenant; see
[Tenant ID](README.md#tenant-id).

## Notes

- `alwaysAllow` and Vanzik's policy compose: Cline skips its own prompt
  for the tool, Vanzik still checks every call against the policy.
