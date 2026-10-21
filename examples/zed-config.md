# Zed — Vanzik MCP Gateway

Drop-in config that routes Zed's Assistant tool calls through the
Vanzik gateway. Zed names its MCP integration *context servers*; the
top-level config key is `context_servers`, not `mcpServers`.

> Source: <https://zed.dev/docs/ai/mcp.html> (verified 2026-05-05). Zed's
> MCP support is stable but the docs note ongoing schema iteration —
> verify the key name and the per-server fields against current docs at
> deploy time.

## Config file path

Zed stores MCP config in its main `settings.json`. Paths:

| OS | Path |
|----|------|
| macOS | `~/.config/zed/settings.json` |
| Linux | `~/.config/zed/settings.json` |
| Windows | `%APPDATA%\Zed\settings.json` |

Open it from inside Zed via the command palette: `zed: open settings`.

## Merging into your settings

`zed-config.json` in this directory is a complete file you can use
verbatim only if `settings.json` is empty. Otherwise, merge the
`context_servers` block into your existing settings:

```jsonc
{
  // ... your existing Zed settings ...

  "context_servers": {
    "vanzik": {
      "command": "vanzik-mcp-gateway",
      "args": [
        "--upstream", "fs:npx -y @modelcontextprotocol/server-filesystem /tmp",
        "--guard-url", "http://127.0.0.1:8080",
        "--policy", "/etc/vanzik/default.yaml",
        "--tenant-id", "local",
        "--policy-mode", "strict"
      ],
      "env": {
        "VANZIK_API_KEY": "set-from-shell-or-secret-store"
      }
    }
  }
}
```

## What this config does

```
Zed (Assistant) ──stdio──► vanzik-mcp-gateway ──► fs / fetch / github upstreams
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

3. **Export the API key** before launching Zed:

   ```bash
   export VANZIK_API_KEY="$(openssl rand -hex 32)"
   ```

   On macOS, Zed launched from Finder/Spotlight may not inherit your
   shell rc files. Either launch from a terminal (`zed .`) or set the
   variable as a launchd / GUI environment variable, then mirror it into
   the `env` block above.

4. **Start the central Vanzik server:**

   ```bash
   vanzik server --policy /etc/vanzik/default.yaml --dashboard --watch --api-key "$VANZIK_API_KEY"
   ```

5. **Save settings.json.** Zed reloads it live; the Assistant should
   surface the merged tool list under the Vanzik context server.

## Verification

In Zed's Assistant panel:

- Ask the model to read a file from `/tmp` → ALLOW (default policy).
- Ask it to read `/etc/passwd` → DENY, visible on the dashboard.
- Open <http://127.0.0.1:8080/dashboard> to see the live event feed.

## API key handling

Zed does not shell-expand `$VAR` inside JSON `args` and has no
`${env:VAR}` syntax (unlike Cursor), so the context server's `env` block
is the only way to feed the key to the gateway; omit `--api-key`. See
[API key handling](README.md#api-key-handling).

## Tenant ID

Keep `--tenant-id local` unless you've registered another tenant; see
[Tenant ID](README.md#tenant-id).

## Notes

- Zed also supports remote / HTTP context servers via a `url`+`headers`
  shape. Zed talks to the Vanzik gateway over stdio; to guard a
  remote server, give the gateway `--upstream-http "<ns>:<url>"` instead
  of pointing Zed at the URL (see
  [`MCP_GATEWAY.md` § 8.5](../docs/MCP_GATEWAY.md#85-streamable-http-upstreams)).
- To keep raw keys out of `settings.json`, have a small launcher script
  export them from your shell's environment.
