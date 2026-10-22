# Cursor — Vanzik MCP Gateway

Drop-in `mcp.json` that routes Cursor's MCP tool calls through the
Vanzik gateway, gating every call against your policy before forwarding
to the real downstream MCP server.

> Source: <https://cursor.com/docs/context/mcp> (verified 2026-05-05).
> Cursor's MCP support evolves quickly — verify the schema against current
> docs at deploy time. The `type: "stdio"` field is documented as required
> for stdio servers in current revisions.

## Config file path

Cursor supports two scopes:

| Scope | Path |
|----|------|
| Global (all projects) | `~/.cursor/mcp.json` |
| Project-specific | `<workspace>/.cursor/mcp.json` |

A project-level file overrides the global file for that workspace, so a
single `vanzik` server entry in `~/.cursor/mcp.json` is enough to gate
every Cursor session, as long as every path in it exists everywhere: the
example's `--policy /etc/vanzik/default.yaml` does, while a
`${workspaceFolder}/.vanzik/policy.yaml` path would need that file in
every workspace (the gateway refuses to start without it).

## What this config does

```
Cursor (Composer / agent mode)
    │ stdio (MCP)
    ▼
vanzik-mcp-gateway
    │
    ├─stdio──► server-filesystem via npx (scoped to ${workspaceFolder} and /tmp)
    ├─stdio──► mcp-server-fetch (uvx)
    ├─stdio──► github-mcp-server (docker)
    │
    └─HTTP──► http://127.0.0.1:8080/v1/check
              (central Vanzik: policy + audit + dashboard)
```

`${workspaceFolder}` is a Cursor variable that expands to the open
project's root, so the filesystem upstream is automatically scoped to the
current workspace (plus `/tmp`, for the verification below). `${env:VAR}` reads the variable from Cursor's launching
environment.

## Setup

Install the launchers (`npx`, `uvx`, `docker`) for the upstreams you keep;
see [Downstream servers](README.md#downstream-servers).

1. **Install binaries** (Go 1.26+):

   ```bash
   go install lictorate.com/vanzik/v2/cmd/vanzik@latest
   go install lictorate.com/vanzik/v2/cmd/vanzik-mcp-gateway@latest
   ```

2. **Pick a policy.** The config points `--policy` at
   `/etc/vanzik/default.yaml`; the gateway and the server must load the
   same file. For a user install or a `go install` setup, see
   [Policy file](README.md#policy-file).

   For a policy that lives in one project instead, copy it to
   `.vanzik/policy.yaml` there, use
   `"--policy", "${workspaceFolder}/.vanzik/policy.yaml"` in that
   project's `.cursor/mcp.json` only, and start the server with the same
   file.

3. **Export the API key** in the shell that starts Cursor:

   ```bash
   export VANZIK_API_KEY="$(openssl rand -hex 32)"
   ```

   Cursor launched from Finder, Spotlight or the Dock on macOS may not
   see exports from `~/.zshrc`, so also put the key in the config's
   `env` block (`"VANZIK_API_KEY": "<the key>"`). On Windows, set it as
   a User Environment Variable or in the `env` block.

4. **Run the central server** in a terminal:

   ```bash
   vanzik server \
     --policy /etc/vanzik/default.yaml \
     --dashboard \
     --watch \
     --api-key "$VANZIK_API_KEY"
   ```

5. **Save the config**, then **reload Cursor** (Cmd/Ctrl-Shift-P → "Reload
   Window"). The MCP server panel should show `vanzik` and its merged
   tools list.

## Verification

In Cursor's chat (Composer):

- "Read `/tmp/hello.txt`" → ALLOW: the default policy allows reads under
  `/tmp` (and `./workspace`).
- "Read `package.json` from this workspace" → DENY under the default
  policy, which doesn't know your project's path. To allow it, add the
  workspace to the read `paths` of the existing `filesystem` block in
  the policy the server loads:

  ```yaml
  - scope: filesystem
    allow:
      - action: read
        paths: ["./workspace/**", "/tmp/**", "/Users/you/projects/myapp/**"]
  ```

  The server reloads the file on save; the same read is then ALLOWed.
- "Read `/etc/passwd`" (or `C:\Windows\System32\drivers\etc\hosts` on
  Windows) → DENY, surfaced on the dashboard at
  <http://127.0.0.1:8080/dashboard>.

## API key handling

Cursor's `${env:VAR}` interpolation has been unreliable across
versions, and plain `$VAR` is never expanded: set `VANZIK_API_KEY` in
the `env` block (or inherit it from Cursor's parent shell) and omit
`--api-key`. See [API key handling](README.md#api-key-handling).

## Tenant ID

Keep `--tenant-id local` unless you've registered another tenant; see
[Tenant ID](README.md#tenant-id). A templated value such as
`cursor-${env:USER}` counts too: each value it expands to must be
registered, or the server answers `404`.

## Notes

- Cursor passes namespace-prefixed tool names through verbatim, so policies
  written against `fs:read_text_file` (or any other namespace) work without
  changes.
- If you have an existing top-level `mcpServers` block, add the
  `vanzik` entry inside it; Cursor merges entries by name.
- Cursor expands `${env:VAR}` before the gateway sees the args; the
  `env` entries reach the gateway and every upstream it spawns.
