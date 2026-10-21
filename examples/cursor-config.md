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

The example config starts three downstream MCP servers, each with its own
launcher:

| Upstream | Launcher | Install |
|---|---|---|
| `fs` — filesystem server | `npx` | [Node.js](https://nodejs.org/) 20+ |
| `fetch` — fetch server | `uvx` | [uv](https://docs.astral.sh/uv/getting-started/installation/) |
| `github` — [GitHub's MCP server](https://github.com/github/github-mcp-server) | `docker` | [Docker](https://docs.docker.com/get-started/get-docker/) |

Install the launchers for the upstreams you keep and delete the
`--upstream` entries you don't need. A missing launcher disables only
that namespace: the gateway logs
`info mcpgw: startup: upstream "fetch" failed to spawn: …` and serves the
others. The GitHub server reads `GITHUB_PERSONAL_ACCESS_TOKEN` from the
config's `env` block; the gateway passes its environment to every
upstream, and `docker run -e GITHUB_PERSONAL_ACCESS_TOKEN` forwards it
into the container.

1. **Install binaries** (Go 1.26+):

   ```bash
   go install lictorate.com/vanzik/v2/cmd/vanzik@latest
   go install lictorate.com/vanzik/v2/cmd/vanzik-mcp-gateway@latest
   ```

2. **Pick a policy.** The config points `--policy` at
   `/etc/vanzik/default.yaml`, the starter policy a root install of the
   [one-line installer](../docs/SETUP.md#1-install) writes; the gateway
   and the server must load the same file. After a user install the
   starter is `~/.config/vanzik/default.yaml`: put its absolute path in
   the config, since nothing expands `~` there. Installed with
   `go install`? Copy `configs/default.yaml` from this repo into place:

   ```bash
   sudo mkdir -p /etc/vanzik
   sudo cp configs/default.yaml /etc/vanzik/default.yaml
   ```

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

Do **not** pass `--api-key "$VANZIK_API_KEY"` as an `args` entry.
Cursor's `${env:VAR}` interpolation has been unreliable across
versions, and JSON-level `$VAR` shell-expansion never happens. The
safe path is to set `VANZIK_API_KEY` in the `env` block (or
inherited from Cursor's parent shell) and **omit** the `--api-key`
flag entirely — the gateway picks up the env var automatically when
the flag is absent.

Today the gateway calls only `/v1/check`, which the server leaves open,
so a missing or literal key doesn't stop it working. The key is still the
bearer it sends on every call, so set the real one.

## Tenant ID

`--tenant-id` picks the tenant whose policy evaluates the gateway's
calls (they go to `/v1/t/<tenant>/check`). Keep `local` — the policy
the server loads with `--policy` — unless you've registered another
tenant on the central server with
`vanzik tenant put <id> --policy <file.yaml>`. A tenant the server
doesn't know (including a templated value such as
`cursor-${env:USER}` that you haven't registered) answers `404`, which the gateway
treats like an unreachable server: `--fail-mode` decides, so with `deny`
every call is refused.

## Notes

- Cursor passes namespace-prefixed tool names through verbatim, so policies
  written against `fs:read_text_file` (or any other namespace) work without
  changes.
- If you have an existing top-level `mcpServers` block, add the
  `vanzik` entry inside it; Cursor merges entries by name.
- The `env` field on a server entry is forwarded to the gateway's parent
  process, which then forwards it to each spawned upstream — but
  `${env:VAR}` interpolation happens at Cursor's level, before the gateway
  sees the args.
