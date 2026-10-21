# FAQ

Questions that come up often in issues and conversations. For symptom-keyed debugging see [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

---

### What is Vanzik, exactly?

**A wire-level checkpoint** that sits between an AI agent and everything it touches — shell, files, network, browser, MCP servers, the model itself. Every action is evaluated against a YAML policy and resolved as `ALLOW` / `DENY` / `REQUIRE_APPROVAL`, with an append-only audit log and a human-in-the-loop approval queue behind it.

The checkpoint runs at three layers, all sharing one policy + audit + approval queue:

- **MCP traffic** → `vanzik-mcp-gateway` (Claude Desktop, Cursor, Cline, Continue, Zed)
- **LLM API calls** → `vanzik-llm-proxy` (OpenAI / Anthropic SDK code, via `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL`)
- **Direct calls** → Python / TypeScript SDK + framework adapters (LangChain, CrewAI, browser-use)

### Is it a sandbox?

No. Vanzik does not intercept syscalls or containerize processes. A determined agent that controls its own runtime can bypass the checkpoint by talking to a different MCP server or ignoring `OPENAI_BASE_URL`. For strong isolation, pair Vanzik with OS-level sandboxing (containers, seccomp, AppArmor) and network-egress controls.

### Do I need to modify my agent code?

Depends on the layer:

- **MCP Gateway** and **LLM API Proxy** — no agent code change. Point the client config or set an env var.
- **SDK** — explicit `guard.check(...)` per call (or `@guarded`), or wrap framework tools with the adapters. This is the opt-in layer; use it for offline scripts, custom transports, or as an advisory gate where you control every call site.

### Which layer should I use?

| Use case | Best fit |
|---|---|
| Claude Desktop / Cursor / Cline / Continue / Zed | MCP Gateway |
| Code already using the OpenAI / Anthropic SDKs | LLM API Proxy |
| Custom agent code where you control every tool call | SDK |
| Framework-based agent (LangChain, CrewAI, browser-use) | SDK adapters + optionally the LLM API Proxy |
| Offline scripts / no network listener in the path | SDK |

Layers compose — running the gateway *and* the LLM proxy *and* the SDK against the same policy is the typical production shape.

### Why is `/v1/check` unauthenticated?

So agents can call it with zero per-request setup. With `--api-key` set, the authenticated endpoints are approve, deny and status, `/v1/audit` (`GET` and `POST`) and `/v1/audit/head`, `/v1/sessions`, the dashboard's `/api/*` routes, and their `/v1/t/<tenant>/…` mirrors; `/v1/check`, `/health`, `/v1/health` and `/metrics` stay open. If your threat model requires `/v1/check` to be authenticated, gate it at the reverse proxy (allowlist source IPs or require a second header) — see [`DEPLOYMENT.md`](DEPLOYMENT.md).

### My agents can't connect remotely, but `curl localhost:8080/health` works.

You're running without `--api-key`. Without it, the server binds to `127.0.0.1` only. Set `--api-key` (or `VANZIK_API_KEY`) and the server will bind `0.0.0.0`.

### Do I have to run it behind a reverse proxy?

For production yes — TLS termination, connection pooling, static IP, and buffering tuning all belong at the edge. Vanzik has no built-in TLS. See [`DEPLOYMENT.md`](DEPLOYMENT.md) for nginx/Docker Compose/K8s examples.

### Can I run multiple replicas?

Yes — point every replica at PostgreSQL (`--store-dsn postgres://…`) with a distinct `--node-id`, and approvals, rate-limit buckets, and session costs are shared across the cluster via background reconciliation (default every 2s; the enforcement hot path never waits on the database). Know the semantics: distributed limiting is **bounded-overshoot** — brief bursts can exceed a cap by roughly `reconcile-interval × peak rate` per extra replica before nodes converge — and approvals resolved on one node reach the others within one reconcile interval, always converging to DENY on a conflict. On the default SQLite store, state stays **per-instance**: pin sessions via load-balancer affinity, divide limits by replica count, or stick to one replica (usually plenty — Vanzik handles 500+ RPS per vCPU). See [`OPERATIONS.md`](OPERATIONS.md#multi-instance-deployments).

### My approval queue is empty after a restart. Where did the approvals go?

It shouldn't be — the queue is **persistent by default**. `--persist` (default `true`) snapshots approvals, rate-limit buckets, and session-cost accumulators to the SQLite store (`vanzik.db`) and rehydrates them on boot. If your queue is empty after a restart, check that you aren't running `--persist=false` (in-memory only) and that the process can write its `--data-dir`. Note the store syncs on a ≥1 s tick, so approvals created in the final second before a crash can still be lost — agents polling across that window hit their SDK timeout and receive a fail-deny response. See [`CLI.md`](CLI.md#persistence--multi-tenancy-v06).

### Does the audit log rotate?

Yes — rotation is **on by default**, controlled by `--audit-max-size-mb` (default 100 MiB), `--audit-max-backups` (default 5), `--audit-max-age-days` (default 30), and `--audit-compress` (default true). Do NOT also configure `logrotate` against `audit.jsonl` — two rotators on one file corrupt the rotation index. See [`OPERATIONS.md`](OPERATIONS.md#audit-log-rotation). To opt out (e.g., when an external shipper handles rotation), set `--audit-max-size-mb 0`. Also note the startup replay: the active file plus a checkpointed prefix of the rotation chain is re-read on boot to seed counters.

### Why does `*.foo.com` not match `foo.com`?

Standard glob semantics — `*.foo.com` requires at least one character + `.` before `foo.com`. Matches `api.foo.com`, not the apex. Add both explicitly if you want both:

```yaml
- domain: "foo.com"
- domain: "*.foo.com"
```

See [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md#pattern-matching-semantics-read-this) for the full pattern table.

### Can I use `time_window` without `require_prior`?

No — it is a **hard policy-load error**. `time_window` only means something as a modifier on a `require_prior` condition (i.e., "only match if the prior action happened within this window"). Either remove the orphan `time_window` or add a `require_prior` clause. See [`DEPRECATIONS.md`](DEPRECATIONS.md).

### Python fail-closed vs TypeScript failMode — which should I use?

Both SDKs default to **fail-closed** (proxy unreachable → `DENY`). This matches the usual security posture: if the guard is down, don't act.

- Python: `Guard(fail_mode="allow")` opts into fail-open.
- TypeScript: `new Vanzik({ failMode: 'allow' })` opts into fail-open.

Use fail-open only when Vanzik is advisory (e.g., you have another enforcement layer downstream).

### Is the SQLite audit backend ready?

Yes — the durable-store backend: run with `--persist --audit-backend=store` and the audit trail lands in the SQLite store's indexed `audit_entries` table (writes stay off the /v1/check hot path via the async buffer, which the store backend force-enables). The default remains the JSON-Lines file logger with rotation.

### Where's the admin API for managing approvers / RBAC?

There isn't one. There is **one API key** — anyone with it has full access to approve/deny/audit/status and the dashboard. Multi-tenant policy and state isolation exist (`/v1/t/{tenant}/...` routes plus the `vanzik tenant` CLI — see [`API.md`](API.md) and [`CLI.md`](CLI.md#vanzik-tenant-v06)), but per-approver identities and RBAC do not. For now, treat the API key like a root password.

### Can I edit policies from the dashboard?

No. Policies are YAML files; edit them on disk — the server hot-reloads on change (fsnotify events, with a 2 s mtime poll as fallback). A dashboard-side policy editor is on the roadmap.

### Does Vanzik support streaming responses / LLM output filtering?

Streaming responses, yes: the LLM API Proxy gates the tool calls inside OpenAI and Anthropic SSE streams, holding each tool call until `/v1/check` answers (see [`LLM_API_PROXY.md`](LLM_API_PROXY.md)). Output filtering, no — Vanzik decides on discrete actions (shell commands, HTTP calls, file writes), not on the model's text tokens. For content filtering at generation time, use a different layer (e.g., a prompt-filtering library or an output-scanning middleware). Vanzik is about what the agent *does*, not what it *says*.

### How do I test my policy without a live agent?

Three ways:

1. **CLI validate** — syntax + load-time checks: `vanzik validate --policy configs/my-policy.yaml`.
2. **Direct curl** — semantics:
   ```bash
   curl -X POST http://localhost:8080/v1/check \
     -H 'Content-Type: application/json' \
     -d '{"agent_id":"test","scope":"shell","command":"rm -rf /"}'
   ```

3. **Policy tests in CI** — `vanzik test` runs a policy against YAML fixture files of requests and expected decisions, with no server, and exits non-zero on a failed case. See [`CLI.md` § `vanzik test`](CLI.md#vanzik-test).

### How much does running Vanzik cost in overhead?

Typical policy evaluation is sub-millisecond. End-to-end `/v1/check` runs in single-digit ms on a modern vCPU. At 500 RPS the service uses ~1 vCPU and ~50 MB RAM (no audit log). Memory grows linearly with audit log size during the startup replay only.

### Can I use it as a library, not a proxy?

The Go policy engine (`pkg/policy`), audit logger (`pkg/audit`), MCP gateway core (`pkg/mcpgw`), and LLM proxy core (`pkg/llmproxy`) are all importable Go packages. The three binaries (`vanzik`, `vanzik-mcp-gateway`, `vanzik-llm-proxy`) are thin wrappers around them, and the SDK + framework adapters assume an HTTP server endpoint — in-process embedding of the SDK story is uncommon and unsupported. If you want to embed the policy engine directly without an HTTP hop, lift `policy.Engine.Check` from `pkg/policy/engine.go`.

### Why YAML and not JSON / HCL / Rego?

YAML is human-friendly for rule lists with comments. JSON is too noisy for nested rules; HCL/Rego add external runtime deps. The policy engine is small enough that swapping languages is possible, but YAML covers every observed use case. If you want programmable policies, wrap the YAML generation in your own tool.

### I think I found a security issue. Where do I report?

Email `hello@lictorate.com`. Do **not** open a public issue. See [`SECURITY.md`](../SECURITY.md) for the disclosure policy.

---

## Related docs

- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — symptom-keyed diagnostics.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — exact policy schema.
- [`docs/OPERATIONS.md`](OPERATIONS.md) — day-2 operational concerns referenced above.
