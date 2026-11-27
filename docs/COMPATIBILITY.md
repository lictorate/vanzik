# Compatibility & Stability — the v1.0 freeze

**Status:** Stabilized as of **v0.9.0**; **frozen as of v1.0.0** — the
additive-only rule is now the hard guarantee. **v2.0.0** renamed the project
from AgentGuard to Vanzik (below); the guarantee carries over to the 2.x line.

This document declares the public surfaces Vanzik froze at 1.0 (stabilized
through the v0.9 release, validated and hardened on the road to 1.0) and states
the backward-compatibility guarantee that holds across a major line: 1.x, and
now 2.x.

## 2.0: the rename

2.0.0 is the major-version event the promise below reserves for breaking
changes, and its only one is the name, including refusing the old
`AGENTGUARD_*` variable names. Every identifier that carried
"AgentGuard" carries "Vanzik" instead, with no alias for the old one: the
binaries (`vanzik`, `vanzik-mcp-gateway`, `vanzik-llm-proxy`), the `VANZIK_*`
environment variables, the folders and the `vanzik.db` database, the login
services, the `X-Vanzik-*` headers, the MCP `_meta` prefix `dev.vanzik/`, the
LLM proxy's `vanzik-refusal` id and `vanzik_error` type, the webhook
`User-Agent: Vanzik/2.0`, the report's `vanzik_version` field, the `vanzik_*`
metrics, the Go module `lictorate.com/vanzik/v2`, and the SDK packages
(`vanzik` on PyPI, `@lictorate/vanzik` on npm) and their `Vanzik*` classes.
[`MIGRATION.md`](MIGRATION.md#v1x-to-v20) lists each old and new name and
how an existing install moves over.

Everything else in 2.0 is an addition or a fix. The policy schema (`version: "1"`), the `/v1/*` wire
protocol (`schema_version: "v1"`), the audit log format
(`schema_version: 2`, its hash chain and seal) and every command's flags
are as in 1.4.0 (2.0 adds one, `vanzik migrate --from-agentguard`), so a 1.x policy and audit log work with 2.0
unchanged. Below, "the stabilized line" means the 2.x line, with these
names.

## Security fixes in 2.1.0

2.1.0 is a security release. No frozen surface changed: no field, route,
flag, subcommand or schema version was removed or renamed. The additions are
one LLM API Proxy flag, new refusal rules, one gate meta key
(`args_digest`), two counters and two histogram buckets. Several fixes do
change behaviour you may rely on, because the old behaviour let a tool call
through that the policy never checked, or let an approval be replayed with
other arguments. Read this list before you upgrade. The limits that remain
are in [`THREAT_MODEL.md` § Known limits](THREAT_MODEL.md#known-limits).

### Build

- Building or importing the Go module needs Go 1.26.11 or later.
- The runtime image runs `apk upgrade zlib libssl3 libcrypto3`
  (CVE-2026-4738 in zlib; CVE-2026-95692, -107496, -95691, -88823 and -88822
  in OpenSSL 3.5.9-r0). While it does, the image is not byte-reproducible.

### LLM API Proxy: responses

- Clients receive uncompressed responses from the proxy on every route,
  including the ungated ones (`/v1/embeddings`, `/v1/completions`). The
  proxy no longer forwards the client's `Accept-Encoding`: it asks the
  upstream for gzip only and decodes it itself.
- A gated 2xx response that still has a `Content-Encoding` after that is
  refused (`deny:llm_api_proxy:undecodable_content_encoding`, counted in
  `vanzik_llmproxy_undecodable_content_encoding_total{provider}`).
- `--max-buffer-bytes` bounds the decoded size.
- Non-streaming refusals are always labelled `Content-Type:
  application/json`.
- Streamed Anthropic server-tool and MCP-connector responses now reach the
  client. They are not gated or audited, matching the non-streaming path.

### LLM API Proxy: refusals that are new in 2.1.0

Each refusal is an HTTP 200 in the provider's shape with one audit entry,
and none is subject to `--fail-mode allow`.

- Responses to the legacy `functions` API (`function_call`) are now
  policy-checked, streaming and non-streaming.
- **Both providers, streams:** SSE lines end at CRLF, a bare CR or a bare
  LF, as in the SSE spec and every client SDK. A tool call after a bare CR
  is now gated; before, it reached the client unchecked. A stream framed
  with bare CRs is now read and forwarded; before, it was dropped or
  forwarded unread.
- **OpenAI-format responses.** These are refused:
  - a stream with conflicting, mixed or repeated tool-name fragments
    (`deny:llm_api_proxy:tool_name_conflict`); a server that repeats the
    tool name on every delta is refused too;
  - a legacy `function_call` and `tool_calls` in one response
    (`deny:llm_api_proxy:mixed_function_call`);
  - a UTF-8 BOM at the start of a body or of any SSE line, when it carries a
    tool call (`deny:llm_api_proxy:undecodable_tool_call`);
  - a UTF-16 or UTF-32 body that carries a tool call
    (`undecodable_tool_call`; Anthropic bodies too);
  - an envelope key that differs only in case from one the gate reads, such
    as `Tool_Calls` beside `tool_calls`, under the new rule
    `deny:llm_api_proxy:case_variant_key`;
  - a body or stream event that even the lenient probe cannot decode (a
    wrong-typed `choices` element, or a `NaN`, `Infinity` or `-Infinity`
    literal) and that has a `tool_calls` or `function_call` key in any
    spelling a client or Go would read (`undecodable_tool_call`). Text-only
    bodies like these are still forwarded unchanged, and text-only stream
    events still dropped.
- **Anthropic streams.** These are refused, under
  `deny:llm_api_proxy:tool_use_interleaved` unless noted:
  - a stream that reuses a content index, or puts a block out of its content
    position;
  - a key that differs only in case on an event, a content block or a delta;
  - an input delta for another block during a tool cycle
    (`deny:llm_api_proxy:orphaned_tool_input`);
  - a missing or `null` `partial_json`;
  - an event, content block or delta whose `type` is not a string; a
    content-block event whose `index` is missing, `null` or not an integer;
    a `tool_use` whose `id` or `name` is not a string. Duplicate keys are
    read as the SDKs read them: the last one wins;
  - a `message_start` whose `message.content` is not empty. A refusal at the
    first `message_start` opens the stream with a synthetic one;
  - a BOM at the start of any line, when the stream carries a client
    `tool_use` (`undecodable_tool_call`). Text-only BOM streams are
    forwarded unchanged;
  - an event with data whose SSE `event:` name is missing, empty or not
    exactly its JSON `type`, for example an input delta sent as `event:
    ping`, or a stream whose intermediary strips `event:` lines. This is the
    new rule `deny:llm_api_proxy:event_type_mismatch`, counted in
    `vanzik_llmproxy_event_type_mismatch_total{provider}` and not in
    `vanzik_llmproxy_protocol_violation_total`.
- **Anthropic non-streaming bodies.** These are refused:
  - a key that differs only in case from one the gate reads, on the message
    (`id`, `type`, `role`, `model`, `content`, `stop_reason`, `usage`) or on
    a content block (`type`, `text`, `id`, `name`, `input`), under
    `case_variant_key`;
  - a body that even the lenient probe cannot decode (a wrong-typed
    `content` element, a `NaN` or `Infinity` literal) and that has a
    `tool_use` block type in any spelling (`undecodable_tool_call`).
- **Audit:** a `deny:llm_api_proxy:duplicate_argument_key` refusal now
  writes an audit entry, for both providers, streaming and non-streaming.
  Without `--api-key` on the proxy against a keyed central server, the entry
  goes through the `/v1/check` fallback and carries the engine's verdict on
  the last value of each duplicated key ([`OPERATIONS.md`](OPERATIONS.md)).
- **Cost:** parsing a streamed event costs about 1.6 µs more than in 2.0.0
  (benchmark averages on an Apple M4: about 1.5 µs from the Anthropic and
  OpenAI parser fixes, about 0.1 µs from the line-ending, event-name and
  undecodable-body fixes). The `/v1/check` latency gate passed.

### LLM API Proxy: flags

- New flag `--upstream-header-timeout`, default `10m`. An upstream that
  sends no headers within it gets a 502; `0` restores the old behaviour.
  Code that builds `llmproxy.Config` directly gets no timeout unless it sets
  the field.

### Metrics

- New counters `vanzik_llmproxy_event_type_mismatch_total{provider}` and
  `vanzik_llmproxy_undecodable_content_encoding_total{provider}`.
- `vanzik_llmproxy_protocol_violation_total` also counts case-variant
  refusals; `vanzik_llmproxy_undecodable_tool_call_total` also counts the
  stream and undecodable-body refusals above. No series was renamed.
- The latency histograms (`vanzik_request_duration_ms`,
  `vanzik_policy_eval_duration_ms`, `vanzik_audit_write_duration_ms`) gain
  `le="0.05"` and `le="0.1"` buckets. Existing buckets are unchanged, so
  existing series keep their meaning.

### Server

- Keyless mode accepts only a loopback `Host`, from the same origin. Another
  localhost origin, `host.docker.internal`, tunnels and reverse proxies now
  need `--api-key` (and `--allowed-origin` for another origin).
- `POST /v1/audit` requires `Content-Type: application/json` in every mode
  (415 otherwise).
- Approval audit text names the real channel instead of "by human"; keyless
  resolutions record `open`.
- `args_digest` is a new key in gate request meta, so it appears in audit
  entries, SSE events, webhooks and `/api/pending`.
- The dashboard's pending card shows the request's redacted argument values.

### Approvals are bound to the exact arguments

- The LLM API Proxy and the MCP Gateway send `meta.args_digest`, a keyed
  HMAC-SHA256 of the tool name and canonical arguments. The central server
  honours an `approval_id` only for a retry with the same digest. Any change
  needs a new approval, costs a rate-limit token and creates a new pending
  entry.
- Values must match. Through the LLM API Proxy, a model re-emitting `1.0`
  for `1`, or `""` for `{}`, asks for approval again. Key order and
  whitespace don't matter.
- `vanzik_approval_replay_mismatch_total` also counts digest mismatches.
- Without `--api-key` on the LLM API Proxy or the MCP Gateway, the digest
  key is random per process, so an approval doesn't survive a restart of
  that gate. With `--api-key`, gates that share the key derive the same
  digest key, and approvals work across restarts and replicas.
- Anyone holding the gates' API key can derive the digest key, and so test
  guesses of a redacted argument value against the `args_digest` in the
  audit log.

#### Approvals during a rolling upgrade

- **A central server older than 2.1.0 gives no argument binding.** It
  ignores `args_digest` and matches a retry on the request's other fields
  only, as before. Upgrade the central server first for the fix to take
  effect.
- An approval made through an upgraded gate is not honoured for a retry
  through a gate that doesn't send the digest yet.
- An approval made through an old gate (no digest) and retried through an
  upgraded gate is matched on the other fields only, as before.

### MCP Gateway

- Masks secret-named arguments (`password`, `token`, `secret`, `api_key`,
  `apikey` or `auth` in the name) as `[REDACTED]` in audit and
  pending-approval meta, as the LLM API Proxy already did. No verdict
  changes, because policy evaluation does not read meta, but the `vanzik
  report` count of redacted entries rises.
- Decodes tool arguments before computing the approval digest, so numbers
  that decode to the same value bind as equal: `1` and `1.0`, and 2^53+1 and
  2^53. The downstream MCP server receives the same normalised bytes.
- Reads the union of both alias lists, so some tools are checked on
  arguments that were ignored before. Eight argument shapes change from
  denied to forwarded ([`THREAT_MODEL.md` § Known
  limits](THREAT_MODEL.md#known-limits)).
- A conflicting alias is denied (`deny:gateway:conflicting_argument_alias`;
  `deny:llm_api_proxy:conflicting_argument_alias` on the proxy).
- Upstream notifications are coalesced and delivered in order.

### Policies

- The bundled agent policies deny:
  - self-approval through the control-plane endpoints and `vanzik approve` /
    `vanzik deny`;
  - reading or writing Vanzik's config folder;
  - stop-type `kill`, `pkill`, `killall`, `taskkill`, `launchctl` and
    `systemctl` commands that name vanzik;
  - writing any agent's hook-settings file, including a project's own
    `.claude/settings.json`.
- `default.yaml` denies `copy_file` and `append_file`.
- **An existing policy is not rewritten.** To get these rules, copy the
  blocks from [`configs/`](../configs/) into your policy.

### Setup and shutdown

- `vanzik setup` preselects "Block them" for a new hook connection
  (`--fail-closed` on the hook command), so the agent's tools are blocked
  while the server is down. The hook command's own default, without
  `--fail-closed`, is unchanged: it lets the call through with a warning.
- Shutdown with a stalled audit backend takes up to 7 s instead of hanging.
  Set the host's stop timeout above `ShutdownTimeout` (10 s) plus 7 s.

## The promise

**As of v0.9 these surfaces are stable, and from v1.0 every change to them is
additive-only.** Concretely:

- No frozen field, route, flag, subcommand, scope, or schema version is removed
  or renamed.
- No field's JSON name or type changes, and no flag's meaning changes.
- New **optional** fields, new routes, new flags, new subcommands, and new
  policy keys **may** be added. Consumers must tolerate unknown additive
  surface (ignore-and-pass-through) — the first-party SDKs and the Go decoders
  already do.
- A genuinely breaking change is a **major-version** event: it ships behind a new
  version identifier (`schema/v2`, audit `schema_version: 3`, a new route
  family), never as a silent mutation of a stabilized surface.

The pre-1.0 validation window is over: from **1.0** the additive-only rule is a
hard guarantee — a `go get -u` / `pip install -U` / `npm update` within the 1.x
line will not break you. (One correction made during that window, per the
reserved right: approval resolutions became write-once/one-shot — see
[`MIGRATION.md`](MIGRATION.md#v090--v100).)

**Security fixes in 1.2.0.** Four fixes change how a policy you already
have behaves, each because the old behaviour let through actions the
policy's own rules deny or send to approval, or exposed secrets:
compound shell commands are checked one command at a time; several rule
blocks for one scope are merged; the MCP gateway checks the host of a
tool's `url` argument rather than a `domain` argument next to it; and
secrets in requests are masked before they reach the audit trail
(`serve --audit-redact=false` turns that off).
No field, route, flag or schema version changed. Details:
[`MIGRATION.md`](MIGRATION.md#v11x--v120).

---

## Frozen surface 1 — Policy YAML schema (`version: "1"`)

The policy file format is frozen at schema **`version: "1"`**.

- The top-level keys (`version`, `name`, `rules`, `agents`, `tool_scope_map`,
  `notifications`, …), the rule-precedence contract
  (`deny → require_approval → allow → default deny`), and the matching
  semantics (string-glob, `filepath.Clean` path normalization) do not change
  across the stabilized line. (1.2.0 applies the same globs to each command
  of a compound shell command — see
  [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md#compound-shell-commands).)
- The built-in scopes are frozen: `shell`, `filesystem`, `network`, `browser`,
  `cost`, `data`, `mcp_tool`, plus the `unmapped` sentinel emitted by the LLM
  API Proxy. New scopes may be **added**; none of these is removed or
  repurposed.
- A v1 policy that loads on v0.9 loads on every later release.

Full schema and gotchas: [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md).

## Frozen surface 2 — Wire protocol (`schema_version: "v1"`)

The `/v1/check` request (`ActionRequest`) and response (`CheckResult`) shapes
are frozen at `schema_version: "v1"`, and the full `/v1/...` route family is
frozen, including its `/v1/t/{tenant}/...` tenant-aware mirrors:

| Route | Tenant-aware mirror |
|---|---|
| `POST /v1/check` | `POST /v1/t/{tenant}/check` |
| `POST /v1/approve/{id}` | `POST /v1/t/{tenant}/approve/{id}` |
| `POST /v1/deny/{id}` | `POST /v1/t/{tenant}/deny/{id}` |
| `GET /v1/status/{id}` | `GET /v1/t/{tenant}/status/{id}` |
| `GET /v1/audit` | `GET /v1/t/{tenant}/audit` |
| `GET /v1/health` | `GET /v1/t/{tenant}/health` |

Supporting endpoints frozen alongside them: `GET /health`, `GET /metrics`,
`POST /auth/login`, `POST /auth/logout`, `GET /api/pending`, `GET /api/stats`,
`GET /api/stream`, `GET /dashboard` (and their `/v1/t/{tenant}/api/...`
mirrors). `GET /v1/audit/head` and `GET /v1/t/{tenant}/audit/head` (1.4.0,
the head of a sealed audit log) are an addition of the kind this surface
allows, as are 1.4.0's `GET /v1/sessions` and `GET /v1/sessions/{id}`
(with their `/v1/t/{tenant}/...` mirrors), the `since`, `until` and
`parent_session_id` parameters of `GET /v1/audit`, and the optional
`parent_session_id` request field.

One deliberate tightening comes with them. Before 1.4, `GET /v1/audit`
did not read `since` or `until`, so any value, well-formed or not, was
ignored and every entry came back. From 1.4 a value that is not an RFC
3339 time, or an `until` before `since`, is answered with `400`. Ignoring
a malformed audit filter returns entries the caller asked to leave out,
which is worse than an error that says what to send.

The wire freeze rules — never remove a field, never change a field's type or
JSON name, decision enum stays the closed set `{ALLOW, DENY, REQUIRE_APPROVAL}`,
new optional fields only — are spelled out in
[`WIRE_PROTOCOL.md`](WIRE_PROTOCOL.md). The machine-readable spec is
[`pkg/proxy/schema/v1/schema.json`](../pkg/proxy/schema/v1/schema.json), pinned
by a Go ↔ Python ↔ TypeScript cross-language contract test that fails CI on
drift.

## Frozen surface 3 — Audit log format (`schema_version: 2`)

The on-disk audit format is frozen at audit **`schema_version: 2`** (the
`{"_meta":{"schema_version":2,...}}` header line, followed by one JSON object
per decision).

- The `Entry` fields (`timestamp`, `tenant_id`, `session_id`, `agent_id`,
  `request`, `result`, `duration_ms`, `transport`) are stable. `tenant_id` is
  `omitempty`, so single-tenant entries carry no `tenant_id`, as before v0.6.
  `transport` is `omitempty` in the format, but the 2.x server writes it on
  every entry (`sdk` for SDK calls); only entries from pre-v0.5 writers lack it.
  `session_id` is always written (`""` when the request had none).
- The same `schema_version: 2` format is produced by both the `file` (JSONL)
  and `store` (SQLite `audit_entries`) backends; their `QueryFilter` semantics
  are pinned by a parity test.
- New optional `Entry` fields may be **added** without a bump (additive readers
  ignore unknown keys). A format change that is *not* backward-readable would
  bump to `schema_version: 3` with a migration, which is a v2.x-class event.

The audit log is **append-only**. Since v1.4 the file backend can also seal
it into a hash chain (`vanzik server --audit-seal`, off by default): each
entry gets `seq`, `prev_hash` and `hash`, and `vanzik audit verify` detects
edited, removed or reordered entries. These fields are additive and omitted
when sealing is off; `schema_version` stays 2. Sealing shows tampering, it does
not prevent it: someone with the key (or, without a key, anyone who can write
the file) can rewrite the chain, and the newest entries can be cut off. Ship
the published anchors, or the log itself, to append-only / WORM storage (S3
Object Lock, a SIEM, or syslog) to cover that. The store backend is not
sealed. Format history and the `schema_version` convention:
[`FILE_FORMATS.md`](FILE_FORMATS.md).

## Frozen surface 4 — CLI flags & subcommands

The `vanzik` subcommands (`serve`, `validate`, `check`, `approve`, `deny`,
`status`, `audit`, `tenant`, `migrate`, `version`) and their existing flags are
frozen: a flag's name, default, and meaning do not change across the stabilized line, and no
subcommand is removed. The same applies to the `vanzik-mcp-gateway` and
`vanzik-llm-proxy` flag sets. New flags and new subcommands may be added.

`server` is the documented name for `serve`; both run the same command, and
`serve` stays for the whole 2.x line. Additions since 1.2.0 are all of the
kind this surface allows: the `server`, `help`, `setup`, `hook` and `test`
subcommands (`hook claude-code` sits in users' Claude Code settings, so it
stays; so do `hook cursor`, `hook gemini-cli` and `hook codex`, which sit in
those agents' settings), `hook`'s `--fail-closed` flag, the audit `transport`
values `claude_code`, `cursor`, `gemini_cli` and `codex_cli`, the
server's `--api-key-file` flag, the `--guard-url` alias of `--url` on the client
subcommands, and fallbacks for flags left unset (`VANZIK_URL`,
`VANZIK_POLICY`, and the API key `vanzik setup` saves, which the client
subcommands, the MCP gateway and the LLM proxy use when no key is given). When `--policy` is not
given and `configs/default.yaml` is missing, `server`, `validate` and `check`
look for the installer's starter policy instead of failing. Flags may now follow
positional arguments; before, a flag after one was ignored without a word. A
stray positional argument is now an error instead of being ignored. 1.4.0 adds
the `audit verify` subcommand and the server's `--audit-seal`,
`--audit-seal-key-file` and `--audit-anchor-interval` flags; sealing is off
unless asked for. It also adds `audit`'s `--session`, `--parent-session`,
`--since` and `--until` flags, and the `report` subcommand, whose JSON
output (`format_version: 1`) follows the same additive-only rule
([`COMPLIANCE.md`](COMPLIANCE.md#json-shape)). See [`CLI.md`](CLI.md).

Full reference: [`CLI.md`](CLI.md) · [`MCP_GATEWAY.md`](MCP_GATEWAY.md) ·
[`LLM_API_PROXY.md`](LLM_API_PROXY.md).

---

## Explicitly *not* frozen

These may change without it being a compatibility break:

- **`CheckResult.reason` wording.** Human-readable; stable enough for log
  aggregation but not a contract. Switch on `decision` and `matched_rule`, not
  on `reason` text.
- **Prometheus metric set.** New series may be added and labels enriched;
  treat dashboards as best-effort across minor versions.
- **Dashboard HTML/CSS/JS** and the `/api/stream` SSE event payloads beyond the
  documented fields.
- **Internal Go package APIs** (anything under `pkg/internal/`, and unexported
  identifiers). Importers of internal packages are not covered by this freeze.
- **Default values that are not a wire/format contract** (e.g. tuning knobs),
  unless changing them would alter a frozen on-disk or wire shape.

## Topology

Two supported topologies as of v1.0:

- **Single-node (`replicas: 1`) — the default.** The approval queue, rate-limit
  buckets, and cost accumulators persist to a local SQLite store and survive
  restarts, but they are not shared across instances.
- **Multi-node on PostgreSQL.** Set `--store-dsn postgres://…` and a distinct
  `--node-id` per replica. Replicas share approval / rate-limit / cost state
  through background reconciliation (`--reconcile-interval`, default 2s) — the
  enforcement hot path never makes a synchronous database call. The documented
  semantics of the shared mode are part of the compatibility promise:
  distributed rate/cost limiting is **bounded-overshoot** (not globally
  strict), cross-node approval staleness is at most one reconcile interval,
  conflicting approval resolutions converge to **DENY**, and a consumed
  one-shot ALLOW is spent cluster-wide once reconciled — the shared store
  merge is monotonic (a resolution is never un-resolved, a resolved DENY is
  never overwritten by a non-DENY, a consumption stamp is never cleared).

The additive v1.0 surface on top of v0.9 — `--store-dsn` accepting
`postgres://`/`postgresql://`, `--node-id`, `--reconcile-interval`,
`--approval-validity`, and the write-once / one-shot approval lifecycle
(HTTP 409 on a conflicting re-resolution) — is frozen under the same rules as
the surfaces above.

## Post-v1, only if a concrete need arises

Out of scope and deliberately not on the stabilization: RBAC / multi-key
auth, signed (asymmetric) audit seals and Merkle checkpoints. (Audit
secret-redaction, once on this list, shipped in 1.2.0; an HMAC hash chain over
the file audit log shipped in 1.4.0 as `--audit-seal`.)
