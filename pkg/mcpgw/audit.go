// Gateway-level audit and SSE are deliberately left unwired: the
// bridge's AuditEmit and SSEEmit hooks are nil by default.
//
// Every tools/call already produces an audit entry and SSE event through
// the central server's /v1/check (the gate stamps
// meta["transport"] = "mcp_gateway"). Events that AREN'T tool calls
// (upstream crash, malformed host frame, startup failure) need a new
// central-server endpoint; defining types here would fix an API before
// that endpoint is designed. Until then: /v1/health warnings, the
// gateway's stderr log (upstream crashes, fail-mode decisions), and
// /v1/audit, which includes the synthetic deny:gateway:fail_closed
// entries.
//
// TODO(#mcp-gateway-events): operator-grade gateway-level audit
// endpoint. Current best guess is a small `/v1/operator/event` endpoint
// scoped to notify-class events (degraded upstream, frame error,
// startup failure) with its own retention + auth posture distinct from
// the policy-decision audit log. Needs a product design decision (new
// endpoint, auth, retention) before implementation; in the meantime
// --fail-audit-log records fail-mode denials locally and stderr carries
// upstream-crash events.

package mcpgw
