package llmproxy

// The PolicyCheck hook against the central server's /v1/check.
//
// Each tool call maps to exactly one existing scope (no mcp_tool
// dual-check as in the MCP gateway): bare LLM tool names and namespaced
// MCP names never collide, so one `tool_scope_map:` table serves both.
// Unmapped tools get scope `unmapped`, which the engine denies unless a
// `scope: unmapped` rule exists. Fail modes: docs/PROXY_ARCHITECTURE.md
// § 6.1.

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"lictorate.com/vanzik/v2/pkg/internal/gateclient"
	"lictorate.com/vanzik/v2/pkg/notify"
	"lictorate.com/vanzik/v2/pkg/policy"
)

// DefaultGuardHTTPTimeout is the per-/v1/check-call timeout the gate
// applies when the operator does not pass a custom http.Client.
const DefaultGuardHTTPTimeout = gateclient.DefaultGuardHTTPTimeout

// Synthetic Rule strings for fail-mode and invalid-response decisions,
// distinct from real policy verdicts. Stable: dashboards alert on them.
const (
	FailModeRuleClosed      = "deny:llm_api_proxy:fail_closed"
	FailModeRuleClosedAudit = "deny:llm_api_proxy:fail_closed_audit"
	FailModeRuleOpen        = "allow:llm_api_proxy:fail_open"
	InvalidResponseRule     = "deny:llm_api_proxy:invalid_response"
)

var llmFailModeRules = gateclient.FailModeRules{
	Open:        FailModeRuleOpen,
	Closed:      FailModeRuleClosed,
	ClosedAudit: FailModeRuleClosedAudit,
	Invalid:     InvalidResponseRule,
}

// HTTPPolicyClient is the proxy's client for the central server's
// /v1/check; one per process. The wire contract and fail-mode
// translation live in pkg/internal/gateclient; this adds scope mapping,
// per-scope argument projection, source-side secret redaction and
// meta.transport="llm_api_proxy".
type HTTPPolicyClient struct {
	GuardURL string // e.g. "http://127.0.0.1:8080"
	APIKey   string // bearer token; empty if --api-key not set
	TenantID string // tenant ID; "local" with the bundled FilePolicyProvider
	FailMode string // "deny" | "allow" | "fail-closed-with-audit"

	// HTTPClient defaults to a DefaultGuardHTTPTimeout client.
	HTTPClient *http.Client

	// policy is atomic so the hot path takes no lock; nil means the
	// bundled DefaultLLMToolScopeMap only.
	policy atomic.Pointer[policy.Policy]

	// mappings caches the merged map for MapScope; replaced by SetPolicy.
	mappings atomic.Pointer[[]policy.ToolScopeMapping]

	// redactor scrubs argument values before they reach /v1/check meta.
	// The central server redacts notifications but not the audit log, so
	// the proxy redacts at the source.
	redactor *notify.Redactor

	// fallback records local audit entries for fail-closed-with-audit
	// denials made while the central server is unreachable. nil (the
	// other fail modes, or --fail-audit-log "") records nothing.
	fallback *gateclient.FallbackAuditWriter
}

// NewHTTPPolicyClient builds a gate client from cfg and an initial
// policy. The caller should call SetPolicy on every policy reload.
func NewHTTPPolicyClient(cfg *Config, pol *policy.Policy) *HTTPPolicyClient {
	c := &HTTPPolicyClient{
		GuardURL:   cfg.GuardURL,
		APIKey:     cfg.APIKey,
		TenantID:   cfg.TenantID,
		FailMode:   cfg.FailMode,
		HTTPClient: &http.Client{Timeout: DefaultGuardHTTPTimeout},
		redactor:   notify.DefaultRedactor(),
	}
	if cfg.FailMode == "fail-closed-with-audit" {
		c.fallback = gateclient.NewFallbackAuditWriter(cfg.FailAuditLog)
	}
	c.SetPolicy(pol)
	return c
}

// SetPolicy atomically swaps the policy and its merged tool-scope
// map. nil resets to the default mappings.
func (c *HTTPPolicyClient) SetPolicy(pol *policy.Policy) {
	c.policy.Store(pol)
	merged := NewLLMToolScopeMap(pol)
	c.mappings.Store(&merged)
}

// MapScope returns the policy scope for a tool name, or UnmappedScope.
// Suitable for Server.ScopeMap.
func (c *HTTPPolicyClient) MapScope(toolName string) string {
	mappings := c.mappings.Load()
	if mappings == nil {
		return MapLLMToolScope(toolName, DefaultLLMToolScopeMap)
	}
	return MapLLMToolScope(toolName, *mappings)
}

// Check implements Server.PolicyCheck: it builds an ActionRequest and
// POSTs it to /v1/check. On a /v1/check failure it returns the
// fail-mode decision together with the error.
func (c *HTTPPolicyClient) Check(ctx context.Context, req *ToolCallCheck) (Decision, error) {
	if req == nil {
		return Decision{Allow: false, Reason: "nil tool call request", Rule: "deny:llm_api_proxy:invalid_request"}, nil
	}

	scope := c.MapScope(req.ToolName)

	ar := policy.ActionRequest{
		SchemaVersion:   "v1",
		Scope:           scope,
		AgentID:         req.AgentID,
		SessionID:       req.SessionID,
		ParentSessionID: req.ParentSessionID,
		Command:         formatLLMCommand(req, scope, c.redactor),
		Path:            projectPath(scope, req.Arguments),
		Domain:          projectDomain(scope, req.Arguments),
		URL:             projectURL(scope, req.Arguments),
		ApprovalID:      req.ApprovalID,
		Meta:            buildLLMMeta(req, scope, c.redactor),
	}
	if scope == "filesystem" {
		ar.Action = gateclient.InferFilesystemAction(req.ToolName)
	}
	if scope == "browser" {
		ar.Action = req.ToolName
	}

	dec, err := c.callV1Check(ctx, ar)
	if err != nil {
		return c.failModeDecision(ar, err), err
	}
	return dec, nil
}

// RecordForcedAudit implements Server.RecordForcedAudit: it records a
// proxy-manufactured refusal in the central audit trail via /v1/audit,
// with the verdict the client received rather than the engine's. The
// ActionRequest is built exactly as in Check so the entry looks like a
// normal gate entry. Best-effort: a failure never changes what the
// client got.
//
// The ActionRequest construction is duplicated from Check on purpose:
// Check is the hot path and must stay byte-identical.
func (c *HTTPPolicyClient) RecordForcedAudit(ctx context.Context, req *ToolCallCheck, decision Decision) {
	if req == nil {
		return
	}

	scope := c.MapScope(req.ToolName)

	ar := policy.ActionRequest{
		SchemaVersion:   "v1",
		Scope:           scope,
		AgentID:         req.AgentID,
		SessionID:       req.SessionID,
		ParentSessionID: req.ParentSessionID,
		Command:         formatLLMCommand(req, scope, c.redactor),
		Path:            projectPath(scope, req.Arguments),
		Domain:          projectDomain(scope, req.Arguments),
		URL:             projectURL(scope, req.Arguments),
		ApprovalID:      req.ApprovalID,
		Meta:            buildLLMMeta(req, scope, c.redactor),
	}
	if scope == "filesystem" {
		ar.Action = gateclient.InferFilesystemAction(req.ToolName)
	}
	if scope == "browser" {
		ar.Action = req.ToolName
	}

	caller := gateclient.Caller{
		GuardURL:   c.GuardURL,
		APIKey:     c.APIKey,
		TenantID:   c.TenantID,
		UserAgent:  "vanzik-llm-proxy/" + BuildVersion,
		HTTPClient: c.HTTPClient,
	}
	if err := caller.RecordForcedAudit(ctx, ar, decision.Reason, decision.Rule); err != nil {
		// Typically the central server is keyed and this proxy has no
		// --api-key: /v1/check is open but /v1/audit returns 401. Replay
		// through /v1/check so an entry still exists, with the engine
		// verdict instead of the client's DENY; the decision is ignored
		// (docs/LLM_API_PROXY.md § 5.4 Audit fidelity).
		log.Printf("vanzik-llm-proxy: forced-audit record failed (client refusal already sent); "+
			"falling back to /v1/check low-fidelity audit — give this proxy --api-key when the central server is keyed for full fidelity: %v", err)
		if _, ferr := c.callV1Check(ctx, ar); ferr != nil {
			log.Printf("vanzik-llm-proxy: forced-audit /v1/check fallback also failed (audit entry lost for this refusal): %v", ferr)
		}
	}
}

// buildLLMMeta builds the /v1/check meta map, with argument values
// redacted so secrets don't reach the audit log.
func buildLLMMeta(req *ToolCallCheck, scope string, red *notify.Redactor) map[string]string {
	out := map[string]string{
		"transport":    "llm_api_proxy",
		"provider":     req.Provider,
		"tool_name":    req.ToolName,
		"tool_call_id": req.ToolCallID,
		"mapped_scope": scope,
	}
	if req.Model != "" {
		out["model"] = req.Model
	}
	if req.Stream {
		out["stream"] = "true"
	}
	if req.ApprovalID != "" {
		out["approval_id"] = req.ApprovalID
	}
	for k, v := range projectMetaArgs(req.Arguments, red) {
		out["arg_"+k] = v
	}
	return out
}

// projectPath returns the first path-like argument for filesystem
// scope, else "".
func projectPath(scope string, args map[string]interface{}) string {
	if scope != "filesystem" {
		return ""
	}
	for _, k := range []string{"path", "file_path", "notebook_path", "filepath", "target", "target_path", "filename", "file", "destination", "src", "dst"} {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// projectURL returns the first URL-like argument for network and
// browser scopes, else "".
func projectURL(scope string, args map[string]interface{}) string {
	if scope != "network" && scope != "browser" {
		return ""
	}
	for _, k := range []string{"url", "uri", "endpoint", "target_url"} {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// projectDomain extracts a domain from a URL-like arg, or returns the
// bare domain/host arg if no URL is present. Mirrors mcpgw's mappedDomain
// (a model-written domain arg never overrides the URL's host).
func projectDomain(scope string, args map[string]interface{}) string {
	if scope != "network" && scope != "browser" {
		return ""
	}
	rawURL := projectURL(scope, args)
	if rawURL == "" {
		for _, k := range []string{"domain", "host", "hostname"} {
			if v, ok := args[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// formatLLMCommand renders the tool call as the string rule patterns
// match, per scope, following existing rule-author conventions:
//
//   - shell:      `<command_arg>` (or `<tool_name>` if no command)
//   - filesystem: `<tool_name> <path>`
//   - network:    `<tool_name> <url>`
//   - browser:    `<tool_name> <url>`
//   - data:       `<value/content/text/data arg>` (or tool name)
//   - cost:       `<tool_name>` (cost gating uses est_cost separately)
//   - unmapped:   `<tool_name>`
//
// Arguments are redacted.
func formatLLMCommand(req *ToolCallCheck, scope string, red *notify.Redactor) string {
	switch scope {
	case "shell":
		if cmd := gateclient.FirstStringArg(req.Arguments, "command", "cmd", "script", "code"); cmd != "" {
			return redactSingle(red, cmd)
		}
		// Tool name + args, so rules on a wrapper tool still fire.
		if argStr := gateclient.FirstStringArg(req.Arguments, "args"); argStr != "" {
			return redactSingle(red, req.ToolName+" "+argStr)
		}
		return req.ToolName

	case "filesystem":
		path := projectPath(scope, req.Arguments)
		if path != "" {
			return redactSingle(red, req.ToolName+" "+path)
		}
		return req.ToolName

	case "network", "browser":
		u := projectURL(scope, req.Arguments)
		if u != "" {
			return redactSingle(red, req.ToolName+" "+u)
		}
		return req.ToolName

	case "data":
		// The submitted value, so data rules can match on it.
		if v := gateclient.FirstStringArg(req.Arguments, "value", "content", "text", "data"); v != "" {
			return redactSingle(red, v)
		}
		return req.ToolName

	default:
		return req.ToolName
	}
}

// projectMetaArgs returns a redacted, string-valued copy of args for
// audit meta; non-strings are JSON-encoded.
func projectMetaArgs(args map[string]interface{}, red *notify.Redactor) map[string]string {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]string, len(args))
	for k, v := range args {
		var s string
		switch t := v.(type) {
		case string:
			s = t
		case nil:
			continue
		default:
			b, err := json.Marshal(v)
			if err != nil {
				continue
			}
			s = string(b)
		}
		if red != nil {
			s = redactSingle(red, s)
		}
		// DefaultRedactor matches `key=value`, not a bare value, so
		// secret-named keys are redacted by name.
		if isSecretKeyName(k) {
			s = "[REDACTED]"
		}
		out[k] = s
	}
	return out
}

// isSecretKeyName reports whether an argument name implies a secret.
func isSecretKeyName(k string) bool {
	lk := strings.ToLower(k)
	for _, needle := range []string{"password", "token", "secret", "api_key", "apikey", "auth"} {
		if strings.Contains(lk, needle) {
			return true
		}
	}
	return false
}

// redactSingle redacts one string by wrapping it in a notify.Event, the
// Redactor's only API.
func redactSingle(red *notify.Redactor, s string) string {
	if s == "" || red == nil {
		return s
	}
	ev := notify.Event{
		Request: policy.ActionRequest{
			Command: s,
		},
	}
	return red.Redact(ev).Request.Command
}

func (c *HTTPPolicyClient) callV1Check(ctx context.Context, ar policy.ActionRequest) (Decision, error) {
	caller := gateclient.Caller{
		GuardURL:   c.GuardURL,
		APIKey:     c.APIKey,
		TenantID:   c.TenantID,
		UserAgent:  "vanzik-llm-proxy/" + BuildVersion,
		HTTPClient: c.HTTPClient,
	}
	return caller.CallV1Check(ctx, ar, llmFailModeRules)
}

// failModeDecision maps a /v1/check failure to the fail-mode verdict;
// with fail-closed-with-audit it is also written to --fail-audit-log.
func (c *HTTPPolicyClient) failModeDecision(ar policy.ActionRequest, err error) Decision {
	d := gateclient.FailModeDecision(c.FailMode, err, llmFailModeRules)
	c.fallback.Record(ar, d, "llm_api_proxy", c.TenantID)
	return d
}
