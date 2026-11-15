package mcpgw

// Alias-key smuggling through the gateway: `{"command":"ls","cmd":"rm -rf /"}`
// used to be checked as `ls` and forwarded. In strict mode a mapped call
// whose alias arguments disagree is refused before any /v1/check call,
// under every fail mode, and recorded via /v1/audit.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"lictorate.com/vanzik/v2/pkg/policy"
)

const gatewayConflictRule = "deny:gateway:conflicting_argument_alias"

type conflictGuard struct {
	srv         *httptest.Server
	checkStatus int
	mu          sync.Mutex
	checks      []policy.ActionRequest
	audits      []policy.AuditRecord
}

func newConflictGuard(t *testing.T, checkStatus int) *conflictGuard {
	t.Helper()
	g := &conflictGuard{checkStatus: checkStatus}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/audit"):
			var rec policy.AuditRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			g.audits = append(g.audits, rec)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"v1","decision":"DENY"}`))
		case strings.HasSuffix(r.URL.Path, "/check"):
			var ar policy.ActionRequest
			_ = json.NewDecoder(r.Body).Decode(&ar)
			g.checks = append(g.checks, ar)
			if g.checkStatus != http.StatusOK {
				http.Error(w, "down", g.checkStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"v1","decision":"ALLOW","reason":"mock","matched_rule":"allow:mock"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *conflictGuard) counts() (checks, audits int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.checks), len(g.audits)
}

func conflictGate(g *conflictGuard, failMode string) *HTTPPolicyClient {
	pol := &policy.Policy{ToolScopeMap: []policy.ToolScopeMapping{
		{Pattern: "sh:*", Scope: "shell"},
		{Pattern: "fs:*", Scope: "filesystem"},
		{Pattern: "fetch:*", Scope: "network"},
		{Pattern: "web:*", Scope: "browser"},
		{Pattern: "form:*", Scope: "data"},
	}}
	return NewHTTPPolicyClient(&Config{GuardURL: g.srv.URL, APIKey: "k", TenantID: "local", PolicyMode: "strict", FailMode: failMode}, pol)
}

var gatewayConflictCases = []struct {
	name     string
	tool     string
	args     map[string]interface{}
	conflict bool
	keys     string
}{
	{"shell command conflict", "sh:run", map[string]interface{}{"command": "ls", "cmd": "rm -rf /"}, true, "('command' and 'cmd')"},
	{"shell command identical", "sh:run", map[string]interface{}{"command": "ls", "cmd": "ls"}, false, ""},
	{"filesystem path conflict", "fs:write_file", map[string]interface{}{"path": "/tmp/ok", "file_path": "/etc/passwd"}, true, "('path' and 'file_path')"},
	{"filesystem path identical", "fs:write_file", map[string]interface{}{"path": "/tmp/ok", "file_path": "/tmp/ok"}, false, ""},
	{"filesystem src and dst differ", "fs:move_file", map[string]interface{}{"src": "/tmp/a", "dst": "/tmp/b"}, false, ""},
	{"filesystem destination conflict", "fs:move_file", map[string]interface{}{"src": "/tmp/a", "destination": "/tmp/b", "dst": "/etc/cron.d/x"}, true, "('destination' and 'dst')"},
	{"network url conflict", "fetch:get", map[string]interface{}{"url": "https://ok.example", "uri": "https://evil.example"}, true, "('url' and 'uri')"},
	{"network url identical", "fetch:get", map[string]interface{}{"url": "https://ok.example", "uri": "https://ok.example"}, false, ""},
	{"browser domain conflict", "web:open", map[string]interface{}{"domain": "ok.example", "host": "evil.example"}, true, "('domain' and 'host')"},
	{"browser domain identical", "web:open", map[string]interface{}{"domain": "ok.example", "host": "ok.example"}, false, ""},
	{"data value conflict", "form:submit", map[string]interface{}{"value": "hi", "text": "sk-live-x"}, true, "('value' and 'text')"},
	{"data value identical", "form:submit", map[string]interface{}{"value": "hi", "text": "hi"}, false, ""},
}

func TestGatewayGate_ArgConflict(t *testing.T) {
	for _, c := range gatewayConflictCases {
		t.Run(c.name, func(t *testing.T) {
			g := newConflictGuard(t, http.StatusOK)
			gate := conflictGate(g, "deny")
			dec, err := gate.Check(context.Background(), toolsCallReq(c.tool, c.args))
			if err != nil {
				t.Fatalf("Check err = %v", err)
			}
			checks, audits := g.counts()
			if !c.conflict {
				// mcp_tool + mapped scope, as before.
				if !dec.Allow || checks != 2 || audits != 0 {
					t.Fatalf("got %+v with %d checks, %d audits; want the usual dual-check ALLOW", dec, checks, audits)
				}
				return
			}
			if dec.Allow || dec.Rule != gatewayConflictRule {
				t.Fatalf("got %+v, want DENY with %s", dec, gatewayConflictRule)
			}
			if !strings.Contains(dec.Reason, c.keys) {
				t.Errorf("reason %q does not name the keys %s", dec.Reason, c.keys)
			}
			if checks != 0 {
				t.Errorf("%d /v1/check calls, want 0 (refused before the engine)", checks)
			}
			if audits != 1 {
				t.Fatalf("%d /v1/audit records, want 1", audits)
			}
			g.mu.Lock()
			rec := g.audits[0]
			g.mu.Unlock()
			if rec.Rule != gatewayConflictRule || rec.Reason != dec.Reason {
				t.Errorf("audit record rule/reason = %q/%q, want %q/%q", rec.Rule, rec.Reason, gatewayConflictRule, dec.Reason)
			}
			if rec.Request.Meta["transport"] != "mcp_gateway" || rec.Request.Command == "" {
				t.Errorf("audit record request = %+v, want the mapped-scope request", rec.Request)
			}
		})
	}
}

func TestGatewayGate_ArgConflict_FailModeAllowCannotOverride(t *testing.T) {
	g := newConflictGuard(t, http.StatusInternalServerError)
	gate := conflictGate(g, "allow")

	if dec, _ := gate.Check(context.Background(), toolsCallReq("sh:run", map[string]interface{}{"command": "ls"})); !dec.Allow {
		t.Fatalf("precondition: fail-mode allow should ALLOW an unconflicted call, got %+v", dec)
	}

	for _, c := range gatewayConflictCases {
		if !c.conflict {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			dec, err := gate.Check(context.Background(), toolsCallReq(c.tool, c.args))
			if err != nil {
				t.Fatalf("Check err = %v", err)
			}
			if dec.Allow || dec.Rule != gatewayConflictRule {
				t.Fatalf("got %+v, want DENY with %s under --fail-mode allow", dec, gatewayConflictRule)
			}
		})
	}
}

// Fast mode projects no arguments, so it has nothing to conflict: one
// mcp_tool check, as before.
func TestGatewayGate_ArgConflict_FastModeUnchanged(t *testing.T) {
	g := newConflictGuard(t, http.StatusOK)
	gate := conflictGate(g, "deny")
	gate.PolicyMode = "fast"
	dec, err := gate.Check(context.Background(), toolsCallReq("sh:run", map[string]interface{}{"command": "ls", "cmd": "rm -rf /"}))
	if err != nil || !dec.Allow {
		t.Fatalf("got %+v, %v; want the mcp_tool ALLOW", dec, err)
	}
	if checks, audits := g.counts(); checks != 1 || audits != 0 {
		t.Errorf("%d checks, %d audits; want 1, 0", checks, audits)
	}
}

// The gateway projects the keys both gates share from one table: `code`,
// `uri`, `notebook_path` and the rest of the LLM proxy's list now reach the
// mapped check instead of being ignored.
func TestBuildMappedActionRequest_SharedKeyTable(t *testing.T) {
	cases := []struct {
		scope string
		args  map[string]interface{}
		get   func(policy.ActionRequest) string
		want  string
	}{
		{"shell", map[string]interface{}{"code": "rm -rf /"}, func(a policy.ActionRequest) string { return a.Command }, "rm -rf /"},
		{"filesystem", map[string]interface{}{"notebook_path": "/etc/x.ipynb"}, func(a policy.ActionRequest) string { return a.Path }, "/etc/x.ipynb"},
		{"filesystem", map[string]interface{}{"src": "/tmp/a", "dst": "/tmp/b"}, func(a policy.ActionRequest) string { return a.Path }, "/tmp/a"},
		{"network", map[string]interface{}{"uri": "https://evil.example/x"}, func(a policy.ActionRequest) string { return a.Domain }, "evil.example"},
		{"browser", map[string]interface{}{"target_url": "https://evil.example/x"}, func(a policy.ActionRequest) string { return a.URL }, "https://evil.example/x"},
		{"data", map[string]interface{}{"endpoint": "https://evil.example/x"}, func(a policy.ActionRequest) string { return a.Domain }, "evil.example"},
	}
	for _, c := range cases {
		ar := buildMappedActionRequest(toolsCallReq("ns:tool", c.args), c.scope)
		if got := c.get(ar); got != c.want {
			t.Errorf("%s %v: projected %q, want %q", c.scope, c.args, got, c.want)
		}
	}
}
