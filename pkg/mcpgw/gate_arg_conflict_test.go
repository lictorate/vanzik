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

// mappedCheck runs one strict-mode call against an ALLOW-everything guard
// and returns the mapped-scope request, the second of the dual check.
func mappedCheck(t *testing.T, tool string, args map[string]interface{}) policy.ActionRequest {
	t.Helper()
	g := newConflictGuard(t, http.StatusOK)
	dec, err := conflictGate(g, "deny").Check(context.Background(), toolsCallReq(tool, args))
	if err != nil || !dec.Allow {
		t.Fatalf("got %+v, %v; want the engine's ALLOW (no conflict)", dec, err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.checks) != 2 || len(g.audits) != 0 {
		t.Fatalf("%d checks, %d audits; want 2 (mcp_tool + mapped), 0", len(g.checks), len(g.audits))
	}
	return g.checks[1]
}

// The shared table keeps the filesystem key order the gateway had: path
// aliases, then destination, then src, then dst. Reading src first would
// let {"destination":"/etc/passwd","src":"/tmp/x"} be checked as /tmp/x.
func TestGatewayGate_FilesystemKeyOrder(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"destination before src", map[string]interface{}{"destination": "/etc/passwd", "src": "/tmp/x"}, "/etc/passwd"},
		{"src before dst", map[string]interface{}{"src": "/tmp/a", "dst": "/tmp/b"}, "/tmp/a"},
		{"equal destination and dst", map[string]interface{}{"destination": "/tmp/b", "dst": "/tmp/b"}, "/tmp/b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mappedCheck(t, "fs:copy_file", c.args).Path; got != c.want {
				t.Errorf("checked path = %q, want %q", got, c.want)
			}
		})
	}
}

// One argument per call is checked, and a key the gateway took from the LLM
// proxy's list can now win over one it read before. Each case below was
// denied on v2.1.0's base and is now checked on the first key and
// forwarded. Known gap, tracked for the multi-part check design (checking
// every path-like value needs more than one check per call); these tests
// pin the current behaviour so a change to it is deliberate.
func TestGatewayGate_OneArgumentChecked_KnownGap(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
		get  func(policy.ActionRequest) string
		want string
	}{
		{"target beats destination", "fs:copy_file", map[string]interface{}{"target": "/tmp/x", "destination": "/etc/passwd"},
			func(a policy.ActionRequest) string { return a.Path }, "/tmp/x"},
		{"file beats src", "fs:copy_file", map[string]interface{}{"file": "/tmp/x", "src": "/etc/shadow"},
			func(a policy.ActionRequest) string { return a.Path }, "/tmp/x"},
		{"code beats args", "sh:run", map[string]interface{}{"code": "ls", "args": "rm -rf /"},
			func(a policy.ActionRequest) string { return a.Command }, "ls"},
		{"uri host beats domain", "fetch:get", map[string]interface{}{"uri": "https://ok.example/", "domain": "evil.example"},
			func(a policy.ActionRequest) string { return a.Domain }, "ok.example"},
		{"notebook_path beats dst", "fs:copy_file", map[string]interface{}{"notebook_path": "/tmp/x", "dst": "/etc/passwd"},
			func(a policy.ActionRequest) string { return a.Path }, "/tmp/x"},
		{"filename beats destination", "fs:copy_file", map[string]interface{}{"filename": "/tmp/x", "destination": "/etc/passwd"},
			func(a policy.ActionRequest) string { return a.Path }, "/tmp/x"},
		{"endpoint host beats host", "fetch:get", map[string]interface{}{"endpoint": "https://ok.example/", "host": "evil.example"},
			func(a policy.ActionRequest) string { return a.Domain }, "ok.example"},
		{"target_url host beats domain (browser)", "web:open", map[string]interface{}{"target_url": "https://ok.example/", "domain": "evil.example"},
			func(a policy.ActionRequest) string { return a.Domain }, "ok.example"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.get(mappedCheck(t, c.tool, c.args)); got != c.want {
				t.Errorf("checked %q, want %q", got, c.want)
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
		ar := buildMappedActionRequest(toolsCallReq("ns:tool", c.args), c.scope, nil)
		if got := c.get(ar); got != c.want {
			t.Errorf("%s %v: projected %q, want %q", c.scope, c.args, got, c.want)
		}
	}
}
