package llmproxy

// Alias-key smuggling: `{"command":"ls","cmd":"rm -rf /"}` used to be
// checked as `ls` and forwarded for a tool that reads `cmd`. Two keys of
// one argument role with different values are now refused before any
// /v1/check call, under every fail mode, and recorded via /v1/audit.

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

const conflictRule = "deny:llm_api_proxy:conflicting_argument_alias"

// conflictGuard records /v1/check and /v1/audit separately. checkStatus
// other than 200 makes /v1/check fail, so the fail mode decides.
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

func conflictGate(t *testing.T, g *conflictGuard, failMode string) *HTTPPolicyClient {
	t.Helper()
	pol := &policy.Policy{ToolScopeMap: []policy.ToolScopeMapping{
		{Pattern: "move_file", Scope: "filesystem"},
		{Pattern: "submit_form", Scope: "data"},
	}}
	return NewHTTPPolicyClient(&Config{GuardURL: g.srv.URL, APIKey: "k", TenantID: "local", FailMode: failMode}, pol)
}

var argConflictCases = []struct {
	name     string
	tool     string
	args     map[string]interface{}
	conflict bool
	keys     string // the keys the reason must name
}{
	{"shell command conflict", "bash", map[string]interface{}{"command": "ls", "cmd": "rm -rf /"}, true, "('command' and 'cmd')"},
	{"shell command identical", "bash", map[string]interface{}{"command": "ls", "cmd": "ls"}, false, ""},
	{"filesystem path conflict", "Write", map[string]interface{}{"path": "/tmp/ok", "file_path": "/etc/passwd"}, true, "('path' and 'file_path')"},
	{"filesystem path identical", "Write", map[string]interface{}{"path": "/tmp/ok", "file_path": "/tmp/ok"}, false, ""},
	{"filesystem src and dst differ", "move_file", map[string]interface{}{"src": "/tmp/a", "dst": "/tmp/b"}, false, ""},
	{"filesystem destination conflict", "move_file", map[string]interface{}{"src": "/tmp/a", "destination": "/tmp/b", "dst": "/etc/cron.d/x"}, true, "('destination' and 'dst')"},
	{"network url conflict", "fetch_url", map[string]interface{}{"url": "https://ok.example", "uri": "https://evil.example"}, true, "('url' and 'uri')"},
	{"network url identical", "fetch_url", map[string]interface{}{"url": "https://ok.example", "uri": "https://ok.example"}, false, ""},
	{"browser domain conflict", "navigate", map[string]interface{}{"domain": "ok.example", "hostname": "evil.example"}, true, "('domain' and 'hostname')"},
	{"browser domain identical", "navigate", map[string]interface{}{"domain": "ok.example", "hostname": "ok.example"}, false, ""},
	{"data value conflict", "submit_form", map[string]interface{}{"value": "hi", "content": "sk-live-x"}, true, "('value' and 'content')"},
	{"data value identical", "submit_form", map[string]interface{}{"value": "hi", "content": "hi"}, false, ""},
}

func TestLLMGate_ArgConflict(t *testing.T) {
	for _, c := range argConflictCases {
		t.Run(c.name, func(t *testing.T) {
			g := newConflictGuard(t, http.StatusOK)
			gate := conflictGate(t, g, "deny")
			dec, err := gate.Check(context.Background(), toolCall("openai", c.tool, c.args))
			if err != nil {
				t.Fatalf("Check err = %v", err)
			}
			checks, audits := g.counts()
			if !c.conflict {
				if !dec.Allow || checks != 1 || audits != 0 {
					t.Fatalf("got %+v with %d checks, %d audits; want the usual single /v1/check ALLOW", dec, checks, audits)
				}
				return
			}
			if dec.Allow || dec.Rule != conflictRule {
				t.Fatalf("got %+v, want DENY with %s", dec, conflictRule)
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
			if rec.Rule != conflictRule || rec.Reason != dec.Reason {
				t.Errorf("audit record rule/reason = %q/%q, want %q/%q", rec.Rule, rec.Reason, conflictRule, dec.Reason)
			}
			if rec.Request.Meta["transport"] != "llm_api_proxy" || rec.Request.Meta["tool_name"] != c.tool {
				t.Errorf("audit record meta = %v, want the gate's usual meta", rec.Request.Meta)
			}
		})
	}
}

// The conflict is a decision, not an outage: --fail-mode allow, which
// opens the gate when /v1/check fails, must not open it here.
func TestLLMGate_ArgConflict_FailModeAllowCannotOverride(t *testing.T) {
	g := newConflictGuard(t, http.StatusInternalServerError)
	gate := conflictGate(t, g, "allow")

	// Sanity: with no conflict, the broken /v1/check plus fail-mode allow
	// does open the gate.
	if dec, _ := gate.Check(context.Background(), toolCall("openai", "bash", map[string]interface{}{"command": "ls"})); !dec.Allow {
		t.Fatalf("precondition: fail-mode allow should ALLOW an unconflicted call, got %+v", dec)
	}

	for _, c := range argConflictCases {
		if !c.conflict {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			dec, err := gate.Check(context.Background(), toolCall("openai", c.tool, c.args))
			if err != nil {
				t.Fatalf("Check err = %v; a nil error is what keeps fail-mode allow out", err)
			}
			if dec.Allow || dec.Rule != conflictRule {
				t.Fatalf("got %+v, want DENY with %s under --fail-mode allow", dec, conflictRule)
			}
		})
	}
}

// End to end through the server's non-streaming path with --fail-mode
// allow: the smuggled call never reaches the agent.
func TestLLMServer_ArgConflictRefusedUnderFailModeAllow(t *testing.T) {
	g := newConflictGuard(t, http.StatusInternalServerError)
	gate := conflictGate(t, g, "allow")
	s := &Server{cfg: &Config{TenantID: "local", FailMode: "allow"}, PolicyCheck: gate.Check}

	args, _ := json.Marshal(map[string]string{"command": "ls", "cmd": "rm -rf /"})
	resp := &ChatCompletionResponse{Model: "m"}
	if err := json.Unmarshal([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"bash","arguments":`+string(mustQuote(t, string(args)))+`}}]}}]}`), resp); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	dec, denied, _ := s.gateOpenAINonStreaming(context.Background(), r, resp)
	if !denied || dec.Rule != conflictRule {
		t.Fatalf("denied=%v decision=%+v, want the conflict DENY", denied, dec)
	}
}

func mustQuote(t *testing.T, s string) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
