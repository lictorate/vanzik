package mcpgw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"lictorate.com/vanzik/v2/pkg/audit"
	"lictorate.com/vanzik/v2/pkg/internal/gateclient"
	"lictorate.com/vanzik/v2/pkg/notify"
	"lictorate.com/vanzik/v2/pkg/policy"
	"lictorate.com/vanzik/v2/pkg/proxy"
)

// Both checks of a strict-mode call carry the digest of the arguments the
// bridge forwards, so whichever one asks for approval binds it to them.
func TestHTTPPolicyClient_SendsArgsDigest(t *testing.T) {
	m := newMockGuardServer(t)
	pol := &policy.Policy{ToolScopeMap: []policy.ToolScopeMapping{{Pattern: "fs:write_*", Scope: "filesystem"}}}
	gate := newGateForTest(t, m, "strict", pol)
	var mu sync.Mutex
	var got []policy.ActionRequest
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		mu.Lock()
		got = append(got, ar)
		mu.Unlock()
		return http.StatusOK, policy.CheckResult{SchemaVersion: "v1", Decision: policy.Allow, Rule: "allow:mock"}, ""
	})

	args := map[string]interface{}{"path": "/tmp/x", "content": "hi", "n": 9007199254740993.0}
	if _, err := gate.Check(context.Background(), toolsCallReq("fs:write_file", args)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	forwarded, _ := json.Marshal(args)
	want := gateclient.ArgsDigest(gate.argsDigestKey[:], "fs:write_file", forwarded)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("expected the mcp_tool and the mapped check, got %d", len(got))
	}
	for _, ar := range got {
		if ar.Meta[gateclient.MetaArgsDigestKey] != want {
			t.Errorf("%s check: args_digest = %q, want %q", ar.Scope, ar.Meta[gateclient.MetaArgsDigestKey], want)
		}
	}
}

// An approval granted through the MCP Gateway is not honoured for a retry
// with other arguments: the headline case is an approved send_email
// replayed to another recipient.
func TestApprovalBoundToArguments(t *testing.T) {
	pol := &policy.Policy{
		Version: "1",
		Name:    "args-digest",
		Rules: []policy.RuleSet{
			{Scope: "mcp_tool", RequireApproval: []policy.Rule{{Pattern: "mail:send_email"}}},
		},
	}
	fl, err := audit.NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { _ = fl.Close() })
	const apiKey = "central-key"
	central := httptest.NewServer(proxy.NewServer(proxy.Config{
		Engine:   policy.NewEngineFromPolicy(pol),
		Logger:   fl,
		Notifier: notify.NewDispatcher(policy.NotificationCfg{}),
		APIKey:   apiKey,
		BaseURL:  "http://127.0.0.1:0",
		Version:  "test",
	}).Handler())
	t.Cleanup(central.Close)

	gate := NewHTTPPolicyClient(&Config{GuardURL: central.URL, APIKey: apiKey, TenantID: "local", PolicyMode: "strict", FailMode: "deny"}, pol)
	check := func(args map[string]interface{}, approvalID string) Decision {
		t.Helper()
		req := toolsCallReq("mail:send_email", args)
		req.ApprovalID = approvalID
		d, err := gate.Check(context.Background(), req)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return d
	}
	email := func(to string) map[string]interface{} {
		return map[string]interface{}{"to": to, "body": "hi"}
	}
	cases := []struct {
		name     string
		retry    map[string]interface{}
		honoured bool
	}{
		{"same arguments", email("alice@example.com"), true},
		{"swapped recipient", email("mallory@example.com"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first := check(email("alice@example.com"), "")
			if !first.RequiresApproval || first.ApprovalID == "" {
				t.Fatalf("first call: %+v, want REQUIRE_APPROVAL", first)
			}
			req, _ := http.NewRequest(http.MethodPost, central.URL+"/v1/approve/"+first.ApprovalID, nil)
			req.Header.Set("Authorization", "Bearer "+apiKey)
			resp, err := http.DefaultClient.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("approve: %v %v", err, resp)
			}
			resp.Body.Close()

			retry := check(c.retry, first.ApprovalID)
			if c.honoured {
				if !retry.Allow || retry.Rule != "allow:approved" {
					t.Errorf("retry: %+v, want ALLOW allow:approved", retry)
				}
				return
			}
			if retry.Allow || !retry.RequiresApproval || retry.ApprovalID == first.ApprovalID {
				t.Errorf("retry: %+v, want a new approval (not %s)", retry, first.ApprovalID)
			}
		})
	}
}
