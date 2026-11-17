package mcpgw

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"lictorate.com/vanzik/v2/pkg/internal/gateclient"
	"lictorate.com/vanzik/v2/pkg/policy"
)

// Secret-named arguments reach /v1/check meta masked, as the LLM API
// Proxy sends them: the central redactor matches `key=value`, not a bare
// value, so without this the audit log and the pending-approval card show
// them in plain text. The digest is still taken from the real values, so
// a retry with another password is not honoured.
func TestHTTPPolicyClient_MasksSecretArgs(t *testing.T) {
	m := newMockGuardServer(t)
	pol := &policy.Policy{ToolScopeMap: []policy.ToolScopeMapping{{Pattern: "db:write_*", Scope: "filesystem"}}}
	gate := newGateForTest(t, m, "strict", pol)
	var mu sync.Mutex
	var got []policy.ActionRequest
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		mu.Lock()
		got = append(got, ar)
		mu.Unlock()
		return http.StatusOK, policy.CheckResult{SchemaVersion: "v1", Decision: policy.Allow, Rule: "allow:mock"}, ""
	})

	args := map[string]interface{}{"path": "/tmp/db", "password": "hunter2", "api_key": "sk-live-abc123"}
	if _, err := gate.Check(context.Background(), toolsCallReq("db:write_row", args)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	forwarded, _ := json.Marshal(args)
	digest := gateclient.ArgsDigest(gate.argsDigestKey[:], "db:write_row", forwarded)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("expected the mcp_tool and the mapped check, got %d", len(got))
	}
	for _, ar := range got {
		for _, k := range []string{"arg_password", "arg_api_key"} {
			if ar.Meta[k] != "[REDACTED]" {
				t.Errorf("%s check: %s = %q, want [REDACTED]", ar.Scope, k, ar.Meta[k])
			}
		}
		if ar.Meta["arg_path"] != "/tmp/db" {
			t.Errorf("%s check: arg_path = %q, want it unmasked", ar.Scope, ar.Meta["arg_path"])
		}
		if ar.Meta[gateclient.MetaArgsDigestKey] != digest {
			t.Errorf("%s check: args_digest is not the digest of the forwarded arguments", ar.Scope)
		}
	}
}
