package llmproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"lictorate.com/vanzik/v2/pkg/audit"
	"lictorate.com/vanzik/v2/pkg/internal/gateclient"
	"lictorate.com/vanzik/v2/pkg/notify"
	"lictorate.com/vanzik/v2/pkg/policy"
	"lictorate.com/vanzik/v2/pkg/proxy"
)

// Every gated path sends a digest of the call's own arguments: the
// /v1/check meta digest matches one taken from the parsed arguments, so
// RawArguments reached the gate on each path.
func TestArgsDigestOnEveryGatedPath(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		body    string
		fixture string // streamed fixture; empty means a non-streaming JSON body
		json    string
	}{
		{"openai-stream", "/v1/chat/completions", `{"model":"gpt-4","messages":[],"stream":true}`, "openai_streaming_single_tool_call.txt", ""},
		{"anthropic-stream", "/v1/messages", `{"model":"claude","messages":[],"stream":true}`, "anthropic_streaming_single_tool_use.txt", ""},
		{"openai-json", "/v1/chat/completions", `{"model":"gpt-4","messages":[]}`, "", "openai_with_tool_calls.json"},
		{"anthropic-json", "/v1/messages", `{"model":"claude","messages":[]}`, "", "anthropic_messages_response.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.fixture != "" {
					w.Header().Set("Content-Type", "text/event-stream")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(readFixture(t, c.fixture))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(readFixture(t, c.json))
			}))
			defer upstream.Close()

			guard := newMockGuardServer(t)
			gate := newGateForTest(t, guard, "deny", nil)
			var mu sync.Mutex
			var calls []ToolCallCheck
			_, base, teardown := newGatedTestServer(t, upstream, upstream, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
				mu.Lock()
				calls = append(calls, *tc)
				mu.Unlock()
				return gate.Check(ctx, tc)
			})
			defer teardown()

			resp, err := http.Post(base+c.path, "application/json", strings.NewReader(c.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			_, _ = io.ReadAll(resp.Body)
			resp.Body.Close()

			sent := guard.Received()
			mu.Lock()
			defer mu.Unlock()
			if len(calls) == 0 || len(sent) != len(calls) {
				t.Fatalf("gated %d calls, /v1/check saw %d; the fixture must carry a tool call", len(calls), len(sent))
			}
			for i, tc := range calls {
				if len(tc.Arguments) == 0 {
					t.Fatalf("call %d has no arguments; the fixture must carry some", i)
				}
				parsed, _ := json.Marshal(tc.Arguments)
				want := gateclient.ArgsDigest(gate.argsDigestKey[:], tc.ToolName, parsed)
				if got := sent[i].Meta[gateclient.MetaArgsDigestKey]; got != want {
					t.Errorf("call %d (%s): args_digest = %q, want the digest of its arguments %q", i, tc.ToolName, got, want)
				}
			}
		})
	}
}

// An approval granted through the LLM API Proxy unlocks only the
// arguments that were approved, as the model re-serialises them.
func TestApprovalBoundToArguments(t *testing.T) {
	pol := &policy.Policy{
		Version: "1",
		Name:    "args-digest",
		Rules: []policy.RuleSet{
			{Scope: "shell", RequireApproval: []policy.Rule{{Pattern: "psql *"}}},
			{Scope: "unmapped", RequireApproval: []policy.Rule{{Pattern: "send_email"}}},
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

	newGate := func(key string) *HTTPPolicyClient {
		return NewHTTPPolicyClient(&Config{GuardURL: central.URL, APIKey: key, TenantID: "local", FailMode: "deny"}, pol)
	}
	check := func(gate *HTTPPolicyClient, tool, raw, approvalID string) Decision {
		t.Helper()
		var args map[string]interface{}
		_ = json.Unmarshal([]byte(raw), &args)
		d, err := gate.Check(context.Background(), &ToolCallCheck{
			Provider: "openai", ToolName: tool, Arguments: args, RawArguments: json.RawMessage(raw),
			AgentID: "agent_a", TenantID: "local", ApprovalID: approvalID,
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return d
	}
	approve := func(id string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, central.URL+"/v1/approve/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("approve: HTTP %d", resp.StatusCode)
		}
	}

	const email = `{"to":"alice@example.com","body":"hi"}`
	cases := []struct {
		name                  string
		tool                  string
		original, retry       string
		originalKey, retryKey string
		retryGateRestarts     bool
		honoured              bool
	}{
		{"reordered keys and whitespace", "send_email", email, "{ \"body\": \"hi\",\n  \"to\": \"alice@example.com\" }", apiKey, apiKey, false, true},
		{"swapped recipient", "send_email", email, `{"to":"mallory@example.com","body":"hi"}`, apiKey, apiKey, false, false},
		{"other password", "bash", `{"command":"psql password=one"}`, `{"command":"psql password=two"}`, apiKey, apiKey, false, false},
		{"restarted proxy with the API key", "send_email", email, email, apiKey, apiKey, true, true},
		{"restarted proxy without an API key", "send_email", email, email, "", "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gate := newGate(c.originalKey)
			first := check(gate, c.tool, c.original, "")
			if !first.RequiresApproval || first.ApprovalID == "" {
				t.Fatalf("first call: %+v, want REQUIRE_APPROVAL", first)
			}
			approve(first.ApprovalID)
			if c.retryGateRestarts {
				gate = newGate(c.retryKey)
			}
			retry := check(gate, c.tool, c.retry, first.ApprovalID)
			if c.honoured {
				if !retry.Allow || retry.Rule != "allow:approved" {
					t.Errorf("retry: %+v, want ALLOW allow:approved", retry)
				}
				return
			}
			if retry.Allow {
				t.Fatalf("retry with other arguments was allowed: %+v", retry)
			}
			if !retry.RequiresApproval || retry.ApprovalID == "" || retry.ApprovalID == first.ApprovalID {
				t.Errorf("retry: %+v, want a new approval (not %s)", retry, first.ApprovalID)
			}
		})
	}
}
