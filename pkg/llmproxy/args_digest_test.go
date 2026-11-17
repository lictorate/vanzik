package llmproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
// digestPolicy asks for approval of `psql *` and of the unmapped send_email.
var digestPolicy = &policy.Policy{
	Version: "1",
	Name:    "args-digest",
	Rules: []policy.RuleSet{
		{Scope: "shell", RequireApproval: []policy.Rule{{Pattern: "psql *"}}},
		{Scope: "unmapped", RequireApproval: []policy.Rule{{Pattern: "send_email"}}},
	},
}

const centralAPIKey = "central-key"

// startCentral runs a real central server on digestPolicy. Every
// /v1/check body it receives is passed to seen, when set.
func startCentral(t *testing.T, seen func(policy.ActionRequest)) string {
	t.Helper()
	fl, err := audit.NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { _ = fl.Close() })
	h := proxy.NewServer(proxy.Config{
		Engine:   policy.NewEngineFromPolicy(digestPolicy),
		Logger:   fl,
		Notifier: notify.NewDispatcher(policy.NotificationCfg{}),
		APIKey:   centralAPIKey,
		BaseURL:  "http://127.0.0.1:0",
		Version:  "test",
	}).Handler()
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil && strings.HasSuffix(r.URL.Path, "/check") {
			body, _ := io.ReadAll(r.Body)
			var ar policy.ActionRequest
			_ = json.Unmarshal(body, &ar)
			seen(ar)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(central.Close)
	return central.URL
}

// approveOn resolves approval id as ALLOW on the central server.
func approveOn(t *testing.T, centralURL, id string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, centralURL+"/v1/approve/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+centralAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve: HTTP %d", resp.StatusCode)
	}
}

func TestApprovalBoundToArguments(t *testing.T) {
	centralURL := startCentral(t, nil)
	const apiKey = centralAPIKey
	newGate := func(key string) *HTTPPolicyClient {
		return NewHTTPPolicyClient(&Config{GuardURL: centralURL, APIKey: key, TenantID: "local", FailMode: "deny"}, digestPolicy)
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
			approveOn(t, centralURL, first.ApprovalID)
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

// A legacy function_call reaches the gate through the tool-call path
// (VR-2), so its approval is bound to its arguments like a tool_call's,
// streaming and non-streaming: the same call re-serialised is honoured,
// a swapped recipient opens a new approval.
func TestLegacyFunctionCall_ApprovalBoundToArguments(t *testing.T) {
	nonStreaming := func(args string) string {
		quoted, _ := json.Marshal(args)
		return `{"id":"chatcmpl-x","object":"chat.completion","created":1,"model":"gpt-4",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":null,` +
			`"function_call":{"name":"send_email","arguments":` + string(quoted) + `}},"finish_reason":"function_call"}]}`
	}
	streaming := func(args string) string {
		return `data: {"choices":[{"index":0,"delta":{"role":"assistant","content":null},"finish_reason":null}]}` + "\n\n" +
			pvOpenAIFunctionCallDelta("send_email", "") +
			pvOpenAIFunctionCallDelta("", args) +
			pvOpenAIFinish(0, "function_call") +
			"data: [DONE]\n\n"
	}
	const email = `{"to":"alice@example.com","body":"hi"}`
	for _, mode := range []struct {
		name   string
		stream bool
	}{{"non-streaming", false}, {"streaming", true}} {
		for _, c := range []struct {
			name     string
			retry    string
			honoured bool
		}{
			{"reordered keys and whitespace", `{ "body": "hi", "to": "alice@example.com" }`, true},
			{"swapped recipient", `{"to":"mallory@example.com","body":"hi"}`, false},
		} {
			t.Run(mode.name+"/"+c.name, func(t *testing.T) {
				var mu sync.Mutex
				var sent []policy.ActionRequest
				centralURL := startCentral(t, func(ar policy.ActionRequest) {
					mu.Lock()
					sent = append(sent, ar)
					mu.Unlock()
				})
				gate := NewHTTPPolicyClient(&Config{GuardURL: centralURL, APIKey: centralAPIKey, TenantID: "local", FailMode: "deny"}, digestPolicy)

				var args string
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					a := args
					mu.Unlock()
					if mode.stream {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, streaming(a))
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, nonStreaming(a))
				}))
				defer upstream.Close()

				var decisions []Decision
				_, base, teardown := newGatedTestServer(t, upstream, upstream, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
					d, err := gate.Check(ctx, tc)
					mu.Lock()
					decisions = append(decisions, d)
					mu.Unlock()
					return d, err
				})
				defer teardown()

				post := func(callArgs, approvalID string) Decision {
					t.Helper()
					mu.Lock()
					args = callArgs
					before := len(decisions)
					mu.Unlock()
					body := fmt.Sprintf(`{"model":"gpt-4","messages":[],"functions":[{"name":"send_email"}],"stream":%t}`, mode.stream)
					req, _ := http.NewRequest(http.MethodPost, base+"/v1/chat/completions", strings.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					if approvalID != "" {
						req.Header.Set(ApprovalIDHeader, approvalID)
					}
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Fatalf("post: %v", err)
					}
					_, _ = io.ReadAll(resp.Body)
					resp.Body.Close()
					mu.Lock()
					defer mu.Unlock()
					if len(decisions) != before+1 {
						t.Fatalf("gated %d calls, want 1: the legacy function_call must reach the gate", len(decisions)-before)
					}
					return decisions[before]
				}

				first := post(email, "")
				if !first.RequiresApproval || first.ApprovalID == "" {
					t.Fatalf("first call: %+v, want REQUIRE_APPROVAL", first)
				}
				mu.Lock()
				digest := sent[0].Meta[gateclient.MetaArgsDigestKey]
				mu.Unlock()
				if digest == "" {
					t.Fatal("the legacy function_call reached /v1/check without args_digest")
				}
				approveOn(t, centralURL, first.ApprovalID)

				retry := post(c.retry, first.ApprovalID)
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
}
