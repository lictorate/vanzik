package llmproxy

// Streaming and non-streaming DENY paths end to end: the client sees the
// central server's rule, and /v1/check carries transport=llm_api_proxy.
// A real HTTPPolicyClient talks to the mock central recorder from
// at_b2_e2e_test.go.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lictorate.com/vanzik/v2/pkg/policy"
)

// TestAT_FullStack_StreamingDenyPath_TransportTaggedAudit: the refusal
// carries the central's rule, and exactly one transport-tagged /v1/check
// was made with provider and mapped_scope set.
func TestAT_FullStack_StreamingDenyPath_TransportTaggedAudit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-at1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}` + "\n\n"))
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-at1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_at_stream_deny","type":"function","function":{"name":"bash","arguments":""}}]},"finish_reason":null}]}` + "\n\n"))
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-at1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":\"rm -rf /\"}"}}]},"finish_reason":null}]}` + "\n\n"))
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-at1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	central := newATCentralRecorder(t, func(ar policy.ActionRequest) policy.CheckResult {
		return policy.CheckResult{
			Decision: policy.Deny,
			Rule:     "deny:shell:rm_rf_at_integration",
			Reason:   "AT integration: rm -rf blocked",
		}
	})

	base, teardown := newATFullStackProxy(t, upstream, central)
	defer teardown()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"clean root"}],"stream":true}`
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// 1. The central server's rule, not a streaming-side constant.
	if !strings.Contains(gotStr, "deny:shell:rm_rf_at_integration") {
		t.Errorf("refusal missing central-server rule: %q", gotStr)
	}
	if strings.Contains(gotStr, "policy_unreachable") {
		t.Errorf("refusal contains pre-F5 hardcoded rule `policy_unreachable`; B4 regression: %q", gotStr)
	}

	// Upstream tool_call ids / args must NOT leak.
	if strings.Contains(gotStr, "call_at_stream_deny") {
		t.Errorf("upstream tool_call id leaked into streaming refusal: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf /") {
		t.Errorf("upstream tool_call args leaked into streaming refusal: %q", gotStr)
	}

	// 2. Central recorder must show exactly one /v1/check, transport-tagged.
	if got := central.calls.Load(); got != 1 {
		t.Errorf("central /v1/check calls = %d, want 1 (one tool_call → one gate hit)", got)
	}
	reqs := central.Requests()
	if len(reqs) != 1 {
		t.Fatalf("central recorded %d requests, want 1", len(reqs))
	}
	ar := reqs[0]

	// 3. The dashboard tells transports apart by this tag.
	if got := ar.Meta["transport"]; got != "llm_api_proxy" {
		t.Errorf("transport meta tag = %q, want llm_api_proxy", got)
	}
	if got := ar.Meta["provider"]; got != "openai" {
		t.Errorf("provider meta tag = %q, want openai", got)
	}
	if got := ar.Meta["stream"]; got != "true" {
		t.Errorf("stream meta tag = %q, want \"true\" (streaming path indicator)", got)
	}
}

// TestAT_FullStack_NonStreamingDenyPath_TransportTaggedAudit is the
// non-streaming twin: same transport tag and rule-string contract.
func TestAT_FullStack_NonStreamingDenyPath_TransportTaggedAudit(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{
			ID:   "call_at_nonstream_deny",
			Type: "function",
			Function: ChatCompletionToolEcho{
				Name:      "bash",
				Arguments: `{"command":"rm -rf /"}`,
			},
		},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	central := newATCentralRecorder(t, func(ar policy.ActionRequest) policy.CheckResult {
		return policy.CheckResult{
			Decision: policy.Deny,
			Rule:     "deny:shell:rm_rf_at_nonstream",
			Reason:   "AT non-streaming integration: rm -rf blocked",
		}
	})

	base, teardown := newATFullStackProxy(t, upstream, central)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"clean root"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// Refusal must decode as a normal chat.completion JSON (not SSE).
	var refusal ChatCompletionResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("non-streaming refusal not valid ChatCompletionResponse: %v\nbody=%q", err, gotStr)
	}
	if !strings.Contains(gotStr, "deny:shell:rm_rf_at_nonstream") {
		t.Errorf("refusal missing central-server rule: %q", gotStr)
	}
	if strings.Contains(gotStr, "call_at_nonstream_deny") {
		t.Errorf("upstream tool_call id leaked into non-streaming refusal: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf /") {
		t.Errorf("upstream tool_call args leaked into non-streaming refusal: %q", gotStr)
	}

	if refusal.Model != "gpt-4" {
		t.Errorf("refusal model = %q, want gpt-4", refusal.Model)
	}

	if got := central.calls.Load(); got != 1 {
		t.Errorf("central /v1/check calls = %d, want 1", got)
	}
	reqs := central.Requests()
	if len(reqs) != 1 {
		t.Fatalf("central recorded %d requests, want 1", len(reqs))
	}
	ar := reqs[0]
	if got := ar.Meta["transport"]; got != "llm_api_proxy" {
		t.Errorf("transport meta tag = %q, want llm_api_proxy (non-streaming F9 path must agree with streaming)", got)
	}
	if got := ar.Meta["provider"]; got != "openai" {
		t.Errorf("provider meta tag = %q, want openai", got)
	}
	if got := ar.Meta["stream"]; got == "true" {
		t.Errorf("stream meta tag = %q on non-streaming path; must NOT be \"true\"", got)
	}

	// The non-streaming refusal is plain JSON, not SSE.
	if bytes.Contains(got, []byte("\ndata:")) {
		t.Errorf("non-streaming refusal contains SSE markers: %q", gotStr)
	}
}
