package llmproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestApprovalIDHeaderReachesCheck pins the LLM proxy's approval
// round-trip: an X-Vanzik-Approval-ID request header lands in
// ToolCallCheck.ApprovalID (which gate.go sends to /v1/check as
// approval_id) on all four gated paths, and never reaches the upstream.
func TestApprovalIDHeaderReachesCheck(t *testing.T) {
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
			var upstreamSaw string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamSaw = r.Header.Get(ApprovalIDHeader)
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

			var mu sync.Mutex
			var seen []string
			_, base, teardown := newGatedTestServer(t, upstream, upstream, func(_ context.Context, tc *ToolCallCheck) (Decision, error) {
				mu.Lock()
				seen = append(seen, tc.ApprovalID)
				mu.Unlock()
				return Decision{Allow: true}, nil
			})
			defer teardown()

			req, _ := http.NewRequest("POST", base+c.path, strings.NewReader(c.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(ApprovalIDHeader, " ap_round_trip ")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			_, _ = io.ReadAll(resp.Body)
			resp.Body.Close()

			mu.Lock()
			defer mu.Unlock()
			if len(seen) == 0 {
				t.Fatalf("PolicyCheck never ran; the fixture must carry a tool call")
			}
			for _, id := range seen {
				if id != "ap_round_trip" {
					t.Errorf("ToolCallCheck.ApprovalID = %q, want %q", id, "ap_round_trip")
				}
			}
			if upstreamSaw != "" {
				t.Errorf("%s leaked upstream: %q", ApprovalIDHeader, upstreamSaw)
			}
		})
	}
}

// TestApprovalIDHeaderAbsentLeavesCheckEmpty: without the header the
// check carries no approval id, so /v1/check evaluates fresh as before.
func TestApprovalIDHeaderAbsentLeavesCheckEmpty(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(readFixture(t, "openai_streaming_single_tool_call.txt"))
	}))
	defer upstream.Close()

	got := "unset"
	_, base, teardown := newGatedTestServer(t, upstream, upstream, func(_ context.Context, tc *ToolCallCheck) (Decision, error) {
		got = tc.ApprovalID
		return Decision{Allow: true}, nil
	})
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[],"stream":true}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if got != "" {
		t.Errorf("ToolCallCheck.ApprovalID = %q without the header, want empty", got)
	}
}
