package llmproxy

// Parser-differential and gate-bypass cases in the streaming parsers.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

// An Anthropic stream that opens a second tool_use before closing the
// first is refused whole. Gating only the first would flush the second's
// start on ALLOW, and its remaining deltas would pass ungated after Reset.
func TestAudit_H1_AnthropicInterleavedToolUse_DoesNotBypassGate(t *testing.T) {
	// Interleaved: tool_use idx0 (read_file) opens and gets a delta, THEN
	// tool_use idx1 (bash) opens before idx0 closes.
	const interleaved = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1"}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_read","name":"read_file","input":{}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"/tmp/ok\"}"}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_bash","name":"bash","input":{}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf /\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, interleaved)
	}))
	defer upstream.Close()

	before := metrics.LLMProxyProtocolViolationFor("anthropic")

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			// bash is denied and must never reach the client.
			if tc.ToolName == "bash" {
				return Decision{Allow: false, Reason: "shell denied", Rule: "deny:shell"}, nil
			}
			return Decision{Allow: true, Rule: "allow:fs"}, nil
		}
	})
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// The denied bash tool_use must NOT have reached the client, in any form.
	if strings.Contains(gotStr, "toolu_bash") {
		t.Errorf("H1 BYPASS: denied bash tool_use id leaked to client: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf") {
		t.Errorf("H1 BYPASS: denied bash arguments leaked to client: %q", gotStr)
	}
	// The stream must have been refused (fail-closed).
	if !strings.Contains(gotStr, "Vanzik denied") {
		t.Errorf("expected a synthetic refusal in the response; got %q", gotStr)
	}
	if after := metrics.LLMProxyProtocolViolationFor("anthropic"); after != before+1 {
		t.Errorf("protocol_violation metric = %d, want %d", after, before+1)
	}
}

// A tool_use whose real arguments arrive in content_block_start.input,
// with no input_json_delta, is gated on those arguments, which the client
// executes, not on an empty {}.
func TestAudit_H2_AnthropicStartInputGated(t *testing.T) {
	// Real dangerous args live in the start block's `input`; NO delta follows.
	const startOnly = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1"}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_x","name":"bash","input":{"command":"rm -rf /"}}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, startOnly)
	}))
	defer upstream.Close()

	var sawArgs string
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			if cmd, ok := tc.Arguments["command"].(string); ok {
				sawArgs = cmd
			}
			// Deny anything that tries to run a destructive command.
			if cmd, _ := tc.Arguments["command"].(string); strings.Contains(cmd, "rm -rf") {
				return Decision{Allow: false, Reason: "destructive shell denied", Rule: "deny:shell"}, nil
			}
			return Decision{Allow: true, Rule: "allow:shell"}, nil
		}
	})
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	if sawArgs != "rm -rf /" {
		t.Errorf("H2: gate saw arguments %q, want %q — start.input was not gated", sawArgs, "rm -rf /")
	}
	if strings.Contains(gotStr, "toolu_x") {
		t.Errorf("H2 BYPASS: denied tool_use reached client: %q", gotStr)
	}
	if !strings.Contains(gotStr, "Vanzik denied") {
		t.Errorf("expected refusal; got %q", gotStr)
	}
}

// A conformant stream (start input {}, arguments via deltas) is gated on
// the deltas and replayed byte-identical on ALLOW.
func TestAudit_H2_ConformantStreamStillGatesViaDeltas(t *testing.T) {
	const conformant = "event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_c","name":"bash","input":{}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, conformant)
	}))
	defer upstream.Close()

	var sawArgs string
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			sawArgs, _ = tc.Arguments["command"].(string)
			return Decision{Allow: true, Rule: "allow:shell"}, nil
		}
	})
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if sawArgs != "ls" {
		t.Errorf("conformant stream: gate saw %q, want \"ls\"", sawArgs)
	}
}

// Arguments with duplicate JSON keys are refused before policy: the gate
// would evaluate the last value while a first-wins executor runs the
// first.
func TestAudit_H3_DuplicateKeyArguments_Refused(t *testing.T) {
	// arguments string has the key "path" twice.
	const dupKeyStream = `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_dup","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"/etc/shadow\",\"path\":\"/tmp/ok\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, dupKeyStream)
	}))
	defer upstream.Close()

	hookCalled := false
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			hookCalled = true // would ALLOW on the last-wins "/tmp/ok"
			return Decision{Allow: true, Rule: "allow:fs"}, nil
		}
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	if strings.Contains(gotStr, "call_dup") {
		t.Errorf("H3 BYPASS: duplicate-key tool_call reached client: %q", gotStr)
	}
	if !strings.Contains(gotStr, "Vanzik denied") {
		t.Errorf("expected duplicate-key refusal; got %q", gotStr)
	}
	if hookCalled {
		t.Errorf("policy hook was called for duplicate-key args; it must be rejected before policy")
	}
}

// The detector catches duplicates at any depth without false positives.
func TestAudit_H3_hasDuplicateJSONKeys(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"empty", "", false},
		{"flat unique", `{"a":1,"b":2}`, false},
		{"flat dup", `{"a":1,"a":2}`, true},
		{"nested dup", `{"outer":{"x":1,"x":2}}`, true},
		{"array of objs one dup", `[{"a":1},{"b":1,"b":2}]`, true},
		{"array unique", `[{"a":1},{"b":2}]`, false},
		{"dup deep in array", `{"k":[1,2,{"z":1,"z":3}]}`, true},
		{"malformed not flagged", `{"a":1,`, false},
		{"scalar", `"hello"`, false},
		{"same key different objects ok", `{"a":{"x":1},"b":{"x":2}}`, false},
	}
	for _, tc := range cases {
		if got := hasDuplicateJSONKeys([]byte(tc.raw)); got != tc.want {
			t.Errorf("%s: hasDuplicateJSONKeys(%q) = %v, want %v", tc.name, tc.raw, got, tc.want)
		}
	}
}

// The OpenAI accumulator keeps the first function name for an index, as
// first-wins clients do.
func TestAudit_M1_OpenAIToolNameFirstWins(t *testing.T) {
	acc := NewOpenAIToolCallAccumulator(0)

	// Fragment 1: name "read_file".
	ev1 := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{}"}}]},"finish_reason":null}]}` + "\n\n")
	// Fragment 2: a SECOND, different name "bash" for the same index.
	ev2 := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"bash"}}]},"finish_reason":null}]}` + "\n\n")
	ev3 := []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n")

	if _, err := acc.FeedEvent(ev1); err != nil {
		t.Fatalf("ev1: %v", err)
	}
	if _, err := acc.FeedEvent(ev2); err != nil {
		t.Fatalf("ev2: %v", err)
	}
	res, err := acc.FeedEvent(ev3)
	if err != nil {
		t.Fatalf("ev3: %v", err)
	}
	if !res.Completed || len(res.CompletedToolCalls) != 1 {
		t.Fatalf("expected 1 completed tool call, got %+v", res)
	}
	if name := res.CompletedToolCalls[0].ToolName; name != "read_file" {
		t.Errorf("tool name = %q, want \"read_file\" (first-wins)", name)
	}
}
