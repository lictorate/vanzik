package llmproxy

// SDK-level parseability of DENY-path refusals (refusal_test.go pins
// the surface shape): every `data:` payload decodes into the envelope an
// SDK expects, in the expected order. The SDKs' parsing is replicated
// minimally in Go, so this checks the wire format, not SDK type drift.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// openAIChunkEnvelope is the minimum a streaming SDK reads per chunk.
type openAIChunkEnvelope struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

// anthropicEventForSDK is the union envelope the Anthropic SDK
// dispatches on (`event.type` discriminator).
type anthropicEventForSDK struct {
	Type         string                 `json:"type"`
	Index        int                    `json:"index"`
	ContentBlock map[string]interface{} `json:"content_block,omitempty"`
	Delta        map[string]interface{} `json:"delta,omitempty"`
	Message      map[string]interface{} `json:"message,omitempty"`
}

// TestAT_RefusalCorrectness_OpenAI_SDKParseable drives a DENY through a
// Server wired like main.go and decodes every `data:` payload as a chunk.
func TestAT_RefusalCorrectness_OpenAI_SDKParseable(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_single_tool_call.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{
				Allow:  false,
				Reason: "shell rule blocks rm",
				Rule:   "deny:shell:rm_rf",
			}, nil
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

	dataPayloads, sawDone := splitSSEDataLines(got)
	if !sawDone {
		t.Errorf("expected [DONE] terminator in OpenAI refusal stream")
	}
	if len(dataPayloads) == 0 {
		t.Fatalf("no data: lines in refusal: %q", string(got))
	}

	// The role delta passes through, then the refusal, which must
	// carry the rule and finish_reason "stop".
	sawRefusalChunk := false
	for i, payload := range dataPayloads {
		var env openAIChunkEnvelope
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			t.Errorf("data[%d] not valid OpenAI chunk JSON: %v\npayload=%q", i, err, payload)
			continue
		}
		if env.Object != "chat.completion.chunk" {
			t.Errorf("data[%d].object = %q, want chat.completion.chunk", i, env.Object)
		}
		if len(env.Choices) == 0 {
			t.Errorf("data[%d]: no choices", i)
			continue
		}
		ch := env.Choices[0]
		if ch.Delta.Role != "" && ch.Delta.Role != "assistant" {
			t.Errorf("data[%d]: role = %q, want empty or assistant (role: tool causes SDK hangs)", i, ch.Delta.Role)
		}
		hasRule := strings.Contains(ch.Delta.Content, "deny:shell:rm_rf")
		hasFinishStop := ch.FinishReason != nil && *ch.FinishReason == "stop"
		if hasRule && hasFinishStop {
			sawRefusalChunk = true
		}
	}
	if !sawRefusalChunk {
		t.Errorf("no data: chunk carried both the rule and finish_reason: stop; SDKs would not surface the refusal cleanly\nbody=%s", string(got))
	}
}

// TestAT_RefusalCorrectness_OpenAI_Approval: the approval refusal carries
// both the approval URL and the retry hint.
func TestAT_RefusalCorrectness_OpenAI_Approval(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_single_tool_call.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{
				Allow:            false,
				RequiresApproval: true,
				Reason:           "needs review",
				Rule:             "require_approval:shell:rm",
				ApprovalID:       "ap_test_round_trip",
				ApprovalURL:      "http://localhost:8080/dashboard?approve=ap_test_round_trip",
			}, nil
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

	for _, want := range []string{
		"ap_test_round_trip",
		"http://localhost:8080/dashboard",
		"X-Vanzik-Approval-ID header", // round-trip hint
		"require_approval:shell:rm",
		"paused this action pending human approval",
	} {
		if !strings.Contains(gotStr, want) {
			t.Errorf("approval refusal missing %q in payload:\n%s", want, gotStr)
		}
	}

	dataPayloads, _ := splitSSEDataLines(got)
	for i, p := range dataPayloads {
		var env openAIChunkEnvelope
		if err := json.Unmarshal([]byte(p), &env); err != nil {
			t.Errorf("approval data[%d] invalid JSON: %v", i, err)
		}
	}
}

// TestAT_RefusalCorrectness_Anthropic_SDKParseable: the refusal is the
// five documented events in order.
func TestAT_RefusalCorrectness_Anthropic_SDKParseable(t *testing.T) {
	fixture := readFixture(t, "anthropic_streaming_single_tool_use.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{
				Allow:  false,
				Reason: "shell denied",
				Rule:   "deny:shell:rm",
			}, nil
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
	dataPayloads, _ := splitSSEDataLines(got)

	wantSequence := []string{
		"content_block_start",
		"content_block_delta",
		"content_block_stop",
		"message_delta",
		"message_stop",
	}
	if len(dataPayloads) < len(wantSequence) {
		t.Fatalf("Anthropic refusal too short: got %d data: lines, want >= %d\nbody=%s",
			len(dataPayloads), len(wantSequence), string(got))
	}
	// The tool_use's own events were discarded; the tail is the refusal.
	tail := dataPayloads[len(dataPayloads)-len(wantSequence):]

	stopReasonSeen := false
	for i, payload := range tail {
		var env anthropicEventForSDK
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			t.Errorf("Anthropic refusal data[%d] not valid JSON: %v\npayload=%q", i, err, payload)
			continue
		}
		if env.Type != wantSequence[i] {
			t.Errorf("event[%d] type=%q, want %q", i, env.Type, wantSequence[i])
		}
		if env.Type == "message_delta" {
			if d := env.Delta; d != nil {
				if v, _ := d["stop_reason"].(string); v == "end_turn" {
					stopReasonSeen = true
				}
			}
		}
	}
	if !stopReasonSeen {
		t.Errorf("Anthropic refusal missing stop_reason: end_turn rewrite (would leave SDK expecting tool result)")
	}
}

// TestAT_RefusalCorrectness_Anthropic_PreservesToolUseIndex: the refusal
// reuses the tool_use's block index; index 0 would corrupt text blocks
// the client already received.
func TestAT_RefusalCorrectness_Anthropic_PreservesToolUseIndex(t *testing.T) {
	// Text blocks at 0-2, then a tool_use at 3.
	fixture := []byte(`event: message_start
data: {"type":"message_start","message":{"id":"msg_ix","type":"message"}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":3,"content_block":{"type":"tool_use","id":"toolu_test","name":"bash","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"x\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":3}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}

event: message_stop
data: {"type":"message_stop"}

`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{Allow: false, Reason: "denied", Rule: "deny:test"}, nil
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
	dataPayloads, _ := splitSSEDataLines(got)

	// The refusal's content_block_start must be at index 3.
	refusalStartIdx := -1
	seenTextBlockStart := false // index 0 from upstream
	for _, p := range dataPayloads {
		var env anthropicEventForSDK
		if err := json.Unmarshal([]byte(p), &env); err != nil {
			continue
		}
		if env.Type == "content_block_start" {
			if !seenTextBlockStart && env.Index == 0 {
				seenTextBlockStart = true
				continue
			}
			// Subsequent content_block_start is the refusal's start.
			refusalStartIdx = env.Index
			break
		}
	}
	if refusalStartIdx == -1 {
		t.Fatalf("could not find synthetic content_block_start in Anthropic DENY output: %s", string(got))
	}
	if refusalStartIdx != 3 {
		t.Errorf("synthetic content_block_start index = %d, want 3 (original tool_use index)", refusalStartIdx)
	}
}

// splitSSEDataLines returns each `data:` payload and whether `[DONE]`
// was seen.
func splitSSEDataLines(b []byte) (payloads []string, sawDone bool) {
	for _, line := range strings.Split(string(b), "\n") {
		l := line
		l = strings.TrimSuffix(l, "\r")
		var payload string
		switch {
		case strings.HasPrefix(l, "data: "):
			payload = strings.TrimPrefix(l, "data: ")
		case strings.HasPrefix(l, "data:"):
			payload = strings.TrimPrefix(l, "data:")
		default:
			continue
		}
		if strings.TrimSpace(payload) == "[DONE]" {
			sawDone = true
			continue
		}
		payloads = append(payloads, payload)
	}
	return payloads, sawDone
}
