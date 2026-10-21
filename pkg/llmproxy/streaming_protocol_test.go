package llmproxy

// A stream the firewall cannot gate must end in a refusal, never in
// ungated bytes and never in silence. Covered here, by test-name prefix:
//
//	TestB7_   Anthropic input_json_delta with no tool_use block open.
//	TestB17_  A cycle still open at EOF or `[DONE]` is gated or refused, not
//	          dropped (and not flushed, which would be the bypass).
//	TestB18_  OpenAI tool_calls on more than one choice; a sibling choice's
//	          finish_reason must not close the cycle.
//	TestB21_  A whitespace-only `{ }` start input is empty, not a seed.
//
// Each case has a parser-level test, an end-to-end test of what the
// client receives, and a counterweight proving valid traffic still flows.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------
// event builders. Named with a pv* prefix so they never collide with the
// fixture helpers other test files define.
// ---------------------------------------------------------------------

// pvOpenAIToolDelta emits one OpenAI tool_call delta on a given choice
// index and tool_calls index.
func pvOpenAIToolDelta(choice, toolIdx int, id, name, args string) string {
	idPart := ""
	if id != "" {
		idPart = fmt.Sprintf(`"id":%q,"type":"function",`, id)
	}
	namePart := ""
	if name != "" {
		namePart = fmt.Sprintf(`"name":%q,`, name)
	}
	return fmt.Sprintf(
		`data: {"choices":[{"index":%d,"delta":{"tool_calls":[{"index":%d,%s"function":{%s"arguments":%q}}]},"finish_reason":null}]}`+"\n\n",
		choice, toolIdx, idPart, namePart, args,
	)
}

// pvOpenAIFinish emits a finish_reason on a given choice index.
func pvOpenAIFinish(choice int, reason string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":%d,"delta":{},"finish_reason":%q}]}`+"\n\n",
		choice, reason,
	)
}

// pvOpenAIContent emits a plain content delta on a given choice index.
func pvOpenAIContent(choice int, text string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":%d,"delta":{"content":%q},"finish_reason":null}]}`+"\n\n",
		choice, text,
	)
}

func pvAnthropicToolStart(index int, id, name, input string) string {
	return "event: content_block_start\n" + fmt.Sprintf(
		`data: {"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":%q,"name":%q,"input":%s}}`+"\n\n",
		index, id, name, input,
	)
}

func pvAnthropicTextStart(index int) string {
	return "event: content_block_start\n" + fmt.Sprintf(
		`data: {"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`+"\n\n",
		index,
	)
}

func pvAnthropicInputDelta(index int, partial string) string {
	return "event: content_block_delta\n" + fmt.Sprintf(
		`data: {"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%q}}`+"\n\n",
		index, partial,
	)
}

func pvAnthropicTextDelta(index int, text string) string {
	return "event: content_block_delta\n" + fmt.Sprintf(
		`data: {"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%q}}`+"\n\n",
		index, text,
	)
}

func pvAnthropicStop(index int) string {
	return "event: content_block_stop\n" + fmt.Sprintf(
		`data: {"type":"content_block_stop","index":%d}`+"\n\n", index,
	)
}

// pvCallSpy is a PolicyCheck stub that records the full tool calls it
// gated: the id proves an audit entry was driven, the raw arguments show
// what the gate evaluated.
type pvCallSpy struct {
	mu       sync.Mutex
	calls    []ToolCallCheck
	decision Decision
	err      error
}

func (g *pvCallSpy) check(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
	g.mu.Lock()
	g.calls = append(g.calls, *tc)
	g.mu.Unlock()
	return g.decision, g.err
}

func (g *pvCallSpy) seen() []ToolCallCheck {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ToolCallCheck, len(g.calls))
	copy(out, g.calls)
	return out
}

// pvRunStream drives one streaming request through the real proxy loop
// against an upstream that writes `body` and closes, so EOF is reached
// deterministically.
func pvRunStream(t *testing.T, provider, body string, spy *pvCallSpy) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, body)
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		// Rich refusals render the Rule string, which is the stable
		// operator-facing contract each of these tests asserts on.
		s.BuildRefusal = BuildRefusalRich
		if spy != nil {
			s.PolicyCheck = spy.check
		}
	})
	defer teardown()

	path := "/v1/chat/completions"
	reqBody := `{"model":"gpt-4","messages":[],"stream":true}`
	if provider == "anthropic" {
		path = "/v1/messages"
		reqBody = `{"model":"claude-3-5-sonnet","messages":[],"stream":true}`
	}
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(reqBody))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

// ---------------------------------------------------------------------
// Orphaned input_json_delta
// ---------------------------------------------------------------------

// TestB7_AnthropicIdleInputJSONDelta_FailsClosed pins that tool-input
// fragments arriving with no tool_use block open are refused, not
// forwarded: a client that rebuilds tool input from deltas would execute
// arguments no gate cycle could ever see.
func TestB7_AnthropicIdleInputJSONDelta_FailsClosed(t *testing.T) {
	acc := NewAnthropicAccumulator(0)

	// An idle text block first — this must still pass through.
	if res, err := acc.FeedEvent([]byte(pvAnthropicTextStart(0))); err != nil || !res.PassThrough {
		t.Fatalf("text start: res=%+v err=%v, want PassThrough", res, err)
	}

	res, err := acc.FeedEvent([]byte(pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`)))
	if err != nil {
		t.Fatalf("orphaned input_json_delta: %v", err)
	}
	if !res.ProtocolViolation {
		t.Fatalf("orphaned input_json_delta returned %+v, want ProtocolViolation (B7 regression: tool input forwarded ungated)", res)
	}
	if res.PassThrough {
		t.Errorf("orphaned input_json_delta must not also be PassThrough: %+v", res)
	}
	if res.violation != violationOrphanedToolInput {
		t.Errorf("violation kind = %d, want violationOrphanedToolInput (%d) — the refusal would name the wrong defect",
			res.violation, violationOrphanedToolInput)
	}
}

// TestB7_AnthropicIdleNonToolDeltas_StillPassThrough: only
// input_json_delta is refused when idle; text deltas must pass.
func TestB7_AnthropicIdleNonToolDeltas_StillPassThrough(t *testing.T) {
	cases := []struct {
		name  string
		event string
	}{
		{"text_delta", pvAnthropicTextDelta(0, "hello")},
		{"unknown_delta_type", "event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}` + "\n\n"},
		{"no_delta_field", "event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0}` + "\n\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			acc := NewAnthropicAccumulator(0)
			res, err := acc.FeedEvent([]byte(c.event))
			if err != nil {
				t.Fatalf("feed: %v", err)
			}
			if res.ProtocolViolation {
				t.Fatalf("idle %s was refused as a protocol violation — B7 over-refused: %+v", c.name, res)
			}
			if !res.PassThrough {
				t.Errorf("idle %s: res=%+v, want PassThrough", c.name, res)
			}
		})
	}
}

// TestB7_AnthropicOrphanedToolInput_RefusesEndToEnd proves the client
// receives a refusal naming the defect, and — the security property —
// that the orphaned arguments never appear in the response body.
func TestB7_AnthropicOrphanedToolInput_RefusesEndToEnd(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_b7","type":"message"}}` + "\n\n" +
		pvAnthropicTextStart(0) +
		pvAnthropicTextDelta(0, "sure, running that") +
		// No content_block_start for a tool_use — the gate never saw a
		// block open, yet tool input streams anyway.
		pvAnthropicInputDelta(1, `{"command":"rm -rf /"}`) +
		pvAnthropicStop(1)

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "anthropic", stream, spy)

	if strings.Contains(got, "rm -rf /") {
		t.Errorf("orphaned tool input reached the client (B7 bypass): %q", got)
	}
	if !strings.Contains(got, "deny:llm_api_proxy:orphaned_tool_input") {
		t.Errorf("expected the orphaned_tool_input refusal rule; got %q", got)
	}
	// The leading text block was legitimate and already flushed.
	if !strings.Contains(got, "sure, running that") {
		t.Errorf("pre-violation text was dropped; got %q", got)
	}
	// The refusal is unconditional but still audited: with no
	// RecordForcedAudit hook, auditStreamRefusal calls PolicyCheck once
	// and ignores its ALLOW.
	if n := len(spy.seen()); n != 1 {
		t.Errorf("PolicyCheck ran %d times for an orphaned delta; want 1 (the audit fallback), and the refusal must stand regardless of its verdict", n)
	}
}

// ---------------------------------------------------------------------
// Whitespace-only empty seed
// ---------------------------------------------------------------------

// TestB21_EmptyObjectSeedVariants_DoNotBlockStreamedArgs drives the
// conformant Anthropic shape (empty start input, arguments via
// input_json_delta) with every spelling of an empty object; none may trip
// the seeded-input conflict refusal.
func TestB21_EmptyObjectSeedVariants_DoNotBlockStreamedArgs(t *testing.T) {
	// Space and tab only: a raw newline cannot appear inside a
	// single-line SSE `data:` field, so it is not a shape this branch
	// can receive on the wire. The newline spellings are covered
	// directly in TestB21_IsEmptyJSONObject.
	seeds := []string{`{}`, `{ }`, "{\t}", "{ \t  }"}
	for _, seed := range seeds {
		t.Run(fmt.Sprintf("seed=%q", seed), func(t *testing.T) {
			acc := NewAnthropicAccumulator(0)
			if res, err := acc.FeedEvent([]byte(pvAnthropicToolStart(0, "toolu_b21", "bash", seed))); err != nil || !res.Accumulating {
				t.Fatalf("tool start: res=%+v err=%v", res, err)
			}
			res, err := acc.FeedEvent([]byte(pvAnthropicInputDelta(0, `{"cmd":"ls"}`)))
			if err != nil {
				t.Fatalf("input delta: %v", err)
			}
			if res.ProtocolViolation {
				t.Fatalf("a conformant stream seeded with %q was refused (B21 regression)", seed)
			}
			res, err = acc.FeedEvent([]byte(pvAnthropicStop(0)))
			if err != nil {
				t.Fatalf("stop: %v", err)
			}
			if !res.Completed || len(res.CompletedToolCalls) != 1 {
				t.Fatalf("stop: res=%+v, want one completed call", res)
			}
			// The gate must see the STREAMED arguments, not an empty
			// object and not a concatenation of both.
			if got := strings.TrimSpace(string(res.CompletedToolCalls[0].RawArguments)); got != `{"cmd":"ls"}` {
				t.Errorf("gated arguments = %q, want %q", got, `{"cmd":"ls"}`)
			}
		})
	}
}

// TestB21_NonEmptySeedStillConflictsWithDeltas: real start arguments
// plus streamed deltas stay refused, including when the arguments are
// padded with whitespace.
func TestB21_NonEmptySeedStillConflictsWithDeltas(t *testing.T) {
	for _, seed := range []string{`{"cmd":"x"}`, `{ "cmd":"x" }`} {
		t.Run(seed, func(t *testing.T) {
			acc := NewAnthropicAccumulator(0)
			if _, err := acc.FeedEvent([]byte(pvAnthropicToolStart(0, "toolu_h2", "bash", seed))); err != nil {
				t.Fatalf("tool start: %v", err)
			}
			res, err := acc.FeedEvent([]byte(pvAnthropicInputDelta(0, `{"cmd":"ls"}`)))
			if err != nil {
				t.Fatalf("input delta: %v", err)
			}
			if !res.ProtocolViolation {
				t.Fatalf("seeded arguments + streamed deltas must fail closed (H2); got %+v", res)
			}
			if res.violation != violationInterleavedToolUse {
				t.Errorf("violation kind = %d, want violationInterleavedToolUse (%d)", res.violation, violationInterleavedToolUse)
			}
		})
	}
}

// TestB21_IsEmptyJSONObject pins the predicate, including shapes that
// must not count as empty: a false positive would discard real
// start-block arguments and let them pass ungated.
func TestB21_IsEmptyJSONObject(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`{}`, true},
		{`{ }`, true},
		{"{\n}", true},
		{"{\t}", true},
		{"{\r\n  \t}", true},
		{`{"a":1}`, false},
		{`{ "a":1 }`, false},
		{`{""}`, false},
		{`null`, false},
		{`[]`, false},
		{`{`, false},
		{`}`, false},
		{``, false},
		{`{}}`, false},
		{`{{}}`, false},
	}
	for _, c := range cases {
		if got := isEmptyJSONObject([]byte(c.in)); got != c.want {
			t.Errorf("isEmptyJSONObject(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestB21_WhitespaceSeedStreamGatesEndToEnd drives the `{ }` shape
// through the real loop: the gate must see the streamed arguments and,
// on ALLOW, the client must receive the upstream bytes rather than a
// spurious refusal.
func TestB21_WhitespaceSeedStreamGatesEndToEnd(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_b21","type":"message"}}` + "\n\n" +
		pvAnthropicToolStart(0, "toolu_ws", "bash", `{ }`) +
		pvAnthropicInputDelta(0, `{"cmd":"ls -la"}`) +
		pvAnthropicStop(0) +
		"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "anthropic", stream, spy)

	if strings.Contains(got, "Vanzik denied") {
		t.Fatalf("a conformant `{ }`-seeded stream was refused (B21 regression): %q", got)
	}
	calls := spy.seen()
	if len(calls) != 1 {
		t.Fatalf("PolicyCheck ran %d times, want 1", len(calls))
	}
	if args := strings.TrimSpace(string(calls[0].RawArguments)); args != `{"cmd":"ls -la"}` {
		t.Errorf("gate evaluated %q, want %q", args, `{"cmd":"ls -la"}`)
	}
	if !strings.Contains(got, "toolu_ws") {
		t.Errorf("ALLOWed tool_use block did not reach the client: %q", got)
	}
}

// ---------------------------------------------------------------------
// Tool calls across multiple choices
// ---------------------------------------------------------------------

// TestB18_ToolCallsOnSecondChoice_FailClosed: with n>1 both choices
// number their calls from 0, so merging by index would gate a splice no
// client executes while the real calls pass unexamined.
func TestB18_ToolCallsOnSecondChoice_FailClosed(t *testing.T) {
	t.Run("separate-events", func(t *testing.T) {
		acc := NewOpenAIToolCallAccumulator(0)
		if res, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(0, 0, "call_a", "bash", `{"cmd":"ls"}`))); err != nil || !res.Accumulating {
			t.Fatalf("choice 0 delta: res=%+v err=%v", res, err)
		}
		res, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(1, 0, "call_b", "bash", `{"cmd":"rm -rf /"}`)))
		if err != nil {
			t.Fatalf("choice 1 delta: %v", err)
		}
		if !res.ProtocolViolation {
			t.Fatalf("tool_calls on a second choice returned %+v, want ProtocolViolation (B18: the two calls would merge)", res)
		}
		if res.violation != violationMultiChoiceToolCalls {
			t.Errorf("violation kind = %d, want violationMultiChoiceToolCalls (%d)", res.violation, violationMultiChoiceToolCalls)
		}
	})

	t.Run("same-event", func(t *testing.T) {
		acc := NewOpenAIToolCallAccumulator(0)
		ev := `data: {"choices":[` +
			`{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"ls\"}"}}]},"finish_reason":null},` +
			`{"index":1,"delta":{"tool_calls":[{"index":0,"id":"call_b","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"rm -rf /\"}"}}]},"finish_reason":null}` +
			`]}` + "\n\n"
		res, err := acc.FeedEvent([]byte(ev))
		if err != nil {
			t.Fatalf("two-choice event: %v", err)
		}
		if !res.ProtocolViolation {
			t.Fatalf("two choices with tool_calls in ONE event returned %+v, want ProtocolViolation", res)
		}
	})
}

// TestB18_SingleChoiceStreamUnaffected: n=1, what every mainstream agent
// framework sends, must be unaffected by the multi-choice guard.
func TestB18_SingleChoiceStreamUnaffected(t *testing.T) {
	acc := NewOpenAIToolCallAccumulator(0)
	events := []string{
		pvOpenAIContent(0, "thinking"),
		pvOpenAIToolDelta(0, 0, "call_1", "bash", `{"cmd":`),
		pvOpenAIToolDelta(0, 0, "", "", `"ls"}`),
		// A second tool call on the SAME choice — legal, and must not
		// be confused with a second CHOICE.
		pvOpenAIToolDelta(0, 1, "call_2", "cat", `{"path":"/etc/hosts"}`),
		pvOpenAIFinish(0, "tool_calls"),
	}
	var last FeedResult
	for i, ev := range events {
		res, err := acc.FeedEvent([]byte(ev))
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if res.ProtocolViolation {
			t.Fatalf("event %d on a single-choice stream was refused (B18 over-refused): %s", i, ev)
		}
		last = res
	}
	if !last.Completed || len(last.CompletedToolCalls) != 2 {
		t.Fatalf("final res=%+v, want Completed with 2 calls", last)
	}
	if got := strings.TrimSpace(string(last.CompletedToolCalls[0].RawArguments)); got != `{"cmd":"ls"}` {
		t.Errorf("call 0 arguments = %q, want %q", got, `{"cmd":"ls"}`)
	}
	if got := strings.TrimSpace(string(last.CompletedToolCalls[1].RawArguments)); got != `{"path":"/etc/hosts"}` {
		t.Errorf("call 1 arguments = %q, want %q", got, `{"path":"/etc/hosts"}`)
	}
}

// TestB18_SiblingChoiceFinishDoesNotCloseCycle: a sibling choice
// finishing first must not close the tool-call cycle, or the gate sees
// truncated arguments and refuses a healthy stream as malformed.
func TestB18_SiblingChoiceFinishDoesNotCloseCycle(t *testing.T) {
	acc := NewOpenAIToolCallAccumulator(0)

	if res, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(0, 0, "call_1", "bash", `{"cmd":"l`))); err != nil || !res.Accumulating {
		t.Fatalf("partial args: res=%+v err=%v", res, err)
	}
	// Sibling choice 1 finishes while choice 0 is mid-arguments.
	res, err := acc.FeedEvent([]byte(pvOpenAIFinish(1, "stop")))
	if err != nil {
		t.Fatalf("sibling finish: %v", err)
	}
	if res.Completed {
		t.Fatalf("a sibling choice's finish_reason closed the cycle early (B18): res=%+v", res)
	}
	if !res.Accumulating {
		t.Errorf("sibling finish: res=%+v, want Accumulating", res)
	}
	// The owning choice streams the rest and closes.
	if _, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(0, 0, "", "", `s"}`))); err != nil {
		t.Fatalf("rest of args: %v", err)
	}
	res, err = acc.FeedEvent([]byte(pvOpenAIFinish(0, "tool_calls")))
	if err != nil {
		t.Fatalf("owning finish: %v", err)
	}
	if !res.Completed || len(res.CompletedToolCalls) != 1 {
		t.Fatalf("owning finish: res=%+v, want Completed with 1 call", res)
	}
	if got := strings.TrimSpace(string(res.CompletedToolCalls[0].RawArguments)); got != `{"cmd":"ls"}` {
		t.Errorf("gated arguments = %q, want the COMPLETE %q", got, `{"cmd":"ls"}`)
	}
}

// TestB18_MultiChoiceToolCalls_RefusesEndToEnd proves neither call's
// bytes reach the client and the refusal names the defect.
func TestB18_MultiChoiceToolCalls_RefusesEndToEnd(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_first", "bash", `{"cmd":"ls"}`) +
		pvOpenAIToolDelta(1, 0, "call_second", "bash", `{"cmd":"rm -rf /"}`) +
		pvOpenAIFinish(0, "tool_calls") +
		"data: [DONE]\n\n"

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "openai", stream, spy)

	if strings.Contains(got, "call_first") || strings.Contains(got, "call_second") {
		t.Errorf("a tool_call leaked from an ungateable multi-choice stream: %q", got)
	}
	if strings.Contains(got, "rm -rf /") {
		t.Errorf("tool arguments leaked from an ungateable multi-choice stream: %q", got)
	}
	if !strings.Contains(got, "deny:llm_api_proxy:multi_choice_tool_calls") {
		t.Errorf("expected the multi_choice_tool_calls refusal rule; got %q", got)
	}
}

// ---------------------------------------------------------------------
// End of stream while a cycle is open
// ---------------------------------------------------------------------

// TestB17_OpenAI_EOFMidToolCall_GatesInsteadOfDropping: a stream ending
// with no finish_reason and no [DONE] (dropped connection) still gates
// the buffered call and delivers it on ALLOW.
func TestB17_OpenAI_EOFMidToolCall_GatesInsteadOfDropping(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_eof", "bash", `{"cmd":"ls"}`)

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "openai", stream, spy)

	calls := spy.seen()
	if len(calls) != 1 {
		t.Fatalf("PolicyCheck ran %d times, want 1 — the cycle was dropped at EOF without gating (B17)", len(calls))
	}
	if args := strings.TrimSpace(string(calls[0].RawArguments)); args != `{"cmd":"ls"}` {
		t.Errorf("gate evaluated %q, want %q", args, `{"cmd":"ls"}`)
	}
	if !strings.Contains(got, "call_eof") {
		t.Errorf("ALLOWed tool_call was not delivered after the EOF close: %q", got)
	}
}

// TestB17_OpenAI_EOFMidToolCall_DenyDoesNotLeak: the EOF closer goes
// through the gate, so a DENY still refuses rather than flushing the
// buffer ungated.
func TestB17_OpenAI_EOFMidToolCall_DenyDoesNotLeak(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_eof_deny", "bash", `{"cmd":"rm -rf /"}`)

	spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "blocked by policy", Rule: "deny:test:rule"}}
	got := pvRunStream(t, "openai", stream, spy)

	if strings.Contains(got, "call_eof_deny") || strings.Contains(got, "rm -rf /") {
		t.Fatalf("a DENIED tool_call leaked to the client at EOF (B17 fail-open): %q", got)
	}
	if !strings.Contains(got, "deny:test:rule") {
		t.Errorf("expected the policy refusal to reach the client; got %q", got)
	}
	if len(spy.seen()) != 1 {
		t.Errorf("PolicyCheck ran %d times, want 1", len(spy.seen()))
	}
}

// TestB17_OpenAI_EOFTruncatedArgs_FailsClosed: a max_tokens cutoff
// mid-arguments lands on the malformed refusal, denied and audited.
func TestB17_OpenAI_EOFTruncatedArgs_FailsClosed(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_trunc", "bash", `{"cmd":"rm -rf `)

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "openai", stream, spy)

	if !strings.Contains(got, "malformed tool call arguments") {
		t.Errorf("expected the malformed fail-closed refusal; got %q", got)
	}
	if strings.Contains(got, "call_trunc") {
		t.Errorf("truncated tool_call leaked to the client: %q", got)
	}
	// The audit path still runs even though the verdict is forced.
	if len(spy.seen()) != 1 {
		t.Errorf("PolicyCheck ran %d times, want 1 (the audit trail for the forced deny)", len(spy.seen()))
	}
}

// TestB17_OpenAI_DoneWhileActive_ClosesTheCycle: `[DONE]` with a
// tool_call open closes the cycle through the gate, in both directions.
func TestB17_OpenAI_DoneWhileActive_ClosesTheCycle(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_done", "bash", `{"cmd":"ls"}`) + "data: [DONE]\n\n"

	t.Run("allow-flushes", func(t *testing.T) {
		spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
		got := pvRunStream(t, "openai", stream, spy)
		if len(spy.seen()) != 1 {
			t.Fatalf("PolicyCheck ran %d times, want 1", len(spy.seen()))
		}
		if !strings.Contains(got, "call_done") {
			t.Errorf("ALLOWed tool_call was not delivered: %q", got)
		}
		if !strings.Contains(got, "[DONE]") {
			t.Errorf("terminator missing from the flushed stream: %q", got)
		}
	})

	t.Run("deny-does-not-leak", func(t *testing.T) {
		spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "no", Rule: "deny:test:rule"}}
		got := pvRunStream(t, "openai", stream, spy)
		if strings.Contains(got, "call_done") {
			t.Fatalf("a DENIED tool_call leaked via the [DONE] path: %q", got)
		}
		if !strings.Contains(got, "deny:test:rule") {
			t.Errorf("expected the policy refusal; got %q", got)
		}
	})
}

// TestB17_OpenAI_DoneWithoutEOF_DoesNotWaitForTheConnectionToClose
// isolates the `[DONE]` closer from the EOF closer: the upstream holds the
// connection open after `[DONE]` (as some gateways do), and the client
// must not wait for it.
func TestB17_OpenAI_DoneWithoutEOF_DoesNotWaitForTheConnectionToClose(t *testing.T) {
	released := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, pvOpenAIToolDelta(0, 0, "call_keepalive", "bash", `{"cmd":"rm -rf /"}`))
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
		// Hold the connection open. The proxy must NOT need this to end.
		select {
		case <-released:
		case <-r.Context().Done():
		case <-time.After(15 * time.Second):
		}
	}))
	defer upstream.Close()
	defer close(released)

	spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "no", Rule: "deny:test:rule"}}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.PolicyCheck = spy.check
	})
	defer teardown()

	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest("POST", base+"/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4","messages":[],"stream":true}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		done <- result{body: string(raw)}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("request: %v", got.err)
		}
		if strings.Contains(got.body, "call_keepalive") || strings.Contains(got.body, "rm -rf /") {
			t.Fatalf("a DENIED tool_call leaked via the [DONE] path: %q", got.body)
		}
		if !strings.Contains(got.body, "deny:test:rule") {
			t.Errorf("expected the policy refusal; got %q", got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client was still waiting 5s after [DONE]: the cycle is not closed until the connection drops (B17)")
	}
}

// TestB17_Anthropic_EOFMidToolUse_GatesInsteadOfDropping: a tool_use
// block still open when upstream vanishes is gated.
func TestB17_Anthropic_EOFMidToolUse_GatesInsteadOfDropping(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_b17","type":"message"}}` + "\n\n" +
		pvAnthropicToolStart(0, "toolu_eof", "bash", `{}`) +
		pvAnthropicInputDelta(0, `{"cmd":"rm -rf /"}`)
	// No content_block_stop, no message_stop — the connection dies here.

	t.Run("deny-does-not-leak", func(t *testing.T) {
		spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "no", Rule: "deny:test:rule"}}
		got := pvRunStream(t, "anthropic", stream, spy)
		if len(spy.seen()) != 1 {
			t.Fatalf("PolicyCheck ran %d times, want 1 — the tool_use was dropped at EOF without gating (B17)", len(spy.seen()))
		}
		if strings.Contains(got, "rm -rf /") {
			t.Fatalf("a DENIED tool_use leaked to the client at EOF: %q", got)
		}
		if !strings.Contains(got, "deny:test:rule") {
			t.Errorf("expected the policy refusal; got %q", got)
		}
	})

	t.Run("allow-delivers", func(t *testing.T) {
		spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
		got := pvRunStream(t, "anthropic", stream, spy)
		if len(spy.seen()) != 1 {
			t.Fatalf("PolicyCheck ran %d times, want 1", len(spy.seen()))
		}
		if !strings.Contains(got, "toolu_eof") {
			t.Errorf("ALLOWed tool_use was not delivered after the EOF close: %q", got)
		}
	})
}

// TestB17_Anthropic_EOFTruncatedInput_FailsClosed: the arguments were
// cut mid-JSON, so the EOF close lands on the malformed refusal.
func TestB17_Anthropic_EOFTruncatedInput_FailsClosed(t *testing.T) {
	stream := pvAnthropicToolStart(0, "toolu_trunc", "bash", `{}`) +
		pvAnthropicInputDelta(0, `{"cmd":"rm -rf `)

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "anthropic", stream, spy)

	if !strings.Contains(got, "malformed tool call arguments") {
		t.Errorf("expected the malformed fail-closed refusal; got %q", got)
	}
	if strings.Contains(got, "rm -rf") {
		t.Errorf("truncated tool input leaked to the client: %q", got)
	}
}

// TestB17_CompletionSignalledExactlyOnce: a properly ended stream gates
// its call once; `[DONE]` or EOF must not re-close a completed cycle and
// gate (and audit) it twice.
func TestB17_CompletionSignalledExactlyOnce(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_once", "bash", `{"cmd":"ls"}`) +
		pvOpenAIFinish(0, "tool_calls") +
		"data: [DONE]\n\n"

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "openai", stream, spy)

	if n := len(spy.seen()); n != 1 {
		t.Fatalf("PolicyCheck ran %d times for one tool call, want exactly 1", n)
	}
	if !strings.Contains(got, "call_once") || !strings.Contains(got, "[DONE]") {
		t.Errorf("normal ALLOW stream was altered: %q", got)
	}
	if strings.Count(got, "call_once") != 1 {
		t.Errorf("tool_call delivered %d times, want once: %q", strings.Count(got, "call_once"), got)
	}
}

// TestB17_CloseAtEOF_IsInertAfterACleanClose pins the same latch at the
// parser boundary, where the orchestrator's Reset is not in the picture.
func TestB17_CloseAtEOF_IsInertAfterACleanClose(t *testing.T) {
	t.Run("openai", func(t *testing.T) {
		acc := NewOpenAIToolCallAccumulator(0)
		if _, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(0, 0, "call_x", "bash", `{}`))); err != nil {
			t.Fatalf("delta: %v", err)
		}
		res, err := acc.FeedEvent([]byte(pvOpenAIFinish(0, "tool_calls")))
		if err != nil || !res.Completed {
			t.Fatalf("finish: res=%+v err=%v", res, err)
		}
		if res, _ := acc.CloseAtEOF(); res.Completed {
			t.Errorf("CloseAtEOF re-completed an already-closed cycle: %+v", res)
		}
	})

	t.Run("anthropic", func(t *testing.T) {
		acc := NewAnthropicAccumulator(0)
		if _, err := acc.FeedEvent([]byte(pvAnthropicToolStart(0, "toolu_x", "bash", `{}`))); err != nil {
			t.Fatalf("start: %v", err)
		}
		res, err := acc.FeedEvent([]byte(pvAnthropicStop(0)))
		if err != nil || !res.Completed {
			t.Fatalf("stop: res=%+v err=%v", res, err)
		}
		if res, _ := acc.CloseAtEOF(); res.Completed {
			t.Errorf("CloseAtEOF re-completed an already-closed cycle: %+v", res)
		}
	})

	t.Run("idle-stream-is-untouched", func(t *testing.T) {
		// No tool call ever started: EOF must do nothing at all.
		acc := NewOpenAIToolCallAccumulator(0)
		if _, err := acc.FeedEvent([]byte(pvOpenAIContent(0, "hi"))); err != nil {
			t.Fatalf("content: %v", err)
		}
		res, err := acc.CloseAtEOF()
		if err != nil || res.Completed || res.PassThrough || res.Accumulating {
			t.Errorf("CloseAtEOF on an idle stream = %+v (err=%v), want the zero result", res, err)
		}
	})
}
