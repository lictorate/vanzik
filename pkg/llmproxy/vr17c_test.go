package llmproxy

// VR-17c (O-4): OpenAI bodies and stream events the gate cannot decode.
// A wrong-typed choices element (`[{...}, 5]`) or a NaN / Infinity
// literal makes encoding/json and the lenient probe reject the body, so
// it passed through unread; openai-python and LangChain run the call
// (Python's json accepts NaN and Infinity), and openai-python and
// openai-node run it for the type error. In a stream such an event was
// dropped silently. Now a body or event the probe cannot read is
// refused when it carries a tool-call key, under undecodable_tool_call.
//
// The fixtures in testdata/vr17c come from the rig (gen17c.py).

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

func TestHasToolCallMarker(t *testing.T) {
	for _, tc := range []struct {
		data string
		want bool
	}{
		{`{"tool_calls":[]}`, true},
		{`{"function_call":{}}`, true},
		{`{"tool_calls":1}`, true},
		{`{"tool_calls":1}`, true},
		{`{"Tool_Calls":1}`, true},
		{`{"TOOL_CALLS":1}`, true},
		{`{"FUNCTION_CALL":1}`, true},
		{`{"tool_callſ":1}`, true},                        // long s folds to s
		{"{\"tool_callſ\":1}", true},                      // the same, unescaped
		{`{"finish_reason":"tool_calls"}`, true},          // values count too
		{`{"a":NaN,"tool_calls":[{"x":Infinity}]}`, true}, // not JSON at all
		{`{"tool_call":1}`, false},
		{`{"tool_calls_x":1}`, false},
		{`{"content":"call tool_calls now"}`, false}, // prose
		{`{"content":"tool_call"}`, false},
		{`{"a":"\q","b":1}`, false}, // an invalid escape is skipped, not matched
		{`{"content":"hello","x":NaN}`, false},
		{`{"tool_calls`, false}, // unterminated: no client parses it
	} {
		if got := hasToolCallMarker([]byte(tc.data), openAIToolCallMarkers); got != tc.want {
			t.Errorf("hasToolCallMarker(%s) = %v, want %v", tc.data, got, tc.want)
		}
	}
}

// Every spelling encoding/json folds onto a marker key is found: each
// character replaced by each rune that folds to it (Kelvin sign and
// long s included), all upper case, and each character \u-escaped.
func TestHasToolCallMarker_EveryGoFoldedSpelling(t *testing.T) {
	type probe struct {
		ToolCalls    json.RawMessage `json:"tool_calls"`
		FunctionCall json.RawMessage `json:"function_call"`
	}
	n := 0
	for _, name := range []string{"tool_calls", "function_call"} {
		var spellings []string
		for i, c := range name {
			for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
				spellings = append(spellings, name[:i]+string(f)+name[i+1:])
			}
			spellings = append(spellings, name[:i]+`\u00`+strings.ToLower(string("0123456789abcdef"[c>>4]))+string("0123456789abcdef"[c&15])+name[i+1:])
		}
		spellings = append(spellings, strings.ToUpper(name))
		for _, sp := range spellings {
			body := `{"` + sp + `":1,"created":NaN}`
			// Sanity: Go reads this spelling as the key (on a decodable copy).
			var p probe
			if err := json.Unmarshal([]byte(strings.Replace(body, "NaN", "1", 1)), &p); err != nil || (p.ToolCalls == nil && p.FunctionCall == nil) {
				t.Fatalf("%q: encoding/json does not fold it onto %s (err %v)", sp, name, err)
			}
			if !hasToolCallMarker([]byte(body), openAIToolCallMarkers) {
				t.Errorf("%q not found", sp)
			}
			n++
		}
	}
	if n < 40 {
		t.Fatalf("only %d spellings generated", n)
	}
}

func readVR17c(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vr17c", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestVR17c_NonStreaming(t *testing.T) {
	var carrying []string
	for _, kind := range []string{"wrongtype", "nan", "infinity", "neginf", "fc_nan", "fc_wrongtype"} {
		for _, marker := range []string{"plain", "escaped", "case"} {
			carrying = append(carrying, kind+"_"+marker)
		}
	}
	for _, name := range carrying {
		t.Run(name, func(t *testing.T) {
			before := metrics.LLMProxyUndecodableToolCallFor("openai")
			got, spy := postNonStreaming(t, readVR17c(t, name+".json"), denyRm)
			rule := ruleUndecodable
			// Valid JSON with a wrong type: VR-15's case-variant check, which
			// runs before the decode, refuses the variant spelling first.
			if strings.HasSuffix(name, "wrongtype_case") {
				rule = ruleCaseVariant
			}
			assertRefusedNonStreaming(t, got, spy, rule)
			if d := metrics.LLMProxyUndecodableToolCallFor("openai") - before; rule == ruleUndecodable && d != 1 {
				t.Errorf("undecodable_tool_call counter moved by %d, want 1", d)
			}
		})
	}
	// Text-only bodies the strict decoder rejects pass through unchanged.
	for _, name := range []string{"text_nan", "text_wrongtype", "text_created_string"} {
		t.Run(name, func(t *testing.T) {
			body := readVR17c(t, name+".json")
			got, spy := postNonStreaming(t, body, denyRm)
			if got != body {
				t.Errorf("text-only body changed:\n got %q\nwant %q", got, body)
			}
			if n := len(spy.recorded()); n != 0 {
				t.Errorf("text-only body audited %d refusals", n)
			}
		})
	}
}

func TestVR17c_Streaming(t *testing.T) {
	for _, kind := range []string{"wrongtype", "nan", "infinity", "neginf"} {
		for _, marker := range []string{"plain", "escaped", "case"} {
			name := kind + "_" + marker
			t.Run(name, func(t *testing.T) {
				before := metrics.LLMProxyUndecodableToolCallFor("openai")
				got, spy := runStreamWithAudit(t, "openai", readVR17c(t, "stream_"+name+".sse"), 0)
				assertRefusedStream(t, got, spy, ruleUndecodable)
				if d := metrics.LLMProxyUndecodableToolCallFor("openai") - before; d != 1 {
					t.Errorf("undecodable_tool_call counter moved by %d, want 1", d)
				}
			})
		}
	}
	// A text-only event the parser cannot decode is still dropped, as
	// before: the rest of the stream reaches the client.
	t.Run("text_nan", func(t *testing.T) {
		stream := readVR17c(t, "stream_text_nan.sse")
		got, spy := runStreamWithAudit(t, "openai", stream, 0)
		events := strings.SplitAfter(stream, "\n\n")
		want := events[0] + strings.Join(events[2:], "")
		if got != want {
			t.Errorf("got %q\nwant %q", got, want)
		}
		if n := len(spy.recorded()); n != 0 {
			t.Errorf("audited %d refusals", n)
		}
	})
}

// A decodable stream event is never probed: the normal path is unchanged.
func TestUndecodableStreamEventHasToolCall(t *testing.T) {
	for _, tc := range []struct {
		event string
		want  bool
	}{
		{`data: {"choices":[{"delta":{"tool_calls":[{"index":0}]}}],"created":"1"}` + "\n\n", true}, // probe reads it
		{`data: {"choices":[{"delta":{"tool_calls":[]}}],"created":"1"}` + "\n\n", false},           // probe: no call
		{`data: {"choices":[{"delta":{"function_call":{"name":"x"}}}],"x":NaN}` + "\n\n", true},     // marker
		{`data: {"choices":[{"delta":{"content":"hi"}}],"x":NaN}` + "\n\n", false},
		{": comment\n\n", false},
	} {
		if got := undecodableStreamEventHasToolCall([]byte(tc.event)); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.event, got, tc.want)
		}
	}
}

// --- N5: Anthropic non-streaming bodies the gate cannot decode ---------------

// New (VR-17c) N5. A NaN or Infinity literal (anthropic-python reads it;
// its tool runner ran rm) or a wrong-typed content element
// (@anthropic-ai/sdk held rm) made the Anthropic probe fail too, so the
// body passed through unread.
func TestVR17c_N5_AnthropicNonStreaming(t *testing.T) {
	post := func(t *testing.T, body string) (string, []forcedAuditCall) {
		t.Helper()
		upstream := upstreamServing(t, body)
		srv, base, teardown := newGatedTestServer(t, upstream, upstream, denyRm)
		defer teardown()
		srv.BuildRefusal = BuildRefusalRich
		spy := &forcedAuditSpy{}
		srv.RecordForcedAudit = spy.record
		resp, err := http.Post(base+"/v1/messages", "application/json",
			strings.NewReader(`{"model":"m","max_tokens":5,"messages":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		return string(got), spy.recorded()
	}
	for _, kind := range []string{"nan", "infinity", "wrongtype"} {
		for _, marker := range []string{"plain", "escaped", "case"} {
			name := kind + "_" + marker
			t.Run(name, func(t *testing.T) {
				before := metrics.LLMProxyUndecodableToolCallFor("anthropic")
				got, audits := post(t, readVR17c(t, "n5_"+name+".json"))
				var msg AnthropicMessagesResponse
				if err := json.Unmarshal([]byte(got), &msg); err != nil {
					t.Fatalf("client did not receive an Anthropic message: %v\n%q", err, got)
				}
				if strings.Contains(got, "rm -rf") || strings.Contains(got, "tool_use\"") {
					t.Errorf("the call reached the client: %q", got)
				}
				if !strings.Contains(got, ruleUndecodable) {
					t.Errorf("no %s refusal: %q", ruleUndecodable, got)
				}
				if len(audits) != 1 || audits[0].decision.Rule != ruleUndecodable {
					t.Errorf("forced audits %+v, want one %s", audits, ruleUndecodable)
				}
				if d := metrics.LLMProxyUndecodableToolCallFor("anthropic") - before; d != 1 {
					t.Errorf("undecodable_tool_call counter moved by %d, want 1", d)
				}
			})
		}
	}
	for _, name := range []string{"text_nan", "text_wrongtype"} {
		t.Run(name, func(t *testing.T) {
			body := readVR17c(t, "n5_"+name+".json")
			got, audits := post(t, body)
			if got != body || len(audits) != 0 {
				t.Errorf("text-only body changed or audited (%d):\n got %q\nwant %q", len(audits), got, body)
			}
		})
	}
	for _, tc := range []struct {
		data string
		want bool
	}{
		{`{"type":"tool_use"}`, true},
		{`{"type":"tool_use"}`, true},
		{`{"type":"TOOL_USE"}`, true},
		{`{"type":"server_tool_use"}`, false},
		{`{"type":"text","text":"use the tool_use block"}`, false},
	} {
		if got := hasToolCallMarker([]byte(tc.data), anthropicToolUseMarkers); got != tc.want {
			t.Errorf("hasToolCallMarker(%s, tool_use) = %v, want %v", tc.data, got, tc.want)
		}
	}
}

// --- N6: Anthropic non-streaming case-variant keys ---------------------------

// New (VR-17c review) N6, the non-streaming half of O-19. encoding/json
// folds `Content` onto `content` and a block's `Type` onto `type`; both
// SDKs read only the exact key. The reviewer's bodies (n6_o19_*) and
// two of mine had all four Anthropic clients, both tool runners
// included, run rm while the gate saw no tool_use or `ls`.
func TestHasAnthropicCaseVariantKey(t *testing.T) {
	const tu = `{"type":"tool_use","id":"t","name":"bash","input":{"command":"ls"}}`
	msg := func(extra string) string {
		return `{"id":"m","type":"message","role":"assistant","model":"x","content":[` + tu + `]` + extra + `,"stop_reason":"tool_use","usage":{"input_tokens":1}}`
	}
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"plain", msg(""), false},
		{"Content beside content", msg(`,"Content":[]`), true},
		{"CONTENT", msg(`,"CONTENT":[]`), true},
		{"escaped C", msg(`,"Content":[]`), true},
		{"escaped exact key is not a variant", `{"content":[` + tu + `]}`, false},
		{"exact duplicate", msg(`,"content":[]`), false},
		{"Stop_Reason", msg(`,"Stop_Reason":"end_turn"`), true},
		{"long s in stop_reason", msg(`,"ſtop_reason":"end_turn"`), true},
		{"long s in usage", msg(`,"uſage":{}`), true},
		{"Model", msg(`,"Model":"y"`), true},
		{"block Type", `{"content":[{"type":"tool_use","id":"t","name":"bash","input":{},"Type":"text"}]}`, true},
		{"block Input", `{"content":[{"type":"tool_use","id":"t","name":"bash","input":{},"Input":{}}]}`, true},
		{"block Name", `{"content":[{"type":"tool_use","id":"t","name":"bash","input":{},"NAME":"x"}]}`, true},
		{"block ID", `{"content":[{"type":"tool_use","id":"t","ID":"u","name":"bash","input":{}}]}`, true},
		{"block Text", `{"content":[{"type":"text","text":"a","Text":"b"}]}`, true},
		// Keys the gate does not read are not checked.
		{"nested Content in a result block", `{"content":[{"type":"web_search_tool_result","tool_use_id":"s","content":[{"Type":"x","Content":"y"}]}]}`, false},
		{"Citations on a text block", `{"content":[{"type":"text","text":"a","Citations":[]}]}`, false},
		{"Container", msg(`,"Container":null`), false},
		{"variant inside input", `{"content":[{"type":"tool_use","id":"t","name":"bash","input":{"Command":"x","command":"y"}}]}`, false},
		{"variant as a value", msg(`,"x":"Content"`), false},
		{"not JSON", `{"Content":NaN}`, false},
	} {
		if got := hasAnthropicCaseVariantKey([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestVR17c_N6_AnthropicCaseVariantKeys(t *testing.T) {
	post := func(t *testing.T, body string) (string, []forcedAuditCall) {
		t.Helper()
		upstream := upstreamServing(t, body)
		srv, base, teardown := newGatedTestServer(t, upstream, upstream, denyRm)
		defer teardown()
		srv.BuildRefusal = BuildRefusalRich
		spy := &forcedAuditSpy{}
		srv.RecordForcedAudit = spy.record
		resp, err := http.Post(base+"/v1/messages", "application/json",
			strings.NewReader(`{"model":"m","max_tokens":5,"messages":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		return string(got), spy.recorded()
	}
	for _, name := range []string{"o19_Content_strict", "o19_Type_strict", "o19_Content_probe", "content_title", "block_Input"} {
		t.Run(name, func(t *testing.T) {
			before := metrics.LLMProxyProtocolViolationFor("anthropic")
			got, audits := post(t, readVR17c(t, "n6_"+name+".json"))
			if strings.Contains(got, "rm -rf") || !strings.Contains(got, ruleCaseVariant) {
				t.Errorf("want the %s refusal and no rm; got %q", ruleCaseVariant, got)
			}
			if len(audits) != 1 || audits[0].decision.Rule != ruleCaseVariant {
				t.Errorf("forced audits %+v, want one %s", audits, ruleCaseVariant)
			}
			if d := metrics.LLMProxyProtocolViolationFor("anthropic") - before; d != 1 {
				t.Errorf("protocol_violation counter moved by %d, want 1", d)
			}
		})
	}
	// Realistic first-party bodies (thinking, server tools, web search and
	// code execution results, citations, container, cache usage) are
	// gated and forwarded byte-identical.
	for _, name := range []string{"real_full_ls", "real_container_ls"} {
		t.Run(name, func(t *testing.T) {
			body := readVR17c(t, "n6_"+name+".json")
			got, audits := post(t, body)
			if got != body || len(audits) != 0 {
				t.Errorf("changed or audited (%d):\n got %q\nwant %q", len(audits), got, body)
			}
		})
	}
}
