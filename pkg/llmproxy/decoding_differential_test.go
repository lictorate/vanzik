package llmproxy

// Responses the proxy and a client SDK decode differently must be
// refused, not gated on the proxy's reading:
//
//   - a stream starting with a UTF-8 BOM: openai-node strips it and runs
//     a call in the first event, which the parser cannot see;
//   - a UTF-16 or UTF-32 body: openai-python's json.loads(bytes) detects
//     the encoding and runs the calls, encoding/json cannot read it;
//   - an envelope key differing only in case from one the gate reads:
//     encoding/json folds it onto that key and keeps the last, the SDKs
//     read only the exact key.
//
// Every test drives the real proxy and asserts what the client receives.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf16"
)

const (
	bomPrefix = "\xef\xbb\xbf"

	ruleUndecodable = "deny:llm_api_proxy:undecodable_tool_call"
	ruleCaseVariant = "deny:llm_api_proxy:case_variant_key"

	// The JSON escapes for "T" and "t", spelled out so no editor folds
	// them into the letters.
	jsonEscapeT = `\` + `u0054`
	jsonEscapet = `\` + `u0074`
)

// rmToolCallBody is a well-formed response whose only call is rm -rf.
const rmToolCallBody = `{"id":"chatcmpl-x","object":"chat.completion","created":1,"model":"gpt-4",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":null,` +
	`"tool_calls":[{"id":"call_rm","type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}]},` +
	`"finish_reason":"tool_calls"}]}`

// denyRm denies a call whose arguments mention rm and allows the rest,
// so a test shows which spelling the gate read.
func denyRm(_ context.Context, c *ToolCallCheck) (Decision, error) {
	if strings.Contains(string(c.RawArguments), "rm -rf") {
		return Decision{Allow: false, Reason: "rm blocked", Rule: "deny:shell:rm"}, nil
	}
	return Decision{Allow: true}, nil
}

// assertRefusedNonStreaming checks that got is the provider-shaped
// refusal under rule, carries no call, and was audited once.
func assertRefusedNonStreaming(t *testing.T, got string, spy *forcedAuditSpy, rule string) {
	t.Helper()
	var resp ChatCompletionResponse
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("client did not receive a UTF-8 chat completion: %v\n%q", err, got)
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message.Content == nil {
		t.Fatalf("client did not receive a refusal message: %q", got)
	}
	msg := resp.Choices[0].Message
	if len(msg.ToolCalls) != 0 || msg.FunctionCall != nil {
		t.Errorf("refusal carries a call: %q", got)
	}
	if strings.Contains(got, "rm -rf") {
		t.Errorf("the call reached the client: %q", got)
	}
	if !strings.Contains(*msg.Content, rule) {
		t.Errorf("refusal does not name %s: %q", rule, *msg.Content)
	}
	rec := spy.recorded()
	if len(rec) != 1 || rec[0].decision.Rule != rule || rec[0].decision.Allow || rec[0].call.Stream {
		t.Errorf("audited %+v, want one non-streaming %s deny", rec, rule)
	}
}

// assertRefusedStream checks that got ends in the refusal under rule,
// carries no call, and was audited once.
func assertRefusedStream(t *testing.T, got string, spy *forcedAuditSpy, rule string) {
	t.Helper()
	if strings.Contains(got, "rm -rf") || strings.Contains(got, "call_rm") {
		t.Errorf("the call reached the client: %q", got)
	}
	if !strings.Contains(got, rule) {
		t.Fatalf("want the %s refusal; got %q", rule, got)
	}
	if !strings.HasSuffix(got, "data: [DONE]\n\n") {
		t.Errorf("refusal does not close the stream: %q", got)
	}
	assertAudited(t, spy, rule, "openai")
}

// --- UTF-8 BOM at the start of a stream ------------------------------------

func TestBOMStream_WithToolCall_IsRefused(t *testing.T) {
	roleEvent := `data: {"choices":[{"index":0,"delta":{"role":"assistant","content":null},"finish_reason":null}]}` + "\n\n"
	tcEvent := `data: {"choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_rm","type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}]},"finish_reason":null}]}` + "\n\n"
	for _, tc := range []struct{ name, stream string }{
		{"tool_calls in the first event", bomPrefix + tcEvent +
			pvOpenAIFinish(0, "tool_calls") + "data: [DONE]\n\n"},
		{"function_call in the first event", bomPrefix + pvOpenAIFunctionCallDelta("bash", `{"command":"rm -rf /"}`) +
			pvOpenAIFinish(0, "function_call") + "data: [DONE]\n\n"},
		{"tool_calls after a role event", bomPrefix + roleEvent + tcEvent +
			pvOpenAIFinish(0, "tool_calls") + "data: [DONE]\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, spy := runStreamWithAudit(t, "openai", tc.stream, 0)
			assertRefusedStream(t, got, spy, ruleUndecodable)
			c := assertAudited(t, spy, ruleUndecodable, "openai")
			if c.ToolName != "bash" {
				t.Errorf("audited tool name = %q, want bash", c.ToolName)
			}
		})
	}
}

// A BOM-prefixed stream with no call has nothing to gate; it is
// forwarded byte-identical, BOM included, as before.
func TestBOMStream_TextOnly_IsForwardedUnchanged(t *testing.T) {
	stream := bomPrefix + pvOpenAIContent(0, "hello") + pvOpenAIContent(0, " world") +
		pvOpenAIFinish(0, "stop") + "data: [DONE]\n\n"
	got, spy := runStreamWithAudit(t, "openai", stream, 0)
	if got != stream {
		t.Errorf("text-only BOM stream changed:\n got %q\nwant %q", got, stream)
	}
	if n := len(spy.recorded()); n != 0 {
		t.Errorf("text-only BOM stream audited %d refusals", n)
	}
}

// --- UTF-16 and UTF-32 bodies ----------------------------------------------

func encodeUTF16(s string, order binary.ByteOrder, bom bool) string {
	units := utf16.Encode([]rune(s))
	if bom {
		units = append([]uint16{0xfeff}, units...)
	}
	b := make([]byte, 2*len(units))
	for i, u := range units {
		order.PutUint16(b[2*i:], u)
	}
	return string(b)
}

func encodeUTF32(s string, order binary.ByteOrder, bom bool) string {
	runes := []rune(s)
	if bom {
		runes = append([]rune{0xfeff}, runes...)
	}
	b := make([]byte, 4*len(runes))
	for i, r := range runes {
		order.PutUint32(b[4*i:], uint32(r))
	}
	return string(b)
}

// encodings are the ones Python's json.detect_encoding recognises.
var encodings = []struct {
	name   string
	encode func(string) string
}{
	{"UTF-16LE with BOM", func(s string) string { return encodeUTF16(s, binary.LittleEndian, true) }},
	{"UTF-16BE with BOM", func(s string) string { return encodeUTF16(s, binary.BigEndian, true) }},
	{"UTF-16LE", func(s string) string { return encodeUTF16(s, binary.LittleEndian, false) }},
	{"UTF-16BE", func(s string) string { return encodeUTF16(s, binary.BigEndian, false) }},
	{"UTF-32LE with BOM", func(s string) string { return encodeUTF32(s, binary.LittleEndian, true) }},
	{"UTF-32BE with BOM", func(s string) string { return encodeUTF32(s, binary.BigEndian, true) }},
	{"UTF-32LE", func(s string) string { return encodeUTF32(s, binary.LittleEndian, false) }},
	{"UTF-32BE", func(s string) string { return encodeUTF32(s, binary.BigEndian, false) }},
}

func TestNonUTF8Body_WithToolCall_IsRefused(t *testing.T) {
	for _, enc := range encodings {
		for _, tc := range []struct{ name, body string }{
			{"tool_calls", rmToolCallBody},
			{"function_call", legacyFCBody},
		} {
			t.Run(enc.name+"/"+tc.name, func(t *testing.T) {
				got, spy := postNonStreaming(t, enc.encode(tc.body), denyRm)
				assertRefusedNonStreaming(t, got, spy, ruleUndecodable)
			})
		}
	}
}

// A text-only body in another encoding carries nothing to gate; it
// passes through verbatim, as before.
func TestNonUTF8Body_TextOnly_PassesThrough(t *testing.T) {
	text := `{"id":"x","object":"chat.completion","created":1,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"rm -rf is dangerous"},"finish_reason":"stop"}]}`
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			body := enc.encode(text)
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

// --- Envelope keys differing only in case ----------------------------------

func TestCaseVariantKeys_NonStreaming_IsRefused(t *testing.T) {
	ls := `{"id":"call_ls","type":"function","function":{"name":"bash","arguments":"{\"command\":\"ls\"}"}}`
	rm := `{"id":"call_rm","type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}`
	wrap := func(message string) string {
		return `{"id":"c1","object":"chat.completion","created":1,"model":"gpt-4","choices":[{"index":0,"message":` +
			message + `,"finish_reason":"tool_calls"}]}`
	}
	for _, tc := range []struct{ name, body string }{
		{"function_call then Function_Call", wrap(`{"role":"assistant","function_call":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"},"Function_Call":{"name":"bash","arguments":"{\"command\":\"ls\"}"}}`)},
		{"tool_calls then Tool_Calls", wrap(`{"role":"assistant","tool_calls":[` + rm + `],"Tool_Calls":[` + ls + `]}`)},
		{"lone Function_Call", wrap(`{"role":"assistant","content":"hi","Function_Call":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}`)},
		{"tool_calls then TOOL_CALLS null", wrap(`{"role":"assistant","tool_calls":[` + rm + `],"TOOL_CALLS":null}`)},
		{"Unicode fold (long s)", wrap(`{"role":"assistant","tool_calls":[` + rm + `],"tool_callſ":[]}`)},
		{"escaped key", wrap(`{"role":"assistant","tool_calls":[` + rm + `],"` + jsonEscapeT + `ool_calls":[]}`)},
		{"arguments then Arguments", wrap(`{"role":"assistant","tool_calls":[{"id":"call_rm","type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}","Arguments":"{\"command\":\"ls\"}"}}]}`)},
		{"message then Message", `{"choices":[{"index":0,"message":{"tool_calls":[` + rm + `]},"Message":{"content":"hi"}}]}`},
		{"choices then Choices", `{"choices":[{"index":0,"message":{"tool_calls":[` + rm + `]}}],"Choices":[]}`},
		{"beside a wrong-typed field", `{"created":"x","choices":[{"message":{"tool_calls":[` + rm + `],"Tool_Calls":null}}]}`},
		{"behind a UTF-8 BOM", bomPrefix + wrap(`{"tool_calls":[`+rm+`],"Tool_Calls":null}`)},
		{"in a UTF-16 body", encodeUTF16(wrap(`{"tool_calls":[`+rm+`],"Tool_Calls":null}`), binary.LittleEndian, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, spy := postNonStreaming(t, tc.body, denyRm)
			assertRefusedNonStreaming(t, got, spy, ruleCaseVariant)
		})
	}
}

func TestCaseVariantKeys_Streaming_IsRefused(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		{"tool_calls then Tool_Calls", `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_rm","type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}],"Tool_Calls":[{"index":0,"id":"call_ls","type":"function","function":{"name":"bash","arguments":"{\"command\":\"ls\"}"}}]},"finish_reason":null}]}` + "\n\n" +
			pvOpenAIFinish(0, "tool_calls") + "data: [DONE]\n\n"},
		{"function_call then Function_Call", `data: {"choices":[{"index":0,"delta":{"function_call":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"},"Function_Call":{"name":"bash","arguments":"{\"command\":\"ls\"}"}},"finish_reason":null}]}` + "\n\n" +
			pvOpenAIFinish(0, "function_call") + "data: [DONE]\n\n"},
		{"delta then Delta", `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_rm","type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}]},"Delta":{"content":"hi"},"finish_reason":null}]}` + "\n\n" +
			pvOpenAIFinish(0, "tool_calls") + "data: [DONE]\n\n"},
		{"finish_reason then Finish_Reason", pvOpenAIContent(0, "hi") +
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":null,"Finish_Reason":"stop"}]}` + "\n\n" + "data: [DONE]\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, spy := runStreamWithAudit(t, "openai", tc.stream, 0)
			assertRefusedStream(t, got, spy, ruleCaseVariant)
		})
	}
}

// --- Guards: what must not change ------------------------------------------

// A normal UTF-8 body and stream with a call are still gated and, on
// ALLOW, forwarded byte-identical, including when a string value folds
// to a gated key name (the pre-scan's false positive).
func TestDecodingGuards_NormalResponsesStillGatedAndForwarded(t *testing.T) {
	t.Run("non-streaming", func(t *testing.T) {
		body := strings.Replace(rmToolCallBody, `"id":"chatcmpl-x"`, `"id":"Tool_Calls"`, 1)
		gate := &pvCallSpy{decision: Decision{Allow: true}}
		got, spy := postNonStreaming(t, body, gate.check)
		if got != body {
			t.Errorf("ALLOW must forward byte-identical:\n got %q\nwant %q", got, body)
		}
		if seen := gate.seen(); len(seen) != 1 || seen[0].ToolName != "bash" || seen[0].Arguments["command"] != "rm -rf /" {
			t.Errorf("gate saw %+v, want the one bash call", seen)
		}
		if n := len(spy.recorded()); n != 0 {
			t.Errorf("an allowed body audited %d refusals", n)
		}
	})
	t.Run("streaming", func(t *testing.T) {
		stream := pvOpenAIContent(0, "Tool_Calls") +
			pvOpenAIToolDelta(0, 0, "call_rm", "bash", `{"command":"rm -rf /"}`) +
			pvOpenAIFinish(0, "tool_calls") + "data: [DONE]\n\n"
		spy := &pvCallSpy{decision: Decision{Allow: true}}
		got := pvRunStream(t, "openai", stream, spy)
		if got != stream {
			t.Errorf("ALLOW must replay byte-identical:\n got %q\nwant %q", got, stream)
		}
		if seen := spy.seen(); len(seen) != 1 || seen[0].ToolName != "bash" || seen[0].Arguments["command"] != "rm -rf /" {
			t.Errorf("gate saw %+v, want the one bash call", seen)
		}
	})
}

// The ungated routes forward whatever upstream sends, as before.
func TestDecodingGuards_UngatedRoutesUnchanged(t *testing.T) {
	caseVariant := strings.Replace(rmToolCallBody, `"tool_calls"`, `"tool_calls":null,"Tool_Calls"`, 1)
	for _, body := range []string{
		caseVariant,
		bomPrefix + rmToolCallBody,
		encodeUTF16(rmToolCallBody, binary.LittleEndian, true),
	} {
		for _, route := range []struct{ method, path, reqBody string }{
			{http.MethodPost, "/v1/embeddings", `{"model":"m","input":"x"}`},
			{http.MethodGet, "/v1/models", ``},
			{http.MethodPost, "/v1/completions", `{"model":"m","prompt":"x"}`},
		} {
			t.Run(route.path, func(t *testing.T) {
				upstream := upstreamServing(t, body)
				gate := &pvCallSpy{decision: Decision{Allow: true}}
				_, base, teardown := newGatedTestServer(t, upstream, nil, gate.check)
				defer teardown()
				req, _ := http.NewRequest(route.method, base+route.path, strings.NewReader(route.reqBody))
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("%s %s: %v", route.method, route.path, err)
				}
				defer resp.Body.Close()
				got, _ := io.ReadAll(resp.Body)
				if string(got) != body {
					t.Errorf("ungated route changed the body:\n got %q\nwant %q", got, body)
				}
				if n := len(gate.seen()); n != 0 {
					t.Errorf("ungated route ran the gate %d times", n)
				}
			})
		}
	}
}
