package llmproxy

// The legacy function_call shape (request `functions`) is still surfaced
// by the OpenAI SDKs and executed by frameworks (LangChain's OpenAI
// functions agent), so it is gated exactly like tool_calls, streaming and
// non-streaming. Also pinned here: a streamed tool name sent in more than
// one non-empty fragment is refused, and a BOM-prefixed body carrying a
// call is refused rather than forwarded ungated.
//
// Every test drives the real proxy or the accumulator through symbols
// that predate the fix, so each one also runs against the base branch.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const legacyFCBody = `{"id":"chatcmpl-x","object":"chat.completion","created":1,"model":"gpt-4",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":null,` +
	`"function_call":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}},"finish_reason":"function_call"}]}`

// postNonStreaming drives one non-streaming chat completion through the
// proxy against an upstream answering body, with check as the gate.
func postNonStreaming(t *testing.T, body string, check func(context.Context, *ToolCallCheck) (Decision, error)) (string, *forcedAuditSpy) {
	t.Helper()
	upstream := upstreamServing(t, body)
	srv, base, teardown := newGatedTestServer(t, upstream, nil, check)
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich
	spy := &forcedAuditSpy{}
	srv.RecordForcedAudit = spy.record

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[],"functions":[{"name":"bash"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	return string(got), spy
}

// denyNamed denies calls to name and allows everything else, recording
// every check it sees.
type denyNamed struct {
	name string
	mu   sync.Mutex
	seen []ToolCallCheck
}

func (d *denyNamed) check(_ context.Context, c *ToolCallCheck) (Decision, error) {
	d.mu.Lock()
	d.seen = append(d.seen, *c)
	d.mu.Unlock()
	if c.ToolName == d.name {
		return Decision{Allow: false, Reason: "blocked", Rule: "deny:shell:rm"}, nil
	}
	return Decision{Allow: true}, nil
}

func (d *denyNamed) calls() []ToolCallCheck {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]ToolCallCheck(nil), d.seen...)
}

func TestLegacyFunctionCall_NonStreaming_Gated(t *testing.T) {
	for _, tc := range []struct {
		name     string
		denyTool string
	}{
		{"deny", "bash"},
		{"allow", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := &denyNamed{name: tc.denyTool}
			got, _ := postNonStreaming(t, legacyFCBody, gate.check)

			seen := gate.calls()
			if len(seen) != 1 || seen[0].ToolName != "bash" || seen[0].Arguments["command"] != "rm -rf /" {
				t.Fatalf("PolicyCheck saw %+v, want one bash call with the legacy arguments", seen)
			}
			if seen[0].ToolCallID != "" {
				t.Errorf("the legacy shape has no id; got %q", seen[0].ToolCallID)
			}
			if tc.denyTool == "" {
				if got != legacyFCBody {
					t.Errorf("ALLOW must forward byte-identical; got %q", got)
				}
				return
			}
			if strings.Contains(got, "function_call") || strings.Contains(got, "rm -rf") {
				t.Errorf("DENY leaked the legacy call: %q", got)
			}
			if !strings.Contains(got, "deny:shell:rm") {
				t.Errorf("refusal missing rule: %q", got)
			}
		})
	}
}

// No real upstream sends both shapes in one message, but a client may
// execute either, so both are gated and either deny refuses the response.
func TestLegacyFunctionCall_NonStreaming_MixedGatesBoth(t *testing.T) {
	body := `{"id":"chatcmpl-x","object":"chat.completion","created":1,"model":"gpt-4",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":null,` +
		`"tool_calls":[{"id":"call_ls","type":"function","function":{"name":"ls","arguments":"{}"}}],` +
		`"function_call":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}},"finish_reason":"tool_calls"}]}`
	gate := &denyNamed{name: "bash"}
	got, _ := postNonStreaming(t, body, gate.check)

	seen := gate.calls()
	if len(seen) != 2 || seen[0].ToolName != "ls" || seen[1].ToolName != "bash" {
		t.Fatalf("PolicyCheck saw %+v, want ls (tool_calls) then bash (function_call)", seen)
	}
	if strings.Contains(got, "call_ls") || strings.Contains(got, "rm -rf") {
		t.Errorf("DENY leaked a call: %q", got)
	}
	if !strings.Contains(got, "deny:shell:rm") {
		t.Errorf("refusal missing rule: %q", got)
	}
}

// A body that fails strict decode is forwarded verbatim unless the lenient
// probe finds a call in it. A UTF-8 BOM fails encoding/json, but Python's
// json.loads(bytes) skips it and runs the calls behind it.
func TestLenientProbe_LegacyAndBOM_NonStreaming(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	for _, tc := range []struct {
		name, body string
		refused    bool
	}{
		{"function_call beside a wrong-typed field", `{"created":"x","choices":[{"message":{"function_call":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}}]}`, true},
		{"function_call with object arguments", `{"choices":[{"message":{"function_call":{"name":"bash","arguments":{"command":"rm -rf /"}}}}]}`, true},
		{"BOM then tool_calls", bom + `{"choices":[{"message":{"tool_calls":[{"id":"call_x","type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}]}}]}`, true},
		{"BOM then function_call", bom + legacyFCBody, true},
		{"BOM then text only", bom + `{"choices":[{"message":{"content":"hi rm -rf"}}]}`, false},
		{"function_call null beside a wrong-typed field", `{"created":"x","choices":[{"message":{"function_call":null,"content":"hi rm -rf"}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, spy := postNonStreaming(t, tc.body, func(context.Context, *ToolCallCheck) (Decision, error) {
				return Decision{Allow: true}, nil
			})
			if !tc.refused {
				if got != tc.body {
					t.Errorf("a body with no call must pass through verbatim; got %q", got)
				}
				if n := len(spy.recorded()); n != 0 {
					t.Errorf("passthrough audited %d refusals", n)
				}
				return
			}
			if strings.Contains(got, "rm -rf") {
				t.Errorf("the call reached the client: %q", got)
			}
			if !strings.Contains(got, "deny:llm_api_proxy:undecodable_tool_call") {
				t.Errorf("want the undecodable_tool_call refusal; got %q", got)
			}
			rec := spy.recorded()
			if len(rec) != 1 || rec[0].decision.Rule != "deny:llm_api_proxy:undecodable_tool_call" {
				t.Errorf("audited %+v, want one undecodable_tool_call entry", rec)
			}
		})
	}
}

// pvOpenAIFunctionCallDelta emits one legacy function_call delta.
func pvOpenAIFunctionCallDelta(name, args string) string {
	namePart := ""
	if name != "" {
		namePart = fmt.Sprintf(`"name":%q,`, name)
	}
	return fmt.Sprintf(
		`data: {"choices":[{"index":0,"delta":{"function_call":{%s"arguments":%q}},"finish_reason":null}]}`+"\n\n",
		namePart, args,
	)
}

func legacyFCStream() string {
	return `data: {"choices":[{"index":0,"delta":{"role":"assistant","content":null},"finish_reason":null}]}` + "\n\n" +
		pvOpenAIFunctionCallDelta("bash", "") +
		pvOpenAIFunctionCallDelta("", `{"command":`) +
		pvOpenAIFunctionCallDelta("", `"rm -rf /"}`) +
		pvOpenAIFinish(0, "function_call") +
		"data: [DONE]\n\n"
}

func TestLegacyFunctionCall_Streaming_Gated(t *testing.T) {
	stream := legacyFCStream()
	for _, tc := range []struct {
		name  string
		allow bool
	}{{"deny", false}, {"allow", true}} {
		t.Run(tc.name, func(t *testing.T) {
			decision := Decision{Allow: false, Reason: "blocked", Rule: "deny:shell:rm"}
			if tc.allow {
				decision = Decision{Allow: true}
			}
			spy := &pvCallSpy{decision: decision}
			got := pvRunStream(t, "openai", stream, spy)

			seen := spy.seen()
			if len(seen) != 1 || seen[0].ToolName != "bash" || seen[0].Arguments["command"] != "rm -rf /" || !seen[0].Stream {
				t.Fatalf("PolicyCheck saw %+v, want one streamed bash call with the assembled arguments", seen)
			}
			if tc.allow {
				if got != stream {
					t.Errorf("ALLOW must replay byte-identical;\n got %q\nwant %q", got, stream)
				}
				return
			}
			if strings.Contains(got, "function_call") || strings.Contains(got, "rm -rf") {
				t.Errorf("DENY leaked the legacy call: %q", got)
			}
			if !strings.Contains(got, "deny:shell:rm") {
				t.Errorf("refusal missing rule: %q", got)
			}
		})
	}
}

// Clients disagree on which shape they execute when both appear, so a
// stream mixing them is refused whichever comes first.
func TestLegacyFunctionCall_Streaming_MixedIsRefused(t *testing.T) {
	fc := pvOpenAIFunctionCallDelta("bash", `{"command":"rm -rf /"}`)
	tcall := pvOpenAIToolDelta(0, 0, "call_ls", "ls", `{}`)
	for _, tc := range []struct{ name, stream string }{
		{"function_call first", fc + tcall + pvOpenAIFinish(0, "tool_calls")},
		{"tool_calls first", tcall + fc + pvOpenAIFinish(0, "function_call")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, spy := runStreamWithAudit(t, "openai", tc.stream, 0)
			if strings.Contains(got, "call_ls") || strings.Contains(got, "rm -rf") {
				t.Errorf("a call leaked from a mixed stream: %q", got)
			}
			if !strings.Contains(got, "deny:llm_api_proxy:mixed_function_call") {
				t.Fatalf("want the mixed_function_call refusal; got %q", got)
			}
			assertAudited(t, spy, "deny:llm_api_proxy:mixed_function_call", "openai")
		})
	}
}

// openai-python concatenates name fragments and openai-node keeps the
// last, so a stream whose later fragment names a different tool has no
// single name to gate. It is refused and audited under the gated (first)
// name.
func TestToolNameConflict_Streaming_IsRefused(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		{"tool_calls", pvOpenAIToolDelta(0, 0, "call_1", "read_file", "") +
			pvOpenAIToolDelta(0, 0, "", "bash", `{"command":"rm -rf /"}`) +
			pvOpenAIFinish(0, "tool_calls")},
		{"function_call", pvOpenAIFunctionCallDelta("read_file", "") +
			pvOpenAIFunctionCallDelta("bash", `{"command":"rm -rf /"}`) +
			pvOpenAIFinish(0, "function_call")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, spy := runStreamWithAudit(t, "openai", tc.stream, 0)
			if strings.Contains(got, "rm -rf") {
				t.Errorf("arguments leaked from a conflicting stream: %q", got)
			}
			if !strings.Contains(got, "deny:llm_api_proxy:tool_name_conflict") {
				t.Fatalf("want the tool_name_conflict refusal; got %q", got)
			}
			c := assertAudited(t, spy, "deny:llm_api_proxy:tool_name_conflict", "openai")
			if c.ToolName != "read_file" {
				t.Errorf("audited tool name = %q, want the first (gated) name", c.ToolName)
			}
		})
	}
}

// A repeat of the same name is a conflict too: openai-python
// concatenates the fragments and runs "bashbash" (n repeats of X give
// X^n), while openai-node keeps "bash", so the gated name is not the one
// every client runs.
func TestToolNameRepeatedIdentical_Streaming_IsRefused(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		{"tool_calls", `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\"com"}}]},"finish_reason":null}]}` + "\n\n" +
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"bash","arguments":"mand\": \"ls\"}"}}]},"finish_reason":null}]}` + "\n\n" +
			pvOpenAIFinish(0, "tool_calls") +
			"data: [DONE]\n\n"},
		{"function_call", pvOpenAIFunctionCallDelta("bash", `{"com`) +
			pvOpenAIFunctionCallDelta("bash", `mand": "ls"}`) +
			pvOpenAIFinish(0, "function_call") +
			"data: [DONE]\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, spy := runStreamWithAudit(t, "openai", tc.stream, 0)
			if strings.Contains(got, `\"ls\"`) || strings.Contains(got, `mand`) {
				t.Errorf("arguments leaked from a repeated-name stream: %q", got)
			}
			if !strings.Contains(got, "deny:llm_api_proxy:tool_name_conflict") {
				t.Fatalf("want the tool_name_conflict refusal; got %q", got)
			}
			c := assertAudited(t, spy, "deny:llm_api_proxy:tool_name_conflict", "openai")
			if c.ToolName != "bash" {
				t.Errorf("audited tool name = %q, want bash", c.ToolName)
			}
		})
	}
}
