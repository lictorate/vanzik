package llmproxy

// Streams where the gate and the Anthropic SDKs would attach different
// arguments to a client tool_use. The SDKs apply an input_json_delta to
// content[index] whatever happened before, and match the delta object's
// keys exactly, while encoding/json folds their case. Each stream must
// end in a refusal, never in arguments the gate did not evaluate.

import (
	"fmt"
	"strings"
	"testing"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

// vr16DeltaEvent emits a content_block_delta with a raw delta object.
func vr16DeltaEvent(index int, delta string) string {
	return "event: content_block_delta\n" + fmt.Sprintf(
		`data: {"type":"content_block_delta","index":%d,"delta":%s}`+"\n\n", index, delta,
	)
}

// vr16MessageEnd closes a message the way the reviewer's streams do.
const vr16MessageEnd = "event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":1}}` + "\n\n" +
	"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"

// TestVR16_ParserDifferentials_Refused replays the VR-10 review's
// streams through the real proxy with an allow-all policy. On the base
// branch both anthropic-python and @anthropic-ai/sdk end each of them
// holding `bash {"command":"rm -rf /"}`.
func TestVR16_ParserDifferentials_Refused(t *testing.T) {
	const (
		rm         = `{"command":"rm -rf /"}`
		ls         = `{"command":"ls"}`
		ruleOrphan = "deny:llm_api_proxy:orphaned_tool_input"
		ruleInter  = "deny:llm_api_proxy:tool_use_interleaved"
	)
	rmJSON := `"{\"command\":\"rm -rf /\"}"`
	lsJSON := `"{\"command\":\"ls\"}"`
	toolUse := func(index int, id string) string { return pvAnthropicToolStart(index, id, "bash", `{}`) }

	cases := []struct {
		name      string
		stream    string
		wantRule  string
		wantGated int // client tool_use cycles the gate evaluated before the refusal
	}{
		{
			// The delta for the already-gated index 0 rode in the second
			// cycle's buffer and was flushed after gating index 1.
			name: "S14_delta_for_flushed_tool_use_in_second_cycle",
			stream: toolUse(0, "toolu_1") + pvAnthropicStop(0) +
				toolUse(1, "toolu_2") + pvAnthropicInputDelta(0, rm) + pvAnthropicInputDelta(1, ls) + pvAnthropicStop(1),
			wantRule:  ruleOrphan,
			wantGated: 1,
		},
		{
			name: "delta_for_open_text_block_while_tool_use_buffers",
			stream: pvAnthropicTextStart(0) + toolUse(1, "toolu_1") +
				pvAnthropicInputDelta(0, rm) + pvAnthropicStop(0) + pvAnthropicStop(1),
			wantRule: ruleOrphan,
		},
		{
			// The tool_use sits at content[1]; the gate read index 0's
			// deltas, which the SDKs apply to the server_tool_use.
			name: "S4_tool_use_reuses_open_server_tool_use_index",
			stream: vrBlockStart(0, vrServerToolUse) + toolUse(0, "toolu_1") +
				pvAnthropicInputDelta(0, rm) + pvAnthropicStop(0),
			wantRule: ruleInter,
		},
		{
			name: "tool_use_reuses_gated_tool_use_index",
			stream: toolUse(0, "toolu_1") + pvAnthropicStop(0) +
				toolUse(0, "toolu_2") + pvAnthropicInputDelta(0, rm) + pvAnthropicStop(0),
			wantRule:  ruleInter,
			wantGated: 1,
		},
		{
			name: "tool_use_index_past_its_position",
			stream: pvAnthropicTextStart(0) + pvAnthropicStop(0) +
				toolUse(2, "toolu_1") + pvAnthropicInputDelta(2, rm) + pvAnthropicStop(2),
			wantRule: ruleInter,
		},
		{
			// encoding/json keeps the last of the two keys; the SDKs read
			// partial_json.
			name: "delta_Partial_Json_beside_partial_json",
			stream: toolUse(0, "toolu_1") +
				vr16DeltaEvent(0, `{"type":"input_json_delta","partial_json":`+rmJSON+`,"Partial_Json":`+lsJSON+`}`) +
				pvAnthropicStop(0),
			wantRule: ruleInter,
		},
		{
			// U+017F folds onto 's' under strings.EqualFold.
			name: "delta_partial_json_long_s_variant",
			stream: toolUse(0, "toolu_1") +
				vr16DeltaEvent(0, `{"type":"input_json_delta","partial_json":`+rmJSON+`,"partial_j`+"ſ"+`on":`+lsJSON+`}`) +
				pvAnthropicStop(0),
			wantRule: ruleInter,
		},
		{
			// The gate reads a text_delta and accumulates nothing.
			name: "delta_Type_beside_type_in_cycle",
			stream: toolUse(0, "toolu_1") +
				vr16DeltaEvent(0, `{"type":"input_json_delta","partial_json":`+rmJSON+`,"Type":"text_delta"}`) +
				pvAnthropicStop(0),
			wantRule: ruleInter,
		},
		{
			// Idle, the gate reads a text_delta and forwards it; the SDKs
			// apply input to the tool_use gated with {}.
			name: "delta_Type_beside_type_after_gated_tool_use",
			stream: toolUse(0, "toolu_1") + pvAnthropicStop(0) +
				vr16DeltaEvent(0, `{"type":"input_json_delta","partial_json":`+rmJSON+`,"TYPE":"text_delta"}`),
			wantRule:  ruleInter,
			wantGated: 1,
		},
		{
			name: "delta_Text_beside_text",
			stream: pvAnthropicTextStart(0) +
				vr16DeltaEvent(0, `{"type":"text_delta","text":"hi","Text":"rm -rf /"}`) + pvAnthropicStop(0),
			wantRule: ruleInter,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
			before := metrics.LLMProxyProtocolViolationFor("anthropic")
			got := pvRunStream(t, "anthropic", vrMessageStart+c.stream+vr16MessageEnd, spy)

			if strings.Contains(got, "rm -rf /") {
				t.Errorf("ungated tool arguments reached the client: %q", got)
			}
			if !strings.Contains(got, c.wantRule) {
				t.Errorf("want a %s refusal; got %q", c.wantRule, got)
			}
			if n := metrics.LLMProxyProtocolViolationFor("anthropic") - before; n != 1 {
				t.Errorf("protocol violation counter moved by %d, want 1", n)
			}
			// Each gated cycle is one PolicyCheck; the refusal adds one
			// more, its audit entry (no RecordForcedAudit hook).
			calls := spy.seen()
			if len(calls) != c.wantGated+1 {
				t.Fatalf("PolicyCheck ran %d times, want %d gated cycle(s) + 1 refusal audit", len(calls), c.wantGated)
			}
			for _, call := range calls[:c.wantGated] {
				if call.ToolName != "bash" || string(call.RawArguments) != `{}` {
					t.Errorf("gate saw %s %s, want bash {}", call.ToolName, call.RawArguments)
				}
			}
		})
	}
}

// TestVR16_GenuineStreams_GatedAsBefore: conformant streams with client
// tool_use blocks, alone or beside provider-executed blocks, reach the
// client unchanged and each client tool_use is gated once with its own
// arguments.
func TestVR16_GenuineStreams_GatedAsBefore(t *testing.T) {
	webSearch := `{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{}}`
	webFetch := `{"type":"server_tool_use","id":"srvtoolu_1","name":"web_fetch","input":{}}`
	searchResult := `{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[]}`
	cases := []struct {
		name   string
		stream string
		want   []string // name + " " + raw arguments, per gated cycle
	}{
		{
			name: "two_client_tool_uses_at_0_and_1",
			stream: pvAnthropicToolStart(0, "toolu_1", "bash", `{}`) +
				pvAnthropicInputDelta(0, `{"command":`) + pvAnthropicInputDelta(0, `"ls"}`) + pvAnthropicStop(0) +
				pvAnthropicToolStart(1, "toolu_2", "read_file", `{}`) +
				pvAnthropicInputDelta(1, `{"path":"/tmp/x"}`) + pvAnthropicStop(1),
			want: []string{`bash {"command":"ls"}`, `read_file {"path":"/tmp/x"}`},
		},
		{
			name: "G1_mixed_genuine",
			stream: pvAnthropicTextStart(0) + pvAnthropicTextDelta(0, "Searching.") + pvAnthropicStop(0) +
				vrBlockStart(1, webSearch) + pvAnthropicInputDelta(1, "") +
				pvAnthropicInputDelta(1, `{"query":`) + pvAnthropicInputDelta(1, `"weather"}`) + pvAnthropicStop(1) +
				vrBlockStart(2, searchResult) + pvAnthropicStop(2) +
				pvAnthropicTextStart(3) + pvAnthropicTextDelta(3, "Now listing.") + pvAnthropicStop(3) +
				pvAnthropicToolStart(4, "toolu_9", "bash", `{}`) +
				pvAnthropicInputDelta(4, `{"command":`) + pvAnthropicInputDelta(4, `"ls"}`) + pvAnthropicStop(4),
			want: []string{`bash {"command":"ls"}`},
		},
		{
			name: "G2_tool_use_after_server_tool",
			stream: pvAnthropicTextStart(0) + pvAnthropicTextDelta(0, "x") + pvAnthropicStop(0) +
				vrBlockStart(1, webFetch) + pvAnthropicInputDelta(1, `{"url":"https://example.com"}`) + pvAnthropicStop(1) +
				pvAnthropicToolStart(2, "toolu_9", "bash", `{}`) + pvAnthropicInputDelta(2, `{"command":"ls"}`) + pvAnthropicStop(2),
			want: []string{`bash {"command":"ls"}`},
		},
		{
			name: "G3_tool_use_before_server_tool",
			stream: pvAnthropicToolStart(0, "toolu_9", "bash", `{}`) + pvAnthropicInputDelta(0, `{"command":"ls"}`) + pvAnthropicStop(0) +
				vrBlockStart(1, webSearch) + pvAnthropicInputDelta(1, `{"query":"q"}`) + pvAnthropicStop(1),
			want: []string{`bash {"command":"ls"}`},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stream := vrMessageStart + c.stream + vr16MessageEnd
			spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
			before := metrics.LLMProxyProtocolViolationFor("anthropic")
			got := pvRunStream(t, "anthropic", stream, spy)

			if got != stream {
				t.Errorf("stream altered\ngot =%q\nwant=%q", got, stream)
			}
			if n := metrics.LLMProxyProtocolViolationFor("anthropic") - before; n != 0 {
				t.Errorf("protocol violation counter moved by %d, want 0", n)
			}
			calls := spy.seen()
			if len(calls) != len(c.want) {
				t.Fatalf("PolicyCheck ran %d times, want %d", len(calls), len(c.want))
			}
			for i, call := range calls {
				if g := call.ToolName + " " + string(call.RawArguments); g != c.want[i] {
					t.Errorf("gated cycle %d = %s, want %s", i, g, c.want[i])
				}
			}
		})
	}
}
