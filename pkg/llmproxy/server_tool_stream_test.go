package llmproxy

// Provider-executed Anthropic blocks (server tools such as web_search,
// and the MCP connector's mcp_tool_use) stream their input as
// input_json_delta, like a client tool_use. The provider runs them and
// the client SDKs never execute them, so their deltas pass through; an
// input_json_delta with no block open at its index is still refused.

import (
	"fmt"
	"strings"
	"testing"
)

// vrBlockStart emits a content_block_start for an arbitrary block.
func vrBlockStart(index int, block string) string {
	return "event: content_block_start\n" + fmt.Sprintf(
		`data: {"type":"content_block_start","index":%d,"content_block":%s}`+"\n\n",
		index, block,
	)
}

const (
	vrServerToolUse = `{"type":"server_tool_use","id":"srvtoolu_vr10","name":"web_search","input":{}}`
	vrMCPToolUse    = `{"type":"mcp_tool_use","id":"mcptoolu_vr10","name":"echo","server_name":"example-mcp","input":{}}`
	vrSearchResult  = `{"type":"web_search_tool_result","tool_use_id":"srvtoolu_vr10","content":[]}`
)

// TestVR10_ProviderExecutedToolStreams_PassThroughUnchanged replays
// streams built from Anthropic's published format (provenance in each
// fixture's header) through the real proxy. The client must get the
// upstream bytes unchanged, and the gate must not run: neither the
// provider-executed call nor its result block is a client tool call.
func TestVR10_ProviderExecutedToolStreams_PassThroughUnchanged(t *testing.T) {
	for _, fx := range []string{
		"anthropic_streaming_server_web_search.txt",
		"anthropic_streaming_server_mcp_connector.txt",
	} {
		t.Run(fx, func(t *testing.T) {
			fixture := string(readFixture(t, fx))
			spy := &pvCallSpy{decision: Decision{Allow: false, Rule: "deny:test"}}
			got := pvRunStream(t, "anthropic", fixture, spy)
			if got != fixture {
				t.Errorf("stream altered (VR-10: provider-executed tool input refused as orphaned)\ngot =%q\nwant=%q", got, fixture)
			}
			if n := len(spy.seen()); n != 0 {
				t.Errorf("PolicyCheck ran %d times; a provider-executed block or its result was gated as a client tool call", n)
			}
		})
	}
}

// TestVR10_InputDeltaWithoutOpenProviderBlock_StillOrphaned keeps the
// orphan refusal for every input_json_delta that has no provider-executed
// block open at its own index.
func TestVR10_InputDeltaWithoutOpenProviderBlock_StillOrphaned(t *testing.T) {
	cases := []struct {
		name   string
		before []string
		delta  string
	}{
		{
			name:   "after_server_tool_use_stopped",
			before: []string{vrBlockStart(0, vrServerToolUse), pvAnthropicInputDelta(0, `{"query":"x"}`), pvAnthropicStop(0)},
			delta:  pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`),
		},
		{
			name:   "after_mcp_tool_use_stopped",
			before: []string{vrBlockStart(0, vrMCPToolUse), pvAnthropicStop(0)},
			delta:  pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`),
		},
		{
			name:   "other_index_than_open_server_tool_use",
			before: []string{vrBlockStart(0, vrServerToolUse)},
			delta:  pvAnthropicInputDelta(1, `{"command":"rm -rf /"}`),
		},
		{
			name:   "on_open_result_block",
			before: []string{vrBlockStart(2, vrSearchResult)},
			delta:  pvAnthropicInputDelta(2, `{"command":"rm -rf /"}`),
		},
		{
			name:   "on_open_unknown_block_type",
			before: []string{vrBlockStart(0, `{"type":"future_block","input":{}}`)},
			delta:  pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			acc := NewAnthropicAccumulator(0)
			for i, ev := range c.before {
				res, err := acc.FeedEvent([]byte(ev))
				if err != nil || !res.PassThrough {
					t.Fatalf("setup event %d: res=%+v err=%v, want PassThrough", i, res, err)
				}
			}
			res, err := acc.FeedEvent([]byte(c.delta))
			if err != nil {
				t.Fatalf("delta: %v", err)
			}
			if !res.ProtocolViolation || res.violation != violationOrphanedToolInput {
				t.Fatalf("delta returned %+v, want the orphaned_tool_input violation", res)
			}
		})
	}
}

// TestVR10_ClientToolUseAfterServerTool_StillGated: a client tool_use
// that follows a provider-executed block is gated as before, with its
// own arguments only.
func TestVR10_ClientToolUseAfterServerTool_StillGated(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_vr10","type":"message"}}` + "\n\n" +
		vrBlockStart(0, vrServerToolUse) +
		pvAnthropicInputDelta(0, `{"query":"weather"}`) +
		pvAnthropicStop(0) +
		vrBlockStart(1, vrSearchResult) +
		pvAnthropicStop(1) +
		pvAnthropicToolStart(2, "toolu_vr10", "bash", `{}`) +
		pvAnthropicInputDelta(2, `{"command":"rm -rf /"}`) +
		pvAnthropicStop(2)

	spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "blocked", Rule: "deny:test"}}
	got := pvRunStream(t, "anthropic", stream, spy)

	calls := spy.seen()
	if len(calls) != 1 {
		t.Fatalf("PolicyCheck ran %d times, want 1 (the client tool_use only)", len(calls))
	}
	if calls[0].ToolName != "bash" || calls[0].ToolCallID != "toolu_vr10" {
		t.Errorf("gated %q/%q, want bash/toolu_vr10", calls[0].ToolName, calls[0].ToolCallID)
	}
	if args := string(calls[0].RawArguments); args != `{"command":"rm -rf /"}` {
		t.Errorf("gated arguments = %q, want only the client tool_use's input", args)
	}
	if strings.Contains(got, "rm -rf /") {
		t.Errorf("denied tool_use arguments reached the client: %q", got)
	}
	if !strings.Contains(got, `\"query\":\"weather\"`) {
		t.Errorf("the provider-executed block's input was not forwarded: %q", got)
	}
}

// vrMessageStart opens a message the way the SDKs require.
const vrMessageStart = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"m","type":"message","role":"assistant","content":[],"model":"x","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}` + "\n\n"

// TestVR10_ReviewBypasses_Refused replays the review's streams. In each,
// both anthropic-python and @anthropic-ai/sdk end with a tool_use
// `bash {"command":"rm -rf /"}` the gate never evaluated: S1, S1b and
// S1d hand a provider-executed block's delta to an earlier client
// tool_use (the SDKs apply a delta to content[index]); S2 to S2e
// use a case-variant key that encoding/json folds onto the real one
// while the SDKs ignore it. The client must get a refusal, never the
// arguments, and every client tool_use the gate did see must have been
// evaluated with the arguments the client holds.
func TestVR10_ReviewBypasses_Refused(t *testing.T) {
	const rm = `{"command":"rm -rf /"}`
	toolUse := func(index int) string { return pvAnthropicToolStart(index, "toolu_1", "bash", `{}`) }
	cases := []struct {
		name      string
		stream    string
		wantRule  string
		wantGated int // client tool_use cycles the gate evaluated before the refusal
	}{
		{
			name: "S1_server_start_reuses_gated_tool_use_index",
			stream: toolUse(0) + pvAnthropicStop(0) +
				vrBlockStart(0, vrServerToolUse) + pvAnthropicInputDelta(0, rm) + pvAnthropicStop(0),
			wantRule:  "deny:llm_api_proxy:orphaned_tool_input",
			wantGated: 1,
		},
		{
			// The tool_use at content[1] with index 7 is itself out of
			// place, so the stream is refused there (VR-16), before the
			// server_tool_use's delta could reach it.
			name: "S1b_server_index_is_not_its_content_position",
			stream: vrBlockStart(0, vrServerToolUse) + pvAnthropicStop(0) +
				toolUse(7) + pvAnthropicStop(7) +
				vrBlockStart(1, vrServerToolUse) + pvAnthropicInputDelta(1, rm) + pvAnthropicStop(1),
			wantRule:  "deny:llm_api_proxy:tool_use_interleaved",
			wantGated: 0,
		},
		{
			// anthropic-python ignores a second message_start and keeps
			// the content, so it must not reset the index bookkeeping.
			name: "S1d_repeated_message_start_then_index_reuse",
			stream: toolUse(0) + pvAnthropicStop(0) + vrMessageStart +
				vrBlockStart(0, vrServerToolUse) + pvAnthropicInputDelta(0, rm) + pvAnthropicStop(0),
			wantRule:  "deny:llm_api_proxy:orphaned_tool_input",
			wantGated: 1,
		},
		{
			name: "S2_case_variant_Type_key_hides_tool_use",
			stream: vrBlockStart(0, `{"type":"tool_use","Type":"server_tool_use","id":"toolu_1","name":"bash","input":{}}`) +
				pvAnthropicInputDelta(0, rm) + pvAnthropicStop(0),
			wantRule: "deny:llm_api_proxy:tool_use_interleaved",
		},
		{
			name:     "S2b_case_variant_Type_key_hides_seeded_tool_use",
			stream:   vrBlockStart(0, `{"type":"tool_use","Type":"text","id":"toolu_1","name":"bash","input":`+rm+`}`) + pvAnthropicStop(0),
			wantRule: "deny:llm_api_proxy:tool_use_interleaved",
		},
		{
			name: "S2c_case_variant_content_block_key_hides_seeded_tool_use",
			stream: "event: content_block_start\n" +
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":` + rm + `},"Content_Block":{"type":"text","text":""}}` + "\n\n" +
				pvAnthropicStop(0),
			wantRule: "deny:llm_api_proxy:tool_use_interleaved",
		},
		{
			// The event's own type is case-variant, so a check inside
			// the content_block_start branch is never reached.
			name: "S2d_case_variant_event_Type_reads_as_ping",
			stream: "event: content_block_start\n" +
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":` + rm + `},"Type":"ping"}` + "\n\n" +
				pvAnthropicStop(0),
			wantRule: "deny:llm_api_proxy:tool_use_interleaved",
		},
		{
			name: "S2e_case_variant_event_TYPE_reads_as_unknown",
			stream: "event: content_block_start\n" +
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":` + rm + `},"TYPE":"zzz"}` + "\n\n" +
				pvAnthropicStop(0),
			wantRule: "deny:llm_api_proxy:tool_use_interleaved",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
			got := pvRunStream(t, "anthropic", vrMessageStart+c.stream, spy)

			if strings.Contains(got, `rm -rf /`) {
				t.Errorf("ungated tool arguments reached the client: %q", got)
			}
			if !strings.Contains(got, c.wantRule) {
				t.Errorf("want a %s refusal; got %q", c.wantRule, got)
			}
			// Each gated cycle is one PolicyCheck; the refusal adds one
			// more, the audit fallback (no RecordForcedAudit hook).
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
