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
			before: []string{vrBlockStart(1, vrServerToolUse), pvAnthropicInputDelta(1, `{"query":"x"}`), pvAnthropicStop(1)},
			delta:  pvAnthropicInputDelta(1, `{"command":"rm -rf /"}`),
		},
		{
			name:   "after_mcp_tool_use_stopped",
			before: []string{vrBlockStart(1, vrMCPToolUse), pvAnthropicStop(1)},
			delta:  pvAnthropicInputDelta(1, `{"command":"rm -rf /"}`),
		},
		{
			name:   "other_index_than_open_server_tool_use",
			before: []string{vrBlockStart(1, vrServerToolUse)},
			delta:  pvAnthropicInputDelta(2, `{"command":"rm -rf /"}`),
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
