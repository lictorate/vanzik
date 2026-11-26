package llmproxy

// @anthropic-ai/sdk drops one UTF-8 BOM from the start of every SSE line
// it splits, so a BOM-prefixed line is an event or data line to it;
// anthropic-python keeps the BOM and ignores the line. The clients
// disagree on what such a stream holds, so a client tool_use in it is
// refused (undecodable_tool_call), as VR-15 does for OpenAI streams.
// Without this, the gate checked `{"command":"ls"}` while
// @anthropic-ai/sdk received a second, BOM-hidden input delta and held
// `{"command":"ls","command":"rm -rf /tmp/vzx"}` (rig scenario a_cr_bom,
// and its LF form below).

import (
	"strings"
	"testing"
)

const anthropicBOMMessageStart = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}` + "\n\n"

func TestAnthropicBOMStream_WithToolUse_IsRefused(t *testing.T) {
	start := pvAnthropicToolStart(0, "toolu_1", "bash", "{}")
	end := pvAnthropicStop(0) + vr16MessageEnd
	for _, tc := range []struct{ name, stream string }{
		{"BOM as the first bytes", bomPrefix + anthropicBOMMessageStart + start +
			pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`) + end},
		{"tool_use start on a BOM line", anthropicBOMMessageStart + "event: content_block_start\n" + bomPrefix +
			strings.TrimPrefix(start, "event: content_block_start\n") +
			pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`) + end},
		{"input delta on a BOM line during the cycle", anthropicBOMMessageStart + start +
			pvAnthropicInputDelta(0, `{"command":"ls"`) +
			"event: content_block_delta\n" + bomPrefix + strings.TrimPrefix(pvAnthropicInputDelta(0, `,"command":"rm -rf /"`), "event: content_block_delta\n") +
			pvAnthropicInputDelta(0, `}`) + end},
		{"BOM on an event line only", anthropicBOMMessageStart + bomPrefix + start +
			pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`) + end},
		{"BOM-only line inside the cycle", anthropicBOMMessageStart + start +
			pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`) + bomPrefix + "\n" + end},
		{"BOM line after a text block, then a tool_use", anthropicBOMMessageStart + pvAnthropicTextStart(0) +
			bomPrefix + pvAnthropicTextDelta(0, "hi") + pvAnthropicStop(0) +
			pvAnthropicToolStart(1, "toolu_1", "bash", "{}") + pvAnthropicInputDelta(1, `{"command":"rm -rf /"}`) +
			pvAnthropicStop(1) + vr16MessageEnd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, spy := runStreamWithAudit(t, "anthropic", tc.stream, 0)
			if strings.Contains(got, "rm -rf") {
				t.Errorf("the call reached the client: %q", got)
			}
			if !strings.Contains(got, ruleUndecodable) {
				t.Fatalf("want the %s refusal; got %q", ruleUndecodable, got)
			}
			if !strings.HasSuffix(got, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n") {
				t.Errorf("refusal does not close the message: %q", got)
			}
			if c := assertAudited(t, spy, ruleUndecodable, "anthropic"); c.ToolName != "bash" {
				t.Errorf("audited tool name = %q, want bash", c.ToolName)
			}
		})
	}
}

// A BOM stream with no client tool_use has nothing to gate: forwarded
// byte-identical, BOMs included.
func TestAnthropicBOMStream_TextOnly_IsForwardedUnchanged(t *testing.T) {
	for _, stream := range []string{
		bomPrefix + anthropicBOMMessageStart + pvAnthropicTextStart(0) + pvAnthropicTextDelta(0, "hello") +
			pvAnthropicStop(0) + vr16MessageEnd,
		anthropicBOMMessageStart + pvAnthropicTextStart(0) + bomPrefix + pvAnthropicTextDelta(0, "hello") +
			pvAnthropicStop(0) + vr16MessageEnd,
	} {
		got, spy := runStreamWithAudit(t, "anthropic", stream, 0)
		if got != stream {
			t.Errorf("text-only BOM stream changed:\n got %q\nwant %q", got, stream)
		}
		if n := len(spy.recorded()); n != 0 {
			t.Errorf("text-only BOM stream audited %d refusals", n)
		}
	}
}
