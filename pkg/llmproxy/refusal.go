package llmproxy

// Production refusal builder (shapes: docs/LLM_API_PROXY.md § 5.4).
// Unlike defaultRefusalBytes, the text names the rule that fired and,
// for REQUIRE_APPROVAL, the approval URL and the approval id to send
// back in ApprovalIDHeader on retry.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BuildRefusalRich implements Server.BuildRefusal for both streaming
// and non-streaming (ctx.NonStreaming) refusals. It never returns an
// empty slice: that would leave the stream open and hang SDK clients.
func BuildRefusalRich(provider string, decision Decision, ctx *RefusalContext) []byte {
	msg := buildRefusalMessage(decision)
	nonStreaming := ctx != nil && ctx.NonStreaming
	model := ""
	if ctx != nil {
		model = ctx.Model
	}

	switch provider {
	case "openai":
		if nonStreaming {
			return buildOpenAIRefusalNonStreaming(msg, model)
		}
		return buildOpenAIRefusalSSE(msg)
	case "anthropic":
		if nonStreaming {
			return buildAnthropicRefusalNonStreaming(msg, model)
		}
		idx := 0
		if ctx != nil && ctx.AnthropicToolUseIndex >= 0 {
			idx = ctx.AnthropicToolUseIndex
		}
		return buildAnthropicRefusalSSE(msg, idx)
	default:
		// Unknown provider: the OpenAI shape is the most widely accepted.
		if nonStreaming {
			return buildOpenAIRefusalNonStreaming(msg, model)
		}
		return buildOpenAIRefusalSSE(msg)
	}
}

// buildRefusalMessage builds the refusal text. Tests assert the exact
// copy.
func buildRefusalMessage(d Decision) string {
	if d.Rule == "deny:llm_api_proxy:buffer_overflow" {
		return buildOverflowMessage(d)
	}

	var b strings.Builder
	b.WriteString("Vanzik ")

	if d.RequiresApproval || d.ApprovalURL != "" || d.ApprovalID != "" {
		b.WriteString("paused this action pending human approval.")
		b.WriteString("\n\nReason: ")
		b.WriteString(refusalReasonOrDefault(d, "policy required human approval"))
		if d.Rule != "" {
			b.WriteString("\nRule: ")
			b.WriteString(d.Rule)
		}
		if d.ApprovalURL != "" {
			b.WriteString("\n\nApproval URL: ")
			b.WriteString(d.ApprovalURL)
		}
		if d.ApprovalID != "" {
			b.WriteString("\nApproval ID: ")
			b.WriteString(d.ApprovalID)
			b.WriteString(" (send it in the " + ApprovalIDHeader + " header on retry to resume after approval)")
		}
		b.WriteString("\n\nWait for human approval, then retry the same call.")
		return b.String()
	}

	b.WriteString("denied this action.")
	b.WriteString("\n\nReason: ")
	b.WriteString(refusalReasonOrDefault(d, "tool call denied by Vanzik policy"))
	if d.Rule != "" {
		b.WriteString("\nRule: ")
		b.WriteString(d.Rule)
	}
	return b.String()
}

// buildOverflowMessage names --max-buffer-bytes so the fix is obvious.
func buildOverflowMessage(d Decision) string {
	var b strings.Builder
	b.WriteString("Vanzik refused this tool call: its accumulated arguments exceeded the gating buffer cap.")
	b.WriteString("\n\nReason: ")
	b.WriteString(refusalReasonOrDefault(d, "tool call arguments exceed gating buffer"))
	b.WriteString("\nRule: ")
	if d.Rule != "" {
		b.WriteString(d.Rule)
	} else {
		b.WriteString("deny:llm_api_proxy:buffer_overflow")
	}
	b.WriteString("\n\nThe per-stream buffer is bounded by the proxy's --max-buffer-bytes flag (default 1 MiB).")
	b.WriteString(" Operators who legitimately need larger tool-call arguments can raise the cap, ")
	b.WriteString("but the more common cause is a model emitting runaway JSON; consider asking the agent to summarise.")
	return b.String()
}

// refusalReasonOrDefault returns d.Reason when non-empty, else fallback.
func refusalReasonOrDefault(d Decision, fallback string) string {
	if d.Reason != "" {
		return d.Reason
	}
	return fallback
}

// buildOpenAIRefusalSSE emits one assistant content delta with
// finish_reason "stop", then [DONE]. Not role "tool": SDKs hang on the
// missing tool_call_id.
func buildOpenAIRefusalSSE(message string) []byte {
	payload := map[string]interface{}{
		"id":      "vanzik-refusal",
		"object":  "chat.completion.chunk",
		"created": 0,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"delta": map[string]interface{}{
					"role":    "assistant",
					"content": message,
				},
				"finish_reason": "stop",
			},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		// Unreachable for this map; keeps the stream well-formed.
		fallback, _ := json.Marshal(map[string]string{"error": "vanzik refusal marshal failed"})
		return []byte("data: " + string(fallback) + "\n\ndata: [DONE]\n\n")
	}
	return []byte("data: " + string(b) + "\n\ndata: [DONE]\n\n")
}

// buildOpenAIRefusalNonStreaming emits a chat.completion object with no
// tool_calls and finish_reason "stop", so SDKs see a normal final
// assistant turn. Empty model becomes "vanzik-refusal".
func buildOpenAIRefusalNonStreaming(message, model string) []byte {
	if model == "" {
		model = "vanzik-refusal"
	}
	payload := map[string]interface{}{
		"id":      "vanzik-refusal",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": message,
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]interface{}{
			"prompt_tokens":     0,
			"completion_tokens": 0,
			"total_tokens":      0,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		// Unreachable for this map; keeps the response decodable.
		return []byte(`{"id":"vanzik-refusal","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Vanzik refusal"},"finish_reason":"stop"}]}`)
	}
	return b
}

// buildAnthropicRefusalNonStreaming emits a message with one text block
// and stop_reason "end_turn", so the SDK expects no tool result.
func buildAnthropicRefusalNonStreaming(message, model string) []byte {
	if model == "" {
		model = "vanzik-refusal"
	}
	payload := map[string]interface{}{
		"id":    "vanzik-refusal",
		"type":  "message",
		"role":  "assistant",
		"model": model,
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": message,
			},
		},
		"stop_reason": "end_turn",
		"usage": map[string]interface{}{
			"input_tokens":  0,
			"output_tokens": 0,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return []byte(`{"id":"vanzik-refusal","type":"message","role":"assistant","content":[{"type":"text","text":"Vanzik refusal"}],"stop_reason":"end_turn"}`)
	}
	return b
}

// buildAnthropicRefusalSSE emits a text block at toolUseIndex (the
// tool_use's own content_block_start was discarded with the buffer, so
// the client sees this start first), then message_delta with
// stop_reason "end_turn" so no tool result is expected, then
// message_stop.
func buildAnthropicRefusalSSE(message string, toolUseIndex int) []byte {
	var buf bytes.Buffer

	emit := func(eventName string, payload map[string]interface{}) {
		body, err := json.Marshal(payload)
		if err != nil {
			body = []byte(`{"error":"vanzik refusal marshal failed"}`)
		}
		fmt.Fprintf(&buf, "event: %s\ndata: %s\n\n", eventName, string(body))
	}

	emit("content_block_start", map[string]interface{}{
		"type":  "content_block_start",
		"index": toolUseIndex,
		"content_block": map[string]interface{}{
			"type": "text",
			"text": "",
		},
	})

	emit("content_block_delta", map[string]interface{}{
		"type":  "content_block_delta",
		"index": toolUseIndex,
		"delta": map[string]interface{}{
			"type": "text_delta",
			"text": message,
		},
	})

	emit("content_block_stop", map[string]interface{}{
		"type":  "content_block_stop",
		"index": toolUseIndex,
	})

	// usage is required: the Anthropic SDKs' stream accumulators read
	// usage.output_tokens on every message_delta and raise without it.
	emit("message_delta", map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason": "end_turn",
		},
		"usage": map[string]interface{}{
			"output_tokens": 0,
		},
	})

	emit("message_stop", map[string]interface{}{
		"type": "message_stop",
	})

	return buf.Bytes()
}
