package llmproxy

// Lenient tool-call detection for non-streaming bodies the typed
// decoders reject.
//
// Such bodies are normally forwarded verbatim, but encoding/json fails
// on a type-mismatched field (`"created":"1730000000"`) that a Python or
// TypeScript SDK ignores while executing the tool_calls next to it. An
// OpenAI-compatible shim (vLLM, Ollama, LiteLLM) that stringifies one
// numeric field is enough; no attacker needed. (A JSON null or an extra
// field does not fail the decode, so only wrong-typed values land here.)
//
// The probe types declare only the path to the tool-call array, so no
// sibling field can fail the decode: the probe constrains nothing a
// lenient client wouldn't. A substring search for "tool_calls" would
// also match model prose and refuse ordinary answers.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

// openAIToolCallProbe declares only choices[].message.tool_calls.
type openAIToolCallProbe struct {
	Choices []struct {
		Message struct {
			ToolCalls    []json.RawMessage `json:"tool_calls"`
			FunctionCall json.RawMessage   `json:"function_call"`
		} `json:"message"`
	} `json:"choices"`
}

// anthropicToolUseProbe declares only content[].type.
type anthropicToolUseProbe struct {
	Content []struct {
		Type string `json:"type"`
	} `json:"content"`
}

// hasLenientToolCall reports whether a body the strict decoder rejected
// still carries a tool call. False (no tool call, unreadable even to the
// probe, or unknown provider) means the caller forwards verbatim.
func hasLenientToolCall(body []byte, provider string) bool {
	// A UTF-8 BOM fails encoding/json, but Python's json.loads(bytes)
	// and other SDK decoders skip it and execute the calls behind it.
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	switch provider {
	case "openai":
		var p openAIToolCallProbe
		if err := json.Unmarshal(body, &p); err != nil {
			return false
		}
		for i := range p.Choices {
			m := p.Choices[i].Message
			if len(m.ToolCalls) > 0 || hasJSONValue(m.FunctionCall) {
				return true
			}
		}
		return false

	case "anthropic":
		var p anthropicToolUseProbe
		if err := json.Unmarshal(body, &p); err != nil {
			return false
		}
		for i := range p.Content {
			if p.Content[i].Type == "tool_use" {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// hasJSONValue reports whether raw holds a value other than null.
func hasJSONValue(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

// undecodableToolCallDecision refuses an undecodable body that carries
// a tool call. Not subject to --fail-mode allow (like the duplicate-key
// refusal): fail-mode covers an unreachable guard, not a guard that
// cannot see what the client will execute.
func undecodableToolCallDecision(provider string) Decision {
	return Decision{
		Allow: false,
		Reason: "upstream response carries a tool call but does not decode as a valid " +
			provider + " response; refused rather than forwarded ungated",
		Rule: "deny:llm_api_proxy:undecodable_tool_call",
	}
}

// auditNonStreamingRefusal records a gated non-streaming refusal
// centrally, so it leaves a trace beyond the client's response: the
// proxy's metrics registry has no scrape endpoint
// (docs/OBSERVABILITY.md). The entry has no tool name or arguments
// (nothing was decoded), only rule, tenant and agent. With a nil
// RecordForcedAudit it falls back to PolicyCheck (engine verdict,
// ignored).
func (s *Server) auditNonStreamingRefusal(r *http.Request, provider, model string, decision Decision) {
	check := ToolCallCheck{
		Provider:        provider,
		Model:           model,
		TenantID:        s.cfg.TenantID,
		AgentID:         strings.TrimSpace(r.Header.Get("X-Agent-ID")),
		SessionID:       strings.TrimSpace(r.Header.Get("X-Session-ID")),
		ParentSessionID: strings.TrimSpace(r.Header.Get(ParentSessionHeader)),
		Stream:          false,
	}
	if check.AgentID == "" {
		check.AgentID = "llm-proxy"
	}
	if s.RecordForcedAudit != nil {
		s.RecordForcedAudit(r.Context(), &check, decision)
		return
	}
	_, _ = s.runPolicyCheck(r.Context(), check)
}
