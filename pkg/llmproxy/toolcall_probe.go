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
// The probe types declare only the paths to the tool calls (OpenAI
// tool_calls and the legacy function_call), so no sibling field can
// fail the decode: the probe constrains nothing a lenient client
// wouldn't. A substring search for "tool_calls" would also match model
// prose and refuse ordinary answers.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// openAIToolCallProbe declares only choices[].message.tool_calls and
// choices[].message.function_call.
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
	body = jsonTextAsUTF8(body)
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

// utf8BOM is the UTF-8 byte order mark.
var utf8BOM = []byte("\xef\xbb\xbf")

// jsonTextAsUTF8 returns body as the UTF-8 text a lenient client
// decodes. encoding/json reads only UTF-8 and rejects a BOM, but
// Python's json.loads(bytes) (openai-python, anthropic-python) skips a
// UTF-8 BOM and detects UTF-16 and UTF-32 the way RFC 4627 §3 describes:
// by BOM, else by where the first bytes are zero (JSON text starts with
// an ASCII character). Such a body is transcoded; any other is returned
// as is. Invalid code units become U+FFFD where Python would raise, so
// at worst the probe sees a call no client runs and refuses.
func jsonTextAsUTF8(body []byte) []byte {
	be, le := binary.BigEndian, binary.LittleEndian
	switch {
	case bytes.HasPrefix(body, []byte("\x00\x00\xfe\xff")):
		return utf32ToUTF8(body[4:], be)
	case bytes.HasPrefix(body, []byte("\xff\xfe\x00\x00")):
		return utf32ToUTF8(body[4:], le)
	case bytes.HasPrefix(body, []byte("\xfe\xff")):
		return utf16ToUTF8(body[2:], be)
	case bytes.HasPrefix(body, []byte("\xff\xfe")):
		return utf16ToUTF8(body[2:], le)
	case bytes.HasPrefix(body, utf8BOM):
		return body[len(utf8BOM):]
	case len(body) < 4:
		// Too short to hold a tool call in any encoding.
		return body
	case body[0] == 0 && body[1] != 0:
		return utf16ToUTF8(body, be)
	case body[0] == 0:
		return utf32ToUTF8(body, be)
	case body[1] == 0 && (body[2] != 0 || body[3] != 0):
		return utf16ToUTF8(body, le)
	case body[1] == 0:
		return utf32ToUTF8(body, le)
	}
	return body
}

func utf16ToUTF8(b []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = order.Uint16(b[2*i:])
	}
	return []byte(string(utf16.Decode(units)))
}

func utf32ToUTF8(b []byte, order binary.ByteOrder) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i+4 <= len(b); i += 4 {
		out = utf8.AppendRune(out, rune(order.Uint32(b[i:])))
	}
	return out
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
