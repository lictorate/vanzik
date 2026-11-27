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

// openAIStreamToolCallProbe is openAIToolCallProbe for a stream chunk:
// choices[].delta.tool_calls and choices[].delta.function_call.
type openAIStreamToolCallProbe struct {
	Choices []struct {
		Delta struct {
			ToolCalls    []json.RawMessage `json:"tool_calls"`
			FunctionCall json.RawMessage   `json:"function_call"`
		} `json:"delta"`
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
			// SECURITY: the probe cannot read the body either: a
			// wrong-typed choices element (`[{...}, 5]`) or a NaN or
			// Infinity literal, which Python's json accepts. openai-python
			// (and openai-node for the type error) still run the call, so
			// decide on the keys alone (O-4).
			return hasToolCallMarker(body, openAIToolCallMarkers)
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
			// SECURITY: as for OpenAI. anthropic-python reads a NaN or
			// Infinity literal and its tool runner runs the call;
			// @anthropic-ai/sdk runs one beside a wrong-typed content
			// element (N5).
			return hasToolCallMarker(body, anthropicToolUseMarkers)
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

// undecodableStreamEventHasToolCall reports whether an OpenAI stream
// event whose data the parser could not decode carries a tool call, as
// hasLenientToolCall does for a body: by the stream probe when it can
// read the data, else by the keys alone.
func undecodableStreamEventHasToolCall(event []byte) bool {
	data, _, hasData := extractOpenAIDataLine(event)
	if !hasData {
		return false
	}
	var p openAIStreamToolCallProbe
	if err := json.Unmarshal(data, &p); err != nil {
		return hasToolCallMarker(data, openAIToolCallMarkers)
	}
	for i := range p.Choices {
		d := p.Choices[i].Delta
		if len(d.ToolCalls) > 0 || hasJSONValue(d.FunctionCall) {
			return true
		}
	}
	return false
}

// openAIToolCallMarkers are the keys an OpenAI client reads calls from.
var openAIToolCallMarkers = [][]byte{[]byte("tool_calls"), []byte("function_call")}

// anthropicToolUseMarkers is the content block type a client runs.
var anthropicToolUseMarkers = [][]byte{[]byte("tool_use")}

// hasToolCallMarker reports whether data, JSON that may not parse, holds
// a string that unescapes to one of markers up to case: Python and JS
// decode `"tool\u005fcalls"` to tool_calls, and encoding/json folds
// keys with Unicode simple folding (strings.EqualFold, so the Kelvin
// sign matches k). Keys and values both count: a body the probe cannot
// read is refused if it could hold a call, never forwarded unread.
func hasToolCallMarker(data []byte, markers [][]byte) bool {
	maxRaw := 0
	for _, m := range markers {
		maxRaw = max(maxRaw, 6*len(m)) // every byte spelled as \uXXXX
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		start, escaped := i+1, false
		j := start
		for ; j < len(data) && data[j] != '"'; j++ {
			if data[j] == '\\' {
				escaped = true
				j++
			}
		}
		if j >= len(data) {
			return false // unterminated string: no client parses this body
		}
		if tok := data[start:j]; len(tok) <= maxRaw {
			s := tok
			if escaped {
				var v string
				if json.Unmarshal(data[start-1:j+1], &v) != nil {
					i = j
					continue
				}
				s = []byte(v)
			}
			for _, m := range markers {
				if bytes.EqualFold(s, m) {
					return true
				}
			}
		}
		i = j
	}
	return false
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
