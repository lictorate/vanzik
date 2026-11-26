package llmproxy

// Anthropic Messages streaming parser and tool_use accumulator (wire
// format: docs/LLM_API_PROXY.md § 5.2). The parser discriminates on the
// JSON `type` field, not the `event:` line, so a missing `event:` line
// is tolerated. tool_use input arrives as input_json_delta.partial_json
// fragments, concatenated verbatim and parsed at content_block_stop.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// anthropicEventEnvelope types only the fields the parser reads.
type anthropicEventEnvelope struct {
	Type         string                      `json:"type"`
	Index        int                         `json:"index,omitempty"`
	ContentBlock *anthropicContentBlockShape `json:"content_block,omitempty"`
	Delta        *anthropicEventDeltaShape   `json:"delta,omitempty"`
}

// anthropicEvent is an event as readAnthropicEvent reads it. Block and
// Delta are values, valid when HasBlock / HasDelta, so reading an event
// allocates nothing for them.
type anthropicEvent struct {
	Type     string
	Index    int
	HasBlock bool
	Block    anthropicContentBlockShape
	HasDelta bool
	Delta    anthropicEventDeltaShape
}

// anthropicContentBlockShape is content_block_start's content_block.
type anthropicContentBlockShape struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	Text  string          `json:"text,omitempty"`
}

// anthropicEventDeltaShape covers text_delta, input_json_delta and
// message_delta (stop_reason) payloads.
type anthropicEventDeltaShape struct {
	Type        string `json:"type,omitempty"`
	Text        string `json:"text,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"`
	StopReason  string `json:"stop_reason,omitempty"`
}

// anthropicProviderExecutedBlocks holds the content block types whose
// call the provider runs itself: server tools (web search, web fetch,
// code execution, tool search) arrive as server_tool_use, MCP connector
// calls as mcp_tool_use. They stream their input as input_json_delta
// like a client tool_use, but no client SDK executes them, so the
// parser forwards those deltas instead of refusing them as orphaned.
// A new provider-executed type needs only an entry here. Result blocks
// (web_search_tool_result, mcp_tool_result, ...) arrive whole, with no
// input deltas, so they need no entry.
// Docs: https://platform.claude.com/docs/en/agents-and-tools/tool-use/server-tools
// and https://platform.claude.com/docs/en/agents-and-tools/mcp-connector
var anthropicProviderExecutedBlocks = map[string]bool{
	"server_tool_use": true,
	"mcp_tool_use":    true,
}

// anthropicBlockState tracks one content block; only tool_use gates.
type anthropicBlockState struct {
	Index     int
	Type      string // content_block.type, e.g. "text", "tool_use", "server_tool_use"
	ID        string
	Name      string
	InputJSON bytes.Buffer
	Closed    bool
	// startSeeded: arguments came from a non-empty
	// content_block_start.input. Conformant streams send `{}` there and
	// use input_json_delta, so a later delta for a seeded block is a
	// conflict and fails closed.
	startSeeded bool
	// inPlace: the block's index was its position in the message's
	// content when it started, and no earlier block used that index.
	// The SDKs apply a delta to content[index], so only then does a
	// delta reach this block and not an earlier one.
	inPlace bool
}

// AnthropicAccumulator is the Anthropic counterpart of
// OpenAIToolCallAccumulator, with the same FeedResult contract.
//
// From a tool_use's content_block_start until its content_block_stop,
// every event is buffered, including non-input deltas for other blocks:
// forwarding them while holding the tool_use would reorder the stream,
// which some clients don't tolerate. An input_json_delta for another
// block is refused instead (see FeedEvent).
type AnthropicAccumulator struct {
	maxBufferBytes int

	blocks map[int]*anthropicBlockState

	// activeToolUseIndex is the buffering tool_use's index, or -1.
	activeToolUseIndex int

	// completed latches once the cycle has signalled Completed, so
	// CloseAtEOF cannot complete it again. Reset clears it.
	completed bool

	bufferedEvents [][]byte
	bufferedBytes  int

	// startCount and startIndexes record every content_block_start of
	// the message. Reset keeps them: the client keeps every block of
	// the message, including those of finished cycles. One accumulator
	// serves one stream, and a stream carries one message. They are not
	// cleared on a repeated message_start: anthropic-python ignores one
	// and keeps the content it already has, and @anthropic-ai/sdk
	// rejects one outright.
	startCount   int
	startIndexes map[int]bool

	// messageStarted: a message_start has been passed to the client. A
	// refusal before one must open the stream itself: both SDKs reject
	// a stream that does not start with message_start.
	messageStarted bool
}

// NewAnthropicAccumulator returns an accumulator with the given
// per-stream buffer cap; <= 0 means no cap.
func NewAnthropicAccumulator(maxBufferBytes int) *AnthropicAccumulator {
	return &AnthropicAccumulator{
		maxBufferBytes:     maxBufferBytes,
		blocks:             map[int]*anthropicBlockState{},
		activeToolUseIndex: -1,
		startIndexes:       map[int]bool{},
	}
}

// BufferedEvents returns the held raw events. Read-only.
func (a *AnthropicAccumulator) BufferedEvents() [][]byte {
	return a.bufferedEvents
}

// MessageStarted reports whether a message_start has been passed on.
func (a *AnthropicAccumulator) MessageStarted() bool {
	return a.messageStarted
}

// ActiveToolUseIndex returns the buffering tool_use's block index, or
// -1, for RefusalContext.AnthropicToolUseIndex.
func (a *AnthropicAccumulator) ActiveToolUseIndex() int {
	return a.activeToolUseIndex
}

// Reset clears state for the next tool_use in the same message.
func (a *AnthropicAccumulator) Reset() {
	a.blocks = map[int]*anthropicBlockState{}
	a.activeToolUseIndex = -1
	a.bufferedEvents = nil
	a.bufferedBytes = 0
	a.completed = false
}

// complete assembles the active block and latches `completed`. Every
// Completed result goes through here.
func (a *AnthropicAccumulator) complete() (FeedResult, error) {
	a.completed = true
	calls, parseErr := a.assembleCompletedCalls()
	return FeedResult{
		Completed:          true,
		CompletedToolCalls: calls,
	}, parseErr
}

// CloseAtEOF completes a tool_use still open at EOF (no
// content_block_stop); see OpenAIToolCallAccumulator.CloseAtEOF.
func (a *AnthropicAccumulator) CloseAtEOF() (FeedResult, error) {
	if a.activeToolUseIndex < 0 || a.completed {
		return FeedResult{}, nil
	}
	return a.complete()
}

// pendingIdentity returns the open tool_use's name and id, or empty
// strings; see OpenAIToolCallAccumulator.pendingIdentity.
func (a *AnthropicAccumulator) pendingIdentity() (name, id string) {
	if a.activeToolUseIndex < 0 {
		return "", ""
	}
	st := a.blocks[a.activeToolUseIndex]
	if st == nil {
		return "", ""
	}
	return st.Name, st.ID
}

// FeedEvent ingests one complete raw SSE event; same contract as
// OpenAIToolCallAccumulator.FeedEvent.
func (a *AnthropicAccumulator) FeedEvent(rawEvent []byte) (FeedResult, error) {
	dataLine, hasData := extractAnthropicDataLine(rawEvent)
	if !hasData {
		if a.activeToolUseIndex >= 0 {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil
	}

	// encoding/json still decides which events are well formed: one it
	// cannot decode into the envelope (a string index, a numeric
	// partial_json) is dropped, as before. Its values are not used.
	if err := json.Unmarshal(dataLine, new(anthropicEventEnvelope)); err != nil {
		return FeedResult{}, fmt.Errorf("anthropic parser: malformed event JSON: %w", err)
	}

	// SECURITY: encoding/json matches keys case-insensitively and the
	// client SDKs match them exactly, so a `"Type"` beside `"type"`
	// makes the gate and the client read different values: event or
	// block types, indexes, ids, names, inputs. No reading is safe;
	// refuse. The event's own keys are checked here, before the switch,
	// because the switch trusts the decoded type. The same input just
	// decoded, so this decode cannot fail.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(dataLine, &fields)
	if hasCaseVariantKey(fields, anthropicEventKeys[:]) {
		return FeedResult{ProtocolViolation: true, violation: violationInterleavedToolUse}, nil
	}
	// SECURITY: every value the switch reads comes from these maps, as
	// the client SDKs read it, never from a struct decode (see
	// readAnthropicEvent).
	env, block, delta, ok := readAnthropicEvent(fields)
	if !ok {
		return FeedResult{ProtocolViolation: true, violation: violationInterleavedToolUse}, nil
	}

	switch env.Type {
	case "content_block_start":
		if hasCaseVariantKey(block, anthropicBlockKeys[:]) {
			return FeedResult{ProtocolViolation: true, violation: violationInterleavedToolUse}, nil
		}
		inPlace := env.Index == a.startCount && !a.startIndexes[env.Index]
		a.startCount++
		a.startIndexes[env.Index] = true
		if env.HasBlock && env.Block.Type == "tool_use" {
			// SECURITY: a second tool_use opening while one buffers
			// would be flushed when the first cycle Resets, and its
			// remaining deltas would pass ungated. One cycle cannot gate
			// two blocks, so refuse the stream. A tool_use out of place
			// is refused too: the gate reads the deltas sent at its
			// index, and the SDKs apply them to content[index], another
			// block, while this one keeps the start's input.
			if a.activeToolUseIndex >= 0 || !inPlace {
				return FeedResult{ProtocolViolation: true, violation: violationInterleavedToolUse}, nil
			}
			st := &anthropicBlockState{
				Index: env.Index,
				Type:  "tool_use",
				ID:    env.Block.ID,
				Name:  env.Block.Name,
			}
			// SECURITY: an adversarial upstream can put the real
			// arguments in the start event's input and send no delta.
			// Client SDKs seed tool input from it, so the gate must too.
			// Emptiness is structural: `{ }` is empty, and treating it
			// as a seed would trip the conflict check on the first
			// conformant input_json_delta.
			if seed := bytes.TrimSpace(env.Block.Input); len(seed) > 0 && !isEmptyJSONObject(seed) {
				st.InputJSON.Write(seed)
				st.startSeeded = true
			}
			a.blocks[env.Index] = st
			if a.activeToolUseIndex < 0 {
				a.activeToolUseIndex = env.Index
			}
			return a.appendBuffered(rawEvent)
		}
		// Non-tool_use block-start.
		if a.activeToolUseIndex >= 0 {
			return a.appendBuffered(rawEvent)
		}
		if env.HasBlock {
			a.blocks[env.Index] = &anthropicBlockState{
				Index:   env.Index,
				Type:    env.Block.Type,
				inPlace: inPlace,
			}
		}
		return FeedResult{PassThrough: true}, nil

	case "content_block_delta":
		// SECURITY: the delta object's keys get the event's case-variant
		// check: `"Type":"text_delta"` beside `"type":"input_json_delta"`
		// would hide arguments from the gate that the SDKs apply.
		if hasCaseVariantKey(delta, anthropicDeltaKeys[:]) {
			return FeedResult{ProtocolViolation: true, violation: violationInterleavedToolUse}, nil
		}
		isInput := env.Delta.Type == "input_json_delta"
		if a.activeToolUseIndex >= 0 {
			// SECURITY: an input delta for another index would be
			// flushed after this cycle's gate, unread by it, and the SDKs
			// would apply it to that block, possibly a tool_use an
			// earlier cycle already gated.
			if isInput && env.Index != a.activeToolUseIndex {
				return FeedResult{ProtocolViolation: true, violation: violationOrphanedToolInput}, nil
			}
			if isInput && env.Delta.PartialJSON != "" {
				st := a.blocks[env.Index]
				if st == nil {
					// Unreachable (start precedes delta); defensive.
					st = &anthropicBlockState{Index: env.Index, Type: "tool_use"}
					a.blocks[env.Index] = st
				}
				// SECURITY: seeded start input plus deltas would
				// concatenate into invalid JSON the gate cannot
				// evaluate faithfully. Conformant streams never do both.
				if st.startSeeded {
					return FeedResult{ProtocolViolation: true, violation: violationInterleavedToolUse}, nil
				}
				projected := totalAnthropicArgsLen(a.blocks) + len(env.Delta.PartialJSON)
				if a.maxBufferBytes > 0 && projected > a.maxBufferBytes {
					return FeedResult{OverflowBufferBytes: true}, nil
				}
				st.InputJSON.WriteString(env.Delta.PartialJSON)
			}
			return a.appendBuffered(rawEvent)
		}
		// SECURITY: an input_json_delta with no tool_use open carries
		// arguments no cycle will gate, and a client that rebuilds
		// input from deltas would execute them. Refuse, unless a
		// provider-executed block is open in place at that index: the
		// provider runs that call, and no client executes it. A block
		// out of place would hand the delta to an earlier block in the
		// client, possibly an already-gated tool_use.
		if isInput {
			if st := a.blocks[env.Index]; st != nil && !st.Closed && st.inPlace && anthropicProviderExecutedBlocks[st.Type] {
				return FeedResult{PassThrough: true}, nil
			}
			return FeedResult{ProtocolViolation: true, violation: violationOrphanedToolInput}, nil
		}
		return FeedResult{PassThrough: true}, nil

	case "content_block_stop":
		if a.activeToolUseIndex >= 0 {
			res, err := a.appendBuffered(rawEvent)
			if err != nil {
				return res, err
			}
			// Only the active tool_use's stop closes the cycle.
			if env.Index == a.activeToolUseIndex {
				st := a.blocks[env.Index]
				if st != nil {
					st.Closed = true
				}
				return a.complete()
			}
			return res, nil
		}
		// A delta after this stop has no open block to belong to, so it
		// must not inherit a provider-executed block's pass-through.
		if st := a.blocks[env.Index]; st != nil {
			st.Closed = true
		}
		return FeedResult{PassThrough: true}, nil

	case "message_start", "message_delta", "message_stop", "ping":
		if env.Type == "message_start" {
			a.messageStarted = true
		}
		if a.activeToolUseIndex >= 0 {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil

	default:
		if a.activeToolUseIndex >= 0 {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil
	}
}

// appendBuffered holds a copy of rawEvent, enforcing the byte cap.
func (a *AnthropicAccumulator) appendBuffered(rawEvent []byte) (FeedResult, error) {
	if a.maxBufferBytes > 0 && a.bufferedBytes+len(rawEvent) > a.maxBufferBytes {
		return FeedResult{OverflowBufferBytes: true}, nil
	}
	copied := make([]byte, len(rawEvent))
	copy(copied, rawEvent)
	a.bufferedEvents = append(a.bufferedEvents, copied)
	a.bufferedBytes += len(copied)
	return FeedResult{Accumulating: true}, nil
}

// assembleCompletedCalls returns the active tool_use as a
// ToolCallCheck. On invalid input JSON it returns an error alongside
// the call (Arguments nil).
func (a *AnthropicAccumulator) assembleCompletedCalls() ([]ToolCallCheck, error) {
	st, ok := a.blocks[a.activeToolUseIndex]
	if !ok || st.Type != "tool_use" {
		return nil, nil
	}
	args := bytes.TrimSpace(st.InputJSON.Bytes())
	if len(args) == 0 {
		// No arguments: "{}" keeps RawArguments parseable.
		args = []byte("{}")
	}
	var parsed map[string]interface{}
	var firstErr error
	if err := json.Unmarshal(args, &parsed); err != nil {
		firstErr = fmt.Errorf("anthropic parser: tool_use[%d] input is not valid JSON: %w", st.Index, err)
		parsed = nil
	}
	tc := ToolCallCheck{
		Provider:     "anthropic",
		ToolName:     st.Name,
		ToolCallID:   st.ID,
		Arguments:    parsed,
		RawArguments: json.RawMessage(args),
	}
	return []ToolCallCheck{tc}, firstErr
}

// isEmptyJSONObject reports whether an already-trimmed seed is `{}`
// with only whitespace inside. A byte scan, not json.Unmarshal, to
// avoid a map allocation per tool_use on the hot path. Malformed seeds
// (`{}}`, `{`) report false, so they are kept and fail the argument
// parse at gate time (fail-closed).
func isEmptyJSONObject(seed []byte) bool {
	if len(seed) < 2 || seed[0] != '{' || seed[len(seed)-1] != '}' {
		return false
	}
	for _, c := range seed[1 : len(seed)-1] {
		switch c {
		case ' ', '\t', '\n', '\r':
		default:
			return false
		}
	}
	return true
}

// anthropicEventKeys, anthropicBlockKeys and anthropicDeltaKeys are the
// keys FeedEvent decodes from an event (anthropicEventEnvelope), from a
// content_block_start's content_block and from a content_block_delta's
// delta.
var (
	anthropicEventKeys = [...]string{"type", "index", "content_block", "delta"}
	anthropicBlockKeys = [...]string{"type", "id", "name", "input"}
	anthropicDeltaKeys = [...]string{"type", "partial_json", "text"}
)

// isJSONString reports whether raw, a value encoding/json has already
// validated, is a JSON string.
func isJSONString(raw json.RawMessage) bool {
	return len(raw) > 0 && raw[0] == '"'
}

// readAnthropicEvent returns the values FeedEvent reads from an event,
// taken the way the client SDKs take them, and the decoded
// content_block and delta objects. ok is false when the event must be
// refused.
//
// SECURITY: JSON.parse and Python's json keep the last of duplicate
// keys and keep null as null. A struct decode does neither: a null
// leaves the field as it was, and a second "delta" object is merged into
// the first. So `"type":"input_json_delta",...,"type":null` was an input
// delta to the gate while both SDKs dropped it, and the gate checked
// arguments the clients never assembled. Every value here comes from
// the last-wins maps, and a value the SDKs would not read as the gate
// does is refused:
//   - "type", when present, must be a string (null makes the SDKs skip
//     the event or delta);
//   - a content_block_* event's "index" must be an integer:
//     @anthropic-ai/sdk reads content.at(index) but writes
//     content[index], so a null or missing index sends the delta nowhere
//     while the gate applied it to block 0;
//   - in a content_block, "type" must be a string, and a tool_use's
//     "id" and "name" strings; in a delta, an input_json_delta's
//     "partial_json" must be a string (@anthropic-ai/sdk appends a null
//     or missing one as the text "null" or "undefined"). A second
//     content_block or delta object replaces the first, as in the SDKs.
//     An absent or null object reads as none, as before;
//   - message_start's message.content must be an empty array. Both SDKs
//     start the message from it, so a tool_use there reaches the client
//     with no content_block_start for the gate to see.
func readAnthropicEvent(fields map[string]json.RawMessage) (env anthropicEvent, block, delta map[string]json.RawMessage, ok bool) {
	if raw, present := fields["type"]; present {
		if env.Type, ok = jsonStringValue(raw); !ok {
			return env, nil, nil, false
		}
	}
	switch env.Type {
	case "content_block_start", "content_block_delta", "content_block_stop":
		if env.Index, ok = jsonIntValue(fields["index"]); !ok {
			return env, nil, nil, false
		}
	case "message_start":
		var message map[string]json.RawMessage
		_ = json.Unmarshal(fields["message"], &message)
		if content, present := message["content"]; present && !isEmptyJSONArray(content) {
			return env, nil, nil, false
		}
		return env, nil, nil, true
	default:
		return env, nil, nil, true
	}

	switch env.Type {
	case "content_block_start":
		// An absent or null content_block reads as none, as before; both
		// SDKs fail on it. Any other non-object failed the envelope decode.
		if json.Unmarshal(fields["content_block"], &block) != nil || block == nil {
			return env, nil, nil, true
		}
		cb := &env.Block
		if cb.Type, ok = jsonStringValue(block["type"]); !ok {
			return env, nil, nil, false
		}
		if cb.Type == "tool_use" {
			if cb.Name, ok = jsonStringValue(block["name"]); !ok {
				return env, nil, nil, false
			}
			if raw, present := block["id"]; present {
				if cb.ID, ok = jsonStringValue(raw); !ok {
					return env, nil, nil, false
				}
			}
			cb.Input = block["input"]
		}
		env.HasBlock = true
	case "content_block_delta":
		// An absent or null delta carries nothing for the gate, and both
		// SDKs fail on it.
		d := &env.Delta
		env.HasDelta = true
		if json.Unmarshal(fields["delta"], &delta) != nil || delta == nil {
			return env, nil, nil, true
		}
		if raw, present := delta["type"]; present {
			if d.Type, ok = jsonStringValue(raw); !ok {
				return env, nil, nil, false
			}
		}
		if d.Type == "input_json_delta" {
			if d.PartialJSON, ok = jsonStringValue(delta["partial_json"]); !ok {
				return env, nil, nil, false
			}
		}
	}
	return env, block, delta, true
}

// jsonStringValue decodes raw, a value encoding/json has already
// validated, when it is a JSON string. Plain ASCII without escapes is
// sliced instead of decoded; that is every type name.
func jsonStringValue(raw json.RawMessage) (string, bool) {
	if !isJSONString(raw) {
		return "", false
	}
	plain := true
	for _, c := range raw {
		if c == '\\' || c >= utf8.RuneSelf {
			plain = false
			break
		}
	}
	if plain {
		if name, known := anthropicTypeNames[string(raw[1:len(raw)-1])]; known {
			return name, true // no allocation for the names every event carries
		}
		return string(raw[1 : len(raw)-1]), true
	}
	var v string
	if json.Unmarshal(raw, &v) != nil {
		return "", false
	}
	return v, true
}

// anthropicTypeNames interns the event, block and delta type names.
var anthropicTypeNames = func() map[string]string {
	m := map[string]string{}
	for _, n := range []string{
		"message_start", "message_delta", "message_stop", "ping", "error",
		"content_block_start", "content_block_delta", "content_block_stop",
		"text", "tool_use", "server_tool_use", "mcp_tool_use", "thinking", "redacted_thinking",
		"text_delta", "input_json_delta", "thinking_delta", "signature_delta", "citations_delta",
	} {
		m[n] = n
	}
	return m
}()

// jsonIntValue decodes raw, a value encoding/json has already
// validated, when it is a JSON integer. null, a missing value, a string
// or a fraction report false.
func jsonIntValue(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return 0, false
	}
	n, err := strconv.Atoi(string(raw))
	return n, err == nil
}

// isEmptyJSONArray reports whether raw is `[]`, whitespace allowed inside.
func isEmptyJSONArray(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) >= 2 && t[0] == '[' && len(bytes.TrimSpace(t[1:len(t)-1])) == 0 && t[len(t)-1] == ']'
}

// hasCaseVariantKey reports whether obj has a key that encoding/json
// would fold onto one of keys without being spelled exactly like it.
// strings.EqualFold is the fold encoding/json uses (see its fold.go).
func hasCaseVariantKey(obj map[string]json.RawMessage, keys []string) bool {
	for k := range obj {
		for _, want := range keys {
			if k != want && strings.EqualFold(k, want) {
				return true
			}
		}
	}
	return false
}

// totalAnthropicArgsLen sums InputJSON bytes across tool_use blocks.
func totalAnthropicArgsLen(blocks map[int]*anthropicBlockState) int {
	n := 0
	for _, st := range blocks {
		if st.Type == "tool_use" {
			n += st.InputJSON.Len()
		}
	}
	return n
}

// extractAnthropicDataLine returns the event's data payload (several
// `data:` lines joined with '\n' per the SSE spec). Lines end at CRLF,
// CR or LF (cutSSELine).
func extractAnthropicDataLine(rawEvent []byte) (dataLine []byte, hasData bool) {
	const dataPrefix = "data: "
	const dataPrefixShort = "data:"
	var buf bytes.Buffer
	for rest := rawEvent; len(rest) > 0; {
		var line []byte
		line, rest = cutSSELine(rest)
		if len(line) == 0 {
			continue
		}
		var payload []byte
		switch {
		case bytes.HasPrefix(line, []byte(dataPrefix)):
			payload = line[len(dataPrefix):]
		case bytes.HasPrefix(line, []byte(dataPrefixShort)):
			payload = line[len(dataPrefixShort):]
		default:
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(payload)
		hasData = true
	}
	if !hasData {
		return nil, false
	}
	return buf.Bytes(), true
}
