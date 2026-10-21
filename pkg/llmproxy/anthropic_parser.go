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
)

// anthropicEventEnvelope types only the fields the parser reads.
type anthropicEventEnvelope struct {
	Type         string                      `json:"type"`
	Index        int                         `json:"index,omitempty"`
	ContentBlock *anthropicContentBlockShape `json:"content_block,omitempty"`
	Delta        *anthropicEventDeltaShape   `json:"delta,omitempty"`
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

// anthropicBlockState tracks one content block; only tool_use gates.
type anthropicBlockState struct {
	Index     int
	Type      string // "text" | "tool_use"
	ID        string
	Name      string
	InputJSON bytes.Buffer
	Closed    bool
	// startSeeded: arguments came from a non-empty
	// content_block_start.input. Conformant streams send `{}` there and
	// use input_json_delta, so a later delta for a seeded block is a
	// conflict and fails closed.
	startSeeded bool
}

// AnthropicAccumulator is the Anthropic counterpart of
// OpenAIToolCallAccumulator, with the same FeedResult contract.
//
// From a tool_use's content_block_start until its content_block_stop,
// every event is buffered, including deltas for other blocks:
// forwarding them while holding the tool_use would reorder the stream,
// which some clients don't tolerate.
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
}

// NewAnthropicAccumulator returns an accumulator with the given
// per-stream buffer cap; <= 0 means no cap.
func NewAnthropicAccumulator(maxBufferBytes int) *AnthropicAccumulator {
	return &AnthropicAccumulator{
		maxBufferBytes:     maxBufferBytes,
		blocks:             map[int]*anthropicBlockState{},
		activeToolUseIndex: -1,
	}
}

// BufferedEvents returns the held raw events. Read-only.
func (a *AnthropicAccumulator) BufferedEvents() [][]byte {
	return a.bufferedEvents
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

	var env anthropicEventEnvelope
	if err := json.Unmarshal(dataLine, &env); err != nil {
		return FeedResult{}, fmt.Errorf("anthropic parser: malformed event JSON: %w", err)
	}

	switch env.Type {
	case "content_block_start":
		if env.ContentBlock != nil && env.ContentBlock.Type == "tool_use" {
			// SECURITY: a second tool_use opening while one buffers
			// would be flushed when the first cycle Resets, and its
			// remaining deltas would pass ungated. One cycle cannot gate
			// two blocks, so refuse the stream.
			if a.activeToolUseIndex >= 0 {
				return FeedResult{ProtocolViolation: true, violation: violationInterleavedToolUse}, nil
			}
			st := &anthropicBlockState{
				Index: env.Index,
				Type:  "tool_use",
				ID:    env.ContentBlock.ID,
				Name:  env.ContentBlock.Name,
			}
			// SECURITY: an adversarial upstream can put the real
			// arguments in the start event's input and send no delta.
			// Client SDKs seed tool input from it, so the gate must too.
			// Emptiness is structural: `{ }` is empty, and treating it
			// as a seed would trip the conflict check on the first
			// conformant input_json_delta.
			if seed := bytes.TrimSpace(env.ContentBlock.Input); len(seed) > 0 && !isEmptyJSONObject(seed) {
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
		if env.ContentBlock != nil {
			a.blocks[env.Index] = &anthropicBlockState{
				Index: env.Index,
				Type:  env.ContentBlock.Type,
			}
		}
		return FeedResult{PassThrough: true}, nil

	case "content_block_delta":
		if a.activeToolUseIndex >= 0 {
			if env.Index == a.activeToolUseIndex && env.Delta != nil &&
				env.Delta.Type == "input_json_delta" && env.Delta.PartialJSON != "" {
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
		// input from deltas would execute them. Refuse.
		if env.Delta != nil && env.Delta.Type == "input_json_delta" {
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
		return FeedResult{PassThrough: true}, nil

	case "message_start", "message_delta", "message_stop", "ping":
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
// `data:` lines joined with '\n' per the SSE spec).
func extractAnthropicDataLine(rawEvent []byte) (dataLine []byte, hasData bool) {
	const dataPrefix = "data: "
	const dataPrefixShort = "data:"
	var buf bytes.Buffer
	for _, line := range bytes.Split(rawEvent, []byte("\n")) {
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
