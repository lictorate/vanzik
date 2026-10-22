package llmproxy

// OpenAI Chat Completions streaming parser and tool_call accumulator
// (wire format: docs/LLM_API_PROXY.md § 5.1). Fragments are keyed by
// tool_calls[i].index, not id (later fragments may omit it);
// `arguments` is partial JSON, concatenated verbatim and parsed only at
// gating time.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// openAIDeltaEnvelope types only the fields the parser reads; the raw
// event bytes are what gets replayed.
type openAIDeltaEnvelope struct {
	Choices []openAIDeltaChoice `json:"choices"`
}

type openAIDeltaChoice struct {
	Index        int                `json:"index"`
	Delta        openAIDeltaMessage `json:"delta"`
	FinishReason string             `json:"finish_reason,omitempty"`
}

type openAIDeltaMessage struct {
	Role      string                `json:"role,omitempty"`
	Content   string                `json:"content,omitempty"`
	ToolCalls []openAIToolCallDelta `json:"tool_calls,omitempty"`
}

type openAIToolCallDelta struct {
	Index    int                      `json:"index"`
	ID       string                   `json:"id,omitempty"`
	Type     string                   `json:"type,omitempty"`
	Function *openAIToolCallFuncDelta `json:"function,omitempty"`
}

type openAIToolCallFuncDelta struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// openAIToolCallState aggregates the fragments of one tool_call.
type openAIToolCallState struct {
	Index       int
	ID          string
	Name        string
	Arguments   strings.Builder
	HasFunction bool
}

// FeedResult tells the streaming orchestrator what to do with one event.
// At most one of the flags is set.
type FeedResult struct {
	// PassThrough: forward the event now, byte-identical (no tool call
	// in flight).
	PassThrough bool

	// Accumulating: a tool call is in flight; hold the event.
	Accumulating bool

	// Completed: a tool-call cycle ended. Gate CompletedToolCalls; on
	// ALLOW flush BufferedEvents, on DENY discard them and refuse.
	Completed bool

	// CompletedToolCalls are the assembled calls in index order; set
	// only with Completed.
	CompletedToolCalls []ToolCallCheck

	// OverflowBufferBytes: buffered bytes exceeded the cap; refuse.
	OverflowBufferBytes bool

	// ProtocolViolation: the stream cannot be gated without risking a
	// bypass. The orchestrator must refuse and stop reading upstream.
	ProtocolViolation bool

	// violation names the defect behind ProtocolViolation. Unexported
	// to keep it off the public API.
	violation protocolViolationKind
}

// protocolViolationKind enumerates the defects that make a stream
// ungateable. The zero value is interleaved tool_use, whose refusal
// text is a wire contract (see protocolViolationDecision).
type protocolViolationKind uint8

const (
	// violationInterleavedToolUse (Anthropic): a second tool_use opened
	// before the first closed, or start-seeded input conflicts with
	// input_json_deltas. Anthropic emits blocks serially; an interleaved
	// second tool_use would pass ungated once the first cycle resets.
	violationInterleavedToolUse protocolViolationKind = iota

	// violationOrphanedToolInput (Anthropic): input_json_delta with no
	// tool_use block open, so no cycle could gate it.
	violationOrphanedToolInput

	// violationMultiChoiceToolCalls (OpenAI): tool_call deltas on more
	// than one choice. tool_calls[i].index is unique only within a
	// choice, so fragments would merge into an argument string the
	// firewall gates and no client executes.
	violationMultiChoiceToolCalls
)

// OpenAIToolCallAccumulator assembles streaming tool_call fragments
// into ToolCallCheck records and holds the raw events for replay on
// ALLOW. One per stream; not safe to share.
type OpenAIToolCallAccumulator struct {
	maxBufferBytes int

	// byIndex is keyed by tool_calls[i].index; a map because indices
	// need not be dense.
	byIndex map[int]*openAIToolCallState

	// bufferedEvents holds whole raw events since the first tool_call
	// delta.
	bufferedEvents [][]byte
	bufferedBytes  int

	// active: a tool_call cycle is open.
	active bool

	// completed latches once the cycle has signalled Completed, so
	// `[DONE]` and CloseAtEOF cannot complete it again. Reset clears
	// it, so each cycle in a stream completes once.
	completed bool

	// toolCallChoice is the choice carrying the cycle's tool_call
	// deltas, or -1. A second choice with tool_calls is a protocol
	// violation, and only this choice's finish_reason closes the cycle.
	toolCallChoice int
}

// NewOpenAIToolCallAccumulator returns an accumulator with the given
// per-stream buffer cap; <= 0 means no cap (tests only).
func NewOpenAIToolCallAccumulator(maxBufferBytes int) *OpenAIToolCallAccumulator {
	return &OpenAIToolCallAccumulator{
		maxBufferBytes: maxBufferBytes,
		byIndex:        map[int]*openAIToolCallState{},
		toolCallChoice: -1,
	}
}

// BufferedEvents returns the held raw events. Read-only; retained
// until Reset.
func (a *OpenAIToolCallAccumulator) BufferedEvents() [][]byte {
	return a.bufferedEvents
}

// Reset clears state for the next gating cycle in the same stream.
func (a *OpenAIToolCallAccumulator) Reset() {
	a.byIndex = map[int]*openAIToolCallState{}
	a.bufferedEvents = nil
	a.bufferedBytes = 0
	a.active = false
	a.completed = false
	a.toolCallChoice = -1
}

// complete assembles the calls and latches `completed`. Every
// Completed result goes through here.
func (a *OpenAIToolCallAccumulator) complete() (FeedResult, error) {
	a.completed = true
	calls, parseErr := a.assembleCompletedCalls()
	return FeedResult{
		Completed:          true,
		CompletedToolCalls: calls,
	}, parseErr
}

// CloseAtEOF completes a cycle still open when upstream ended without
// a terminal finish_reason. The orchestrator must call it once at EOF
// and gate-or-refuse a Completed result like any other: flushing the
// buffered (ungated) events is a fail-open, discarding them loses the
// audit trail. Truncated arguments return an error, which routes to
// the malformed refusal. Returns the zero FeedResult when nothing is
// open.
func (a *OpenAIToolCallAccumulator) CloseAtEOF() (FeedResult, error) {
	if !a.active || a.completed {
		return FeedResult{}, nil
	}
	return a.complete()
}

// pendingIdentity returns the name and id of the lowest-indexed named
// tool_call in flight, or empty strings. Used to label the audit entry
// of a structural refusal, where no call assembled.
func (a *OpenAIToolCallAccumulator) pendingIdentity() (name, id string) {
	best := -1
	for idx, st := range a.byIndex {
		if st.Name == "" {
			continue
		}
		if best < 0 || idx < best {
			best = idx
		}
	}
	if best < 0 {
		return "", ""
	}
	st := a.byIndex[best]
	return st.Name, st.ID
}

// FeedEvent ingests one complete raw SSE event. An error means
// malformed JSON: with Completed set the orchestrator refuses the
// cycle, otherwise it drops the event.
func (a *OpenAIToolCallAccumulator) FeedEvent(rawEvent []byte) (FeedResult, error) {
	dataLine, isDone, hasData := extractOpenAIDataLine(rawEvent)
	if !hasData {
		// Comment, retry or event-name only: buffer while a cycle is
		// open, else pass through.
		if a.active {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil
	}

	if isDone {
		// `[DONE]` with a cycle open and no finish_reason: complete it
		// here. Buffer `[DONE]` so it replays in order on ALLOW;
		// flushing the ungated buffer instead would be the bypass.
		if a.active && !a.completed {
			res, err := a.appendBuffered(rawEvent)
			if err != nil || res.OverflowBufferBytes {
				return res, err
			}
			return a.complete()
		}
		if a.active {
			// Already completed, not yet Reset: keep buffering.
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil
	}

	var env openAIDeltaEnvelope
	if err := json.Unmarshal(dataLine, &env); err != nil {
		return FeedResult{}, fmt.Errorf("openai parser: malformed delta JSON: %w", err)
	}

	// tool_call deltas can land on any choice.
	hasToolCallDelta := false
	for _, ch := range env.Choices {
		if len(ch.Delta.ToolCalls) > 0 {
			hasToolCallDelta = true
			break
		}
	}

	// Ordering: an event can carry both the closing argument fragment
	// and finish_reason. Apply the delta first, then check for
	// completion; returning Accumulating early would lose the finish
	// signal and the gate would never fire.

	if hasToolCallDelta {
		a.active = true
		// Accumulate before buffering so overflow aborts without
		// storing the event.
		for _, ch := range env.Choices {
			if len(ch.Delta.ToolCalls) == 0 {
				continue
			}
			// SECURITY: with n>1 each choice numbers its calls from
			// 0, so fragments would splice into a call no client
			// executes while the real ones pass unexamined. The first
			// choice with tool_calls claims the cycle; a second fails
			// the stream closed. n=1 never reaches this.
			if a.toolCallChoice >= 0 && ch.Index != a.toolCallChoice {
				return FeedResult{ProtocolViolation: true, violation: violationMultiChoiceToolCalls}, nil
			}
			a.toolCallChoice = ch.Index
			for _, tc := range ch.Delta.ToolCalls {
				st, ok := a.byIndex[tc.Index]
				if !ok {
					st = &openAIToolCallState{Index: tc.Index}
					a.byIndex[tc.Index] = st
				}
				if tc.ID != "" {
					st.ID = tc.ID
				}
				if tc.Function != nil {
					st.HasFunction = true
					// SECURITY: first non-empty name wins, matching
					// client SDKs. Last-wins would let a second, different
					// name be gated while the client executes the first.
					if tc.Function.Name != "" && st.Name == "" {
						st.Name = tc.Function.Name
					}
					if tc.Function.Arguments != "" {
						// The cap applies to cumulative argument bytes,
						// the PolicyCheck input.
						projected := totalArgsLen(a.byIndex) + len(tc.Function.Arguments)
						if a.maxBufferBytes > 0 && projected > a.maxBufferBytes {
							return FeedResult{OverflowBufferBytes: true}, nil
						}
						st.Arguments.WriteString(tc.Function.Arguments)
					}
				}
			}
		}
		appendRes, err := a.appendBuffered(rawEvent)
		if err != nil {
			return appendRes, err
		}
		// Same event may also carry the finish_reason.
		if a.finishObserved(env) {
			return a.complete()
		}
		return appendRes, nil
	}

	if a.active {
		appendRes, err := a.appendBuffered(rawEvent)
		if err != nil {
			return appendRes, err
		}

		if a.finishObserved(env) {
			// An error here (invalid argument JSON) makes the
			// orchestrator refuse the cycle.
			return a.complete()
		}

		return appendRes, nil
	}

	return FeedResult{PassThrough: true}, nil
}

// appendBuffered holds rawEvent, enforcing the byte cap.
func (a *OpenAIToolCallAccumulator) appendBuffered(rawEvent []byte) (FeedResult, error) {
	if a.maxBufferBytes > 0 && a.bufferedBytes+len(rawEvent) > a.maxBufferBytes {
		return FeedResult{OverflowBufferBytes: true}, nil
	}
	// Copy: rawEvent's backing array is reused by the next read.
	copied := make([]byte, len(rawEvent))
	copy(copied, rawEvent)
	a.bufferedEvents = append(a.bufferedEvents, copied)
	a.bufferedBytes += len(copied)
	return FeedResult{Accumulating: true}, nil
}

// assembleCompletedCalls returns the calls in index order. If any
// arguments fail to parse it returns an error, but still the full
// slice (Arguments nil, RawArguments kept) so the calls can be
// audited.
func (a *OpenAIToolCallAccumulator) assembleCompletedCalls() ([]ToolCallCheck, error) {
	if len(a.byIndex) == 0 {
		return nil, nil
	}
	// Index order keeps audit entries deterministic.
	indices := make([]int, 0, len(a.byIndex))
	for i := range a.byIndex {
		indices = append(indices, i)
	}
	for i := 1; i < len(indices); i++ {
		for j := i; j > 0 && indices[j-1] > indices[j]; j-- {
			indices[j-1], indices[j] = indices[j], indices[j-1]
		}
	}

	var firstErr error
	out := make([]ToolCallCheck, 0, len(indices))
	for _, idx := range indices {
		st := a.byIndex[idx]
		args := strings.TrimSpace(st.Arguments.String())
		raw := json.RawMessage(args)
		var parsed map[string]interface{}
		if args != "" {
			if err := json.Unmarshal([]byte(args), &parsed); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("openai parser: tool_call[%d] arguments are not valid JSON: %w", idx, err)
				}
				parsed = nil
			}
		}
		out = append(out, ToolCallCheck{
			Provider:     "openai",
			ToolName:     st.Name,
			ToolCallID:   st.ID,
			Arguments:    parsed,
			RawArguments: raw,
		})
	}
	return out, firstErr
}

// finishObserved reports whether env closes the open cycle. Any
// non-empty finish_reason counts ("stop" and "length" too), or the
// accumulator would dangle. Once a choice owns the cycle, only its
// finish_reason counts: with n>1 a sibling often finishes while the
// owner still streams arguments, and closing then would refuse a
// valid stream. A missing finish_reason is handled by CloseAtEOF.
func (a *OpenAIToolCallAccumulator) finishObserved(env openAIDeltaEnvelope) bool {
	for _, ch := range env.Choices {
		if a.toolCallChoice >= 0 && ch.Index != a.toolCallChoice {
			continue
		}
		if ch.FinishReason != "" {
			return true
		}
	}
	return false
}

// totalArgsLen sums argument bytes across all tool_call states.
func totalArgsLen(byIndex map[int]*openAIToolCallState) int {
	n := 0
	for _, st := range byIndex {
		n += st.Arguments.Len()
	}
	return n
}

// extractOpenAIDataLine returns the event's data payload (several
// `data:` lines joined with '\n' per the SSE spec), whether it is the
// `[DONE]` sentinel, and whether any `data:` line exists.
func extractOpenAIDataLine(rawEvent []byte) (dataLine []byte, isDone bool, hasData bool) {
	const dataPrefix = "data: "
	const dataPrefixShort = "data:" // some servers omit the space
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
		return nil, false, false
	}
	bb := buf.Bytes()
	if bytes.Equal(bytes.TrimSpace(bb), []byte("[DONE]")) {
		return bb, true, true
	}
	return bb, false, true
}
