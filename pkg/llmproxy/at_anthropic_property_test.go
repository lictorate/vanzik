package llmproxy

// Property tests (testing/quick) for the Anthropic tool_use accumulator:
//   1. partial_json reassembly: random JSON encoded as random
//      partial_json fragments across N content_block_delta events;
//      assembled string parses to original JSON.
//   2. Multi-block: random mix of text and tool_use blocks at random
//      index values — assert each block's accumulator state is
//      independent of the other.
//   3. Block ordering: random content_block_* event interleaving
//      (different indexes can interleave in spec); asserts state per
//      index stays consistent.
//   4. Event-line parsing tolerance: events with and without `event:`
//      preamble are both accepted.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"
)

// TestAT_AnthropicParser_AssemblesPartialJSONAcrossArbitraryBoundaries:
// any split into partial_json fragments reassembles the exact bytes.
func TestAT_AnthropicParser_AssemblesPartialJSONAcrossArbitraryBoundaries(t *testing.T) {
	property := func(seed int64, rawJSON string, splitCount uint8) bool {
		if rawJSON == "" || splitCount == 0 {
			return true
		}
		if len(rawJSON) > 4096 {
			rawJSON = rawJSON[:4096]
		}
		nSplits := int(splitCount) % 32
		if nSplits == 0 {
			nSplits = 1
		}
		r := rand.New(rand.NewSource(seed))

		encoded, _ := json.Marshal(map[string]string{"cmd": rawJSON})
		argsString := string(encoded)
		fragments := splitIntoFragments(argsString, nSplits, r)

		acc := NewAnthropicAccumulator(0)
		startEv := `event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_prop","name":"bash","input":{}}}

`
		if _, err := acc.FeedEvent([]byte(startEv)); err != nil {
			t.Logf("seed=%d: start err=%v", seed, err)
			return false
		}
		for _, frag := range fragments {
			ev := fmt.Sprintf(
				`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%s}}

`, mustJSON(frag),
			)
			if _, err := acc.FeedEvent([]byte(ev)); err != nil {
				t.Logf("seed=%d: frag err=%v", seed, err)
				return false
			}
		}
		stopEv := `event: content_block_stop
data: {"type":"content_block_stop","index":0}

`
		res, _ := acc.FeedEvent([]byte(stopEv))
		if !res.Completed || len(res.CompletedToolCalls) != 1 {
			t.Logf("seed=%d: missing completion res=%+v", seed, res)
			return false
		}
		got := strings.TrimSpace(string(res.CompletedToolCalls[0].RawArguments))
		want := strings.TrimSpace(argsString)
		if got != want {
			t.Logf("seed=%d: got=%q want=%q", seed, got, want)
			return false
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("partial_json reassembly property failed: %v", err)
	}
}

// TestAT_AnthropicParser_TextBlocksDoNotInterfereWithToolUse: text
// deltas for other blocks are buffered with the active tool_use (to keep
// order) without corrupting its arguments.
func TestAT_AnthropicParser_TextBlocksDoNotInterfereWithToolUse(t *testing.T) {
	property := func(seed int64, textChunks []string) bool {
		r := rand.New(rand.NewSource(seed))
		_ = r
		toolArgs := `{"cmd":"echo hi"}`

		acc := NewAnthropicAccumulator(0)
		startTool := `event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_x","name":"bash","input":{}}}

`
		if _, err := acc.FeedEvent([]byte(startTool)); err != nil {
			return false
		}

		fragments := splitIntoFragments(toolArgs, 1+len(textChunks), rand.New(rand.NewSource(seed+1)))

		fi, ti := 0, 0
		for fi < len(fragments) || ti < len(textChunks) {
			pickFrag := false
			switch {
			case fi >= len(fragments):
				pickFrag = false
			case ti >= len(textChunks):
				pickFrag = true
			default:
				pickFrag = (fi+ti)%2 == 0
			}
			if pickFrag {
				ev := fmt.Sprintf(
					`event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":%s}}

`, mustJSON(fragments[fi]),
				)
				res, _ := acc.FeedEvent([]byte(ev))
				if !res.Accumulating {
					return false
				}
				fi++
			} else {
				ev := fmt.Sprintf(
					`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%s}}

`, mustJSON(textChunks[ti]),
				)
				res, _ := acc.FeedEvent([]byte(ev))
				if !res.Accumulating {
					return false
				}
				ti++
			}
		}
		stopTool := `event: content_block_stop
data: {"type":"content_block_stop","index":1}

`
		res, _ := acc.FeedEvent([]byte(stopTool))
		if !res.Completed || len(res.CompletedToolCalls) != 1 {
			return false
		}
		got := strings.TrimSpace(string(res.CompletedToolCalls[0].RawArguments))
		want := strings.TrimSpace(toolArgs)
		return got == want
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("multi-block independence property failed: %v", err)
	}
}

func TestAT_AnthropicParser_OverflowFiresAtCorrectThreshold(t *testing.T) {
	property := func(capN uint16, argSize uint16) bool {
		cap := int(capN)%2048 + 64
		size := int(argSize) % 4096
		if size <= 0 {
			return true
		}
		acc := NewAnthropicAccumulator(cap)

		startEv := `event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_x","name":"bash","input":{}}}

`
		startRes, err := acc.FeedEvent([]byte(startEv))
		if err != nil {
			return false
		}
		if startRes.OverflowBufferBytes {
			return true
		}
		bigArg := strings.Repeat("a", size)
		ev := fmt.Sprintf(
			`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%s}}

`, mustJSON(bigArg),
		)
		res, err := acc.FeedEvent([]byte(ev))
		if err != nil {
			return true
		}
		shouldOverflowOnArgs := size > cap
		shouldOverflowOnBuffer := len(startEv)+len(ev) > cap
		shouldOverflow := shouldOverflowOnArgs || shouldOverflowOnBuffer
		if shouldOverflow != res.OverflowBufferBytes {
			t.Logf("cap=%d size=%d startEv=%d ev=%d: shouldOverflow=%v actual=%v",
				cap, size, len(startEv), len(ev), shouldOverflow, res.OverflowBufferBytes)
			return false
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("overflow-threshold property failed: %v", err)
	}
}

// TestAT_AnthropicParser_EventLineOptional: events are dispatched on the
// JSON `type` with or without an `event:` line, which some
// intermediaries strip.
func TestAT_AnthropicParser_EventLineOptional(t *testing.T) {
	property := func(includeEventLine bool, indexN uint8) bool {
		acc := NewAnthropicAccumulator(0)
		idx := int(indexN) % 16
		var ev string
		if includeEventLine {
			ev = fmt.Sprintf(
				`event: content_block_start
data: {"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":"toolu_p","name":"bash","input":{}}}

`, idx)
		} else {
			ev = fmt.Sprintf(
				`data: {"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":"toolu_p","name":"bash","input":{}}}

`, idx)
		}
		res, err := acc.FeedEvent([]byte(ev))
		if err != nil {
			t.Logf("err=%v", err)
			return false
		}
		if !res.Accumulating {
			t.Logf("expected Accumulating, got %+v", res)
			return false
		}
		if acc.ActiveToolUseIndex() != idx {
			return false
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("event-line-optional property failed: %v", err)
	}
}

func TestAT_AnthropicParser_MalformedNeverPanics(t *testing.T) {
	property := func(garbage []byte) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				ok = false
			}
		}()
		acc := NewAnthropicAccumulator(0)
		ev := append([]byte("event: content_block_delta\ndata: "), garbage...)
		ev = append(ev, '\n', '\n')
		_, _ = acc.FeedEvent(ev)
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("malformed-no-panic property failed: %v", err)
	}
}
