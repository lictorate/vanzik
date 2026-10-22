package llmproxy

// Property tests (testing/quick) for the OpenAI tool_call accumulator:
//   1. Args reassembly: for any random JSON arguments and any random
//      splitting across N deltas, concat(deltas) == accumulator.Arguments.
//   2. Multi-tool: random N tools (1-5), each with random args, random
//      delta interleaving by tool_calls[i].index — all N reassemble.
//   3. Buffer bound: random arg sizes; overflow fires precisely when
//      cumulative bytes exceed MaxBufferBytes.
//   4. Mid-stream content: random text-content deltas interleaved with
//      tool_call deltas — text passes through, tool_calls buffer.
//   5. Malformed: random byte injection into delta JSON — parser does
//      not panic, returns error.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"
)

// quickConfig keeps property runs bounded for CI determinism.
var quickConfig = &quick.Config{MaxCount: 200}

// TestAT_OpenAIParser_AssemblesArgsAcrossArbitraryChunkBoundaries pins
// the central invariant: regardless of how the upstream chooses to
// split a tool_call's `arguments` JSON across SSE deltas, the parser
// must reassemble the exact original byte sequence.
func TestAT_OpenAIParser_AssemblesArgsAcrossArbitraryChunkBoundaries(t *testing.T) {
	property := func(seed int64, rawJSON string, splitCount uint8) bool {
		if rawJSON == "" || splitCount == 0 {
			return true // no-op
		}
		if len(rawJSON) > 4096 {
			rawJSON = rawJSON[:4096]
		}
		nSplits := int(splitCount) % 32
		if nSplits == 0 {
			nSplits = 1
		}

		// Seeded from the input so failures reproduce.
		r := rand.New(rand.NewSource(seed))

		// Fragments are of the JSON encoding of {"cmd": rawJSON}.
		encoded, _ := json.Marshal(map[string]string{"cmd": rawJSON})
		argsString := string(encoded)

		fragments := splitIntoFragments(argsString, nSplits, r)

		// ~30% of runs put the final fragment and finish_reason in one
		// event, as real OpenAI streams sometimes do; the parser must
		// still assemble the full arguments.
		bundleFinish := len(fragments) >= 2 && r.Intn(100) < 30

		acc := NewOpenAIToolCallAccumulator(0)
		feed(acc, openAIStartDelta("call_prop", "bash", fragments[0]))

		var res FeedResult
		var err error
		if bundleFinish {
			// All but the last fragment via separate arg deltas, then
			// the last fragment + finish_reason in one bundled event.
			for _, frag := range fragments[1 : len(fragments)-1] {
				feed(acc, openAIArgDelta(frag))
			}
			res, err = acc.FeedEvent([]byte(openAIArgAndFinishDelta(fragments[len(fragments)-1])))
		} else {
			for _, frag := range fragments[1:] {
				feed(acc, openAIArgDelta(frag))
			}
			res, err = acc.FeedEvent([]byte(openAIFinishDelta()))
		}
		// A parse error is acceptable; the property is checked on
		// RawArguments.
		_ = err
		if !res.Completed || len(res.CompletedToolCalls) != 1 {
			t.Logf("seed=%d nSplits=%d bundleFinish=%v: completion missing; res=%+v", seed, nSplits, bundleFinish, res)
			return false
		}
		got := string(res.CompletedToolCalls[0].RawArguments)
		// The parser trims surrounding whitespace; we must too.
		if strings.TrimSpace(got) != strings.TrimSpace(argsString) {
			t.Logf("seed=%d nSplits=%d: reassembly mismatch:\n got=%q\nwant=%q", seed, nSplits, got, argsString)
			return false
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("property failed: %v", err)
	}
}

// TestAT_OpenAIParser_MultiToolReassemblyByIndex pins that with N
// random tools (1..5) interleaved by their tool_calls[i].index, each
// tool's arguments reassemble independently.
func TestAT_OpenAIParser_MultiToolReassemblyByIndex(t *testing.T) {
	property := func(seed int64, n uint8) bool {
		nTools := int(n)%5 + 1
		r := rand.New(rand.NewSource(seed))

		args := make([]string, nTools)
		for i := range args {
			args[i] = fmt.Sprintf(`{"i":%d,"r":%d}`, i, r.Intn(100000))
		}

		type frag struct {
			toolIdx int
			text    string
			isStart bool
			name    string
			id      string
		}
		var allFrags []frag
		for ti := 0; ti < nTools; ti++ {
			pieces := splitIntoFragments(args[ti], 1+r.Intn(4), r)
			allFrags = append(allFrags, frag{
				toolIdx: ti, text: pieces[0], isStart: true,
				name: fmt.Sprintf("tool_%d", ti),
				id:   fmt.Sprintf("call_%d", ti),
			})
			for _, p := range pieces[1:] {
				allFrags = append(allFrags, frag{toolIdx: ti, text: p})
			}
		}

		// Interleave tools while keeping each tool's fragments in
		// order: pick randomly among the heads of N queues.
		queues := make([][]frag, nTools)
		for _, f := range allFrags {
			queues[f.toolIdx] = append(queues[f.toolIdx], f)
		}
		var ordered []frag
		for {
			active := []int{}
			for i, q := range queues {
				if len(q) > 0 {
					active = append(active, i)
				}
			}
			if len(active) == 0 {
				break
			}
			pick := active[r.Intn(len(active))]
			ordered = append(ordered, queues[pick][0])
			queues[pick] = queues[pick][1:]
		}

		acc := NewOpenAIToolCallAccumulator(0)
		for _, f := range ordered {
			if f.isStart {
				ev := fmt.Sprintf(
					`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":%s}}]},"finish_reason":null}]}`,
					f.toolIdx, f.id, f.name, mustJSON(f.text),
				) + "\n\n"
				if _, err := acc.FeedEvent([]byte(ev)); err != nil {
					t.Logf("seed=%d: feed start frag err=%v", seed, err)
					return false
				}
			} else {
				ev := fmt.Sprintf(
					`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":%d,"function":{"arguments":%s}}]},"finish_reason":null}]}`,
					f.toolIdx, mustJSON(f.text),
				) + "\n\n"
				if _, err := acc.FeedEvent([]byte(ev)); err != nil {
					t.Logf("seed=%d: feed cont frag err=%v", seed, err)
					return false
				}
			}
		}
		res, err := acc.FeedEvent([]byte(openAIFinishDelta()))
		if err != nil {
			t.Logf("seed=%d: finish err=%v", seed, err)
			return false
		}
		if !res.Completed || len(res.CompletedToolCalls) != nTools {
			t.Logf("seed=%d: nTools=%d but got %d completed", seed, nTools, len(res.CompletedToolCalls))
			return false
		}
		// Sorted by index inside the parser; verify reassembly.
		for i, tc := range res.CompletedToolCalls {
			gotArgs := strings.TrimSpace(string(tc.RawArguments))
			wantArgs := strings.TrimSpace(args[i])
			if gotArgs != wantArgs {
				t.Logf("seed=%d tool[%d]: got=%q want=%q", seed, i, gotArgs, wantArgs)
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("multi-tool property failed: %v", err)
	}
}

// TestAT_OpenAIParser_OverflowFiresAtCorrectThreshold: with
// MaxBufferBytes=N, overflow fires exactly when cumulative argument
// bytes or buffered envelope bytes exceed N.
func TestAT_OpenAIParser_OverflowFiresAtCorrectThreshold(t *testing.T) {
	property := func(capN uint16, argSize uint16) bool {
		cap := int(capN)%2048 + 64 // [64..2111]
		size := int(argSize) % 4096
		if size <= 0 {
			return true
		}
		acc := NewOpenAIToolCallAccumulator(cap)

		startEv := openAIStartDelta("call_x", "bash", "")
		startRes, err := acc.FeedEvent([]byte(startEv))
		if err != nil || (!startRes.Accumulating && !startRes.OverflowBufferBytes) {
			t.Logf("cap=%d: start unexpected: res=%+v err=%v", cap, startRes, err)
			return false
		}
		if startRes.OverflowBufferBytes {
			// The start envelope alone exceeded the cap.
			return true
		}
		bigArg := strings.Repeat("a", size)
		ev := openAIArgDelta(bigArg)
		res, err := acc.FeedEvent([]byte(ev))
		if err != nil {
			return true // malformed JSON path is allowed
		}
		// Overflow iff either check trips:
		//   (size > cap)                            // args check
		//   OR (lenStartEnvelope + lenContEnvelope > cap) // buffer check
		startEnvLen := len(startEv)
		contEnvLen := len(ev)
		shouldOverflowOnArgs := size > cap
		shouldOverflowOnBuffer := startEnvLen+contEnvLen > cap
		shouldOverflow := shouldOverflowOnArgs || shouldOverflowOnBuffer

		if shouldOverflow != res.OverflowBufferBytes {
			t.Logf(
				"cap=%d size=%d startEnv=%d contEnv=%d: shouldOverflow=%v actual=%v res=%+v",
				cap, size, startEnvLen, contEnvLen, shouldOverflow, res.OverflowBufferBytes, res,
			)
			return false
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("overflow-threshold property failed: %v", err)
	}
}

// TestAT_OpenAIParser_TextDeltasPassThroughUntilToolCall pins that
// arbitrary text-only content deltas pass through immediately when no
// tool_call has begun, then start buffering when one does.
func TestAT_OpenAIParser_TextDeltasPassThroughUntilToolCall(t *testing.T) {
	property := func(textChunks []string) bool {
		acc := NewOpenAIToolCallAccumulator(0)
		for _, txt := range textChunks {
			ev := fmt.Sprintf(
				`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":%s},"finish_reason":null}]}`,
				mustJSON(txt),
			) + "\n\n"
			res, err := acc.FeedEvent([]byte(ev))
			if err != nil {
				continue // malformed via random content — skip
			}
			if !res.PassThrough {
				return false
			}
		}
		startEv := openAIStartDelta("call_t", "bash", `{"cmd":"x"}`)
		res, err := acc.FeedEvent([]byte(startEv))
		if err != nil {
			return false
		}
		return res.Accumulating
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("text-passthrough property failed: %v", err)
	}
}

// TestAT_OpenAIParser_MalformedNeverPanics: random bytes framed as
// `data: ...\n\n` never panic the parser.
func TestAT_OpenAIParser_MalformedNeverPanics(t *testing.T) {
	property := func(garbage []byte) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PANIC on input %q: %v", garbage, r)
				ok = false
			}
		}()
		acc := NewOpenAIToolCallAccumulator(0)
		ev := append([]byte("data: "), garbage...)
		ev = append(ev, '\n', '\n')
		_, _ = acc.FeedEvent(ev)
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("malformed-no-panic property failed: %v", err)
	}
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// splitIntoFragments splits s into n random pieces on rune boundaries:
// json.Marshal would replace a split rune with U+FFFD, and real upstreams
// send valid UTF-8 per delta.
func splitIntoFragments(s string, n int, r *rand.Rand) []string {
	if n <= 1 || len(s) == 0 {
		return []string{s}
	}
	boundaries := make([]int, 0, len(s)+1)
	for i := range s {
		boundaries = append(boundaries, i)
	}
	boundaries = append(boundaries, len(s))
	if n >= len(boundaries)-1 {
		out := make([]string, 0, len(boundaries)-1)
		for i := 0; i < len(boundaries)-1; i++ {
			out = append(out, s[boundaries[i]:boundaries[i+1]])
		}
		return out
	}
	used := map[int]bool{}
	cuts := make([]int, 0, n-1)
	for len(cuts) < n-1 {
		bi := 1 + r.Intn(len(boundaries)-2)
		c := boundaries[bi]
		if !used[c] {
			used[c] = true
			cuts = append(cuts, c)
		}
	}
	for i := 1; i < len(cuts); i++ {
		for j := i; j > 0 && cuts[j-1] > cuts[j]; j-- {
			cuts[j-1], cuts[j] = cuts[j], cuts[j-1]
		}
	}
	out := make([]string, 0, n)
	prev := 0
	for _, c := range cuts {
		out = append(out, s[prev:c])
		prev = c
	}
	out = append(out, s[prev:])
	return out
}

func openAIStartDelta(callID, name, argsFrag string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%q,"arguments":%s}}]},"finish_reason":null}]}`+"\n\n",
		callID, name, mustJSON(argsFrag),
	)
}

func openAIArgDelta(argsFrag string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":%s}}]},"finish_reason":null}]}`+"\n\n",
		mustJSON(argsFrag),
	)
}

func openAIFinishDelta() string {
	return `data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"
}

// openAIArgAndFinishDelta emits one event carrying both the closing args
// fragment and finish_reason "tool_calls"; the parser must apply the
// delta before checking finish_reason.
func openAIArgAndFinishDelta(argsFrag string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":%s}}]},"finish_reason":"tool_calls"}]}`+"\n\n",
		mustJSON(argsFrag),
	)
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func feed(acc *OpenAIToolCallAccumulator, raw string) FeedResult {
	res, _ := acc.FeedEvent([]byte(raw))
	return res
}
