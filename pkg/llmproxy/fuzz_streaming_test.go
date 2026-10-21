package llmproxy

// Fuzz targets for the two SSE accumulators. Unlike the property tests,
// which feed structurally valid events, these feed arbitrary bytes:
//
//	FeedEvent must never panic and must always return (no hang) on ANY
//	input.
//
// Each input is split on "\n\n" into an event sequence fed to a fresh
// accumulator. Seeds come from testdata/ fixtures plus hand-written edge
// cases.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// feedTimeout bounds one FeedEvent call; it only trips on a real hang.
const feedTimeout = 5 * time.Second

// maxFuzzEventBytes bounds one event's size per iteration.
const maxFuzzEventBytes = 1 << 20 // 1 MiB

// callWithinTimeout runs fn on a goroutine, re-raising its panic on the
// test goroutine so the fuzz engine records a crasher, and fails if fn
// does not return within d.
func callWithinTimeout(t *testing.T, d time.Duration, desc string, fn func()) {
	t.Helper()
	done := make(chan interface{}, 1) // carries the recovered panic value, or nil
	go func() {
		defer func() { done <- recover() }()
		fn()
	}()
	select {
	case rec := <-done:
		if rec != nil {
			panic(rec)
		}
	case <-time.After(d):
		t.Fatalf("%s did not return within %v (possible hang / infinite loop)", desc, d)
	}
}

// splitSSEEvents splits on "\n\n" and re-appends the terminator, as
// the orchestrator frames events. No boundary yields one event.
func splitSSEEvents(data []byte) [][]byte {
	segs := bytes.Split(data, []byte("\n\n"))
	out := make([][]byte, 0, len(segs))
	for _, s := range segs {
		if len(s) == 0 {
			continue
		}
		ev := make([]byte, 0, len(s)+2)
		ev = append(ev, s...)
		ev = append(ev, '\n', '\n')
		out = append(out, ev)
	}
	if len(out) == 0 {
		// Exercise the no-data path.
		return [][]byte{[]byte("\n\n")}
	}
	return out
}

// readSeedFixture returns a testdata fixture, or nil if unreadable.
func readSeedFixture(name string) []byte {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		return nil
	}
	return b
}

// handWrittenStreamSeeds are provider-agnostic edge cases every SSE
// accumulator should survive.
var handWrittenStreamSeeds = [][]byte{
	[]byte(""),
	[]byte("\n\n"),
	[]byte("data: [DONE]\n\n"),
	[]byte(": a bare comment line\n\n"),
	[]byte("event: ping\n\n"),
	[]byte("data:\n\n"),                        // data prefix, empty payload
	[]byte("data: {\n\n"),                      // truncated / malformed JSON
	[]byte("data: {}\n\n"),                     // valid-JSON, no fields
	[]byte("data: not json at all\n\n"),        // non-JSON payload
	[]byte("data: {\"type\":\"unknown\"}\n\n"), // unknown event type
	[]byte("data: [1,2,3]\n\n"),                // JSON array where object expected
	[]byte("data: \"a string\"\n\n"),           // JSON scalar
	[]byte("data: 12345\n\n"),                  // JSON number
	[]byte("data: null\n\n"),                   // JSON null
	// Multi-line data: SSE-spec continuation (payload joined by '\n').
	[]byte("data: {\"type\":\n data: \"ping\"}\n\n"),
}

func FuzzAnthropicFeedEvent(f *testing.F) {
	for _, name := range []string{
		"anthropic_streaming_single_tool_use.txt",
		"anthropic_streaming_text_only.txt",
		"anthropic_streaming_text_then_tool.txt",
	} {
		if b := readSeedFixture(name); b != nil {
			f.Add(b)
		}
	}
	// A couple of representative single events pulled from the format.
	f.Add([]byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_x\",\"name\":\"bash\",\"input\":{}}}\n\n"))
	f.Add([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}\n\n"))
	f.Add([]byte("data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"))
	for _, s := range handWrittenStreamSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		acc := NewAnthropicAccumulator(0)
		for _, ev := range splitSSEEvents(data) {
			if len(ev) > maxFuzzEventBytes {
				ev = ev[:maxFuzzEventBytes]
			}
			ev := ev // capture for closure
			callWithinTimeout(t, feedTimeout, "AnthropicAccumulator.FeedEvent", func() {
				_, _ = acc.FeedEvent(ev)
			})
		}
	})
}

func FuzzOpenAIFeedEvent(f *testing.F) {
	for _, name := range []string{
		"openai_streaming_single_tool_call.txt",
		"openai_streaming_multi_tool_call.txt",
		"openai_streaming_mixed_text_and_tool.txt",
		"openai_streaming_args_and_finish_in_one_event.txt",
		"openai_streaming_text_only.txt",
	} {
		if b := readSeedFixture(name); b != nil {
			f.Add(b)
		}
	}
	// Representative single events.
	f.Add([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n"))
	f.Add([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n"))
	f.Add([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n"))
	for _, s := range handWrittenStreamSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		acc := NewOpenAIToolCallAccumulator(0)
		for _, ev := range splitSSEEvents(data) {
			if len(ev) > maxFuzzEventBytes {
				ev = ev[:maxFuzzEventBytes]
			}
			ev := ev // capture for closure
			callWithinTimeout(t, feedTimeout, "OpenAIToolCallAccumulator.FeedEvent", func() {
				_, _ = acc.FeedEvent(ev)
			})
		}
	})
}
