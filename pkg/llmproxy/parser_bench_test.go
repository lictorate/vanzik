package llmproxy

// Benchmarks for the two accumulators' FeedEvent, a hot path: every
// streaming event passes through one of them. The idle text delta matters
// most: it is the most frequent event, so anything added to that branch
// is paid per token.

import (
	"testing"
)

var (
	benchAnthropicTextDelta = []byte("event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"the quick brown fox"}}` + "\n\n")

	benchAnthropicToolStart = []byte("event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_bench","name":"bash","input":{}}}` + "\n\n")

	benchAnthropicInputDelta = []byte("event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls -la\"}"}}` + "\n\n")

	benchAnthropicStop = []byte("event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n")

	benchOpenAIContentDelta = []byte(
		`data: {"choices":[{"index":0,"delta":{"content":"the quick brown fox"},"finish_reason":null}]}` + "\n\n")

	benchOpenAIToolDelta = []byte(
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_bench","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"ls -la\"}"}}]},"finish_reason":null}]}` + "\n\n")

	benchOpenAIFinish = []byte(
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n")
)

// BenchmarkAnthropicFeedEvent_IdleTextDelta measures idle non-tool
// deltas, which carry the orphaned-input check.
func BenchmarkAnthropicFeedEvent_IdleTextDelta(b *testing.B) {
	acc := NewAnthropicAccumulator(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := acc.FeedEvent(benchAnthropicTextDelta)
		if err != nil || !res.PassThrough {
			b.Fatalf("unexpected: res=%+v err=%v", res, err)
		}
	}
}

// BenchmarkAnthropicFeedEvent_ToolUseCycle measures a whole gating cycle:
// start (with the empty-seed check), one input delta, stop.
func BenchmarkAnthropicFeedEvent_ToolUseCycle(b *testing.B) {
	acc := NewAnthropicAccumulator(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := acc.FeedEvent(benchAnthropicToolStart); err != nil {
			b.Fatal(err)
		}
		if _, err := acc.FeedEvent(benchAnthropicInputDelta); err != nil {
			b.Fatal(err)
		}
		res, err := acc.FeedEvent(benchAnthropicStop)
		if err != nil || !res.Completed {
			b.Fatalf("unexpected: res=%+v err=%v", res, err)
		}
		acc.Reset()
	}
}

// BenchmarkOpenAIFeedEvent_IdleContentDelta is the OpenAI equivalent of
// the text-delta path: no tool call in flight, forward verbatim.
func BenchmarkOpenAIFeedEvent_IdleContentDelta(b *testing.B) {
	acc := NewOpenAIToolCallAccumulator(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := acc.FeedEvent(benchOpenAIContentDelta)
		if err != nil || !res.PassThrough {
			b.Fatalf("unexpected: res=%+v err=%v", res, err)
		}
	}
}

// BenchmarkOpenAIFeedEvent_ToolCallCycle covers the per-choice scan plus
// argument accumulation, then close.
func BenchmarkOpenAIFeedEvent_ToolCallCycle(b *testing.B) {
	acc := NewOpenAIToolCallAccumulator(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := acc.FeedEvent(benchOpenAIToolDelta); err != nil {
			b.Fatal(err)
		}
		res, err := acc.FeedEvent(benchOpenAIFinish)
		if err != nil || !res.Completed {
			b.Fatalf("unexpected: res=%+v err=%v", res, err)
		}
		acc.Reset()
	}
}
