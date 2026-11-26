package llmproxy

// Per-event cost of the SSE splitter and of a whole stream loop
// (splitter, BOM check, FeedEvent, write). The FeedEvent benchmarks in
// parser_bench_test.go do not cover the splitter.

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// repeatReader returns b over and over, never EOF.
type repeatReader struct {
	b   []byte
	off int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c := copy(p[n:], r.b[r.off:])
		n += c
		r.off = (r.off + c) % len(r.b)
	}
	return n, nil
}

// BenchmarkReadSSEEvent_LF splits LF-framed OpenAI content deltas, one
// event per op.
func BenchmarkReadSSEEvent_LF(b *testing.B) {
	r := bufio.NewReader(&repeatReader{b: benchOpenAIContentDelta})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev, err := readSSEEvent(r, 0)
		if err != nil || len(ev) != len(benchOpenAIContentDelta) {
			b.Fatalf("event %q err %v", ev, err)
		}
	}
}

type benchDiscardWriter struct{ h http.Header }

func (w *benchDiscardWriter) Header() http.Header         { return w.h }
func (w *benchDiscardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *benchDiscardWriter) WriteHeader(int)             {}
func (w *benchDiscardWriter) Flush()                      {}

func benchStreamServer(b *testing.B) *Server {
	b.Helper()
	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    "https://api.openai.com",
		UpstreamAnthropic: "https://api.anthropic.com",
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "bench",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	if err := cfg.Validate(); err != nil {
		b.Fatal(err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		b.Fatal(err)
	}
	return srv
}

const benchStreamEvents = 256

// benchmarkStreamLoop runs one whole text stream per op and reports the
// cost per event.
func benchmarkStreamLoop(b *testing.B, provider string, stream []byte) {
	srv := benchStreamServer(b)
	w := &benchDiscardWriter{h: http.Header{}}
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if provider == "anthropic" {
			srv.runAnthropicStreamLoop(w, w, req, bytes.NewReader(stream))
		} else {
			srv.runOpenAIStreamLoop(w, w, req, bytes.NewReader(stream))
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*benchStreamEvents), "ns/event")
}

// BenchmarkOpenAIStreamLoop_TextStream: 254 content deltas, a finish
// and [DONE], LF-framed as OpenAI sends them.
func BenchmarkOpenAIStreamLoop_TextStream(b *testing.B) {
	stream := append(bytes.Repeat(benchOpenAIContentDelta, benchStreamEvents-2),
		[]byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\ndata: [DONE]\n\n")...)
	benchmarkStreamLoop(b, "openai", stream)
}

// BenchmarkAnthropicStreamLoop_TextStream: one text block of 252
// deltas inside a message, LF-framed as Anthropic sends them.
func BenchmarkAnthropicStreamLoop_TextStream(b *testing.B) {
	var s []byte
	s = append(s, "event: message_start\n"+`data: {"type":"message_start","message":{"id":"msg_b","type":"message","role":"assistant","model":"m","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}`+"\n\n"...)
	s = append(s, "event: content_block_start\n"+`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`+"\n\n"...)
	s = append(s, bytes.Repeat(benchAnthropicTextDelta, benchStreamEvents-4)...)
	s = append(s, benchAnthropicStop...)
	s = append(s, "event: message_stop\n"+`data: {"type":"message_stop"}`+"\n\n"...)
	benchmarkStreamLoop(b, "anthropic", s)
}
