package llmproxy

// Compressed upstream responses must not slip past the gate. The proxy
// drops the client's Accept-Encoding so net/http negotiates gzip itself
// and decodes it; any Content-Encoding left on a gated 2xx response is
// refused (rule deny:llm_api_proxy:undecodable_content_encoding).

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

const (
	encOpenAIToolBody = `{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_enc","type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}]},"finish_reason":"tool_calls"}]}`
	encOpenAISSE      = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_enc\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}]},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n" +
		"data: [DONE]\n\n"
)

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// encodingUpstream records the Accept-Encoding it receives and answers
// with body under contentEncoding ("" = identity). If gzipIfOffered, it
// gzips only when the request offers gzip, like a real compressing API.
func encodingUpstream(t *testing.T, body []byte, ctype, contentEncoding string, gzipIfOffered bool) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ae := r.Header.Get("Accept-Encoding")
		mu.Lock()
		seen = append(seen, ae)
		mu.Unlock()
		out := body
		ce := contentEncoding
		if gzipIfOffered && strings.Contains(ae, "gzip") {
			out, ce = gz(t, body), "gzip"
		}
		w.Header().Set("Content-Type", ctype)
		if ce != "" {
			w.Header().Set("Content-Encoding", ce)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

func postWithAE(t *testing.T, url, body, ae string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if ae != "" {
		req.Header.Set("Accept-Encoding", ae) // explicit: net/http then leaves decoding to us
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

type denyAll struct{ calls atomic.Int64 }

func (d *denyAll) hook(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
	d.calls.Add(1)
	return Decision{Allow: false, Reason: "denied", Rule: "deny:test"}, nil
}

// A client offering br/zstd must not make the proxy forward that offer:
// the upstream sees only the gzip net/http adds itself, on every path.
func TestUpstreamRequest_DropsClientAcceptEncoding(t *testing.T) {
	const clientAE = "gzip, deflate, br, zstd"
	cases := []struct{ name, path, body string }{
		{"openai-nonstream", "/v1/chat/completions", `{"model":"m","messages":[]}`},
		{"openai-stream", "/v1/chat/completions", `{"model":"m","stream":true,"messages":[]}`},
		{"anthropic-nonstream", "/v1/messages", `{"model":"m","max_tokens":5,"messages":[]}`},
		{"anthropic-stream", "/v1/messages", `{"model":"m","max_tokens":5,"stream":true,"messages":[]}`},
		{"openai-ungated-models", "/v1/embeddings", `{"model":"m","input":"x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up, seen := encodingUpstream(t, []byte(`{}`), "application/json", "", false)
			_, base, teardown := newGatedTestServer(t, up, up, nil)
			defer teardown()
			postWithAE(t, base+tc.path, tc.body, clientAE)
			got := seen()
			if len(got) != 1 || got[0] != "gzip" {
				t.Errorf("upstream saw Accept-Encoding %q, want exactly [\"gzip\"]", got)
			}
		})
	}
}

// The regression: a gzip upstream response (the client offered gzip) was
// forwarded undecoded and ungated. It must now reach the gate decoded.
func TestNonStreaming_GzipUpstream_IsGated(t *testing.T) {
	up, _ := encodingUpstream(t, []byte(encOpenAIToolBody), "application/json", "", true)
	var d denyAll
	srv, base, teardown := newGatedTestServer(t, up, nil, d.hook)
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	resp, body := postWithAE(t, base+"/v1/chat/completions", `{"model":"m","messages":[]}`, "gzip, deflate, br, zstd")
	if d.calls.Load() == 0 {
		t.Fatal("gzip response never reached the policy hook (ungated)")
	}
	if bytes.Contains(body, []byte("rm -rf")) || bytes.Contains(body, []byte("call_enc")) {
		t.Errorf("denied tool call reached the client: %s", body)
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("refusal carries Content-Encoding %q for a plain body", ce)
	}
}

func TestStreaming_GzipUpstream_IsGated(t *testing.T) {
	up, _ := encodingUpstream(t, []byte(encOpenAISSE), "text/event-stream", "", true)
	var d denyAll
	srv, base, teardown := newGatedTestServer(t, up, nil, d.hook)
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	_, body := postWithAE(t, base+"/v1/chat/completions", `{"model":"m","stream":true,"messages":[]}`, "gzip, deflate, br, zstd")
	if d.calls.Load() == 0 {
		t.Fatal("gzip SSE never reached the policy hook (ungated)")
	}
	if bytes.Contains(body, []byte("rm -rf")) {
		t.Errorf("denied tool call reached the client: %s", body)
	}
}

// Encodings net/http does not decode (br, zstd, deflate, stacked gzip),
// or any encoding sent although none was requested, are refused and
// audited on gated 2xx responses.
func TestGated2xx_UndecodableContentEncoding_IsRefused(t *testing.T) {
	for _, enc := range []string{"br", "zstd", "deflate", "gzip, gzip", "x-unknown"} {
		for _, stream := range []bool{false, true} {
			name := enc
			if stream {
				name += "/stream"
			}
			t.Run(name, func(t *testing.T) {
				ctype, payload, reqBody := "application/json", encOpenAIToolBody, `{"model":"m","messages":[]}`
				if stream {
					ctype, payload, reqBody = "text/event-stream", encOpenAISSE, `{"model":"m","stream":true,"messages":[]}`
				}
				up, _ := encodingUpstream(t, []byte(payload), ctype, enc, false)
				before := metrics.LLMProxyUndecodableContentEncodingFor("openai")
				var audited []Decision
				var mu sync.Mutex
				srv, base, teardown := newGatedTestServer(t, up, nil, nil)
				defer teardown()
				srv.BuildRefusal = BuildRefusalRich
				srv.RecordForcedAudit = func(_ context.Context, _ *ToolCallCheck, d Decision) {
					mu.Lock()
					audited = append(audited, d)
					mu.Unlock()
				}
				resp, body := postWithAE(t, base+"/v1/chat/completions", reqBody, "gzip, deflate, br, zstd")
				if bytes.Contains(body, []byte("rm -rf")) || bytes.Contains(body, []byte("call_enc")) {
					t.Errorf("undecoded upstream body reached the client: %q", body)
				}
				if ce := resp.Header.Get("Content-Encoding"); ce != "" {
					t.Errorf("refusal carries Content-Encoding %q", ce)
				}
				// 200 and provider-shaped: a non-2xx would make the SDK raise
				// before the agent saw why.
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status = %d, want 200", resp.StatusCode)
				}
				if stream {
					if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
						t.Errorf("Content-Type = %q, want text/event-stream", ct)
					}
					if !strings.HasSuffix(string(body), "data: [DONE]\n\n") || !strings.Contains(string(body), "undecodable_content_encoding") {
						t.Errorf("not an OpenAI SSE refusal naming the rule: %q", body)
					}
				} else {
					var parsed ChatCompletionResponse
					if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Choices) != 1 ||
						parsed.Choices[0].Message.Content == nil || !strings.Contains(*parsed.Choices[0].Message.Content, "undecodable_content_encoding") {
						t.Errorf("not an OpenAI chat.completion refusal naming the rule (err=%v): %q", err, body)
					}
				}
				if got := metrics.LLMProxyUndecodableContentEncodingFor("openai") - before; got != 1 {
					t.Errorf("counter moved by %d, want 1", got)
				}
				mu.Lock()
				defer mu.Unlock()
				if len(audited) != 1 || audited[0].Rule != "deny:llm_api_proxy:undecodable_content_encoding" || audited[0].Allow {
					t.Errorf("audit = %+v, want one deny:llm_api_proxy:undecodable_content_encoding", audited)
				}
			})
		}
	}
}

// Anthropic shares the streaming/non-streaming paths; one case each.
func TestGated2xx_UndecodableContentEncoding_Anthropic(t *testing.T) {
	for _, stream := range []bool{false, true} {
		up, _ := encodingUpstream(t, []byte(`{"type":"message","note":"UPSTREAM_MARK"}`), "application/json", "br", false)
		before := metrics.LLMProxyUndecodableContentEncodingFor("anthropic")
		srv, base, teardown := newGatedTestServer(t, nil, up, nil)
		var got []Decision
		srv.RecordForcedAudit = func(_ context.Context, _ *ToolCallCheck, d Decision) { got = append(got, d) }
		srv.BuildRefusal = BuildRefusalRich
		reqBody := `{"model":"m","max_tokens":5,"messages":[]}`
		if stream {
			reqBody = `{"model":"m","max_tokens":5,"stream":true,"messages":[]}`
		}
		resp, body := postWithAE(t, base+"/v1/messages", reqBody, "gzip, br")
		teardown()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("stream=%v: status = %d, want 200", stream, resp.StatusCode)
		}
		if got := metrics.LLMProxyUndecodableContentEncodingFor("anthropic") - before; got != 1 {
			t.Errorf("stream=%v: counter moved by %d, want 1", stream, got)
		}
		if stream {
			// The Anthropic SDKs reject a stream that does not open with
			// message_start.
			if !strings.HasPrefix(string(body), "event: message_start\n") || !strings.HasSuffix(string(body), "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n") {
				t.Errorf("not a complete Anthropic stream: %q", body)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
				t.Errorf("Content-Type = %q, want text/event-stream", ct)
			}
		} else {
			var parsed AnthropicMessagesResponse
			if err := json.Unmarshal(body, &parsed); err != nil || parsed.Type != "message" {
				t.Errorf("not an Anthropic message refusal (err=%v): %q", err, body)
			}
		}
		if len(got) != 1 || got[0].Rule != "deny:llm_api_proxy:undecodable_content_encoding" {
			t.Errorf("stream=%v: audit = %+v", stream, got)
		}
		if strings.Contains(string(body), "UPSTREAM_MARK") {
			t.Errorf("stream=%v: undecoded body reached the client", stream)
		}
	}
}

// --max-buffer-bytes bounds the decoded size: a small gzip body that
// inflates past the cap is refused, not buffered whole.
func TestNonStreaming_GzipBomb_BoundedByDecodedCap(t *testing.T) {
	big := []byte(`{"id":"b","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"` +
		strings.Repeat("A", 5<<20) + `"},"finish_reason":"stop"}]}`)
	up, _ := encodingUpstream(t, big, "application/json", "", true)
	srv, base, teardown := newGatedTestServer(t, up, nil, nil, func(c *Config) { c.MaxBufferBytes = 64 << 10 })
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	_, body := postWithAE(t, base+"/v1/chat/completions", `{"model":"m","messages":[]}`, "gzip")
	if len(body) > 8<<10 {
		t.Errorf("client received %d bytes; want a small refusal", len(body))
	}
	if !strings.Contains(string(body), "exceeds gating buffer") {
		t.Errorf("want buffer-overflow refusal, got %.200s", body)
	}
}

// The ungated forwarder hands the client a decoded body with no stale
// Content-Encoding, whatever the client offered.
func TestUngated_GzipUpstream_ClientGetsDecodedBody(t *testing.T) {
	up, _ := encodingUpstream(t, []byte(`{"data":[]}`), "application/json", "", true)
	_, base, teardown := newGatedTestServer(t, up, nil, nil)
	defer teardown()
	resp, body := postWithAE(t, base+"/v1/embeddings", `{"model":"m","input":"x"}`, "gzip, br")
	if ce := resp.Header.Get("Content-Encoding"); ce != "" || string(body) != `{"data":[]}` {
		t.Errorf("CE=%q body=%q, want decoded body and no Content-Encoding", ce, body)
	}
}

func TestUndecodedContentEncoding(t *testing.T) {
	for _, tc := range []struct {
		vals []string
		want string
	}{
		{nil, ""}, {[]string{""}, ""}, {[]string{"identity"}, ""}, {[]string{"Identity"}, ""},
		{[]string{"br"}, "br"}, {[]string{"GZIP"}, "GZIP"}, {[]string{"gzip, gzip"}, "gzip, gzip"},
		{[]string{"identity", "zstd"}, "identity, zstd"},
	} {
		h := http.Header{}
		for _, v := range tc.vals {
			h.Add("Content-Encoding", v)
		}
		if got := undecodedContentEncoding(h); got != tc.want {
			t.Errorf("%q -> %q, want %q", tc.vals, got, tc.want)
		}
	}
}

// The non-streaming overflow refusal replaces a response the client
// would otherwise have received, so it is audited like every other
// gated refusal.
func TestNonStreaming_BufferOverflow_IsAudited(t *testing.T) {
	big := []byte(`{"id":"b","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"` +
		strings.Repeat("A", 4096) + `"},"finish_reason":"stop"}]}`)
	up, _ := encodingUpstream(t, big, "application/json", "", false)
	var mu sync.Mutex
	var audited []Decision
	var checks []ToolCallCheck
	srv, base, teardown := newGatedTestServer(t, up, nil, nil, func(c *Config) { c.MaxBufferBytes = 256 })
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich
	srv.RecordForcedAudit = func(_ context.Context, tc *ToolCallCheck, d Decision) {
		mu.Lock()
		audited = append(audited, d)
		checks = append(checks, *tc)
		mu.Unlock()
	}

	_, body := postWithAE(t, base+"/v1/chat/completions", `{"model":"m","messages":[]}`, "")
	if !strings.Contains(string(body), "exceeds gating buffer") {
		t.Fatalf("want buffer-overflow refusal, got %.200s", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(audited) != 1 || audited[0].Rule != "deny:llm_api_proxy:non_streaming_buffer_overflow" || audited[0].Allow {
		t.Fatalf("audit = %+v, want one deny:llm_api_proxy:non_streaming_buffer_overflow", audited)
	}
	if checks[0].Provider != "openai" || checks[0].Stream || checks[0].AgentID != "llm-proxy" {
		t.Errorf("audit check = %+v, want provider openai, non-stream, agent llm-proxy", checks[0])
	}
}
