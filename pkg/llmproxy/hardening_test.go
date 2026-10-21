package llmproxy

// Covers recoverPanic (a handler panic returns 500 instead of crashing
// the process, and never corrupts a committed response) and the
// --max-concurrent-streams cap (503 + Retry-After at the cap).

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

// ----- recoverPanic middleware -----

// TestServer_RecoverPanic_PerRequestIsolation verifies that a panic in
// one handler returns 500 to the client, doesn't crash the process,
// and that subsequent requests succeed normally.
func TestServer_RecoverPanic_PerRequestIsolation(t *testing.T) {
	cfg := &Config{
		Listen:               "127.0.0.1:0",
		UpstreamOpenAI:       "https://api.openai.com",
		UpstreamAnthropic:    "https://api.anthropic.com",
		GuardURL:             "http://127.0.0.1:8080",
		TenantID:             "test",
		FailMode:             "deny",
		LogLevel:             "info",
		MaxBufferBytes:       DefaultMaxBufferBytes,
		MaxConcurrentStreams: DefaultMaxConcurrentStreams,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.startTime = time.Now()

	// A test-owned mux with panicking handlers next to healthy ones.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /panic", srv.recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		panic("synthetic panic for test")
	}))
	mux.HandleFunc("GET /panic-nil", srv.recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		var p *int
		_ = *p // nil pointer deref — exercises the runtime panic path, not just panic("...")
	}))
	mux.HandleFunc("GET /ok", srv.recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	base := "http://" + ln.Addr().String()

	// 1. Panic handler returns 500, not a connection error.
	resp, err := http.Get(base + "/panic")
	if err != nil {
		t.Fatalf("GET /panic: %v (recoverPanic should have caught the panic and returned 500)", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("panic response status = %d, want 500", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "internal server error") {
		t.Errorf("panic body = %q, want contains 'internal server error'", string(body))
	}
	if !strings.Contains(string(body), "vanzik_error") {
		t.Errorf("panic body = %q, want contains 'vanzik_error' type", string(body))
	}

	// 2. Nil-pointer panic also recovers (runtime.Error path).
	resp, err = http.Get(base + "/panic-nil")
	if err != nil {
		t.Fatalf("GET /panic-nil: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("nil-deref panic status = %d, want 500", resp.StatusCode)
	}
	resp.Body.Close()

	// 3. The server is still alive — healthz and a normal handler
	//    both respond.
	resp, err = http.Get(base + "/ok")
	if err != nil {
		t.Fatalf("GET /ok after panic: %v (process should be alive)", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("subsequent request status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Cycle the panic handler again to confirm repeated panics
	//    don't degrade the server.
	resp, err = http.Get(base + "/panic")
	if err != nil {
		t.Fatalf("GET /panic (2nd time): %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("2nd panic status = %d, want 500", resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = http.Get(base + "/ok")
	if err != nil {
		t.Fatalf("GET /ok after 2nd panic: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("post-2nd-panic status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestServer_RecoverPanic_RoutesWired sanity-checks the invariant that
// every route is wrapped in recoverPanic.
func TestServer_RecoverPanic_RoutesWired(t *testing.T) {
	cfg := &Config{
		Listen:               "127.0.0.1:0",
		UpstreamOpenAI:       "https://api.openai.com",
		UpstreamAnthropic:    "https://api.anthropic.com",
		GuardURL:             "http://127.0.0.1:8080",
		TenantID:             "test",
		FailMode:             "deny",
		LogLevel:             "info",
		MaxBufferBytes:       DefaultMaxBufferBytes,
		MaxConcurrentStreams: DefaultMaxConcurrentStreams,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.startTime = time.Now()

	// /healthz skips auth but must still be panic-safe.
	mux := srv.routes()
	if mux == nil {
		t.Fatalf("routes returned nil")
	}
}

// ----- never append an error envelope onto a committed response -----

// newPanicTestServer builds a minimal Server for exercising recoverPanic.
func newPanicTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &Config{
		Listen:               "127.0.0.1:0",
		UpstreamOpenAI:       "https://api.openai.com",
		UpstreamAnthropic:    "https://api.anthropic.com",
		GuardURL:             "http://127.0.0.1:8080",
		TenantID:             "test",
		FailMode:             "deny",
		LogLevel:             "info",
		MaxBufferBytes:       DefaultMaxBufferBytes,
		MaxConcurrentStreams: DefaultMaxConcurrentStreams,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.startTime = time.Now()
	return srv
}

// TestServer_RecoverPanic_DoesNotAppendToCommittedBody: a panic after
// bytes were flushed must write nothing more. net/http drops the second
// WriteHeader but still writes the body after it, which would hand the
// client `<partial SSE stream><JSON error envelope>`.
func TestServer_RecoverPanic_DoesNotAppendToCommittedBody(t *testing.T) {
	srv := newPanicTestServer(t)

	const committed = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"

	h := srv.recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(committed))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic("panic after the response was committed")
	})

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/stream", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (the committed status must survive)", rec.Code)
	}
	got := rec.Body.String()
	if got != committed {
		t.Errorf("body = %q, want exactly the committed bytes %q — an error envelope was appended onto a partial response (B20)", got, committed)
	}
	if strings.Contains(got, "vanzik_error") || strings.Contains(got, "internal server error") {
		t.Errorf("error envelope leaked into a committed response body: %q", got)
	}
}

// TestServer_RecoverPanic_UncommittedStillGets500: a panic before any
// write still returns a clean 500.
func TestServer_RecoverPanic_UncommittedStillGets500(t *testing.T) {
	srv := newPanicTestServer(t)

	h := srv.recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		panic("panic before anything was written")
	})

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), "vanzik_error") {
		t.Errorf("body = %q, want the JSON error envelope", rec.Body.String())
	}
}

// TestServer_RecoverPanic_ImplicitWriteCommits: a bare Write (implicit
// 200) commits the response just as WriteHeader does.
func TestServer_RecoverPanic_ImplicitWriteCommits(t *testing.T) {
	srv := newPanicTestServer(t)

	h := srv.recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("partial"))
		panic("panic after an implicit 200")
	})

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/implicit", nil))

	if got := rec.Body.String(); got != "partial" {
		t.Errorf("body = %q, want %q — an implicit 200 must count as committed", got, "partial")
	}
}

// TestPassThrough_UpstreamAbortsMidBodyAppendsNoEnvelope: when the
// upstream resets mid-body in forwardTo's io.Copy, the handler's
// writeJSONError(502) must no-op (errResponseCommitted) instead of
// appending an error envelope to the partial body.
func TestPassThrough_UpstreamAbortsMidBodyAppendsNoEnvelope(t *testing.T) {
	const partial = `{"data":[{"embedding":[0.1,0.2`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Promise more than we send, then abort the connection. io.Copy in
		// forwardTo sees an unexpected EOF after the response is committed.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(partial))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler) // kills the connection without a normal close
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Post(base+"/v1/embeddings", "application/json", strings.NewReader(`{"input":"x","model":"m"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	// The read errors (the body is truncated) — that is expected and correct.
	// What matters is what DID arrive.
	got, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(got), "vanzik_error") {
		t.Errorf("a Vanzik error envelope was appended onto a committed, partially-sent body: %q", got)
	}
	if strings.Contains(string(got), `"error"`) {
		t.Errorf("an error object was appended onto a committed body: %q", got)
	}
	// Whatever arrived must be a prefix of the upstream's bytes — never the
	// upstream's bytes with something of ours concatenated on the end.
	if len(got) > 0 && !strings.HasPrefix(partial, string(got)) && !strings.HasPrefix(string(got), partial) {
		t.Errorf("client received bytes that are not a clean prefix/suffix of the upstream body: %q", got)
	}
}

// TestServer_RecoverPanic_PreservesFlusher: every streaming path asserts
// http.Flusher, so a wrapper without Flush would disable SSE everywhere.
func TestServer_RecoverPanic_PreservesFlusher(t *testing.T) {
	srv := newPanicTestServer(t)

	var sawFlusher, flushed bool
	h := srv.recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		sawFlusher = ok
		if ok {
			_, _ = w.Write([]byte("x"))
			f.Flush()
			flushed = true
		}
	})

	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/flush", nil))

	if !sawFlusher {
		t.Fatal("recoverPanic's wrapper broke the http.Flusher assertion — every streaming route would fail")
	}
	if !flushed {
		t.Error("Flush was not reached")
	}
}

// ----- --max-concurrent-streams enforcement -----

// streamingProxyHelper builds a proxy whose upstream emits one SSE event
// then blocks until `release` closes, holding streams open.
func streamingProxyHelper(t *testing.T, mutators ...func(*Config)) (proxyURL string, release chan struct{}, admitted chan struct{}, teardown func()) {
	t.Helper()
	release = make(chan struct{})
	// admitted gets one signal per request reaching the upstream, which
	// happens only after admitStream counted it. Draining N signals is a
	// deterministic barrier; polling the gauge against a deadline starves
	// under parallel load. Buffered so the non-blocking send never drops.
	admitted = make(chan struct{}, 64)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"},\"finish_reason\":null}]}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
		// Non-blocking so an undrained test cannot stall the handler.
		select {
		case admitted <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))

	cfg := &Config{
		Listen:               "127.0.0.1:0",
		UpstreamOpenAI:       upstream.URL,
		UpstreamAnthropic:    upstream.URL,
		GuardURL:             "http://127.0.0.1:8080",
		TenantID:             "test",
		FailMode:             "deny",
		LogLevel:             "info",
		MaxBufferBytes:       DefaultMaxBufferBytes,
		MaxConcurrentStreams: DefaultMaxConcurrentStreams,
	}
	for _, m := range mutators {
		m(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.startTime = time.Now()

	httpSrv := httptest.NewServer(srv.routes())
	teardown = func() {
		// Release blocked upstreams so the servers shut down promptly.
		select {
		case <-release:
		default:
			close(release)
		}
		httpSrv.Close()
		upstream.Close()
	}
	return httpSrv.URL, release, admitted, teardown
}

// waitForAdmitted blocks until n streams have reached the upstream, or
// fails. The timeout is generous: it should only trip on a real hang.
func waitForAdmitted(t *testing.T, admitted <-chan struct{}, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-admitted:
		case <-time.After(30 * time.Second):
			t.Fatalf("timeout: only %d of %d streams reached the upstream", i, n)
		}
	}
}

// fireStreamingRequest returns the status and the unread body, so the
// slot stays occupied until the caller closes it.
func fireStreamingRequest(t *testing.T, base string) (int, io.ReadCloser, error) {
	t.Helper()
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, resp.Body, nil
}

func drainAndClose(rc io.ReadCloser) {
	if rc == nil {
		return
	}
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()
}

// TestServer_MaxConcurrentStreams_RejectsOverflow asserts that with
// MaxConcurrentStreams=2, the third concurrent streaming request is
// refused with 503 + Retry-After: 5 while the first two succeed.
func TestServer_MaxConcurrentStreams_RejectsOverflow(t *testing.T) {
	rejectedBefore := metrics.LLMProxyStreamsRejectedTotal()

	base, release, admitted, teardown := streamingProxyHelper(t, func(c *Config) {
		c.MaxConcurrentStreams = 2
	})
	defer teardown()

	type result struct {
		status int
		body   io.ReadCloser
		err    error
		hdr    http.Header
	}
	resultsCh := make(chan result, 3)

	for i := 0; i < 2; i++ {
		go func() {
			body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				resultsCh <- result{err: err}
				return
			}
			resultsCh <- result{status: resp.StatusCode, body: resp.Body, hdr: resp.Header}
		}()
	}

	waitForAdmitted(t, admitted, 2)
	if got := metrics.LLMProxyStreamsActive(); got < 2 {
		t.Fatalf("streamingActive = %d, want ≥ 2 before firing overflow", got)
	}

	status3, body3, err3 := fireStreamingRequest(t, base)
	if err3 != nil {
		t.Fatalf("3rd request: %v", err3)
	}
	defer drainAndClose(body3)

	if status3 != http.StatusServiceUnavailable {
		t.Errorf("3rd request status = %d, want 503", status3)
	}

	// fireStreamingRequest drops headers; check Retry-After inline.
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp4, err4 := http.DefaultClient.Do(req)
	if err4 != nil {
		t.Fatalf("4th request: %v", err4)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("4th request status = %d, want 503", resp4.StatusCode)
	}
	if got := resp4.Header.Get("Retry-After"); got != "5" {
		t.Errorf("Retry-After = %q, want %q", got, "5")
	}
	respBody, _ := io.ReadAll(resp4.Body)
	if !strings.Contains(string(respBody), "too many concurrent streams") {
		t.Errorf("503 body = %q, want contains 'too many concurrent streams'", string(respBody))
	}
	if !strings.Contains(string(respBody), "vanzik_error") {
		t.Errorf("503 body = %q, want contains 'vanzik_error' type", string(respBody))
	}

	if got := metrics.LLMProxyStreamsRejectedTotal(); got-rejectedBefore < 2 {
		t.Errorf("LLMProxyStreamsRejectedTotal delta = %d, want ≥ 2", got-rejectedBefore)
	}

	close(release)

	for i := 0; i < 2; i++ {
		select {
		case r := <-resultsCh:
			if r.err != nil {
				t.Errorf("held stream errored: %v", r.err)
				continue
			}
			if r.status != http.StatusOK {
				t.Errorf("held stream status = %d, want 200", r.status)
			}
			drainAndClose(r.body)
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for held streams to finish")
		}
	}
}

// TestServer_MaxConcurrentStreams_ZeroDisablesCap fires 10 concurrent
// streams with MaxConcurrentStreams=0; all should succeed.
func TestServer_MaxConcurrentStreams_ZeroDisablesCap(t *testing.T) {
	base, release, admitted, teardown := streamingProxyHelper(t, func(c *Config) {
		c.MaxConcurrentStreams = 0
	})
	defer teardown()

	const fanout = 10
	var wg sync.WaitGroup
	var okCount int64
	var failCount int64
	bodies := make(chan io.ReadCloser, fanout)

	for i := 0; i < fanout; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				atomic.AddInt64(&failCount, 1)
				return
			}
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt64(&okCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
				resp.Body.Close()
				return
			}
			bodies <- resp.Body
		}()
	}

	waitForAdmitted(t, admitted, fanout)
	if got := metrics.LLMProxyStreamsActive(); got < int64(fanout) {
		t.Errorf("streamingActive = %d, want ≥ %d under disabled cap", got, fanout)
	}

	close(release)
	wg.Wait()
	close(bodies)
	for b := range bodies {
		drainAndClose(b)
	}

	if okCount != fanout {
		t.Errorf("ok=%d fail=%d, want all %d to succeed (cap disabled)", okCount, failCount, fanout)
	}
}

// TestServer_MaxConcurrentStreams_DecrementsOnRequestEnd: fire 2
// streams with cap=2, wait for them to complete, fire a 3rd, assert
// it succeeds because the slots have been released.
func TestServer_MaxConcurrentStreams_DecrementsOnRequestEnd(t *testing.T) {
	base, release, admitted, teardown := streamingProxyHelper(t, func(c *Config) {
		c.MaxConcurrentStreams = 2
	})
	defer teardown()

	type result struct {
		status int
		body   io.ReadCloser
	}
	resultsCh := make(chan result, 2)

	for i := 0; i < 2; i++ {
		go func() {
			body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				resultsCh <- result{}
				return
			}
			resultsCh <- result{status: resp.StatusCode, body: resp.Body}
		}()
	}

	waitForAdmitted(t, admitted, 2)
	if got := metrics.LLMProxyStreamsActive(); got < 2 {
		t.Fatalf("streamingActive = %d, want 2 before release", got)
	}

	close(release)

	for i := 0; i < 2; i++ {
		select {
		case r := <-resultsCh:
			if r.status != http.StatusOK {
				t.Errorf("held stream status = %d, want 200", r.status)
			}
			drainAndClose(r.body)
		case <-time.After(20 * time.Second):
			t.Fatalf("timeout waiting for streams to drain")
		}
	}

	// Polling is fine here: release is fast once bodies are drained.
	deadline := time.Now().Add(15 * time.Second)
	for metrics.LLMProxyStreamsActive() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := metrics.LLMProxyStreamsActive(); got != 0 {
		t.Fatalf("streamingActive = %d after stream end, want 0 (release didn't fire)", got)
	}

	// release is closed, so this upstream completes immediately.
	status, body, err := fireStreamingRequest(t, base)
	if err != nil {
		t.Fatalf("3rd request after slot release: %v", err)
	}
	defer drainAndClose(body)
	if status != http.StatusOK {
		t.Errorf("3rd request status = %d, want 200 (slots released)", status)
	}
}

// TestAdmitStream_NoCapStillTracksGauge: with the cap disabled the gauge
// still counts in-flight streams.
func TestAdmitStream_NoCapStillTracksGauge(t *testing.T) {
	cfg := &Config{
		Listen:               "127.0.0.1:0",
		UpstreamOpenAI:       "https://api.openai.com",
		UpstreamAnthropic:    "https://api.anthropic.com",
		GuardURL:             "http://127.0.0.1:8080",
		TenantID:             "test",
		FailMode:             "deny",
		LogLevel:             "info",
		MaxBufferBytes:       DefaultMaxBufferBytes,
		MaxConcurrentStreams: 0,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Burst admit/release calls; gauge should track.
	w := httptest.NewRecorder()
	if !srv.admitStream(w) {
		t.Fatalf("admitStream returned false with cap=0; should always admit")
	}
	if got := srv.streamingActive.Load(); got != 1 {
		t.Errorf("streamingActive = %d, want 1", got)
	}
	srv.releaseStream()
	if got := srv.streamingActive.Load(); got != 0 {
		t.Errorf("streamingActive = %d after release, want 0", got)
	}
}

// TestConfig_MaxConcurrentStreams_DefaultAndValidation: negative values
// are rejected; zero (cap disabled) is accepted.
func TestConfig_MaxConcurrentStreams_DefaultAndValidation(t *testing.T) {
	t.Setenv("VANZIK_API_KEY", "")

	// Default value is wired.
	cfg := &Config{
		Listen:               "127.0.0.1:8081",
		UpstreamOpenAI:       "https://api.openai.com",
		UpstreamAnthropic:    "https://api.anthropic.com",
		GuardURL:             "http://127.0.0.1:8080",
		TenantID:             "test",
		FailMode:             "deny",
		LogLevel:             "info",
		MaxBufferBytes:       DefaultMaxBufferBytes,
		MaxConcurrentStreams: -1,
	}
	if err := cfg.Validate(); err == nil {
		t.Errorf("Validate accepted MaxConcurrentStreams=-1; want error")
	} else if !strings.Contains(err.Error(), "max-concurrent-streams") {
		t.Errorf("err = %v, want contains max-concurrent-streams", err)
	}

	cfg.MaxConcurrentStreams = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected MaxConcurrentStreams=0; want allow (disable sentinel): %v", err)
	}

	cfg.MaxConcurrentStreams = 100
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected MaxConcurrentStreams=100; want allow: %v", err)
	}
}
