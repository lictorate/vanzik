package llmproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// delayedUpstream withholds response headers for hold (or until
// released at cleanup).
func delayedUpstream(t *testing.T, hold time.Duration) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(hold):
		case <-release:
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[]}`))
	}))
	// Cleanups run LIFO: release first, or Close waits out the stall.
	t.Cleanup(up.Close)
	t.Cleanup(func() { close(release) })
	return up
}

func newHeaderTimeoutProxy(t *testing.T, up *httptest.Server, timeout time.Duration) string {
	t.Helper()
	cfg := &Config{
		Listen:                "127.0.0.1:0",
		UpstreamOpenAI:        up.URL,
		UpstreamAnthropic:     up.URL,
		GuardURL:              "http://127.0.0.1:8080",
		TenantID:              "test",
		FailMode:              "deny",
		LogLevel:              "info",
		MaxBufferBytes:        DefaultMaxBufferBytes,
		UpstreamHeaderTimeout: timeout,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.startTime = time.Now()
	hs := httptest.NewServer(srv.routes())
	t.Cleanup(hs.Close)
	return hs.URL
}

func postChat(t *testing.T, base string, stream bool) (int, string, time.Duration) {
	t.Helper()
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]`
	if stream {
		body += `,"stream":true`
	}
	body += `}`
	start := time.Now()
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), time.Since(start)
}

func TestUpstreamHeaderTimeout_StalledUpstreamReturns502(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "non-streaming"
		if stream {
			name = "streaming"
		}
		t.Run(name, func(t *testing.T) {
			up := delayedUpstream(t, time.Minute)
			base := newHeaderTimeoutProxy(t, up, 200*time.Millisecond)
			code, body, took := postChat(t, base, stream)
			if code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502 (body %q)", code, body)
			}
			if !strings.Contains(body, "error") {
				t.Errorf("body %q lacks error envelope", body)
			}
			if took > 5*time.Second {
				t.Errorf("took %s, want well under the 1m stall", took)
			}
		})
	}
}

func TestUpstreamHeaderTimeout_ZeroDisables(t *testing.T) {
	up := delayedUpstream(t, 600*time.Millisecond)
	base := newHeaderTimeoutProxy(t, up, 0)
	code, body, _ := postChat(t, base, false)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with timeout disabled (body %q)", code, body)
	}
}

func TestUpstreamHeaderTimeout_Config(t *testing.T) {
	cfg, err := ParseConfigWithOutput(nil, &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpstreamHeaderTimeout != 10*time.Minute {
		t.Errorf("default = %s, want 10m", cfg.UpstreamHeaderTimeout)
	}
	cfg, err = ParseConfigWithOutput([]string{"--upstream-header-timeout", "0"}, &strings.Builder{})
	if err != nil || cfg.UpstreamHeaderTimeout != 0 {
		t.Errorf("0: cfg=%v err=%v", cfg, err)
	}
	if _, err = ParseConfigWithOutput([]string{"--upstream-header-timeout", "-1s"}, &strings.Builder{}); err == nil {
		t.Error("negative accepted")
	}
}
