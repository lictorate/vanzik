package llmproxy

// Byte identity through the full Server and its routes: on ALLOW a real
// HTTP client receives the upstream SSE bytes unchanged; on DENY no
// upstream tool_call bytes leak. Chunked-encoding framing is stripped by
// the client, so bytes.Equal needs no normalization.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAT_E2E_ByteIdentity_ALLOW(t *testing.T) {
	for _, fx := range []string{
		"openai_streaming_text_only.txt",
		"openai_streaming_single_tool_call.txt",
		"openai_streaming_multi_tool_call.txt",
		"openai_streaming_mixed_text_and_tool.txt",
	} {
		t.Run(fx, func(t *testing.T) {
			fixture := readFixture(t, fx)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(fixture)
			}))
			defer upstream.Close()

			base, teardown := newStreamingTestServer(t, upstream)
			defer teardown()

			body := `{"model":"gpt-4","messages":[],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, fixture) {
				t.Errorf("byte-identity violated for %s: got %d bytes, fixture %d bytes",
					fx, len(got), len(fixture))
				if len(got) < 4096 && len(fixture) < 4096 {
					t.Errorf("got =%q\nwant=%q", string(got), string(fixture))
				}
			}
		})
	}
}

func TestAT_E2E_ByteIdentity_DENY_DoesNotLeakUpstreamToolCalls(t *testing.T) {
	cases := []struct {
		fx          string
		secretIDs   []string // ids that MUST NOT appear in client bytes
		fingerprint string   // a substring from the fixture body that MUST NOT leak
	}{
		{
			fx:          "openai_streaming_single_tool_call.txt",
			secretIDs:   []string{"call_abc123"},
			fingerprint: `"name":"bash"`,
		},
		{
			fx:          "openai_streaming_multi_tool_call.txt",
			secretIDs:   []string{"call_a", "call_b"},
			fingerprint: `"path":"/tmp/x"`,
		},
	}
	for _, c := range cases {
		t.Run(c.fx, func(t *testing.T) {
			fixture := readFixture(t, c.fx)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(fixture)
			}))
			defer upstream.Close()

			base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
				s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
					return Decision{Allow: false, Reason: "policy denies " + tc.ToolName, Rule: "deny:test"}, nil
				}
			})
			defer teardown()

			body := `{"model":"gpt-4","messages":[],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)

			// The fixture must contain the ids checked below.
			fixtureStr := string(fixture)
			for _, id := range c.secretIDs {
				if !strings.Contains(fixtureStr, id) {
					t.Fatalf("fixture %s does not contain expected id %q (test invariant broken)", c.fx, id)
				}
			}
			gotStr := string(got)
			for _, id := range c.secretIDs {
				if strings.Contains(gotStr, id) {
					t.Errorf("upstream tool_call id %q leaked into DENY-path client bytes", id)
				}
			}
			if strings.Contains(gotStr, c.fingerprint) {
				t.Errorf("upstream fingerprint %q leaked into DENY-path client bytes", c.fingerprint)
			}
			if !strings.Contains(gotStr, "[DONE]") {
				t.Errorf("expected [DONE] in OpenAI refusal; got %q", gotStr)
			}
		})
	}
}

func TestAT_E2E_ByteIdentity_DENY_Anthropic_NoLeak(t *testing.T) {
	fixture := readFixture(t, "anthropic_streaming_single_tool_use.txt")
	if !strings.Contains(string(fixture), "toolu_xyz") {
		t.Fatalf("fixture provenance changed: expected toolu_xyz in fixture")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{Allow: false, Reason: "shell denied", Rule: "deny:shell"}, nil
		}
	})
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	if strings.Contains(gotStr, "toolu_xyz") {
		t.Errorf("Anthropic tool_use id leaked into DENY path: %q", gotStr)
	}
	if strings.Contains(gotStr, `"name":"bash"`) {
		t.Errorf("Anthropic tool_use name leaked into DENY path: %q", gotStr)
	}
	if !strings.Contains(gotStr, "stop_reason") {
		t.Errorf("expected stop_reason rewrite in Anthropic refusal; got %q", gotStr)
	}
}

// TestAT_E2E_ByteIdentity_SSEPayloadEquality compares the sequence of
// `data:` lines rather than raw bytes, so it survives an intermediary
// that re-chunks the stream.
func TestAT_E2E_ByteIdentity_SSEPayloadEquality(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_single_tool_call.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream)
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	gotData := extractDataLines(got)
	wantData := extractDataLines(fixture)
	if len(gotData) != len(wantData) {
		t.Fatalf("data-line count mismatch: got=%d want=%d", len(gotData), len(wantData))
	}
	for i := range gotData {
		if gotData[i] != wantData[i] {
			t.Errorf("data line %d mismatch:\n got=%q\nwant=%q", i, gotData[i], wantData[i])
		}
	}
}

func extractDataLines(b []byte) []string {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "data: ") || strings.HasPrefix(line, "data:") {
			out = append(out, line)
		}
	}
	return out
}
