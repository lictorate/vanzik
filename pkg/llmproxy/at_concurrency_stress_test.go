package llmproxy

// Concurrency stress: 100 streams with mixed ALLOW / DENY /
// REQUIRE_APPROVAL outcomes; no client may receive another request's
// bytes. Run with -race.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestAT_Concurrency_NoCrossRequestLeak: each request has a unique
// tool_call id and a deterministic outcome; each response must show its
// own id (or refusal) and never another request's.
func TestAT_Concurrency_NoCrossRequestLeak(t *testing.T) {
	const concurrency = 100

	// The upstream echoes the client's tag into the tool_call id.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callID := r.Header.Get("X-Test-Call-ID")
		if callID == "" {
			callID = "default"
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`+"\n\n")
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"true\"}"}}]},"finish_reason":null}]}`+"\n\n",
			callID)
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	// Outcome is `i % 3`, decided from the ToolCallID.
	const (
		outcomeAllow    = 0
		outcomeDeny     = 1
		outcomeApproval = 2
	)
	expectedOutcome := func(i int) int { return i % 3 }

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			var idx int
			if _, err := fmt.Sscanf(tc.ToolCallID, "call_stress_%d", &idx); err != nil {
				return Decision{Allow: true, Rule: "allow:fallback"}, nil
			}
			switch expectedOutcome(idx) {
			case outcomeAllow:
				return Decision{Allow: true, Rule: "allow:test"}, nil
			case outcomeDeny:
				return Decision{Allow: false, Reason: "stress test deny", Rule: "deny:stress"}, nil
			case outcomeApproval:
				return Decision{
					Allow:            false,
					RequiresApproval: true,
					Reason:           "stress test approval",
					Rule:             "require_approval:stress",
					ApprovalID:       fmt.Sprintf("ap_stress_%d", idx),
					ApprovalURL:      fmt.Sprintf("http://localhost:8080/approve/ap_stress_%d", idx),
				}, nil
			}
			return Decision{Allow: true}, nil
		}
	})
	defer teardown()

	var wg sync.WaitGroup
	var failures atomic.Int64

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			callID := fmt.Sprintf("call_stress_%d", i)
			body := `{"model":"gpt-4","messages":[],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Test-Call-ID", callID)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("client %d: post: %v", i, err)
				failures.Add(1)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("client %d: status = %d", i, resp.StatusCode)
				failures.Add(1)
				return
			}
			got, _ := io.ReadAll(resp.Body)
			gotStr := string(got)

			// Match quoted ids: `call_stress_4` is a substring of
			// `call_stress_48`.
			for j := 0; j < concurrency; j++ {
				if j == i {
					continue
				}
				other := fmt.Sprintf(`"call_stress_%d"`, j)
				if strings.Contains(gotStr, other) {
					t.Errorf("client %d leaked another client's id %q\nbody=%s",
						i, other, gotStr)
					failures.Add(1)
				}
			}
			ownIDQuoted := fmt.Sprintf(`"%s"`, callID)
			ownApprovalQuoted := fmt.Sprintf(`ap_stress_%d`, i)

			switch expectedOutcome(i) {
			case outcomeAllow:
				if !strings.Contains(gotStr, ownIDQuoted) {
					t.Errorf("client %d (ALLOW): expected own id %q, got %q", i, callID, gotStr)
					failures.Add(1)
				}
				if !strings.Contains(gotStr, "tool_calls") {
					t.Errorf("client %d (ALLOW): expected tool_calls finish_reason; got %q", i, gotStr)
					failures.Add(1)
				}
			case outcomeDeny:
				if strings.Contains(gotStr, ownIDQuoted) {
					t.Errorf("client %d (DENY): leaked own buffered id %q", i, callID)
					failures.Add(1)
				}
				if !strings.Contains(gotStr, "deny:stress") {
					t.Errorf("client %d (DENY): refusal missing rule; got %q", i, gotStr)
					failures.Add(1)
				}
			case outcomeApproval:
				if strings.Contains(gotStr, ownIDQuoted) {
					t.Errorf("client %d (APPROVAL): leaked own buffered id %q", i, callID)
					failures.Add(1)
				}
				if !strings.Contains(gotStr, ownApprovalQuoted) {
					t.Errorf("client %d (APPROVAL): missing own approval_id %q; got %q",
						i, ownApprovalQuoted, gotStr)
					failures.Add(1)
				}
				// Other clients' approval ids must not appear; match at
				// a boundary since ap_stress_5 is a prefix of ap_stress_50.
				for j := 0; j < concurrency; j++ {
					if j == i {
						continue
					}
					otherAp := fmt.Sprintf("ap_stress_%d", j)
					if containsAtBoundary(gotStr, otherAp) {
						t.Errorf("client %d (APPROVAL): leaked other approval %q", i, otherAp)
						failures.Add(1)
					}
				}
			}
		}(i)
	}
	wg.Wait()
	if failures.Load() > 0 {
		t.Fatalf("%d concurrency failures across %d streams", failures.Load(), concurrency)
	}
}

// containsAtBoundary reports whether needle appears in s not followed
// by an identifier byte, so `ap_stress_5` does not match `ap_stress_50`.
func containsAtBoundary(s, needle string) bool {
	idx := 0
	for {
		off := strings.Index(s[idx:], needle)
		if off < 0 {
			return false
		}
		end := idx + off + len(needle)
		if end >= len(s) {
			return true
		}
		next := s[end]
		if (next >= '0' && next <= '9') || (next >= 'A' && next <= 'Z') || (next >= 'a' && next <= 'z') || next == '_' {
			idx = end
			continue
		}
		return true
	}
}

// TestAT_Concurrency_FailModeAllowAndDenyRespected: under load, a
// PolicyCheck error is handled per the configured fail-mode on every
// stream.
func TestAT_Concurrency_FailModeAllowAndDenyRespected(t *testing.T) {
	const concurrency = 30
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_fm","type":"function","function":{"name":"bash","arguments":"{}"}}]},"finish_reason":null}]}`+"\n\n")
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	t.Run("fail-mode-deny", func(t *testing.T) {
		base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
			s.cfg.FailMode = "deny"
			// Only the rich builder renders the Rule operators alert on.
			s.BuildRefusal = BuildRefusalRich
			s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
				return Decision{}, fmt.Errorf("simulated /v1/check unreachable")
			}
		})
		defer teardown()

		var wg sync.WaitGroup
		var leaks atomic.Int64
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := `{"model":"gpt-4","messages":[],"stream":true}`
				req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					leaks.Add(1)
					return
				}
				defer resp.Body.Close()
				got, _ := io.ReadAll(resp.Body)
				gotStr := string(got)
				if strings.Contains(gotStr, `"call_fm"`) {
					leaks.Add(1)
				}
				if !strings.Contains(gotStr, FailModeRuleClosed) {
					leaks.Add(1)
				}
				// The audit variant belongs to a different fail-mode.
				if strings.Contains(gotStr, FailModeRuleClosedAudit) {
					leaks.Add(1)
				}
			}()
		}
		wg.Wait()
		if leaks.Load() > 0 {
			t.Errorf("fail-mode deny: %d clients saw upstream tool_call leak or missing fail-closed marker", leaks.Load())
		}
	})

	t.Run("fail-mode-allow", func(t *testing.T) {
		base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
			s.cfg.FailMode = "allow"
			s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
				return Decision{}, fmt.Errorf("simulated /v1/check unreachable")
			}
		})
		defer teardown()

		var wg sync.WaitGroup
		var miss atomic.Int64
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := `{"model":"gpt-4","messages":[],"stream":true}`
				req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					miss.Add(1)
					return
				}
				defer resp.Body.Close()
				got, _ := io.ReadAll(resp.Body)
				// The gate error is ignored; the stream must still end
				// with [DONE].
				if !strings.Contains(string(got), "[DONE]") {
					miss.Add(1)
				}
			}()
		}
		wg.Wait()
		if miss.Load() > 0 {
			t.Errorf("fail-mode allow: %d clients did not see [DONE] terminator", miss.Load())
		}
	})
}
