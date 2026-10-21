package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lictorate.com/vanzik/v2/pkg/audit"
	"lictorate.com/vanzik/v2/pkg/notify"
	"lictorate.com/vanzik/v2/pkg/policy"
)

// resolutionEntries returns the audit entries the approve/deny handlers
// wrote (rule approval:resolved:*).
func resolutionEntries(t *testing.T, srv *Server) []audit.Entry {
	t.Helper()
	all, err := srv.cfg.Logger.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var out []audit.Entry
	for _, e := range all {
		if strings.HasPrefix(e.Result.Rule, "approval:resolved:") {
			out = append(out, e)
		}
	}
	return out
}

// testResolutionAudit resolves one pending approval twice through the HTTP
// handler and checks that exactly one audit entry records the decision and
// the actor; the idempotent repeat writes nothing.
func testResolutionAudit(t *testing.T, path string, handler func(*Server) http.HandlerFunc, want policy.Decision) {
	srv := newTestServer(t)
	pending := mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo reboot", AgentID: "agent-b", SessionID: "s1"},
		policy.CheckResult{Decision: policy.RequireApproval, Rule: "require_approval:shell"},
	)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, path+pending.ID, nil)
		req.Header.Set("Authorization", "Bearer test-secret")
		req.RemoteAddr = "203.0.113.7:4242"
		w := httptest.NewRecorder()
		handler(srv)(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("call %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}

	entries := resolutionEntries(t, srv)
	if len(entries) != 1 {
		t.Fatalf("expected 1 resolution entry, got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Result.Decision != want {
		t.Errorf("decision: got %s, want %s", e.Result.Decision, want)
	}
	if e.Result.Rule != "approval:resolved:bearer" {
		t.Errorf("rule: got %q, want approval:resolved:bearer", e.Result.Rule)
	}
	if e.Result.ApprovalID != pending.ID {
		t.Errorf("approval_id: got %q, want %q", e.Result.ApprovalID, pending.ID)
	}
	if !strings.Contains(e.Result.Reason, "203.0.113.7") {
		t.Errorf("reason %q does not name the peer address", e.Result.Reason)
	}
	if e.AgentID != "agent-b" || e.SessionID != "s1" || e.Request.Command != "sudo reboot" {
		t.Errorf("entry does not carry the original request: %+v", e)
	}
	if e.Transport != audit.TransportSDK {
		t.Errorf("transport: got %q, want %q", e.Transport, audit.TransportSDK)
	}
}

func TestApproveWritesAuditEntry(t *testing.T) {
	testResolutionAudit(t, "/v1/approve/", func(s *Server) http.HandlerFunc { return s.handleApprove }, policy.Allow)
}

func TestDenyWritesAuditEntry(t *testing.T) {
	testResolutionAudit(t, "/v1/deny/", func(s *Server) http.HandlerFunc { return s.handleDeny }, policy.Deny)
}

// TestRateLimitDenyNotifies: an on_deny target receives rate-limit denies,
// as configs/default.yaml documents.
func TestRateLimitDenyNotifies(t *testing.T) {
	got := make(chan notify.Event, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev notify.Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err == nil {
			got <- ev
		}
	}))
	t.Cleanup(hook.Close)

	logger, err := audit.NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	disp := notify.NewDispatcher(policy.NotificationCfg{
		OnDeny: []policy.NotifyTarget{{Type: "webhook", URL: hook.URL}},
	})
	t.Cleanup(disp.Close)

	pol := &policy.Policy{
		Version: "1",
		Name:    "ratelimit-notify-test",
		Rules: []policy.RuleSet{{
			Scope:     "shell",
			Allow:     []policy.Rule{{Pattern: "echo *"}},
			RateLimit: &policy.RateLimitCfg{MaxRequests: 1, Window: "1m"},
		}},
	}
	srv := NewServer(Config{
		Engine:   policy.NewEngineFromPolicy(pol),
		Logger:   logger,
		Notifier: disp,
		BaseURL:  "http://localhost:0",
		Version:  "test",
	})

	body := `{"scope":"shell","command":"echo hi","agent_id":"a1"}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		srv.handleCheck(httptest.NewRecorder(), req)
	}

	select {
	case ev := <-got:
		if ev.Type != "denied" {
			t.Errorf("event type: got %q, want denied", ev.Type)
		}
		if ev.Result.Rule != "deny:ratelimit:shell" {
			t.Errorf("rule: got %q, want deny:ratelimit:shell", ev.Result.Rule)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no on_deny notification for the rate-limit deny")
	}
}
