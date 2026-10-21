package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lictorate.com/vanzik/v2/pkg/audit"
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
