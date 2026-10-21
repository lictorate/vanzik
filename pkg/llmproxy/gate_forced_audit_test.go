package llmproxy

// When RecordForcedAudit's POST /v1/audit fails (typically a keyed central
// server and an unkeyed proxy: /v1/check is open, /v1/audit returns 401),
// it replays the ActionRequest through /v1/check so an entry still exists,
// with the engine verdict. The failure never reaches the client.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRecordForcedAudit_AuditFailureFallsBackToCheck(t *testing.T) {
	var auditHits, checkHits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/audit"):
			// Keyed server, unkeyed proxy: /v1/audit is auth-gated → 401.
			auditHits.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case strings.HasSuffix(r.URL.Path, "/check"):
			checkHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"v1","decision":"ALLOW","reason":"engine allow","matched_rule":"allow:mock"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	gate := NewHTTPPolicyClient(&Config{
		GuardURL: srv.URL,
		// APIKey empty: unkeyed proxy.
		TenantID: "local",
		FailMode: "deny",
	}, nil)

	decision := malformedToolCallDecision()
	req := toolCall("openai", "bash", map[string]interface{}{"command": "ls"})

	// Fire-and-forget: must not panic or block whatever /v1/audit does.
	gate.RecordForcedAudit(context.Background(), req, decision)

	if got := auditHits.Load(); got != 1 {
		t.Errorf("expected exactly 1 /v1/audit attempt, got %d", got)
	}
	if got := checkHits.Load(); got != 1 {
		t.Fatalf("expected the fallback to drive exactly 1 /v1/check call after /v1/audit 401, got %d "+
			"(audit trail would be dark for this refusal)", got)
	}
}

// TestRecordForcedAudit_AuditSuccessDoesNotFallBack: when /v1/audit
// succeeds, /v1/check is not also called, which would double-log.
func TestRecordForcedAudit_AuditSuccessDoesNotFallBack(t *testing.T) {
	var auditHits, checkHits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/audit"):
			auditHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"v1","decision":"DENY","reason":"recorded verbatim","matched_rule":"deny:llm_api_proxy:malformed_tool_call"}`))
		case strings.HasSuffix(r.URL.Path, "/check"):
			checkHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"v1","decision":"ALLOW"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	gate := NewHTTPPolicyClient(&Config{
		GuardURL: srv.URL,
		APIKey:   "matched-key",
		TenantID: "local",
		FailMode: "deny",
	}, nil)

	gate.RecordForcedAudit(context.Background(),
		toolCall("openai", "bash", map[string]interface{}{"command": "ls"}),
		malformedToolCallDecision())

	if got := auditHits.Load(); got != 1 {
		t.Errorf("expected 1 /v1/audit call, got %d", got)
	}
	if got := checkHits.Load(); got != 0 {
		t.Errorf("expected NO /v1/check fallback on audit success, got %d", got)
	}
}
