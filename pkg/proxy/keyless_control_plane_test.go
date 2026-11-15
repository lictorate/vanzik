package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lictorate.com/vanzik/v2/pkg/audit"
	"lictorate.com/vanzik/v2/pkg/policy"
)

// TestHandleAuditRecord_RequiresJSONContentType: a cross-origin page can send
// text/plain (or form) bodies without a CORS preflight, so the ingest only
// accepts application/json, in keyed and keyless mode alike.
func TestHandleAuditRecord_RequiresJSONContentType(t *testing.T) {
	body := `{"rule":"deny:llm_api_proxy:malformed_tool_call","request":{"scope":"shell","command":"x","agent_id":"ct-bot"}}`
	cases := []struct {
		contentType string
		want        int
	}{
		{"application/json", http.StatusOK},
		{"application/json; charset=utf-8", http.StatusOK},
		{"Application/JSON", http.StatusOK},
		{"text/plain", http.StatusUnsupportedMediaType},
		{"text/plain;charset=UTF-8", http.StatusUnsupportedMediaType},
		{"application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"multipart/form-data; boundary=x", http.StatusUnsupportedMediaType},
		{"application/jsonp", http.StatusUnsupportedMediaType},
		{"", http.StatusUnsupportedMediaType},
	}
	modes := []struct {
		name   string
		apiKey string
	}{{"keyed", "test-secret"}, {"keyless", ""}}
	for _, m := range modes {
		for _, tc := range cases {
			t.Run(m.name+"/"+tc.contentType, func(t *testing.T) {
				srv := newTestServer(t, func(c *Config) { c.APIKey = m.apiKey })
				r := httptest.NewRequest(http.MethodPost, "/v1/audit", strings.NewReader(body))
				r.Host = "localhost:8080"
				if tc.contentType != "" {
					r.Header.Set("Content-Type", tc.contentType)
				}
				if m.apiKey != "" {
					r.Header.Set("Authorization", "Bearer "+m.apiKey)
				}
				w := httptest.NewRecorder()
				srv.Handler().ServeHTTP(w, r)
				if w.Code != tc.want {
					t.Errorf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
				}
				entries, err := srv.cfg.Logger.Query(audit.QueryFilter{AgentID: "ct-bot"})
				if err != nil {
					t.Fatalf("query: %v", err)
				}
				wantEntries := 0
				if tc.want == http.StatusOK {
					wantEntries = 1
				}
				if len(entries) != wantEntries {
					t.Errorf("audit entries = %d, want %d", len(entries), wantEntries)
				}
			})
		}
	}
}

// TestResolutionAuditText_NamesChannelNotHuman: the audit text must not claim
// a human acted. A bearer caller can be a script and an unauthenticated one
// is nobody in particular; the entry says which channel admitted the call.
func TestResolutionAuditText_NamesChannelNotHuman(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*http.Request)
		wantVia string
	}{
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer test-secret") }, "bearer"},
		{"session", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "s"}) }, "session"},
		{"unauthenticated", func(*http.Request) {}, "open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			pending := mustAdd(t, srv.approval,
				policy.ActionRequest{Scope: "shell", Command: "sudo reboot", AgentID: "agent-w"},
				policy.CheckResult{Decision: policy.RequireApproval, Rule: "require_approval:shell"},
			)
			req := httptest.NewRequest(http.MethodPost, "/v1/approve/"+pending.ID, nil)
			tc.prepare(req)
			req.RemoteAddr = "203.0.113.7:4242"
			w := httptest.NewRecorder()
			srv.handleApprove(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("approve: %d %s", w.Code, w.Body.String())
			}

			entries := resolutionEntries(t, srv)
			if len(entries) != 1 {
				t.Fatalf("resolution entries = %d, want 1", len(entries))
			}
			reason := entries[0].Result.Reason
			if strings.Contains(reason, "by human") {
				t.Errorf("reason %q claims a human resolved it", reason)
			}
			want := "approval " + pending.ID + " resolved ALLOW via " + tc.wantVia + " from 203.0.113.7"
			if reason != want {
				t.Errorf("reason = %q, want %q", reason, want)
			}

			// The retry's own audit text must not claim a human either.
			pa, _ := srv.approval.Lookup(pending.ID, policy.LocalTenantID)
			res := srv.resolvedApprovalToResult(pending.Request, pa)
			if strings.Contains(res.Reason, "by human") {
				t.Errorf("retry reason %q claims a human resolved it", res.Reason)
			}
		})
	}
}

// TestKeyless_CrossOriginAuditForgeryBlocked drives the full handler chain
// with the verified attack: a page on another localhost port POSTing a
// text/plain body to the keyless /v1/audit. It must be refused before the
// handler, and nothing may reach the audit log.
func TestKeyless_CrossOriginAuditForgeryBlocked(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.APIKey = "" })
	body := `{"rule":"deny:forged","request":{"scope":"shell","command":"x","agent_id":"forged-bot"}}`
	r := httptest.NewRequest(http.MethodPost, "/v1/audit", strings.NewReader(body))
	r.Host = "localhost:8080"
	r.Header.Set("Origin", "http://localhost:3000")
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	entries, err := srv.cfg.Logger.Query(audit.QueryFilter{AgentID: "forged-bot"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("forged audit entries = %d, want 0", len(entries))
	}
}
