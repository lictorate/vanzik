package proxy

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"

	"lictorate.com/vanzik/v2/pkg/internal/gateclient"
	"lictorate.com/vanzik/v2/pkg/metrics"
	"lictorate.com/vanzik/v2/pkg/policy"
)

// The gates' args_digest binds an approval to the full tool arguments
// once the original carries one. An original without one (an SDK caller)
// keeps the field-only binding.
func TestMatchesOriginalRequest_ArgsDigest(t *testing.T) {
	base := policy.ActionRequest{AgentID: "a", Scope: "unmapped", Command: "send_email"}
	with := func(digest string) policy.ActionRequest {
		r := base
		r.Meta = map[string]string{"transport": "llm_api_proxy"}
		if digest != "" {
			r.Meta[gateclient.MetaArgsDigestKey] = digest
		}
		return r
	}
	cases := []struct {
		name            string
		original, retry string
		want            bool
	}{
		{"no digest on either side", "", "", true},
		{"original without digest", "", "d2", true},
		{"same digest", "d1", "d1", true},
		{"different digest", "d1", "d2", false},
		{"retry drops the digest", "d1", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchesOriginalRequest(with(c.retry), with(c.original)); got != c.want {
				t.Errorf("matchesOriginalRequest = %v, want %v", got, c.want)
			}
		})
	}
	// A retry with no meta map at all is a dropped digest too.
	if matchesOriginalRequest(base, with("d1")) {
		t.Error("retry with nil meta honoured a digest-bound approval")
	}
}

// End to end through handleCheck. The redacted command is the same for
// both passwords, so before the digest a replay with another password
// was honoured; now it is evaluated fresh and opens a new approval.
func TestHandleCheck_ApprovalIDReplay_ArgsDigest(t *testing.T) {
	const command = "sudo psql password=[REDACTED]"
	body := func(digest, approvalID string) string {
		meta := `{"transport":"llm_api_proxy","arg_command":"` + command + `"`
		if digest != "" {
			meta += `,"args_digest":"` + digest + `"`
		}
		meta += "}"
		b := fmt.Sprintf(`{"scope":"shell","command":%q,"agent_id":"agent_a","meta":%s`, command, meta)
		if approvalID != "" {
			b += fmt.Sprintf(`,"approval_id":%q`, approvalID)
		}
		return b + "}"
	}
	cases := []struct {
		name            string
		original, retry string
		honoured        bool
		outcome         string
	}{
		{"same arguments", "d-password-one", "d-password-one", true, ""},
		{"other password", "d-password-one", "d-password-two", false, "args_digest=different"},
		{"retry drops the digest", "d-password-one", "", false, "args_digest=missing"},
		{"no digest on either side", "", "", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newReplayTestServer(t)
			approvalID := seedReplayApproval(t, srv, body(c.original, ""))
			mismatchBefore := metrics.ApprovalReplayMismatchTotal()

			var logs bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&logs)
			result, _ := retryCheck(t, srv, body(c.retry, approvalID))
			log.SetOutput(prev)

			if c.honoured {
				if result.Rule != "allow:approved" {
					t.Fatalf("rule = %q, want allow:approved", result.Rule)
				}
				return
			}
			assertNotShortCircuited(t, result)
			if result.Decision != policy.RequireApproval || result.ApprovalID == "" || result.ApprovalID == approvalID {
				t.Errorf("got %s with approval_id %q, want a new approval (not %q)", result.Decision, result.ApprovalID, approvalID)
			}
			if metrics.ApprovalReplayMismatchTotal() <= mismatchBefore {
				t.Error("ApprovalReplayMismatchTotal not incremented")
			}
			if !strings.Contains(logs.String(), c.outcome) {
				t.Errorf("mismatch log lacks %q: %s", c.outcome, logs.String())
			}
			if c.retry != "" && strings.Contains(logs.String(), c.retry) {
				t.Errorf("mismatch log carries the digest value: %s", logs.String())
			}
		})
	}
}

// The approver sees the arguments the approval is bound to, written as
// text: they are agent-controlled.
func TestDashboard_PendingCardShowsArguments(t *testing.T) {
	start := strings.Index(dashboardHTML, "const reqMeta = item.request.meta || {};")
	end := strings.Index(dashboardHTML, "div.appendChild(args);")
	if start < 0 || end < start {
		t.Fatal("pending card does not render the request's arguments")
	}
	block := dashboardHTML[start:end]
	for _, want := range []string{
		"filter(k => k.startsWith('arg_'))",
		"row.textContent = k.slice(4) + ': ' + reqMeta[k];",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("argument block lacks %q", want)
		}
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML"} {
		if strings.Contains(block, bad) {
			t.Errorf("argument block uses %s", bad)
		}
	}
}
