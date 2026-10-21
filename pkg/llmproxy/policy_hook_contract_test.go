package llmproxy

// Contract tests for the nil-PolicyCheck behaviour, the llmproxy
// twin of pkg/mcpgw/policy_hook_contract_test.go.
//
// Tripwires, not cages: they pin the fail-open-when-unwired default and
// the two guarantees that make it survivable: the allow is identifiable,
// and the duplicate-JSON-key deny fires even with no hook. Making the
// unwired server fail closed (the recommended direction) should break
// them, alongside a CHANGELOG entry.

import (
	"context"
	"strings"
	"testing"
)

func hookContractServer(t *testing.T) *Server {
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
	if srv.PolicyCheck != nil {
		t.Fatal("precondition: a freshly constructed Server must have no PolicyCheck wired")
	}
	return srv
}

// TestRunPolicyCheck_NilHookAllows pins the fail-open default.
func TestRunPolicyCheck_NilHookAllows(t *testing.T) {
	s := hookContractServer(t)

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider: "openai", ToolName: "bash", RawArguments: []byte(`{"command":"ls"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck with a nil hook returned an error: %v", err)
	}
	if !dec.Allow {
		t.Fatal("the unwired default is documented as ALLOW; if this changed deliberately, " +
			"update this test AND the CHANGELOG — it flips an observable default for embedders (B5)")
	}
}

// TestRunPolicyCheck_NilHookIsIdentifiable: with no startup guard, the rule
// string is the only trace that the proxy is forwarding tool calls it never
// evaluated. Asserts the marker is present and distinctive, not byte-exact, so
// the wording stays free to change.
func TestRunPolicyCheck_NilHookIsIdentifiable(t *testing.T) {
	s := hookContractServer(t)

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider: "openai", ToolName: "bash", RawArguments: []byte(`{"command":"ls"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if dec.Rule == "" {
		t.Fatal("an unwired allow carries no rule string; an unwired proxy would be invisible (B5)")
	}
	if !strings.Contains(dec.Rule, "no_hook") && !strings.Contains(dec.Rule, "unwired") {
		t.Errorf("rule = %q; the unwired allow must stay greppable/alertable", dec.Rule)
	}
}

// TestRunPolicyCheck_DuplicateKeysDenyEvenWithNilHook: the duplicate-key
// deny (a parser-differential defense; see argcheck.go) sits before the
// nil-hook check so an unwired deployment cannot bypass it. Moving the nil
// check first would let an unwired proxy forward exactly that payload.
func TestRunPolicyCheck_DuplicateKeysDenyEvenWithNilHook(t *testing.T) {
	s := hookContractServer(t)

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider:     "openai",
		ToolName:     "bash",
		RawArguments: []byte(`{"command":"ls","command":"rm -rf /"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if dec.Allow {
		t.Fatal("duplicate JSON keys were ALLOWED with no hook wired — the parser-differential " +
			"defense must run BEFORE the nil-hook default, not after it")
	}
	if !strings.Contains(dec.Rule, "duplicate") {
		t.Errorf("rule = %q, want it to identify the duplicate-key refusal", dec.Rule)
	}
}

// TestRunPolicyCheck_DuplicateKeysDenyOverridesWiredAllow: the deny also
// beats a wired hook that allows, and is not subject to --fail-mode allow.
func TestRunPolicyCheck_DuplicateKeysDenyOverridesWiredAllow(t *testing.T) {
	s := hookContractServer(t)
	s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		return Decision{Allow: true, Rule: "allow:test:permissive"}, nil
	}

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider:     "openai",
		ToolName:     "bash",
		RawArguments: []byte(`{"command":"ls","command":"rm -rf /"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if dec.Allow {
		t.Fatal("a permissive wired hook overrode the duplicate-key hard deny; that refusal is " +
			"documented as unconditional")
	}
}

// TestRunPolicyCheck_WiredHookIsAuthoritative: the nil-safe default must never
// shadow a wired hook on ordinary input.
func TestRunPolicyCheck_WiredHookIsAuthoritative(t *testing.T) {
	s := hookContractServer(t)

	var sawCall bool
	s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		sawCall = true
		return Decision{Allow: false, Reason: "denied by test", Rule: "deny:test:rule"}, nil
	}

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider: "openai", ToolName: "bash", RawArguments: []byte(`{"command":"ls"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if !sawCall {
		t.Fatal("the wired PolicyCheck hook was never invoked")
	}
	if dec.Allow {
		t.Fatal("a wired hook's DENY was overridden by the nil-safe ALLOW default")
	}
	if dec.Rule != "deny:test:rule" {
		t.Errorf("rule = %q, want the hook's verdict to pass through unmodified", dec.Rule)
	}
}
