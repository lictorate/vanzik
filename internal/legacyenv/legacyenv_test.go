package legacyenv

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	for _, n := range []string{"VANZIK_API_KEY", "AGENTGUARD_API_KEY"} {
		t.Setenv(n, "")
	}
	if err := Check("API_KEY"); err != nil {
		t.Fatalf("neither set: %v", err)
	}

	t.Setenv("AGENTGUARD_API_KEY", "k")
	err := Check("API_KEY")
	if err == nil || !strings.Contains(err.Error(), "VANZIK_API_KEY") {
		t.Fatalf("only the old one set: want an error naming VANZIK_API_KEY, got %v", err)
	}

	t.Setenv("VANZIK_API_KEY", "k")
	if err := Check("API_KEY"); err != nil {
		t.Fatalf("both set, the new one wins: %v", err)
	}
}

func TestSetAndNewName(t *testing.T) {
	for _, n := range Names {
		t.Setenv(n, "")
	}
	t.Setenv("AGENTGUARD_URL", "http://x")
	t.Setenv("AGENTGUARD_PURGE", "1")
	if got := strings.Join(Set(), ","); got != "AGENTGUARD_URL,AGENTGUARD_PURGE" {
		t.Fatalf("Set() = %s", got)
	}
	if got := NewName("AGENTGUARD_NO_MODIFY_PATH"); got != "VANZIK_NO_MODIFY_PATH" {
		t.Fatalf("NewName = %s", got)
	}
	if len(Names) != 12 {
		t.Fatalf("AgentGuard 1.x documented 12 variables; Names has %d", len(Names))
	}
}
