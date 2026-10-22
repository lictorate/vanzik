package mcpgw

import (
	"testing"
)

// TestGatewayLevelAuditDeferred locks in the decision to leave
// gateway-level audit/SSE wiring nil by default: NewBridge returns a
// Bridge whose AuditEmit and SSEEmit hooks are nil. Wiring them by
// default must be a deliberate change that replaces this test. See
// pkg/mcpgw/audit.go for the rationale.
func TestGatewayLevelAuditDeferred(t *testing.T) {
	cfg := &Config{
		PolicyMode:                "fast",
		FailMode:                  "deny",
		TenantID:                  "local",
		LogLevel:                  "info",
		SupportedProtocolVersions: []string{"2025-11-25"},
	}
	b := NewBridge(cfg, nil, "test")

	if b.AuditEmit != nil {
		t.Errorf("expected AuditEmit nil by default; got non-nil hook")
	}
	if b.SSEEmit != nil {
		t.Errorf("expected SSEEmit nil by default; got non-nil hook")
	}
}
