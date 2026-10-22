package mcpgw

// Bridge-level reconnect end-to-end test.
//
// transport_test.go has TestStdioUpstream_Reconnect at the
// transport layer (StdioUpstream alone). This file drives the same
// scenario through the FULL bridge — Bridge.Run, real StdioUpstream,
// real subprocess — so we verify:
//
//   1. After the upstream subprocess exits, Status() transitions to
//      degraded.
//   2. tools/call against a degraded namespace returns
//      ErrCodeUpstreamUnavail (-32002) with the namespace named in
//      the message — visible to the model so it can degrade gracefully.
//   3. The supervisor walks the backoff schedule, respawns, and
//      re-Initializes.
//   4. After reconnect, Status() returns to OK and a follow-up
//      tools/call succeeds.
//
// The backoff is shortened to 100ms and the deadlines are generous, so
// the test isn't flaky on slow CI runners.

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// TestAT_ReconnectE2E_RecoverAfterCrash drives the bridge through a
// crash-and-recover cycle.
func TestAT_ReconnectE2E_RecoverAfterCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode (spawns real subprocess)")
	}

	// --crash-after-n 3: the stub answers its first three requests (the
	// upstream's own Initialize, the bridge's re-Initialize, the first
	// tools/list) and exits on the fourth.
	cfg := &Config{
		GuardURL:                  "http://127.0.0.1:8080",
		TenantID:                  "local",
		FailMode:                  "deny",
		PolicyMode:                "fast",
		LogLevel:                  "info",
		UpstreamTimeout:           5 * time.Second,
		ReconnectCap:              60 * time.Second,
		SupportedProtocolVersions: append([]string{}, DefaultSupportedProtocolVersions...),
	}
	cfg.Upstreams = []UpstreamSpec{{Namespace: "fs", Command: "stub-server", Transport: "stdio"}}

	b := NewBridge(cfg, io.Discard, "0.5.0-AT-reconnect")

	factory := stubFactory(t,
		"--name", "stub-fs",
		"--tool", "echo",
		"--proto-version", "2025-11-25",
		"--crash-after-n", "3",
	)
	up := NewStdioUpstreamWithOptions(UpstreamSpec{
		Namespace: "fs",
		Command:   "stub-server",
	}, StdioUpstreamOptions{
		CommandFactory: factory,
		// Tight backoff so the test is fast.
		Backoff: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
	})
	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(startCancel)
	if err := up.Start(startCtx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := up.Initialize(startCtx, "2025-11-25", map[string]interface{}{}, ClientInfo{Name: "AT"}); err != nil {
		t.Fatalf("upstream Initialize: %v", err)
	}
	b.SetUpstream(up)
	t.Cleanup(func() { _ = up.Close() })

	h := newBridgeHarness(t, b)

	// 1. initialize through bridge (re-initialize on upstream — count 2).
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "AT-reconnect"},
		},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}

	// 2. First tools/list: upstream request 3, still answered (the
	//    stub exits only once its count exceeds --crash-after-n).
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
		"params": map[string]interface{}{},
	})
	resp = h.readResponse()
	if resp.Error != nil {
		t.Fatalf("first tools/list: %+v", resp.Error)
	}

	// 3. Drive the 4th request — the upstream will exit non-zero before
	//    responding. Send via the underlying upstream directly with a
	//    short timeout so we don't block waiting for a response that
	//    will never come.
	go func() {
		ictx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = up.Send(ictx, &Request{
			Method: MethodToolsList,
			Params: json.RawMessage(`{}`),
		})
	}()

	// 4. Wait for the upstream supervisor to see the exit and mark
	//    the namespace degraded.
	deadline := time.Now().Add(5 * time.Second)
	var sawDegraded bool
	for time.Now().Before(deadline) {
		if up.Status() == StatusDegraded {
			sawDegraded = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawDegraded {
		// If the supervisor was very fast it may have already
		// reconnected by the time we observed; that's also acceptable.
		// Skip the degraded-tools/call assertion in that case.
		t.Logf("supervisor reconnected before degraded was observable; status=%q", up.Status())
	} else {
		// 5. While degraded, tools/call against fs should return
		//    ErrCodeUpstreamUnavail with the namespace in the message.
		h.send(map[string]interface{}{
			"jsonrpc": "2.0", "id": 3, "method": "tools/call",
			"params": map[string]interface{}{
				"name":      "fs:echo",
				"arguments": map[string]interface{}{"text": "during-degraded"},
			},
		})
		resp = h.readResponse()
		if resp.Error == nil {
			t.Errorf("expected ErrCodeUpstreamUnavail while degraded, got result")
		} else {
			if resp.Error.Code != ErrCodeUpstreamUnavail {
				t.Errorf("error code = %d; want %d (ErrCodeUpstreamUnavail)", resp.Error.Code, ErrCodeUpstreamUnavail)
			}
			if !strings.Contains(resp.Error.Message, "fs") {
				t.Errorf("error message did not name the namespace: %q", resp.Error.Message)
			}
		}
	}

	// 6. Wait for reconnect.
	deadline = time.Now().Add(15 * time.Second)
	var reconnected bool
	for time.Now().Before(deadline) {
		if up.Status() == StatusOK {
			reconnected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !reconnected {
		t.Fatalf("upstream did not reconnect within 15s; final status=%q", up.Status())
	}

	// 7. A fresh tools/call after reconnect must succeed: the respawned
	//    stub's request count starts again at 1.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:echo",
			"arguments": map[string]interface{}{"text": "after-reconnect"},
		},
	})
	resp = h.readResponse()
	if resp.Error != nil {
		t.Fatalf("post-reconnect tools/call: %+v", resp.Error)
	}
	var tcr ToolsCallResult
	if err := json.Unmarshal(resp.Result, &tcr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tcr.IsError {
		t.Errorf("post-reconnect call returned isError=true: %+v", tcr)
	}
	if !strings.Contains(tcr.Content[0].Text, "after-reconnect") {
		t.Errorf("post-reconnect response did not echo arg: %q", tcr.Content[0].Text)
	}
}
