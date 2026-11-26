package llmproxy

// VR-17b (O-3): the Anthropic SDKs dispatch a stream event on its SSE
// `event:` name, the gate on its JSON `type`. Both SDKs skip an event
// named `ping` or with no name, and raise on `error`; anthropic-python
// also skips an empty name, which @anthropic-ai/sdk dispatches; both
// dispatch any other name on the JSON type. The report's splice sent an
// input delta as `event: ping`: the gate allowed
// bash {"command":"ls","x":"rm -rf /"} and the SDKs ran rm -rf /.
//
// The fixtures in testdata/vr17b come from the rig: the splice D1
// `{"command":"`, D2 `ls","x":"`, D3 `rm -rf /tmp/vzx"}` with D2 under a
// different event line in each.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

const ruleEventTypeMismatch = "deny:llm_api_proxy:event_type_mismatch"

func TestExtractAnthropicEvent_Name(t *testing.T) {
	const data = "data: {}\n"
	for _, tc := range []struct {
		event   string
		name    string
		hasName bool
	}{
		{"event: content_block_delta\n" + data, "content_block_delta", true},
		{"event:content_block_delta\n" + data, "content_block_delta", true},
		{data + "event: ping\n", "ping", true},                                 // order does not matter
		{"event: a\nevent: b\n" + data, "b", true},                             // the last one wins
		{"event: content_block_delta \n" + data, "content_block_delta ", true}, // trailing space kept
		{"event:  x\n" + data, " x", true},                                     // one leading space removed
		{"event:\n" + data, "", true},
		{"event\n" + data, "", true}, // no colon: the whole line is the field name
		{data, "", false},
		{"Event: content_block_delta\n" + data, "", false}, // field names are exact
		{"events: x\n" + data, "", false},
		{": event: x\n" + data, "", false}, // a comment
		{"event: a\r" + data, "a", true},   // VR-17a line endings
	} {
		_, hasData, name, hasName := extractAnthropicEvent([]byte(tc.event))
		if !hasData || string(name) != tc.name || hasName != tc.hasName {
			t.Errorf("%q: name %q hasName %v hasData %v; want %q %v true", tc.event, name, hasName, hasData, tc.name, tc.hasName)
		}
	}
}

func TestVR17b_EventNameFixtures(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		rule    string   // refusal rule, or "" for forwarded byte-identical
		gated   []string // arguments the gate saw
	}{
		// Control: every name matches; everyone, gate included, reads ls.
		{"match", "", []string{`{"command":"ls","x":"rm -rf /tmp/vzx"}`}},
		// Both SDKs skip D2 and hold rm (report §4.2 O-3).
		{"ping", ruleEventTypeMismatch, nil},
		{"none", ruleEventTypeMismatch, nil},
		{"field_case", ruleEventTypeMismatch, nil},
		{"last_ping", ruleEventTypeMismatch, nil},
		// anthropic-python skips D2, @anthropic-ai/sdk applies it.
		{"empty", ruleEventTypeMismatch, nil},
		{"empty_nocolon", ruleEventTypeMismatch, nil},
		// Both SDKs raise on `error`.
		{"error", ruleEventTypeMismatch, nil},
		{"error_start", ruleEventTypeMismatch, nil},
		// Both SDKs apply D2 on its JSON type: they agree with the gate,
		// but the name is not the type, and that is refused too.
		{"unknown", ruleEventTypeMismatch, nil},
		{"trailing_space", ruleEventTypeMismatch, nil},
		{"two_spaces", ruleEventTypeMismatch, nil},
		{"case_name", ruleEventTypeMismatch, nil},
		// @anthropic-ai/sdk strips the BOM and applies D2; anthropic-python
		// ignores the line, skips D2 and runs rm. The BOM rule (VR-17a)
		// refuses it first.
		{"bom", ruleUndecodable, nil},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "vr17b", tc.fixture+".sse"))
			if err != nil {
				t.Fatal(err)
			}
			before := metrics.LLMProxyEventTypeMismatchFor("anthropic")
			beforePV := metrics.LLMProxyProtocolViolationFor("anthropic")
			gate := &commandGate{}
			got, audits := runAnthropicFixture(t, string(raw), gate.check)
			if strings.Join(gate.seen, "|") != strings.Join(tc.gated, "|") {
				t.Errorf("gate saw %q, want %q", gate.seen, tc.gated)
			}
			if tc.rule == "" {
				if got != string(raw) {
					t.Errorf("not forwarded byte-identical:\n got %q\nwant %q", got, raw)
				}
				if len(audits) != 0 {
					t.Errorf("forced audits %+v, want none", audits)
				}
				return
			}
			if strings.Contains(got, "rm -rf") {
				t.Errorf("the call reached the client: %q", got)
			}
			if !strings.Contains(got, tc.rule) {
				t.Errorf("no %s refusal in %q", tc.rule, got)
			}
			if len(audits) != 1 || audits[0].decision.Rule != tc.rule {
				t.Errorf("forced audits %+v, want one %s", audits, tc.rule)
			}
			wantMismatch := uint64(0)
			if tc.rule == ruleEventTypeMismatch {
				wantMismatch = 1
			}
			if d := metrics.LLMProxyEventTypeMismatchFor("anthropic") - before; d != wantMismatch {
				t.Errorf("event_type_mismatch counter moved by %d, want %d", d, wantMismatch)
			}
			if d := metrics.LLMProxyProtocolViolationFor("anthropic") - beforePV; d != 0 {
				t.Errorf("protocol_violation counter moved by %d, want 0", d)
			}
		})
	}
}

// Real ping events (name ping, type ping) still pass, inside and
// outside a tool cycle, and an event with no data needs no name.
func TestVR17b_RealPingAndDatalessEventsPass(t *testing.T) {
	ping := "event: ping\ndata: {\"type\": \"ping\"}\n\n"
	stream := anthropicBOMMessageStart + ping +
		pvAnthropicToolStart(0, "toolu_1", "bash", "{}") + ping +
		pvAnthropicInputDelta(0, `{"command":"ls"}`) + "event: ping\n\n" + ": keep-alive\n\n" +
		pvAnthropicStop(0) + ping + vr16MessageEnd
	gate := &commandGate{}
	got, audits := runAnthropicFixture(t, stream, gate.check)
	if got != stream {
		t.Errorf("not forwarded byte-identical:\n got %q\nwant %q", got, stream)
	}
	if len(audits) != 0 || strings.Join(gate.seen, "|") != `{"command":"ls"}` {
		t.Errorf("audits %+v, gate saw %q", audits, gate.seen)
	}
}

// A mismatch at the first message_start gets a synthetic one, so the
// SDKs read the refusal.
func TestVR17b_RefusalBeforeMessageStartOpensTheStream(t *testing.T) {
	stream := "event: ping\n" + strings.TrimPrefix(anthropicBOMMessageStart, "event: message_start\n")
	got, _ := runAnthropicFixture(t, stream, (&commandGate{}).check)
	if !strings.HasPrefix(got, "event: message_start\n") || !strings.Contains(got, ruleEventTypeMismatch) {
		t.Errorf("got %q", got)
	}
}
