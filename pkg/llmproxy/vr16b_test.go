package llmproxy

// VR-16b: findings N1-N4 of the VR-16 confirmation review. The fixtures
// in testdata/vr16b are the reviewer's rig scenarios. On the base
// branch both Anthropic SDKs and both tool runners hold or run
// `rm -rf /` for N1-N3 while the gate allowed `ls` or saw nothing.
//
//   - N1: a tool_use inside message_start's message.content. Both SDKs
//     start the message from it; the gate never saw a content_block_start.
//   - N2: a null or duplicate "type", or a second "delta" object. The
//     struct decode kept the first value or merged the objects; the SDKs
//     take the last value and drop the delta.
//   - N3: a missing, null or duplicate-null "index" on a content_block_*
//     event. Go read 0; @anthropic-ai/sdk writes content["null"].
//   - N4: duplicate_argument_key refusals wrote no audit entry.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const ruleInterleaved = "deny:llm_api_proxy:tool_use_interleaved"

func TestReadAnthropicEvent(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		refuse     bool
		typ        string
		index      int
		deltaType  string
		partial    string
		blockType  string
	}{
		{name: "text delta", data: `{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"hi"}}`, typ: "content_block_delta", index: 2, deltaType: "text_delta"},
		{name: "input delta", data: `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"a\":\"é\\n\"}"}}`, typ: "content_block_delta", deltaType: "input_json_delta", partial: "{\"a\":\"é\\n\"}"},
		{name: "last type wins", data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta"},"type":"ping"}`, typ: "ping"},
		{name: "last delta object wins", data: `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"x"},"delta":{"partial_json":"y"}}`, typ: "content_block_delta"},
		{name: "last delta type wins", data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","type":"input_json_delta","partial_json":"z"}}`, typ: "content_block_delta", deltaType: "input_json_delta", partial: "z"},
		{name: "null delta is no delta", data: `{"type":"content_block_delta","index":0,"delta":null}`, typ: "content_block_delta"},
		{name: "missing delta is no delta", data: `{"type":"content_block_delta","index":0}`, typ: "content_block_delta"},
		{name: "event type null", data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta"},"type":null}`, refuse: true},
		{name: "event type number", data: `{"type":5}`, refuse: true},
		{name: "delta type null", data: `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"x","type":null}}`, refuse: true},
		{name: "partial_json null after a string", data: `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"x","partial_json":null}}`, refuse: true},
		{name: "index missing", data: `{"type":"content_block_delta","delta":{"type":"text_delta"}}`, refuse: true},
		{name: "index null", data: `{"type":"content_block_delta","index":null,"delta":{"type":"text_delta"}}`, refuse: true},
		{name: "index then null", data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta"},"index":null}`, refuse: true},
		{name: "stop index null", data: `{"type":"content_block_stop","index":null}`, refuse: true},
		{name: "start index null", data: `{"type":"content_block_start","index":null,"content_block":{"type":"text","text":""}}`, refuse: true},
		{name: "last index wins", data: `{"type":"content_block_stop","index":0,"index":3}`, typ: "content_block_stop", index: 3},
		{name: "block type null", data: `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"bash","input":{},"type":null}}`, refuse: true},
		{name: "tool_use name null", data: `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":null,"input":{}}}`, refuse: true},
		{name: "tool_use id number", data: `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":1,"name":"bash","input":{}}}`, refuse: true},
		{name: "last block wins", data: `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"bash","input":{}},"content_block":{"type":"text","text":""}}`, typ: "content_block_start", blockType: "text"},
		{name: "message_start content empty", data: `{"type":"message_start","message":{"id":"m","content":[ ]}}`, typ: "message_start"},
		{name: "message_start content tool_use", data: `{"type":"message_start","message":{"id":"m","content":[{"type":"tool_use","id":"t","name":"bash","input":{}}]}}`, refuse: true},
		{name: "message_start content text", data: `{"type":"message_start","message":{"id":"m","content":[{"type":"text","text":"x"}]}}`, refuse: true},
		{name: "message_start content null", data: `{"type":"message_start","message":{"id":"m","content":null}}`, refuse: true},
		{name: "message_start later content wins", data: `{"type":"message_start","message":{"id":"m","content":[],"content":[{"type":"text","text":"x"}]}}`, refuse: true},
		{name: "message_start later message wins", data: `{"type":"message_start","message":{"content":[]},"message":{"content":[{"type":"text","text":"x"}]}}`, refuse: true},
		{name: "unknown event", data: `{"type":"something_new","index":null}`, typ: "something_new"},
		{name: "no type", data: `{"index":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.data), &fields); err != nil {
				t.Fatal(err)
			}
			env, _, _, ok := readAnthropicEvent(fields)
			if ok == tc.refuse {
				t.Fatalf("ok = %v, want %v", ok, !tc.refuse)
			}
			if tc.refuse {
				return
			}
			if env.Type != tc.typ || env.Index != tc.index {
				t.Errorf("type, index = %q, %d; want %q, %d", env.Type, env.Index, tc.typ, tc.index)
			}
			if tc.typ == "content_block_delta" && (!env.HasDelta || env.Delta.Type != tc.deltaType || env.Delta.PartialJSON != tc.partial) {
				t.Errorf("delta = %+v, want type %q partial %q", env.Delta, tc.deltaType, tc.partial)
			}
			if tc.blockType != "" && (!env.HasBlock || env.Block.Type != tc.blockType) {
				t.Errorf("block = %+v, want type %q", env.Block, tc.blockType)
			}
		})
	}
}

// commandGate decides on the "command" value the way the SDKs read the
// arguments (last key wins), as the rig policy does: rm is denied,
// anything else allowed.
type commandGate struct {
	mu   sync.Mutex
	seen []string
}

func (g *commandGate) check(_ context.Context, tc *ToolCallCheck) (Decision, error) {
	g.mu.Lock()
	g.seen = append(g.seen, string(tc.RawArguments))
	g.mu.Unlock()
	var args map[string]any
	_ = json.Unmarshal(tc.RawArguments, &args)
	if cmd, _ := args["command"].(string); strings.HasPrefix(cmd, "rm") {
		return Decision{Allow: false, Reason: "rm blocked", Rule: "deny:shell:rm"}, nil
	}
	return Decision{Allow: true}, nil
}

func TestVR16b_ReviewFixtures(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		outcome string   // "refused" (tool_use_interleaved), "denied" (policy) or "forwarded" (byte-identical)
		gated   []string // arguments the gate saw
	}{
		// The control: no trick event; everyone, gate included, reads ls.
		{"w16_control", "forwarded", []string{`{"command":"ls","z":"rm -rf /"}`}},
		{"w16_msgstart_content", "refused", nil},
		{"w16_msgstart_content_plus", "refused", nil},
		{"w16_dtype_dup_null", "refused", nil},
		{"w16_etype_dup_null", "refused", nil},
		// The last delta object has no type, so neither the gate nor an
		// SDK applies it: both read rm, and the policy denies it.
		{"w16_delta_dup_obj", "denied", []string{`{"command":"rm -rf /"}`}},
		// A null last delta: the SDKs fail, the gate adds nothing; rm.
		{"w16_delta_dup_null", "denied", []string{`{"command":"rm -rf /"}`}},
		{"w16_idx_missing", "refused", nil},
		{"w16_idx_null", "refused", nil},
		{"w16_idx_dup_null", "refused", nil},
		// A string index fails the envelope decode: the event is
		// dropped, so no client receives it, and the gate reads rm.
		{"w16_idx_string", "denied", []string{`{"command":"rm -rf /"}`}},
		{"w16_stop_idx_null", "refused", nil},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "vr16b", tc.fixture+".sse"))
			if err != nil {
				t.Fatal(err)
			}
			gate := &commandGate{}
			got, audits := runAnthropicFixture(t, string(raw), gate.check)
			if strings.Join(gate.seen, "|") != strings.Join(tc.gated, "|") {
				t.Errorf("gate saw %q, want %q", gate.seen, tc.gated)
			}
			switch tc.outcome {
			case "forwarded":
				if got != string(raw) {
					t.Errorf("not forwarded byte-identical:\n got %q\nwant %q", got, raw)
				}
			case "denied":
				if strings.Contains(got, `rm -rf /\"`) || !strings.Contains(got, "deny:shell:rm") {
					t.Errorf("want the policy refusal and no rm; got %q", got)
				}
			case "refused":
				if strings.Contains(got, "rm -rf") {
					t.Errorf("the call reached the client: %q", got)
				}
				if !strings.Contains(got, ruleInterleaved) {
					t.Errorf("no %s refusal in %q", ruleInterleaved, got)
				}
				if !strings.HasPrefix(got, "event: message_start\n") {
					t.Errorf("stream does not open with message_start: %.120q", got)
				}
				if strings.Count(got, "event: message_start\n") != 1 {
					t.Errorf("want exactly one message_start: %q", got)
				}
				if len(audits) != 1 || audits[0].decision.Rule != ruleInterleaved {
					t.Errorf("forced audits %+v, want one %s", audits, ruleInterleaved)
				}
			}
		})
	}
}

// newLoopTestServer builds a Server for driving a stream loop directly.
func newLoopTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    "https://api.openai.com",
		UpstreamAnthropic: "https://api.anthropic.com",
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "test",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

// runAnthropicFixture feeds raw to the Anthropic stream loop in one read.
func runAnthropicFixture(t *testing.T, raw string, check func(context.Context, *ToolCallCheck) (Decision, error)) (string, []forcedAuditCall) {
	t.Helper()
	srv := newLoopTestServer(t)
	audits := &forcedAuditSpy{}
	srv.PolicyCheck = check
	srv.RecordForcedAudit = audits.record
	srv.BuildRefusal = BuildRefusalRich
	w := httptest.NewRecorder()
	srv.runAnthropicStreamLoop(w, w, httptest.NewRequest("POST", "/v1/messages", nil), strings.NewReader(raw))
	return w.Body.String(), audits.recorded()
}

// --- N4: duplicate_argument_key is audited ----------------------------------

func TestVR16b_DuplicateArgumentKey_IsAudited(t *testing.T) {
	const rule = "deny:llm_api_proxy:duplicate_argument_key"
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("testdata", "vr16b", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	check := func(t *testing.T, got string, rec []forcedAuditCall, stream bool) {
		t.Helper()
		if !strings.Contains(got, rule) {
			t.Errorf("want the %s refusal; got %q", rule, got)
		}
		if len(rec) != 1 || rec[0].decision.Rule != rule || rec[0].decision.Allow {
			t.Fatalf("forced audits %+v, want one %s deny", rec, rule)
		}
		c := rec[0].call
		if c.ToolName != "bash" || c.TenantID != "test" || c.Stream != stream {
			t.Errorf("audited call %+v: want bash, tenant test, stream %v", c, stream)
		}
	}
	t.Run("anthropic stream", func(t *testing.T) {
		got, spy := runStreamWithAudit(t, "anthropic", read("v16_dupkey_control.sse"), 0)
		check(t, got, spy.recorded(), true)
	})
	t.Run("openai stream", func(t *testing.T) {
		got, spy := runStreamWithAudit(t, "openai", read("o16_dupkey_stream.sse"), 0)
		check(t, got, spy.recorded(), true)
	})
	t.Run("openai non-stream", func(t *testing.T) {
		got, spy := postNonStreaming(t, read("o16_dupkey_nonstream.json"), denyRm)
		check(t, got, spy.recorded(), false)
	})
	t.Run("anthropic non-stream", func(t *testing.T) {
		body := `{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[` +
			`{"type":"tool_use","id":"toolu_1","name":"bash","input":{"command":"rm -rf /","command":"ls"}}],` +
			`"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`
		upstream := upstreamServing(t, body)
		srv, base, teardown := newGatedTestServer(t, upstream, upstream, denyRm)
		defer teardown()
		srv.BuildRefusal = BuildRefusalRich
		spy := &forcedAuditSpy{}
		srv.RecordForcedAudit = spy.record
		resp, err := http.Post(base+"/v1/messages", "application/json",
			strings.NewReader(`{"model":"m","max_tokens":5,"messages":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		check(t, string(got), spy.recorded(), false)
	})
}
