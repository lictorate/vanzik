package llmproxy

// SSE lines end at CRLF, a bare CR or a bare LF (WHATWG SSE; every client
// SDK splits this way). The proxy used to split on LF only, so
// `: x\rdata: {call}` was one comment line to the gate and a data line
// to openai-python, openai-node, LangChain and both Anthropic SDKs, which
// ran the call (O-2).
//
// The fixtures in testdata/line_endings come from the VR-17a rig (a fake
// upstream serving these bytes, the proxy binary, one client script per
// SDK). sseReadBoundary marks where the rig's upstream flushed and
// paused, so the proxy read the parts separately; the tests below feed
// the parts as separate reads too.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const sseReadBoundary = "\x00|SPLIT|\x00"

// readsReader returns a reader that hands out each part in its own Read.
func readsReader(parts []string) io.Reader {
	rs := make([]io.Reader, len(parts))
	for i, p := range parts {
		rs[i] = strings.NewReader(p)
	}
	return io.MultiReader(rs...)
}

func TestReadSSEEvent_LineEndings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reads []string // each element is one Read
		want  []string // events, in order; the last may be a partial at EOF
	}{
		{"LF", []string{"data: a\n\ndata: b\n\n"}, []string{"data: a\n\n", "data: b\n\n"}},
		{"CRLF", []string{"data: a\r\n\r\ndata: b\r\n\r\n"}, []string{"data: a\r\n\r\n", "data: b\r\n\r\n"}},
		{"bare CR", []string{"data: a\r\rdata: b\r\r"}, []string{"data: a\r\r", "data: b\r\r"}},
		{"comment then data after a bare CR", []string{": x\rdata: b\r\n\n"}, []string{": x\rdata: b\r\n\n"}},
		{"CR blank line after an LF line", []string{"data: a\n\rdata: b\n\n"}, []string{"data: a\n\r", "data: b\n\n"}},
		{"CRLF lines, then an LF blank line", []string{"data: a\r\ndata: b\r\ndata: c\n\n"}, []string{"data: a\r\ndata: b\r\ndata: c\n\n"}},
		{"mixed", []string{"id: 1\rdata: a\r\n\r: c\rdata: b\n\ndata: c\r\n\r\n"},
			[]string{"id: 1\rdata: a\r\n\r", ": c\rdata: b\n\n", "data: c\r\n\r\n"}},
		{"CR at the end of a read, LF at the start of the next, inside an event",
			[]string{"data: a\r", "\ndata: b\r\n\r\n"}, []string{"data: a\r\ndata: b\r\n\r\n"}},
		{"CR at the end of a read, then a data line",
			[]string{": x\r", "data: b\r", "\r"}, []string{": x\rdata: b\r\r"}},
		{"CR blank line at the end of a read, its LF in the next",
			[]string{"data: a\r\r", "\ndata: b\n\n"}, []string{"data: a\r\r", "\ndata: b\n\n"}},
		{"CR blank line with its LF in the same read", []string{"data: a\r\r\ndata: b\n\n"}, []string{"data: a\r\r\n", "data: b\n\n"}},
		{"CR line ending split from its LF, then a CR blank line",
			[]string{"data: a\r", "\n", "\r", "\n", "data: b\r\r"}, []string{"data: a\r\n\r", "\ndata: b\r\r"}},
		{"leading LF then a blank line", []string{"\n\ndata: a\n\n"}, []string{"\n\n", "data: a\n\n"}},
		{"partial event at EOF ending in CR", []string{"data: a\r"}, []string{"data: a\r"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(readsReader(tc.reads))
			var got []string
			for {
				ev, err := readSSEEvent(r, 0)
				if len(ev) > 0 {
					got = append(got, string(ev))
				}
				if err != nil {
					if err != io.EOF {
						t.Fatalf("err = %v", err)
					}
					break
				}
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("events:\n got %q\nwant %q", got, tc.want)
			}
			if strings.Join(got, "") != strings.Join(tc.reads, "") {
				t.Errorf("events do not add up to the input bytes")
			}
		})
	}
}

// A line longer than the reader's buffer comes back in pieces; a lone CR
// or LF piece is the end of that line, not a blank line.
func TestReadSSEEvent_LongLineCRFragmentNotMistakenForBlankLine(t *testing.T) {
	for _, nl := range []string{"\r", "\r\n", "\n"} {
		line := "data: 0123456789" + nl // 16 bytes fill the buffer
		event := line + nl
		r := bufio.NewReaderSize(strings.NewReader(event+"data: next"+nl+nl), 16)
		got, err := readSSEEvent(r, 0)
		if err != nil {
			t.Fatalf("nl=%q: err = %v", nl, err)
		}
		if string(got) != event {
			t.Errorf("nl=%q: event = %q, want %q", nl, got, event)
		}
	}
}

// A blob of bare CRs with no blank line is one growing event: the cap
// still applies, per read.
func TestReadSSEEvent_CRFloodHitsCap(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x\r", 5000)), 16)
	got, err := readSSEEvent(r, 1024)
	if err != errSSEEventTooLarge {
		t.Fatalf("err = %v, want errSSEEventTooLarge", err)
	}
	if len(got) > 1024+16 {
		t.Errorf("accumulated %d bytes past a 1024 cap", len(got))
	}
}

func TestExtractDataLine_CRAndCRLFLineEndings(t *testing.T) {
	for _, tc := range []struct{ event, want string }{
		{": x\rdata: {\"a\":1}\n\n", `{"a":1}`},
		{"event: e\rdata: {\"a\":1}\r\r", `{"a":1}`},
		{"data: {\"a\":\r\ndata: 1}\r\n\r\n", "{\"a\":\n1}"},
		{"data: {\"a\":\rdata:1}\n\n", "{\"a\":\n1}"},
		{"\ndata: {\"a\":1}\n\n", `{"a":1}`}, // the LF of a CRLF that ended the previous event
	} {
		got, _, ok := extractOpenAIDataLine([]byte(tc.event))
		if !ok || string(got) != tc.want {
			t.Errorf("openai %q: got %q ok=%v, want %q", tc.event, got, ok, tc.want)
		}
		got, ok = extractAnthropicDataLine([]byte(tc.event))
		if !ok || string(got) != tc.want {
			t.Errorf("anthropic %q: got %q ok=%v, want %q", tc.event, got, ok, tc.want)
		}
	}
	if _, isDone, _ := extractOpenAIDataLine([]byte(": x\rdata: [DONE]\r\r")); !isDone {
		t.Error("[DONE] after a bare CR not recognised")
	}
}

func TestStripLineBOMs_CRLineEndings(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		found    bool
	}{
		{": x\r" + bomPrefix + "data: a\n\n", ": x\rdata: a\n\n", true},
		{": x\r\n" + bomPrefix + "data: a\r\n\r\n", ": x\r\ndata: a\r\n\r\n", true},
		{"data: a\r" + bomPrefix + "\r", "data: a\r\r", true}, // a BOM-only line is a blank line to openai-node
		{"data: a" + bomPrefix + "\r\r", "data: a" + bomPrefix + "\r\r", false},
	} {
		got, found := stripLineBOMs([]byte(tc.in))
		if string(got) != tc.want || found != tc.found {
			t.Errorf("stripLineBOMs(%q) = %q, %v; want %q, %v", tc.in, got, found, tc.want, tc.found)
		}
	}
}

// --- rig fixtures, through the stream loops ---------------------------------

// lineEndingGate records what the gate saw and denies rm, like the rig's
// policy.
type lineEndingGate struct {
	mu   sync.Mutex
	args []string
}

func (g *lineEndingGate) check(_ context.Context, tc *ToolCallCheck) (Decision, error) {
	g.mu.Lock()
	g.args = append(g.args, tc.ToolName+" "+string(tc.RawArguments))
	g.mu.Unlock()
	if strings.Contains(string(tc.RawArguments), "rm -rf") {
		return Decision{Allow: false, Reason: "rm blocked", Rule: "deny:shell:rm"}, nil
	}
	return Decision{Allow: true}, nil
}

// runLineEndingFixture feeds parts to the provider's stream loop, one
// Read each, and returns the client's bytes, the gated calls and the
// forced-audit entries.
func runLineEndingFixture(t *testing.T, provider string, parts []string) (string, []string, []forcedAuditCall) {
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
	gate, audits := &lineEndingGate{}, &forcedAuditSpy{}
	srv.PolicyCheck = gate.check
	srv.RecordForcedAudit = audits.record
	srv.BuildRefusal = BuildRefusalRich

	w := httptest.NewRecorder()
	if provider == "anthropic" {
		srv.runAnthropicStreamLoop(w, w, httptest.NewRequest("POST", "/v1/messages", nil), readsReader(parts))
	} else {
		srv.runOpenAIStreamLoop(w, w, httptest.NewRequest("POST", "/v1/chat/completions", nil), readsReader(parts))
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return w.Body.String(), append([]string(nil), gate.args...), audits.recorded()
}

func TestVR17a_LineEndingFixtures(t *testing.T) {
	const (
		rmCall = `bash {"command": "rm -rf /tmp/vzx"}` // what every SDK holds on base
		lsCall = `bash {"command": "ls /tmp/vzx"}`
	)
	for _, tc := range []struct {
		fixture string
		gated   []string // calls the gate must see, in order
		outcome string   // "denied", "undecodable" or "forwarded" (byte-identical)
	}{
		{"o_cr_comment", []string{rmCall}, "denied"},
		{"o_cr_only", []string{rmCall}, "denied"},
		{"o_mixed", []string{rmCall}, "denied"},
		{"o_split", []string{rmCall}, "denied"},
		{"o_split_cr_data", []string{rmCall}, "denied"},
		{"o_split_crlf_multiline_rm", []string{rmCall}, "denied"},
		{"o_cr_bom", nil, "undecodable"},
		{"o_cr_comment_ls", []string{lsCall}, "forwarded"},
		{"o_cr_only_ls", []string{lsCall}, "forwarded"},
		{"o_mixed_ls", []string{lsCall}, "forwarded"},
		{"o_split_ls", []string{lsCall}, "forwarded"},
		{"o_split_cr_data_ls", []string{lsCall}, "forwarded"},
		{"o_split_crlf_multiline_ls", []string{`bash {"command": "ls"}`}, "forwarded"},
		{"o_cr_text", nil, "forwarded"},
		{"a_cr_comment", []string{rmCall}, "denied"},
		{"a_cr_only", []string{rmCall}, "denied"},
		{"a_mixed", []string{rmCall}, "denied"},
		{"a_split", []string{rmCall}, "denied"},
		{"a_cr_comment_ls", []string{lsCall}, "forwarded"},
		{"a_cr_only_ls", []string{lsCall}, "forwarded"},
		{"a_mixed_ls", []string{lsCall}, "forwarded"},
		{"a_split_ls", []string{lsCall}, "forwarded"},
		{"a_cr_text", nil, "forwarded"},
		{"a_cr_bom", nil, "undecodable"},
	} {
		raw, err := os.ReadFile(filepath.Join("testdata", "line_endings", tc.fixture+".sse"))
		if err != nil {
			t.Fatal(err)
		}
		provider := "openai"
		if tc.fixture[0] == 'a' {
			provider = "anthropic"
		}
		parts := strings.Split(string(raw), sseReadBoundary)
		whole := strings.Join(parts, "")
		for _, reads := range []struct {
			name  string
			parts []string
		}{{"as recorded", parts}, {"one read", []string{whole}}} {
			t.Run(tc.fixture+"/"+reads.name, func(t *testing.T) {
				got, gated, audits := runLineEndingFixture(t, provider, reads.parts)
				if strings.Join(gated, "|") != strings.Join(tc.gated, "|") {
					t.Errorf("gate saw %q, want %q", gated, tc.gated)
				}
				switch tc.outcome {
				case "forwarded":
					if got != whole {
						t.Errorf("not forwarded byte-identical:\n got %q\nwant %q", got, whole)
					}
					if len(audits) != 0 {
						t.Errorf("forced audits %+v, want none", audits)
					}
				case "denied":
					if strings.Contains(got, "rm -rf") {
						t.Errorf("the call reached the client: %q", got)
					}
					if !strings.Contains(got, "deny:shell:rm") {
						t.Errorf("no policy refusal in %q", got)
					}
				case "undecodable":
					if strings.Contains(got, "rm -rf") {
						t.Errorf("the call reached the client: %q", got)
					}
					if !strings.Contains(got, ruleUndecodable) {
						t.Errorf("no %s refusal in %q", ruleUndecodable, got)
					}
					if len(audits) != 1 || audits[0].decision.Rule != ruleUndecodable {
						t.Errorf("forced audits %+v, want one %s", audits, ruleUndecodable)
					}
				}
			})
		}
	}
}

// Every published-format fixture still reads as the same events: LF-only
// streams split exactly as before.
func TestReadSSEEvent_PublishedFixturesUnchanged(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*_streaming_*.txt"))
	if len(files) == 0 {
		t.Fatal("no fixtures")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.IndexByte(raw, '\r') >= 0 {
			t.Fatalf("%s: published fixture has a CR", f)
		}
		r := bufio.NewReader(bytes.NewReader(raw))
		var n int
		var rebuilt []byte
		for {
			ev, err := readSSEEvent(r, 0)
			rebuilt = append(rebuilt, ev...)
			if len(ev) > 0 {
				n++
				if !bytes.HasSuffix(ev, []byte("\n\n")) && err == nil {
					t.Errorf("%s: event %d does not end at a blank line: %q", f, n, ev)
				}
			}
			if err != nil {
				break
			}
		}
		if !bytes.Equal(rebuilt, raw) {
			t.Errorf("%s: events do not add up to the file", f)
		}
		if want := bytes.Count(raw, []byte("\n\n")); n < want {
			t.Errorf("%s: %d events, want at least %d", f, n, want)
		}
	}
}
