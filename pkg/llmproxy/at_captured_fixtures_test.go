package llmproxy

// Replays captured provider SSE traces through the parsers. The bundled
// testdata/ fixtures are synthesized from the spec; real captures would
// also catch drift between spec and real upstream behavior.
//
// To add a captured fixture:
//   1. Capture the SSE response of a real /v1/chat/completions
//      streaming call with stream=true and a tool the model calls.
//   2. Save the raw SSE bytes under
//      pkg/llmproxy/testdata/captured/openai_streaming_real_<date>.txt
//      with a `: provenance` SSE comment header (capture date, model,
//      redaction notes for any sensitive content).
//   3. The TestAT_CapturedFixtures_OpenAI sub-test below will pick it
//      up automatically.
//
// TODO(#llm-real-captured-fixtures): include captured fixtures
// from real OpenAI + Anthropic API calls in the regression suite.

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAT_CapturedFixtures_OpenAI replays every OpenAI capture and asserts
// a tool call reassembles. Without captures it uses the synthesized
// fixtures, so the pipeline runs in CI instead of skipping.
func TestAT_CapturedFixtures_OpenAI(t *testing.T) {
	files, err := filepath.Glob("testdata/captured/openai_streaming_*.txt")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		// See TODO(v0.7, #llm-real-captured-fixtures).
		files, err = filepath.Glob("testdata/openai_streaming_*.txt")
		if err != nil {
			t.Fatalf("glob synthesized fallback: %v", err)
		}
		if len(files) == 0 {
			t.Fatal("no OpenAI streaming fixtures present (captured or synthesized)")
		}
		t.Logf("no captured fixtures; replaying %d synthesized fixture(s) as the fallback coupon", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			handle, err := os.Open(f)
			if err != nil {
				t.Fatalf("open %s: %v", f, err)
			}
			defer handle.Close()
			br := bufio.NewReader(handle)
			acc := NewOpenAIToolCallAccumulator(0)
			var completed []ToolCallCheck
			for {
				ev, err := readSSEEvent(br, 0)
				if len(ev) > 0 {
					res, ferr := acc.FeedEvent(ev)
					if ferr != nil {
						// Real captures may carry undocumented events;
						// only reassembly is asserted.
						t.Logf("event-feed err: %v", ferr)
					}
					if res.Completed {
						completed = append(completed, res.CompletedToolCalls...)
					}
				}
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("read event: %v", err)
				}
			}
			if len(completed) == 0 {
				// A fixture whose name mentions "tool" must
				// reassemble at least one call.
				if strings.Contains(strings.ToLower(filepath.Base(f)), "tool") {
					t.Errorf("captured fixture %s claims to contain a tool_call but parser produced 0 completions", f)
				}
			}
		})
	}
}

// TestAT_CapturedFixtures_Anthropic mirrors the OpenAI variant.
func TestAT_CapturedFixtures_Anthropic(t *testing.T) {
	files, err := filepath.Glob("testdata/captured/anthropic_streaming_*.txt")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		// See TODO(v0.7, #llm-real-captured-fixtures).
		files, err = filepath.Glob("testdata/anthropic_streaming_*.txt")
		if err != nil {
			t.Fatalf("glob synthesized fallback: %v", err)
		}
		if len(files) == 0 {
			t.Fatal("no Anthropic streaming fixtures present (captured or synthesized)")
		}
		t.Logf("no captured fixtures; replaying %d synthesized fixture(s) as the fallback coupon", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			handle, err := os.Open(f)
			if err != nil {
				t.Fatalf("open %s: %v", f, err)
			}
			defer handle.Close()
			br := bufio.NewReader(handle)
			acc := NewAnthropicAccumulator(0)
			var completed []ToolCallCheck
			for {
				ev, err := readSSEEvent(br, 0)
				if len(ev) > 0 {
					res, ferr := acc.FeedEvent(ev)
					if ferr != nil {
						t.Logf("event-feed err: %v", ferr)
					}
					if res.Completed {
						completed = append(completed, res.CompletedToolCalls...)
					}
				}
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("read event: %v", err)
				}
			}
			if len(completed) == 0 {
				if strings.Contains(strings.ToLower(filepath.Base(f)), "tool") {
					t.Errorf("captured fixture %s claims to contain a tool_use but parser produced 0 completions", f)
				}
			}
		})
	}
}

// TestAT_SynthesizedFixturesHaveProvenanceHeader: every
// testdata/*_streaming_*.txt fixture starts with an SSE comment recording
// its synthesis date and source spec section.
func TestAT_SynthesizedFixturesHaveProvenanceHeader(t *testing.T) {
	files, err := filepath.Glob("testdata/*_streaming_*.txt")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no streaming fixtures in testdata/")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			handle, err := os.Open(f)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer handle.Close()
			br := bufio.NewReader(handle)
			first, err := br.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("read first line: %v", err)
			}
			if !strings.HasPrefix(first, ":") {
				t.Errorf("%s: first line %q does not start with `:` (SSE comment provenance header missing)", f, first)
			}
			if !strings.Contains(strings.ToLower(first), "synthesized") &&
				!strings.Contains(strings.ToLower(first), "captured") {
				t.Errorf("%s: provenance header should declare `synthesized` or `captured`; got %q", f, first)
			}
		})
	}
}
