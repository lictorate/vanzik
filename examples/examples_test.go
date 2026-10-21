package examples_test

// Verifies that every client-config JSON file under examples/ parses,
// has a "vanzik" server entry, and uses only flags the gateway
// understands. Operators copy-paste these hand-edited files, so a
// trailing comma or a renamed flag would be a silent UX failure; as a
// `go test` it runs in the same CI gate as everything else.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// expectedFlags are the long-form flags an example config may use (any
// subset). The set is a hand-kept copy of gateway flags, not read from
// pkg/mcpgw.ParseConfig: add a flag here when an example starts using
// one the gateway gained.
var expectedFlags = []string{
	"--upstream",
	"--upstream-http",
	"--upstream-header",
	"--guard-url",
	"--api-key",
	"--policy",
	"--tenant-id",
	"--policy-mode",
	"--fail-mode",
	"--log-level",
}

func TestExamples_ClientConfigsParseAsJSON(t *testing.T) {
	matches, err := filepath.Glob("*.json")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no *.json files found in examples/ directory; this test must run from the examples/ directory")
	}

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			var doc map[string]interface{}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("invalid JSON: %v\n--- contents ---\n%s", err, string(data))
			}

			// The server map is "mcpServers" in every client except Zed,
			// which uses "context_servers".
			var servers map[string]interface{}
			if v, ok := doc["mcpServers"].(map[string]interface{}); ok {
				servers = v
			} else if v, ok := doc["context_servers"].(map[string]interface{}); ok {
				servers = v
			} else {
				t.Fatalf("missing mcpServers or context_servers field; doc keys=%v", mapKeys(doc))
			}
			ag, ok := servers["vanzik"].(map[string]interface{})
			if !ok {
				t.Fatalf("missing or non-object .vanzik entry; servers=%v", servers)
			}

			cmd, ok := ag["command"].(string)
			if !ok || cmd == "" {
				t.Fatalf("missing or empty command field; ag=%v", ag)
			}
			if !strings.Contains(cmd, "vanzik-mcp-gateway") {
				t.Errorf("command %q does not reference vanzik-mcp-gateway", cmd)
			}

			argsRaw, ok := ag["args"].([]interface{})
			if !ok {
				t.Fatalf("missing or non-array args field; ag=%v", ag)
			}
			args := make([]string, 0, len(argsRaw))
			for _, a := range argsRaw {
				if s, ok := a.(string); ok {
					args = append(args, s)
				}
			}

			// Every flag that appears must be in the documented set; not
			// every documented flag has to appear.
			for _, arg := range args {
				if !strings.HasPrefix(arg, "--") {
					continue // value, not a flag
				}
				if !flagInSet(arg, expectedFlags) {
					t.Errorf("config uses flag %q which is not in the documented gateway flag set %v", arg, expectedFlags)
				}
			}

			// Sanity: at least one upstream must be present (the gateway
			// requires --upstream or --upstream-http).
			hasUpstream := false
			for _, arg := range args {
				if arg == "--upstream" || arg == "--upstream-http" {
					hasUpstream = true
					break
				}
			}
			if !hasUpstream {
				t.Errorf("config %s does not declare any --upstream or --upstream-http", path)
			}
		})
	}
}

func flagInSet(flag string, set []string) bool {
	for _, f := range set {
		if flag == f {
			return true
		}
	}
	return false
}

func mapKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
