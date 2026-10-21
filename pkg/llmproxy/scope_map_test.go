package llmproxy

// Tool-name to scope mapping: default coverage per scope, browser globs,
// UnmappedScope for unknown names, operator entries beating defaults, and
// nil/empty policies.

import (
	"testing"

	"lictorate.com/vanzik/v2/pkg/policy"
)

func TestMapLLMToolScope_ShellTools(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"bash", "shell"},
		{"sh", "shell"},
		{"shell", "shell"},
		{"run_command", "shell"},
		{"execute_command", "shell"},
		{"cmd", "shell"},
		{"system", "shell"},
		{"exec", "shell"},
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, c := range cases {
		got := MapLLMToolScope(c.tool, mappings)
		if got != c.want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestMapLLMToolScope_FilesystemTools(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"read_file", "filesystem"},
		{"write_file", "filesystem"},
		{"list_directory", "filesystem"},
		{"list_files", "filesystem"},
		{"file_read", "filesystem"},
		{"file_write", "filesystem"},
		{"edit_file", "filesystem"},
		{"delete_file", "filesystem"},
		{"create_directory", "filesystem"},
		{"ls", "filesystem"},
		{"cat", "filesystem"},
		{"find", "filesystem"},
		{"glob", "filesystem"},
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, c := range cases {
		got := MapLLMToolScope(c.tool, mappings)
		if got != c.want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestMapLLMToolScope_NetworkTools(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"web_search", "network"},
		{"fetch_url", "network"},
		{"http_request", "network"},
		{"http_get", "network"},
		{"http_post", "network"},
		{"search", "network"},
		{"fetch", "network"},
		{"url_request", "network"},
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, c := range cases {
		got := MapLLMToolScope(c.tool, mappings)
		if got != c.want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestMapLLMToolScope_BrowserGlob(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"playwright_click", "browser"},
		{"playwright_navigate", "browser"},
		{"playwright_screenshot", "browser"},
		{"browser_navigate", "browser"},
		{"browser_click", "browser"},
		{"chrome_devtools", "browser"},
		{"firefox_open", "browser"},
		{"selenium_find_element", "browser"},
		{"navigate", "browser"},
		{"click", "browser"},
		{"screenshot", "browser"},
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, c := range cases {
		got := MapLLMToolScope(c.tool, mappings)
		if got != c.want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestMapLLMToolScope_Unmapped(t *testing.T) {
	cases := []string{
		"unknown_tool",
		"my_company_internal_thing",
		"random_function",
		// Namespaced MCP names must not match the bare defaults.
		"fs:read_file",
		"github:create_issue",
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, tool := range cases {
		got := MapLLMToolScope(tool, mappings)
		if got != UnmappedScope {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", tool, got, UnmappedScope)
		}
	}
}

func TestMapLLMToolScope_EmptyToolName(t *testing.T) {
	mappings := NewLLMToolScopeMap(nil)
	got := MapLLMToolScope("", mappings)
	if got != UnmappedScope {
		t.Errorf("MapLLMToolScope(\"\") = %q, want %q", got, UnmappedScope)
	}
}

func TestMapLLMToolScope_EmptyMappings(t *testing.T) {
	got := MapLLMToolScope("bash", nil)
	if got != UnmappedScope {
		t.Errorf("MapLLMToolScope(_, nil) = %q, want %q", got, UnmappedScope)
	}
	got = MapLLMToolScope("bash", []policy.ToolScopeMapping{})
	if got != UnmappedScope {
		t.Errorf("MapLLMToolScope(_, []) = %q, want %q", got, UnmappedScope)
	}
}

func TestMapLLMToolScope_OperatorOverride(t *testing.T) {
	// The operator remaps `read_file` (default filesystem) to data.
	pol := &policy.Policy{
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "read_file", Scope: "data"},
		},
	}
	mappings := NewLLMToolScopeMap(pol)

	if got := MapLLMToolScope("read_file", mappings); got != "data" {
		t.Errorf("operator override: MapLLMToolScope(read_file) = %q, want data", got)
	}

	if got := MapLLMToolScope("bash", mappings); got != "shell" {
		t.Errorf("default fallthrough after override: MapLLMToolScope(bash) = %q, want shell", got)
	}
}

func TestMapLLMToolScope_OperatorAddsNewTool(t *testing.T) {
	pol := &policy.Policy{
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "deploy_to_prod", Scope: "shell"},
			{Pattern: "send_email", Scope: "network"},
		},
	}
	mappings := NewLLMToolScopeMap(pol)

	if got := MapLLMToolScope("deploy_to_prod", mappings); got != "shell" {
		t.Errorf("operator-added tool: deploy_to_prod = %q, want shell", got)
	}
	if got := MapLLMToolScope("send_email", mappings); got != "network" {
		t.Errorf("operator-added tool: send_email = %q, want network", got)
	}
	if got := MapLLMToolScope("read_file", mappings); got != "filesystem" {
		t.Errorf("default after operator-add: read_file = %q, want filesystem", got)
	}
}

func TestNewLLMToolScopeMap_NilPolicy(t *testing.T) {
	got := NewLLMToolScopeMap(nil)
	if len(got) != len(DefaultLLMToolScopeMap) {
		t.Fatalf("nil policy: got %d entries, want %d", len(got), len(DefaultLLMToolScopeMap))
	}
	if got[0].Pattern != DefaultLLMToolScopeMap[0].Pattern {
		t.Errorf("nil policy: first entry pattern = %q, want %q",
			got[0].Pattern, DefaultLLMToolScopeMap[0].Pattern)
	}
}

func TestNewLLMToolScopeMap_EmptyPolicyMap(t *testing.T) {
	pol := &policy.Policy{Version: "1", Name: "x"}
	got := NewLLMToolScopeMap(pol)
	if len(got) != len(DefaultLLMToolScopeMap) {
		t.Fatalf("empty policy map: got %d entries, want %d",
			len(got), len(DefaultLLMToolScopeMap))
	}
}

func TestNewLLMToolScopeMap_MergeOrder(t *testing.T) {
	// Operator entries come first, so first-match-wins favors them.
	pol := &policy.Policy{
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "read_file", Scope: "data"},
			{Pattern: "custom_tool", Scope: "shell"},
		},
	}
	got := NewLLMToolScopeMap(pol)

	wantLen := 2 + len(DefaultLLMToolScopeMap)
	if len(got) != wantLen {
		t.Fatalf("merged length = %d, want %d", len(got), wantLen)
	}

	if got[0].Pattern != "read_file" || got[0].Scope != "data" {
		t.Errorf("got[0] = %+v, want {read_file data}", got[0])
	}
	if got[1].Pattern != "custom_tool" || got[1].Scope != "shell" {
		t.Errorf("got[1] = %+v, want {custom_tool shell}", got[1])
	}
	if got[2].Pattern != DefaultLLMToolScopeMap[0].Pattern {
		t.Errorf("got[2].Pattern = %q, want %q (first default)",
			got[2].Pattern, DefaultLLMToolScopeMap[0].Pattern)
	}
}

func TestNewLLMToolScopeMap_DoesNotMutateInput(t *testing.T) {
	// The merge must not mutate the operator's slice: it is a live
	// snapshot shared with the policy watcher.
	pol := &policy.Policy{
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "deploy", Scope: "shell"},
		},
	}
	original := pol.ToolScopeMap
	originalLen := len(original)
	originalCap := cap(original)

	_ = NewLLMToolScopeMap(pol)

	if len(pol.ToolScopeMap) != originalLen {
		t.Errorf("operator slice len mutated: was %d, now %d",
			originalLen, len(pol.ToolScopeMap))
	}
	if cap(pol.ToolScopeMap) != originalCap {
		t.Errorf("operator slice cap mutated: was %d, now %d",
			originalCap, cap(pol.ToolScopeMap))
	}
	if &pol.ToolScopeMap[0] != &original[0] {
		t.Errorf("operator backing array reseated")
	}
}

func TestDefaultLLMToolScopeMap_NoEmptyEntries(t *testing.T) {
	// Bundled defaults must pass policy.validateToolScopeMap.
	for i, m := range DefaultLLMToolScopeMap {
		if m.Pattern == "" {
			t.Errorf("DefaultLLMToolScopeMap[%d]: empty pattern (scope=%q)", i, m.Scope)
		}
		if m.Scope == "" {
			t.Errorf("DefaultLLMToolScopeMap[%d]: empty scope (pattern=%q)", i, m.Pattern)
		}
	}
}

func TestDefaultLLMToolScopeMap_OnlyKnownScopes(t *testing.T) {
	// Defaults may only use scopes the engine recognises.
	known := map[string]bool{
		"shell":      true,
		"filesystem": true,
		"network":    true,
		"browser":    true,
		"data":       true,
		"cost":       true,
		"mcp_tool":   true,
	}
	for i, m := range DefaultLLMToolScopeMap {
		if !known[m.Scope] {
			t.Errorf("DefaultLLMToolScopeMap[%d]: scope %q is not a known engine scope (pattern=%q)",
				i, m.Scope, m.Pattern)
		}
	}
}

// Claude Code routed through the proxy names its tools Bash, Edit, … —
// capitalised, so they need their own entries: the lowercase ones don't
// match, and an unmapped tool is denied.
func TestDefaultLLMToolScopeMap_ClaudeCodeTools(t *testing.T) {
	cases := map[string]string{
		"Bash": "shell", "PowerShell": "shell",
		"Read": "filesystem", "Write": "filesystem", "Edit": "filesystem", "MultiEdit": "filesystem",
		"NotebookEdit": "filesystem", "Glob": "filesystem", "Grep": "filesystem",
		"WebFetch": "network",
	}
	for tool, want := range cases {
		if got := MapLLMToolScope(tool, DefaultLLMToolScopeMap); got != want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", tool, got, want)
		}
	}
	if got := projectPath("filesystem", map[string]interface{}{"notebook_path": "/n.ipynb"}); got != "/n.ipynb" {
		t.Errorf("NotebookEdit's notebook_path isn't read as the path: %q", got)
	}
}
