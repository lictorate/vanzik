package llmproxy

// Tool name to existing policy scope mapping (docs/LLM_API_PROXY.md
// § 4, docs/POLICY_REFERENCE.md § "LLM API Proxy tool scope mapping").
// It reuses policy.Policy.ToolScopeMap rather than a separate table:
// namespaced MCP names (`<ns>:<tool>`) and bare LLM names never
// collide, so one `tool_scope_map:` section serves both transports.

import (
	"lictorate.com/vanzik/v2/pkg/policy"
)

// UnmappedScope is the scope for tool names matching no entry. The
// engine has no built-in rules for it, so it is denied unless a
// `scope: unmapped` rule exists. Stable string (documented in
// docs/POLICY_REFERENCE.md).
const UnmappedScope = "unmapped"

// DefaultLLMToolScopeMap is the bundled mapping for common tool names.
// Patterns use the policy glob matcher, first match wins; the policy's
// `tool_scope_map:` entries take precedence. `data` and `cost` have no
// defaults: operators map form tools to `data` themselves, and cost is
// gated via SDK est_cost, not tool names.
var DefaultLLMToolScopeMap = []policy.ToolScopeMapping{
	// --- Claude Code's built-in tools (matching is case-sensitive, so
	// "Bash" needs its own entry) ---
	{Pattern: "Bash", Scope: "shell"},
	{Pattern: "PowerShell", Scope: "shell"},
	{Pattern: "Read", Scope: "filesystem"},
	{Pattern: "Write", Scope: "filesystem"},
	{Pattern: "Edit", Scope: "filesystem"},
	{Pattern: "MultiEdit", Scope: "filesystem"},
	{Pattern: "NotebookEdit", Scope: "filesystem"},
	{Pattern: "Glob", Scope: "filesystem"},
	{Pattern: "Grep", Scope: "filesystem"},
	{Pattern: "WebFetch", Scope: "network"},

	// --- Shell / command execution ---
	{Pattern: "bash", Scope: "shell"},
	{Pattern: "sh", Scope: "shell"},
	{Pattern: "shell", Scope: "shell"},
	{Pattern: "run_command", Scope: "shell"},
	{Pattern: "execute_command", Scope: "shell"},
	{Pattern: "cmd", Scope: "shell"},
	{Pattern: "system", Scope: "shell"},
	{Pattern: "exec", Scope: "shell"},

	// --- Filesystem ---
	{Pattern: "read_file", Scope: "filesystem"},
	{Pattern: "write_file", Scope: "filesystem"},
	{Pattern: "list_directory", Scope: "filesystem"},
	{Pattern: "list_files", Scope: "filesystem"},
	{Pattern: "file_read", Scope: "filesystem"},
	{Pattern: "file_write", Scope: "filesystem"},
	{Pattern: "edit_file", Scope: "filesystem"},
	{Pattern: "delete_file", Scope: "filesystem"},
	{Pattern: "create_directory", Scope: "filesystem"},
	{Pattern: "ls", Scope: "filesystem"},
	{Pattern: "cat", Scope: "filesystem"},
	{Pattern: "find", Scope: "filesystem"},
	{Pattern: "glob", Scope: "filesystem"},

	// --- Network (HTTP / web search) ---
	{Pattern: "web_search", Scope: "network"},
	{Pattern: "fetch_url", Scope: "network"},
	{Pattern: "http_request", Scope: "network"},
	{Pattern: "http_get", Scope: "network"},
	{Pattern: "http_post", Scope: "network"},
	{Pattern: "search", Scope: "network"},
	{Pattern: "fetch", Scope: "network"},
	{Pattern: "url_request", Scope: "network"},

	// --- Browser (wildcard for prefix-based families) ---
	{Pattern: "playwright_*", Scope: "browser"},
	{Pattern: "browser_*", Scope: "browser"},
	{Pattern: "chrome_*", Scope: "browser"},
	{Pattern: "firefox_*", Scope: "browser"},
	{Pattern: "selenium_*", Scope: "browser"},
	{Pattern: "navigate", Scope: "browser"},
	{Pattern: "click", Scope: "browser"},
	{Pattern: "screenshot", Scope: "browser"},
}

// NewLLMToolScopeMap returns the policy's entries followed by the
// defaults, so operator entries win. With no policy entries it returns
// DefaultLLMToolScopeMap itself, which callers must not mutate;
// otherwise the slice is freshly allocated.
func NewLLMToolScopeMap(pol *policy.Policy) []policy.ToolScopeMapping {
	if pol == nil || len(pol.ToolScopeMap) == 0 {
		return DefaultLLMToolScopeMap
	}

	merged := make([]policy.ToolScopeMapping, 0, len(pol.ToolScopeMap)+len(DefaultLLMToolScopeMap))
	merged = append(merged, pol.ToolScopeMap...)
	merged = append(merged, DefaultLLMToolScopeMap...)
	return merged
}

// MapLLMToolScope returns the scope of the first matching entry, or
// UnmappedScope. To let unknown tools through, operators write a
// `scope: unmapped` rule, typically require_approval on "*".
//
// It goes through a throwaway policy.Policy to reuse pkg/policy's
// unexported glob matcher rather than export or duplicate it.
func MapLLMToolScope(toolName string, mappings []policy.ToolScopeMapping) string {
	if toolName == "" {
		return UnmappedScope
	}
	if len(mappings) == 0 {
		return UnmappedScope
	}
	synthetic := &policy.Policy{ToolScopeMap: mappings}
	if scope, ok := synthetic.MapToolScope(toolName); ok {
		return scope
	}
	return UnmappedScope
}
