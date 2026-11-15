package gateclient

import (
	"fmt"
	"strings"
)

// Argument roles: what a scope's rules check. Each role has its own alias
// keys, so a move's source and destination are separate roles and may
// differ; two keys of the same role may not.
const (
	ArgCommand     = "command"
	ArgArgs        = "args"
	ArgPath        = "path"
	ArgSource      = "source"
	ArgDestination = "destination"
	ArgURL         = "url"
	ArgDomain      = "domain"
	ArgValue       = "value"
)

type argRole struct {
	role string
	keys []string
}

var (
	urlArgKeys    = []string{"url", "uri", "endpoint", "target_url"}
	domainArgKeys = []string{"domain", "host", "hostname"}
)

// scopeArgs is the one list of argument names both gates project into an
// ActionRequest: scope → roles → alias keys, in lookup order. A key added
// here is projected and conflict-checked by the LLM API Proxy and the MCP
// Gateway alike. plugins/python/vanzik/adapters/_common.py (_ALIASES)
// covers part of it; TestArgTable_PythonAliases pins the difference.
var scopeArgs = map[string][]argRole{
	"shell": {
		{ArgCommand, []string{"command", "cmd", "script", "code"}},
		{ArgArgs, []string{"args"}},
	},
	"filesystem": {
		{ArgPath, []string{"path", "file_path", "notebook_path", "filepath", "target", "target_path", "filename", "file"}},
		{ArgSource, []string{"src"}},
		{ArgDestination, []string{"destination", "dst"}},
	},
	"network": {
		{ArgURL, urlArgKeys},
		{ArgDomain, domainArgKeys},
	},
	"browser": {
		{ArgURL, urlArgKeys},
		{ArgDomain, domainArgKeys},
	},
	"data": {
		{ArgValue, []string{"value", "content", "text", "data"}},
		{ArgURL, urlArgKeys},
	},
}

// ScopeArg returns the first non-empty string argument for scope, trying
// roles in the order given and each role's keys in table order. "" when
// none is set.
func ScopeArg(args map[string]interface{}, scope string, roles ...string) string {
	if len(args) == 0 {
		return ""
	}
	for _, role := range roles {
		for _, r := range scopeArgs[scope] {
			if r.role != role {
				continue
			}
			for _, k := range r.keys {
				if s, ok := args[k].(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// ArgConflict is a role whose alias keys carry different values.
type ArgConflict struct {
	Role string
	Keys []string // every key of Role holding a non-empty string, in table order
}

// FindArgConflict reports the first role of scope, in table order, where
// two keys carry different non-empty strings. The gate checks the first
// such key but the tool reads whichever one its signature names, so no
// verdict on either value is safe.
func FindArgConflict(args map[string]interface{}, scope string) (ArgConflict, bool) {
	if len(args) == 0 {
		return ArgConflict{}, false
	}
	for _, r := range scopeArgs[scope] {
		var keys []string
		first, conflict := "", false
		for _, k := range r.keys {
			s, ok := args[k].(string)
			if !ok || s == "" {
				continue
			}
			keys = append(keys, k)
			if first == "" {
				first = s
			} else if s != first {
				conflict = true
			}
		}
		if conflict {
			return ArgConflict{Role: r.role, Keys: keys}, true
		}
	}
	return ArgConflict{}, false
}

// Reason is the refusal text, worded as the Python adapters' (vanzik.
// adapters._common.ConflictingToolInput). It names keys, never values:
// the values are model-written and land in the audit log.
func (c ArgConflict) Reason() string {
	quoted := make([]string, len(c.Keys))
	for i, k := range c.Keys {
		quoted[i] = "'" + k + "'"
	}
	return fmt.Sprintf("conflicting values for '%s' in tool arguments (%s); refusing to guess which one the tool uses",
		c.Role, strings.Join(quoted, " and "))
}
