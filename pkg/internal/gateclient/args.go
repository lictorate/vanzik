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

// argKey is one argument name and the role it feeds.
type argKey struct {
	key  string
	role string
}

var (
	urlArgKeys = []argKey{
		{"url", ArgURL}, {"uri", ArgURL}, {"endpoint", ArgURL}, {"target_url", ArgURL},
	}
	domainArgKeys = []argKey{
		{"domain", ArgDomain}, {"host", ArgDomain}, {"hostname", ArgDomain},
	}
)

// scopeArgs is the one list of argument names both gates project into an
// ActionRequest: scope → keys in lookup order, each tagged with its role.
// Lookup order is per key, not per role, because a field can draw on
// several roles with their keys interleaved: a filesystem path reads
// `destination` before `src` before `dst`. A key added here is projected
// and conflict-checked by the LLM API Proxy and the MCP Gateway alike.
// plugins/python/vanzik/adapters/_common.py (_ALIASES) covers part of it;
// TestArgTable_PythonAliases pins the difference.
var scopeArgs = map[string][]argKey{
	"shell": {
		{"command", ArgCommand}, {"cmd", ArgCommand}, {"script", ArgCommand}, {"code", ArgCommand},
		{"args", ArgArgs},
	},
	"filesystem": {
		{"path", ArgPath}, {"file_path", ArgPath}, {"notebook_path", ArgPath}, {"filepath", ArgPath},
		{"target", ArgPath}, {"target_path", ArgPath}, {"filename", ArgPath}, {"file", ArgPath},
		{"destination", ArgDestination}, {"src", ArgSource}, {"dst", ArgDestination},
	},
	"network": append(append([]argKey{}, urlArgKeys...), domainArgKeys...),
	"browser": append(append([]argKey{}, urlArgKeys...), domainArgKeys...),
	"data": append([]argKey{
		{"value", ArgValue}, {"content", ArgValue}, {"text", ArgValue}, {"data", ArgValue},
	}, urlArgKeys...),
}

// ScopeArg returns the first non-empty string argument of scope, in table
// order, among the keys whose role is one of roles. "" when none is set.
func ScopeArg(args map[string]interface{}, scope string, roles ...string) string {
	if len(args) == 0 {
		return ""
	}
	for _, e := range scopeArgs[scope] {
		if !hasRole(roles, e.role) {
			continue
		}
		if s, ok := args[e.key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsSecretKeyName reports whether an argument name implies a secret. The
// default redactor matches `key=value`, not a bare value, so both gates
// mask these arguments' meta values by name.
func IsSecretKeyName(k string) bool {
	lk := strings.ToLower(k)
	for _, needle := range []string{"password", "token", "secret", "api_key", "apikey", "auth"} {
		if strings.Contains(lk, needle) {
			return true
		}
	}
	return false
}

// ArgConflict is a role whose alias keys carry different values.
type ArgConflict struct {
	Role string
	Keys []string // every key of Role holding a non-empty string, in table order
}

// FindArgConflict reports the first role of scope, by the table position
// of its conflicting key, where two keys carry different non-empty
// strings. The gate checks the first such key but the tool reads whichever
// one its signature names, so no verdict on either value is safe.
func FindArgConflict(args map[string]interface{}, scope string) (ArgConflict, bool) {
	if len(args) == 0 {
		return ArgConflict{}, false
	}
	first := map[string]string{}
	keys := map[string][]string{}
	conflictRole := ""
	for _, e := range scopeArgs[scope] {
		s, ok := args[e.key].(string)
		if !ok || s == "" {
			continue
		}
		keys[e.role] = append(keys[e.role], e.key)
		if v, seen := first[e.role]; !seen {
			first[e.role] = s
		} else if v != s && conflictRole == "" {
			conflictRole = e.role
		}
	}
	if conflictRole == "" {
		return ArgConflict{}, false
	}
	return ArgConflict{Role: conflictRole, Keys: keys[conflictRole]}, true
}

// Reason is the refusal text, worded as the Python adapters' (vanzik.
// adapters._common.ConflictingToolInput). It names the keys only; the
// audit entry's request still carries the arguments, as every gate entry
// does.
func (c ArgConflict) Reason() string {
	quoted := make([]string, len(c.Keys))
	for i, k := range c.Keys {
		quoted[i] = "'" + k + "'"
	}
	return fmt.Sprintf("conflicting values for '%s' in tool arguments (%s); refusing to guess which one the tool uses",
		c.Role, strings.Join(quoted, " and "))
}
