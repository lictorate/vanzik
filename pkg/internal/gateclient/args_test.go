package gateclient

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestFindArgConflict(t *testing.T) {
	cases := []struct {
		name     string
		scope    string
		args     map[string]interface{}
		wantRole string // "" = no conflict
		wantKeys []string
	}{
		{"command conflict", "shell", map[string]interface{}{"command": "ls", "cmd": "rm -rf /"}, ArgCommand, []string{"command", "cmd"}},
		{"command conflict on a later alias", "shell", map[string]interface{}{"command": "ls", "cmd": "ls", "code": "rm -rf /"}, ArgCommand, []string{"command", "cmd", "code"}},
		{"command identical", "shell", map[string]interface{}{"command": "ls", "cmd": "ls"}, "", nil},
		{"command empty alias ignored", "shell", map[string]interface{}{"command": "", "cmd": "ls"}, "", nil},
		{"command non-string alias ignored", "shell", map[string]interface{}{"command": 1, "cmd": "ls"}, "", nil},
		{"path conflict", "filesystem", map[string]interface{}{"path": "/tmp/ok", "file_path": "/etc/shadow"}, ArgPath, []string{"path", "file_path"}},
		{"path identical", "filesystem", map[string]interface{}{"path": "/tmp/ok", "file_path": "/tmp/ok"}, "", nil},
		{"src and dst differ", "filesystem", map[string]interface{}{"src": "/tmp/a", "dst": "/tmp/b"}, "", nil},
		{"path and destination differ", "filesystem", map[string]interface{}{"path": "/tmp/a", "destination": "/tmp/b"}, "", nil},
		{"destination conflict", "filesystem", map[string]interface{}{"destination": "/tmp/b", "dst": "/etc/cron.d/x"}, ArgDestination, []string{"destination", "dst"}},
		{"url conflict", "network", map[string]interface{}{"url": "https://ok.example", "uri": "https://evil.example"}, ArgURL, []string{"url", "uri"}},
		{"url identical", "network", map[string]interface{}{"url": "https://ok.example", "uri": "https://ok.example"}, "", nil},
		{"url and domain differ", "network", map[string]interface{}{"url": "https://ok.example", "domain": "other.example"}, "", nil},
		{"domain conflict", "browser", map[string]interface{}{"domain": "ok.example", "host": "evil.example"}, ArgDomain, []string{"domain", "host"}},
		{"value conflict", "data", map[string]interface{}{"value": "hello", "text": "sk-secret"}, ArgValue, []string{"value", "text"}},
		{"value identical", "data", map[string]interface{}{"value": "hello", "text": "hello"}, "", nil},
		{"scope without a table entry", "unmapped", map[string]interface{}{"command": "ls", "cmd": "rm -rf /"}, "", nil},
		{"nil args", "shell", nil, "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := FindArgConflict(c.args, c.scope)
			if c.wantRole == "" {
				if ok {
					t.Fatalf("FindArgConflict = %+v, want no conflict", got)
				}
				return
			}
			if !ok {
				t.Fatalf("FindArgConflict found no conflict, want role %q", c.wantRole)
			}
			if got.Role != c.wantRole || !reflect.DeepEqual(got.Keys, c.wantKeys) {
				t.Errorf("FindArgConflict = %+v, want role %q keys %v", got, c.wantRole, c.wantKeys)
			}
		})
	}
}

func TestArgConflictReason_NamesKeysNotValues(t *testing.T) {
	c, ok := FindArgConflict(map[string]interface{}{"command": "ls", "cmd": "rm -rf /"}, "shell")
	if !ok {
		t.Fatal("expected a conflict")
	}
	// Same wording as the Python adapters' ConflictingToolInput.
	want := "conflicting values for 'command' in tool arguments ('command' and 'cmd'); refusing to guess which one the tool uses"
	if got := c.Reason(); got != want {
		t.Errorf("Reason() = %q, want %q", got, want)
	}
	if strings.Contains(c.Reason(), "rm -rf") {
		t.Errorf("Reason() leaks an argument value: %q", c.Reason())
	}
}

func TestScopeArg_RoleOrder(t *testing.T) {
	args := map[string]interface{}{"dst": "/tmp/b", "src": "/tmp/a"}
	if got := ScopeArg(args, "filesystem", ArgPath, ArgSource, ArgDestination); got != "/tmp/a" {
		t.Errorf("ScopeArg = %q, want the source /tmp/a (roles are tried in the order given)", got)
	}
	args["file"] = "/tmp/c"
	if got := ScopeArg(args, "filesystem", ArgPath, ArgSource, ArgDestination); got != "/tmp/c" {
		t.Errorf("ScopeArg = %q, want the path /tmp/c", got)
	}
	if got := ScopeArg(args, "network", ArgPath); got != "" {
		t.Errorf("ScopeArg for a role the scope lacks = %q, want \"\"", got)
	}
}

// Roles of the Go table that the Python adapters read through one key or not
// at all, and Go keys missing from a Python alias group. Recorded so this test
// fails when either side changes; the Python side is deliberately not edited
// here.
var (
	pythonUnaliasedRoles = map[string]bool{ArgURL: true, ArgDomain: true, ArgDestination: true, ArgValue: true}
	pythonMissingKeys    = map[string][]string{
		ArgCommand: {"script", "code"},
		ArgPath:    {"notebook_path", "filepath", "target", "target_path", "filename", "file"},
	}
)

// TestArgTable_PythonAliases is a tripwire: the Python adapters keep their own
// alias list (plugins/python/vanzik/adapters/_common.py, _ALIASES). It must
// equal this table's role keys minus the recorded gaps above.
func TestArgTable_PythonAliases(t *testing.T) {
	src := readRepoFile(t, filepath.Join("plugins", "python", "vanzik", "adapters", "_common.py"))
	block := regexp.MustCompile(`(?s)_ALIASES[^=]*=\s*\((.*?)\n\)`).FindStringSubmatch(src)
	if block == nil {
		t.Fatal("_ALIASES not found in _common.py; update this tripwire's parser")
	}
	groups := regexp.MustCompile(`\(\s*"(\w+)"\s*,\s*\(([^)]*)\)\s*\)`).FindAllStringSubmatch(block[1], -1)
	if len(groups) == 0 {
		t.Fatal("no alias groups parsed from _ALIASES; the tripwire would be vacuous")
	}
	python := map[string][]string{}
	for _, g := range groups {
		for _, k := range regexp.MustCompile(`"(\w+)"`).FindAllStringSubmatch(g[2], -1) {
			python[g[1]] = append(python[g[1]], k[1])
		}
	}

	goKeys := map[string][]string{}
	for scope, roles := range scopeArgs {
		for _, r := range roles {
			if prev, ok := goKeys[r.role]; ok && !reflect.DeepEqual(prev, r.keys) {
				t.Errorf("role %q has different keys in different scopes (%s: %v vs %v)", r.role, scope, r.keys, prev)
			}
			goKeys[r.role] = r.keys
		}
	}

	for role, keys := range python {
		gk, ok := goKeys[role]
		if !ok {
			t.Errorf("Python aliases %q %v, which the Go table has no role for", role, keys)
			continue
		}
		var want []string
		for _, k := range gk {
			if !contains(pythonMissingKeys[role], k) {
				want = append(want, k)
			}
		}
		if !reflect.DeepEqual(keys, want) {
			t.Errorf("Python aliases for %q = %v, want %v (Go table %v minus recorded gaps %v); update both sides or the recorded gaps",
				role, keys, want, gk, pythonMissingKeys[role])
		}
	}
	for role, keys := range goKeys {
		if _, ok := python[role]; ok || len(keys) < 2 {
			continue
		}
		if !pythonUnaliasedRoles[role] {
			t.Errorf("Go role %q has aliases %v the Python adapters don't list; add them to _ALIASES or record the gap", role, keys)
		}
	}
	for role := range pythonUnaliasedRoles {
		if _, ok := python[role]; ok {
			t.Errorf("Python now aliases %q; remove it from pythonUnaliasedRoles", role)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
