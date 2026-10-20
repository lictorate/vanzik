package main

// Tests for moving an AgentGuard 1.x install to Vanzik: hook entries, the
// config and data folders, the database, setup.json and the login service.
// Everything runs in temp folders with fake (or command-recording) login
// services: the migration must never touch the real machine's settings.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	"lictorate.com/vanzik/v2/configs"
	"lictorate.com/vanzik/v2/pkg/store"
)

// v1 hook commands, as AgentGuard 1.x's setup wrote them.
const (
	v1Exe    = "/home/u/.local/bin/agentguard"
	v1WinExe = "C:/Users/u/AppData/Local/Programs/AgentGuard/bin/agentguard.exe"
)

func TestRewriteLegacyCommand(t *testing.T) {
	exe := "/home/u/.local/bin/vanzik"
	for _, c := range []struct {
		command, agent, want string
	}{
		{`"` + v1Exe + `" hook claude-code`, claudeAgentID, `"` + exe + `" hook claude-code`},
		{`"` + v1Exe + `" hook codex --fail-closed`, codexAgentID, `"` + exe + `" hook codex --fail-closed`},
		{`& "` + v1WinExe + `" hook gemini-cli`, geminiAgentID, `& "` + exe + `" hook gemini-cli`},
		{`"C:/x/AgentGuard.EXE" hook cursor`, cursorAgentID, `"` + exe + `" hook cursor`},
		// Not AgentGuard's: another agent's entry, the user's own wrapper,
		// an entry that already runs vanzik, extra arguments.
		{`"` + v1Exe + `" hook cursor`, claudeAgentID, ""},
		{`"/opt/agentguard-wrapper.sh" hook cursor`, cursorAgentID, ""},
		{`/opt/agentguard-wrapper.sh hook cursor-audit`, cursorAgentID, ""},
		{`"` + exe + `" hook cursor`, cursorAgentID, ""},
		{`"` + v1Exe + `" hook cursor --verbose`, cursorAgentID, ""},
	} {
		got, ok := rewriteLegacyCommand(c.command, c.agent, exe)
		if ok != (c.want != "") || got != c.want {
			t.Errorf("rewriteLegacyCommand(%q, %s) = %q, %v; want %q", c.command, c.agent, got, ok, c.want)
		}
	}
}

// legacySettings writes each agent's settings file the way a user of
// AgentGuard 1.x has it: AgentGuard's entries (one failing closed), the
// user's own hooks, and a wrapper of their own that merely looks similar.
// It returns the files' original contents.
func legacySettings(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{
		claudeAgentID: `{
  "permissions": {"allow": ["Bash(ls:*)"]},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "./my-check.sh"}]},
      {"matcher": "` + claudeHookMatcher + `", "hooks": [{"type": "command", "command": "\"` + v1Exe + `\" hook claude-code --fail-closed", "timeout": 330}]},
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "\"/opt/agentguard-wrapper.sh\" hook claude-code"}]}
    ]
  }
}
`,
		cursorAgentID: `{
  "version": 1,
  "hooks": {
    "afterFileEdit": [{"command": "./format.sh"}],
    "beforeShellExecution": [{"command": "\"` + v1Exe + `\" hook cursor", "timeout": 330}],
    "beforeReadFile": [{"command": "\"` + v1Exe + `\" hook cursor", "timeout": 330}]
  }
}
`,
		geminiAgentID: `{
  "ui": {"theme": "dark"},
  "hooks": {
    "BeforeTool": [{"matcher": "` + geminiHookMatcher + `", "hooks": [{"type": "command", "command": "& \"` + v1WinExe + `\" hook gemini-cli", "name": "agentguard", "timeout": 330000, "description": "Checks tool calls against your AgentGuard policy"}]}]
  }
}
`,
		codexAgentID: `{
  "hooks": {
    "PreToolUse": [{"matcher": "` + codexHookMatcher + `", "hooks": [{"type": "command", "command": "\"` + v1Exe + `\" hook codex --fail-closed", "timeout": 330, "statusMessage": "Checking with AgentGuard"}]}]
  }
}
`,
	}
	for agent, body := range files {
		path := integration(t, agent).settingsPath()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func TestRewriteLegacyHooks(t *testing.T) {
	m := testMachine(t)
	original := legacySettings(t)
	wantFailClosed := map[string]bool{claudeAgentID: true, cursorAgentID: false, geminiAgentID: false, codexAgentID: true}
	wantCommands := map[string]int{claudeAgentID: 1, cursorAgentID: 2, geminiAgentID: 1, codexAgentID: 1}

	for _, a := range agentIntegrations {
		path := a.settingsPath()
		if connected, _ := a.connected(); connected {
			t.Fatalf("%s: a 1.x entry already counts as Vanzik's", a.name)
		}
		n, err := rewriteLegacyHooks(path, a.agentID, m.exe, a.lists)
		if err != nil || n != wantCommands[a.agentID] {
			t.Fatalf("%s: rewrote %d commands (err %v), want %d", a.name, n, err, wantCommands[a.agentID])
		}
		// Vanzik now sees its own entry, failing the way the old one did.
		connected, failClosed := a.connected()
		if !connected || failClosed != wantFailClosed[a.agentID] {
			t.Errorf("%s: connected=%v failClosed=%v after the rewrite, want true/%v", a.name, connected, failClosed, wantFailClosed[a.agentID])
		}
		b, _ := os.ReadFile(path)
		text := string(b)
		if strings.Contains(strings.ToLower(text), `agentguard\" hook`) || strings.Contains(strings.ToLower(text), `agentguard.exe\" hook`) {
			t.Errorf("%s still runs agentguard:\n%s", a.name, text)
		}
		backup, err := os.ReadFile(path + ".vanzik-backup")
		if err != nil || string(backup) != original[a.agentID] {
			t.Errorf("%s: the backup isn't the original file (err %v)", a.name, err)
		}
		// A second run has nothing to do and leaves the file alone.
		if n, err := rewriteLegacyHooks(path, a.agentID, m.exe, a.lists); n != 0 || err != nil {
			t.Errorf("%s: a second rewrite changed %d commands (err %v)", a.name, n, err)
		}
	}

	claude, _ := os.ReadFile(integration(t, claudeAgentID).settingsPath())
	for _, keep := range []string{"./my-check.sh", `\"/opt/agentguard-wrapper.sh\" hook claude-code`, `"Bash(ls:*)"`} {
		if !strings.Contains(string(claude), keep) {
			t.Errorf("Claude Code's settings lost %s:\n%s", keep, claude)
		}
	}
	gemini, _ := os.ReadFile(integration(t, geminiAgentID).settingsPath())
	for _, want := range []string{`"name": "vanzik"`, `"description": "` + geminiHookDescription + `"`, `"theme": "dark"`} {
		if !strings.Contains(string(gemini), want) {
			t.Errorf("Gemini CLI's settings lack %s:\n%s", want, gemini)
		}
	}
	var g struct {
		Hooks struct {
			BeforeTool []struct {
				Hooks []struct{ Command string } `json:"hooks"`
			}
		} `json:"hooks"`
	}
	if err := json.Unmarshal(gemini, &g); err != nil || len(g.Hooks.BeforeTool) != 1 || len(g.Hooks.BeforeTool[0].Hooks) != 1 {
		t.Fatalf("Gemini CLI's settings: %v\n%s", err, gemini)
	}
	if got, want := g.Hooks.BeforeTool[0].Hooks[0].Command, `& "`+filepath.ToSlash(m.exe)+`" hook gemini-cli`; got != want {
		t.Errorf("Gemini CLI's command is %q, want %q (the PowerShell & kept)", got, want)
	}
	codex, _ := os.ReadFile(integration(t, codexAgentID).settingsPath())
	if !strings.Contains(string(codex), `"statusMessage": "`+codexStatusMessage+`"`) {
		t.Errorf("Codex's status message wasn't updated:\n%s", codex)
	}
}

// A settings file saved with a UTF-8 byte order mark (Notepad does that) is
// still read and rewritten.
func TestRewriteLegacyHooksInAFileWithABOM(t *testing.T) {
	m := testMachine(t)
	a := integration(t, claudeAgentID)
	body := "\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"\"` + v1WinExe + `\" hook claude-code"}]}]}}`
	_ = os.MkdirAll(filepath.Dir(a.settingsPath()), 0o700)
	if err := os.WriteFile(a.settingsPath(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := rewriteLegacyHooks(a.settingsPath(), a.agentID, m.exe, a.lists); n != 1 || err != nil {
		t.Fatalf("rewrote %d (err %v), want 1", n, err)
	}
	if connected, _ := a.connected(); !connected {
		t.Error("not connected to Vanzik after the rewrite")
	}
}

// A settings file setup can't parse (Gemini CLI allows comments) that still
// runs agentguard is reported, not silently skipped, and is left as it was.
func TestRewriteLegacyHooksInAFileWithComments(t *testing.T) {
	m := testMachine(t)
	a := integration(t, geminiAgentID)
	body := "{\n  // my settings\n  \"hooks\": {\"BeforeTool\": [{\"matcher\": \"*\", \"hooks\": [{\"type\": \"command\", \"command\": \"\\\"" + v1Exe + "\\\" hook gemini-cli\"}]}]}\n}\n"
	_ = os.MkdirAll(filepath.Dir(a.settingsPath()), 0o700)
	if err := os.WriteFile(a.settingsPath(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := rewriteLegacyHooks(a.settingsPath(), a.agentID, m.exe, a.lists)
	if err == nil || !strings.Contains(err.Error(), "agentguard hook gemini-cli") {
		t.Fatalf("want an error saying what to change by hand, got %v", err)
	}
	if b, _ := os.ReadFile(a.settingsPath()); string(b) != body {
		t.Error("the file was changed")
	}
	if fileExists(a.settingsPath() + ".vanzik-backup") {
		t.Error("a backup was written for a file that wasn't changed")
	}
}

// legacyInstall lays out an AgentGuard 1.x setup beside m's (empty) Vanzik
// folders and returns a migrator for it with fake login services.
func legacyInstall(t *testing.T, m machine) (*migrator, *fakeService, *fakeService, *bytes.Buffer) {
	t.Helper()
	root := filepath.Dir(filepath.Dir(m.configDir))
	// Keep the leftover checks (MCP configs, old programs) in the sandbox.
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("GOBIN", filepath.Join(root, "gobin"))
	for _, n := range []string{"AGENTGUARD_API_KEY", "AGENTGUARD_URL", "AGENTGUARD_POLICY", "AGENTGUARD_TENANT_ID"} {
		t.Setenv(n, "")
	}
	out := &bytes.Buffer{}
	g := newMigrator(m, out)
	g.oldConfigDir = filepath.Join(filepath.Dir(m.configDir), "agentguard")
	g.oldDataDir = filepath.Join(filepath.Dir(m.dataDir), "agentguard")
	oldSvc, svc := &fakeService{installed: true}, &fakeService{}
	g.oldSvc, g.svc = oldSvc, svc

	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := json.Marshal(setupState{
		Port: 8123, Policy: filepath.Join(g.oldConfigDir, "default.yaml"), DataDir: g.oldDataDir,
		APIKey: true, LoginStart: true, Seal: true,
	})
	write(filepath.Join(g.oldConfigDir, "default.yaml"), "version: \"1\"\nname: mine\n", 0o644)
	write(filepath.Join(g.oldConfigDir, "api-key"), "0123abcd\n", 0o600)
	write(filepath.Join(g.oldConfigDir, "setup.json"), string(st), 0o600)
	write(filepath.Join(g.oldDataDir, legacyDBFile), "sqlite db", 0o600)
	write(filepath.Join(g.oldDataDir, legacyDBFile+"-wal"), "wal", 0o600)
	write(filepath.Join(g.oldDataDir, "audit.jsonl"), "{\"seq\":1}\n{\"seq\":2}\n", 0o600)
	write(filepath.Join(g.oldDataDir, "audit-seal.key"), "seal", 0o600)
	return g, oldSvc, svc, out
}

func TestMigrateFromAgentGuard(t *testing.T) {
	serverUp(t)
	m := testMachine(t)
	legacySettings(t)
	g, oldSvc, svc, out := legacyInstall(t, m)
	oldConfig, oldData := g.oldConfigDir, g.oldDataDir

	if !g.found() {
		t.Fatal("found() missed the AgentGuard install")
	}
	if !g.run() {
		t.Fatalf("migration failed:\n%s", out)
	}

	// The old server was stopped and its service removed, before anything
	// moved; the new one is installed for the migrated setup.
	if oldSvc.installed || strings.Join(oldSvc.calls, ",") != "remove" {
		t.Errorf("old service: installed=%v calls=%v, want removed", oldSvc.installed, oldSvc.calls)
	}
	if !svc.installed || svc.spec.Exe != m.exe {
		t.Fatalf("new service: installed=%v exe=%q, want %q", svc.installed, svc.spec.Exe, m.exe)
	}
	args := strings.Join(svc.spec.Args, " ")
	for _, want := range []string{"--policy " + filepath.Join(m.configDir, "default.yaml"), "--data-dir " + m.dataDir, "--port 8123", "--api-key-file " + m.keyPath(), "--audit-seal-key-file " + filepath.Join(m.dataDir, "audit-seal.key")} {
		if !strings.Contains(args, want) {
			t.Errorf("the new service's command line lacks %q: %s", want, args)
		}
	}
	if strings.Contains(args, "agentguard") {
		t.Errorf("the new service still names AgentGuard's folders: %s", args)
	}

	// Files moved byte for byte; the database took Vanzik's name.
	for path, want := range map[string]string{
		filepath.Join(m.configDir, "default.yaml"): "version: \"1\"\nname: mine\n",
		m.keyPath():                                "0123abcd\n",
		filepath.Join(m.dataDir, dbFile):           "sqlite db",
		filepath.Join(m.dataDir, dbFile+"-wal"):    "wal",
		filepath.Join(m.dataDir, "audit.jsonl"):    "{\"seq\":1}\n{\"seq\":2}\n",
		filepath.Join(m.dataDir, "audit-seal.key"): "seal",
	} {
		if b, err := os.ReadFile(path); err != nil || string(b) != want {
			t.Errorf("%s: %q (err %v), want %q", path, b, err, want)
		}
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(m.keyPath()); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the API key's mode changed: %v", info.Mode())
		}
	}
	if fileExists(filepath.Join(m.dataDir, legacyDBFile)) || dirExists(oldData) {
		t.Error("AgentGuard's database or data folder is still there")
	}

	// setup.json points into the new folders and keeps the rest.
	st, err := loadState(m)
	if err != nil || st == nil {
		t.Fatalf("setup.json: %v", err)
	}
	if st.Policy != filepath.Join(m.configDir, "default.yaml") || st.DataDir != m.dataDir || st.Port != 8123 || !st.APIKey || !st.Seal || !st.LoginStart {
		t.Errorf("setup.json after the move: %+v", st)
	}

	// The old config folder is now a link to the new one, so an agent
	// session still running the old program finds its key; where links
	// can't be made, the user is told to restart those sessions.
	if sameDir(oldConfig, m.configDir) {
		if b, err := os.ReadFile(filepath.Join(oldConfig, "api-key")); err != nil || string(b) != "0123abcd\n" {
			t.Errorf("the key isn't readable through the link: %q %v", b, err)
		}
	} else if runtime.GOOS != "windows" || !strings.Contains(out.String(), "Restart Claude Code") {
		t.Errorf("no link at %s and no note to restart the sessions:\n%s", oldConfig, out)
	}

	// Every agent's hook runs vanzik; Codex needs its hook trusted again.
	for _, a := range agentIntegrations {
		if connected, _ := a.connected(); !connected {
			t.Errorf("%s isn't connected to Vanzik after the migration", a.name)
		}
	}
	if !strings.Contains(out.String(), "Trust the changed hook in Codex") {
		t.Errorf("no note to trust the Codex hook:\n%s", out)
	}

	// Run again: nothing left to do, and nothing changes.
	again := &bytes.Buffer{}
	g2 := newMigrator(m, again)
	g2.oldConfigDir, g2.oldDataDir, g2.oldSvc, g2.svc = oldConfig, oldData, &fakeService{}, &fakeService{}
	if g2.found() {
		t.Error("found() still finds something after the migration")
	}
	if !g2.run() || !strings.Contains(again.String(), "nothing to migrate") {
		t.Errorf("second run:\n%s", again)
	}
}

// When the old server can't be stopped, nothing moves: the 1.x install
// keeps working exactly as it was.
func TestMigrateChangesNothingWhenTheOldServerCantStop(t *testing.T) {
	m := testMachine(t)
	original := legacySettings(t)
	g, _, svc, out := legacyInstall(t, m)
	g.oldSvc = &stuckService{fakeService{installed: true}}

	if g.run() {
		t.Fatalf("the migration went ahead:\n%s", out)
	}
	if !dirExists(g.oldConfigDir) || !dirExists(g.oldDataDir) || dirExists(m.configDir) || svc.installed {
		t.Error("something moved although the old server is still running")
	}
	for agent, body := range original {
		if b, _ := os.ReadFile(integration(t, agent).settingsPath()); string(b) != body {
			t.Errorf("%s's settings changed", agent)
		}
	}
}

type stuckService struct{ fakeService }

func (s *stuckService) Remove() error { return errors.New("access denied") }

// A folder Vanzik already has keeps Vanzik's files; AgentGuard's copies
// of the same files stay where they were and the run says so. A starter
// policy nobody edited is the exception: the user's policy replaces it.
func TestMigrateKeepsBothCopiesOnConflict(t *testing.T) {
	serverUp(t)
	m := testMachine(t)
	g, _, _, out := legacyInstall(t, m)
	_ = os.MkdirAll(m.configDir, 0o700)
	if err := os.WriteFile(m.keyPath(), []byte("new key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.configDir, "default.yaml"), configs.Default, 0o644); err != nil {
		t.Fatal(err)
	}

	if g.run() {
		t.Fatalf("a conflict was not reported:\n%s", out)
	}
	if b, _ := os.ReadFile(m.keyPath()); string(b) != "new key\n" {
		t.Errorf("Vanzik's API key was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(g.oldConfigDir, "api-key")); string(b) != "0123abcd\n" {
		t.Errorf("AgentGuard's API key wasn't kept in place: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(m.configDir, "default.yaml")); string(b) != "version: \"1\"\nname: mine\n" {
		t.Errorf("the untouched starter policy wasn't replaced by the user's: %q", b)
	}
	if !strings.Contains(out.String(), "api-key") {
		t.Errorf("the report doesn't name the conflicting file:\n%s", out)
	}
}

func TestAdoptLegacyDB(t *testing.T) {
	dir := t.TempDir()
	if adopted, err := adoptLegacyDB(dir); adopted || err != nil {
		t.Fatalf("empty folder: %v %v", adopted, err)
	}
	for _, f := range []string{legacyDBFile, legacyDBFile + "-wal", legacyDBFile + "-shm"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte(f), 0o600)
	}
	if adopted, err := adoptLegacyDB(dir); !adopted || err != nil {
		t.Fatalf("adopt: %v %v", adopted, err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if b, err := os.ReadFile(filepath.Join(dir, dbFile+suffix)); err != nil || string(b) != legacyDBFile+suffix {
			t.Errorf("%s%s: %q %v", dbFile, suffix, b, err)
		}
		if fileExists(filepath.Join(dir, legacyDBFile+suffix)) {
			t.Errorf("%s%s is still there", legacyDBFile, suffix)
		}
	}
	// Both present: nothing changes.
	_ = os.WriteFile(filepath.Join(dir, legacyDBFile), []byte("old"), 0o600)
	if _, err := adoptLegacyDB(dir); !errors.Is(err, errLegacyDBLeftOver) {
		t.Fatalf("both present: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, dbFile)); string(b) != legacyDBFile {
		t.Error("vanzik.db was overwritten")
	}
}

// The server, started on a data folder AgentGuard 1.x used, opens the old
// database under its new name instead of starting an empty one.
func TestOpenStoreAdoptsTheAgentGuardDatabase(t *testing.T) {
	dir := t.TempDir()
	old, err := store.NewSQLiteStore(filepath.Join(dir, legacyDBFile))
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	s, path, err := openStore(persistOpts{Enabled: true, DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if path != filepath.Join(dir, dbFile) || fileExists(filepath.Join(dir, legacyDBFile)) {
		t.Errorf("opened %s; agentguard.db still there: %v", path, fileExists(filepath.Join(dir, legacyDBFile)))
	}
}

// recordCommands replaces runCommand for the test, recording each command
// line (PowerShell scripts decoded) and answering with ok.
func recordCommands(t *testing.T, ok func(line string) bool) *[]string {
	t.Helper()
	var lines []string
	prev := runCommand
	runCommand = func(_ string, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		if name == "powershell.exe" {
			line = "powershell " + decodePowerShell(t, args[len(args)-1])
		}
		lines = append(lines, line)
		if ok != nil && !ok(line) {
			return "", errors.New("failed")
		}
		return "", nil
	}
	t.Cleanup(func() { runCommand = prev })
	return &lines
}

func decodePowerShell(t *testing.T, encoded string) string {
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// AgentGuard 1.x's login services are found and removed by their old
// names, and only those: Vanzik's own are not touched.
func TestLegacyLoginServices(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, ".config"))
	write := func(path string) {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, []byte("x"), 0o644)
	}

	t.Run("systemd", func(t *testing.T) {
		lines := recordCommands(t, nil)
		m := machine{goos: "linux", configDir: filepath.Join(root, ".config", "vanzik")}
		unit := filepath.Join(root, ".config", "systemd", "user", legacySystemdUnit)
		write(unit)
		svc := legacyLoginService(m, "/d")
		if !svc.Installed() || newLoginService(m).Installed() {
			t.Fatal("the old unit should count as the legacy service only")
		}
		if err := svc.Remove(); err != nil {
			t.Fatal(err)
		}
		if fileExists(unit) || !strings.Contains(strings.Join(*lines, "\n"), "systemctl --user disable --now agentguard.service") {
			t.Errorf("unit left behind, or the wrong unit disabled: %v", *lines)
		}
	})

	t.Run("launchd", func(t *testing.T) {
		lines := recordCommands(t, nil)
		m := machine{goos: "darwin"}
		plist := filepath.Join(root, "Library", "LaunchAgents", legacyLaunchdLabel+".plist")
		write(plist)
		svc := legacyLoginService(m, "/d")
		if !svc.Installed() || newLoginService(m).Installed() {
			t.Fatal("the old plist should count as the legacy service only")
		}
		if err := svc.Remove(); err != nil {
			t.Fatal(err)
		}
		if fileExists(plist) || !strings.Contains(strings.Join(*lines, "\n"), "launchctl bootout gui/") || !strings.Contains(strings.Join(*lines, "\n"), "/"+legacyLaunchdLabel) {
			t.Errorf("plist left behind, or the wrong label booted out: %v", *lines)
		}
	})

	t.Run("task scheduler", func(t *testing.T) {
		// schtasks knows only AgentGuard's task.
		lines := recordCommands(t, func(line string) bool {
			return !strings.HasPrefix(line, "schtasks.exe") || strings.HasSuffix(line, "/TN "+legacyTaskName)
		})
		m := machine{goos: "windows"}
		svc := legacyLoginService(m, `C:\Users\u\AppData\Local\AgentGuard\data`)
		if !svc.Installed() || newLoginService(m).Installed() {
			t.Fatal("the AgentGuard task should count as the legacy service only")
		}
		if err := svc.Remove(); err != nil {
			t.Fatal(err)
		}
		all := strings.Join(*lines, "\n")
		for _, want := range []string{"Stop-ScheduledTask -TaskName 'AgentGuard'", "Name='agentguard.exe'", `AgentGuard\data`, "Unregister-ScheduledTask -TaskName 'AgentGuard'"} {
			if !strings.Contains(all, want) {
				t.Errorf("removing the task didn't run %q:\n%s", want, all)
			}
		}
		if strings.Contains(all, "'Vanzik'") {
			t.Errorf("Vanzik's task was touched:\n%s", all)
		}
	})
}

// The variables AgentGuard 1.x read are never used, but a server or check
// that would have fallen back to one stops instead of running without it.
func TestLegacyEnvironmentStopsServerSettings(t *testing.T) {
	for _, n := range []string{"VANZIK_API_KEY", "VANZIK_POLICY", "VANZIK_URL"} {
		t.Setenv(n, "")
	}
	t.Setenv("AGENTGUARD_API_KEY", "old")
	if _, err := serverAPIKey("", ""); err == nil || !strings.Contains(err.Error(), "VANZIK_API_KEY") {
		t.Errorf("server with only AGENTGUARD_API_KEY: %v", err)
	}
	if key, err := serverAPIKey("flag", ""); err != nil || key != "flag" {
		t.Errorf("--api-key wins over the old variable: %q %v", key, err)
	}
	t.Setenv("VANZIK_API_KEY", "new")
	if key, err := serverAPIKey("", ""); err != nil || key != "new" {
		t.Errorf("VANZIK_API_KEY set: %q %v", key, err)
	}

	t.Setenv("AGENTGUARD_POLICY", "/old/policy.yaml")
	if _, _, err := findPolicy("", false); err == nil || !strings.Contains(err.Error(), "VANZIK_POLICY") {
		t.Errorf("findPolicy with only AGENTGUARD_POLICY: %v", err)
	}
	if p, _, err := findPolicy("/given.yaml", true); err != nil || p != "/given.yaml" {
		t.Errorf("--policy wins: %q %v", p, err)
	}

	t.Setenv("AGENTGUARD_URL", "http://old:8080")
	if code := run([]string{"status"}); code == 0 {
		t.Error("status ran with only AGENTGUARD_URL set")
	}
}

// The hook never refuses to run (an agent lets the call through when it
// does), but says which old variable is set when it couldn't check a call.
func TestHookNamesALegacyVariable(t *testing.T) {
	cfg := hookConfig{serverURL: "http://127.0.0.1:1", legacyNote: " AGENTGUARD_URL is set, but Vanzik reads VANZIK_URL."}
	code, out, _ := runHook(t, cfg, hookInput("Bash", map[string]any{"command": "ls"}))
	if code != 0 || !strings.Contains(out, "AGENTGUARD_URL is set") {
		t.Errorf("code %d, output %s", code, out)
	}
}

func TestMigrateFromAgentGuardTakesNoOtherFlag(t *testing.T) {
	if code := run([]string{"migrate", "--from-agentguard", "--dry-run"}); code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}
