package main

// migrate_agentguard.go: moving an AgentGuard 1.x install to Vanzik for the
// current user. AgentGuard was this project's name before 2.0, and its
// programs, folders, login service and hook entries all carried it. The
// installers run this as `vanzik migrate --from-agentguard` once the new
// programs are in place; `vanzik setup` runs it before its menu.
//
// The order matters. The old login service goes first, so nothing holds
// the files while they move. Then the folders and the database. Then the
// coding agents' hook entries, which still name the agentguard program:
// most agents let a tool call through when a hook's program is missing, so
// an entry left behind would stop checking the day that program goes. Last,
// the login service is installed again under the new name, so the server
// still starts at login.
//
// Nothing is rewritten that doesn't have to be. Folders and files are
// moved, byte for byte (the audit log's seal covers its bytes); setup.json
// only has its paths updated; a settings file that is edited keeps its old
// copy as <file>.vanzik-backup.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"lictorate.com/vanzik/v2/configs"
	"lictorate.com/vanzik/v2/internal/legacyenv"
	"lictorate.com/vanzik/v2/internal/localconfig"
)

// What AgentGuard 1.x was called where Vanzik is now.
const (
	legacyTool         = "agentguard"
	legacySystemdUnit  = "agentguard.service"
	legacyLaunchdLabel = "com.lictorate.agentguard"
	legacyTaskName     = "AgentGuard"
	legacyDBFile       = "agentguard.db"
)

var legacyTools = []string{"agentguard", "agentguard-mcp-gateway", "agentguard-llm-proxy"}

// legacyLoginService is the login service an AgentGuard 1.x setup made.
// dataDir is that server's --data-dir, which stopping it on Windows
// matches the process by.
func legacyLoginService(m machine, dataDir string) loginService {
	old := m
	old.dataDir = dataDir
	switch m.goos {
	case "linux":
		return &systemdService{m: old, unit: legacySystemdUnit}
	case "darwin":
		return &launchdService{m: old, label: legacyLaunchdLabel}
	case "windows":
		return &taskService{m: old, name: legacyTaskName, exe: "agentguard.exe"}
	default:
		return unsupportedService{goos: m.goos}
	}
}

// migrator moves one user's AgentGuard 1.x install into m's layout.
type migrator struct {
	m                        machine
	oldConfigDir, oldDataDir string
	oldSvc, svc              loginService
	w                        io.Writer

	failed bool
	// todo is what the user still has to do, printed at the end.
	todo []string
}

func newMigrator(m machine, w io.Writer) *migrator {
	g := &migrator{
		m:            m,
		oldConfigDir: localconfig.LegacyConfigDir(m.goos),
		oldDataDir:   localconfig.LegacyDataDir(m.goos),
		svc:          newLoginService(m),
		w:            w,
	}
	g.oldSvc = legacyLoginService(m, g.oldDataDir)
	return g
}

func (g *migrator) ok(label, detail string) { fmt.Fprintf(g.w, " ✓ %-18s %s\n", label, detail) }
func (g *migrator) note(text string)        { fmt.Fprintf(g.w, "   %s\n", text) }
func (g *migrator) fail(label, detail string) {
	g.failed = true
	fmt.Fprintf(g.w, " ✗ %-18s %s\n", label, detail)
}

// found reports whether anything of AgentGuard 1.x is left to migrate.
func (g *migrator) found() bool {
	if g.pendingDir(g.oldConfigDir, g.m.configDir) || g.pendingDir(g.oldDataDir, g.m.dataDir) || g.oldSvc.Installed() {
		return true
	}
	for _, a := range agentIntegrations {
		if n, err := countLegacyHooks(a.settingsPath(), a.agentID, g.m.exe, a.lists); n > 0 || err != nil {
			return true
		}
	}
	return false
}

// pendingDir reports whether old is a folder still to move into dir: it
// exists and isn't (a link to) dir itself.
func (g *migrator) pendingDir(old, dir string) bool {
	return old != "" && dirExists(old) && !sameDir(old, dir)
}

// run migrates and reports whether every step worked. With nothing to
// migrate it prints one line.
func (g *migrator) run() bool {
	if !g.found() {
		fmt.Fprintln(g.w, " No AgentGuard 1.x install found for this user; nothing to migrate.")
		return true
	}
	fmt.Fprintf(g.w, " Moving AgentGuard 1.x to Vanzik v%s\n", version)

	// 1. The old server stops, and won't start again at login. If that
	// fails nothing else moves: the old install keeps working as it was.
	hadService := g.oldSvc.Installed()
	if hadService {
		if err := g.oldSvc.Remove(); err != nil {
			g.fail("AgentGuard server", "couldn't stop it: "+err.Error())
			g.note("Nothing was changed. Stop the AgentGuard server yourself, then run this again.")
			return false
		}
		g.ok("AgentGuard server", "stopped, and removed its "+g.oldSvc.Describe())
	}

	// 2. The folders, then the database inside the data folder.
	configMoved := g.moveDir("Config folder", g.oldConfigDir, g.m.configDir)
	dataMoved := g.moveDir("Data folder", g.oldDataDir, g.m.dataDir)
	if configMoved {
		g.linkOldConfigDir()
	}
	st := g.updateState(configMoved, dataMoved)
	dataDir := ""
	switch {
	case st != nil:
		dataDir = st.DataDir
	case dataMoved:
		dataDir = g.m.dataDir
	}
	if dataDir != "" {
		switch adopted, err := adoptLegacyDB(dataDir); {
		case errors.Is(err, errLegacyDBLeftOver):
			g.fail("Database", err.Error())
		case err != nil:
			g.fail("Database", err.Error())
		case adopted:
			g.ok("Database", "renamed "+legacyDBFile+" to "+dbFile+" in "+dataDir)
		}
	}

	// 3. The coding agents' hooks.
	g.moveHooks()

	// 4. The server starts at login again, as Vanzik.
	if hadService {
		g.restartService(st)
	}

	g.checkLeftovers()
	if len(g.todo) > 0 {
		fmt.Fprintln(g.w, "\n Still to do:")
		for _, t := range g.todo {
			fmt.Fprintf(g.w, "  - %s\n", t)
		}
	}
	if g.failed {
		fmt.Fprintln(g.w, "\n Some steps failed (marked ✗). What they would have changed is as it was; fix what they say, then run `vanzik migrate --from-agentguard` again.")
	}
	return !g.failed
}

// moveDir moves the folder from into to and reports whether anything moved.
// When to doesn't exist yet that is one rename. Otherwise each entry moves
// on its own; one that is in both folders stays where it was and is
// reported, except a starter policy nobody edited, which the old policy
// replaces (the installer may write one before migrating).
func (g *migrator) moveDir(label, from, to string) bool {
	if !g.pendingDir(from, to) || to == "" {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		g.fail(label, err.Error())
		return false
	}
	if _, err := os.Lstat(to); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(from, to); err != nil {
			g.fail(label, "couldn't move "+from+": "+err.Error())
			return false
		}
		g.ok(label, from+" → "+to)
		removeLegacyParent(from)
		return true
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		g.fail(label, err.Error())
		return false
	}
	var kept []string
	moved := false
	for _, e := range entries {
		src, dst := filepath.Join(from, e.Name()), filepath.Join(to, e.Name())
		if _, err := os.Lstat(dst); err == nil && !isUntouchedStarterPolicy(dst) {
			kept = append(kept, e.Name())
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			g.fail(label, "couldn't move "+src+": "+err.Error())
			kept = append(kept, e.Name())
			continue
		}
		moved = true
	}
	if len(kept) > 0 {
		g.fail(label, fmt.Sprintf("%s has its own %s: kept those, and left AgentGuard's in %s. Compare them, keep what you want in %s, and delete %s.",
			to, strings.Join(kept, ", "), from, to, from))
		return moved
	}
	_ = os.Remove(from)
	removeLegacyParent(from)
	g.ok(label, "moved what was in "+from+" into "+to)
	return true
}

// removeLegacyParent removes %LOCALAPPDATA%\AgentGuard once its data folder
// has moved, if nothing else is in it. Other parents (~/.local/share) are
// never touched.
func removeLegacyParent(dir string) {
	if parent := filepath.Dir(dir); strings.EqualFold(filepath.Base(parent), legacyTaskName) {
		_ = os.Remove(parent)
	}
}

// isUntouchedStarterPolicy reports whether path is the starter policy as
// shipped, so a policy moving in from AgentGuard may replace it.
func isUntouchedStarterPolicy(path string) bool {
	if filepath.Base(path) != localconfig.PolicyFile {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	lf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	return bytes.Equal(lf(b), lf(configs.Default))
}

// linkOldConfigDir leaves a link in the old config folder's place,
// pointing at the new one. Agents read their hooks when a session starts,
// so a running session keeps calling the old agentguard program until it
// restarts. That program looks for its API key and server port in the old
// folder; without the link it would find neither, and its tool calls would
// go ahead unchecked. The link is harmless once nothing runs agentguard.
func (g *migrator) linkOldConfigDir() {
	link := func() error {
		if err := os.Symlink(filepath.Base(g.m.configDir), g.oldConfigDir); err == nil || g.m.goos != "windows" {
			return err
		}
		// A symlink needs Developer Mode on Windows; a junction doesn't.
		_, err := runCommand("", "cmd.exe", "/d", "/c", "mklink", "/J", g.oldConfigDir, g.m.configDir)
		return err
	}
	if filepath.Dir(g.oldConfigDir) != filepath.Dir(g.m.configDir) {
		return // a link by base name only works between siblings
	}
	if _, err := os.Lstat(g.oldConfigDir); !errors.Is(err, os.ErrNotExist) {
		return // part of it stayed behind (a conflict, reported already)
	}
	if err := link(); err != nil {
		g.todo = append(g.todo, "Restart Claude Code, Cursor, Gemini CLI and Codex sessions that are open now: they still run the old agentguard program, which can't find its API key since "+g.oldConfigDir+" moved ("+err.Error()+").")
		return
	}
	g.note(g.oldConfigDir + " now points at " + g.m.configDir + ", for agent sessions that still run agentguard; remove it once you've restarted them.")
}

// updateState fixes the paths in setup.json that pointed into a folder that
// moved, and returns the state (nil when there is none).
func (g *migrator) updateState(configMoved, dataMoved bool) *setupState {
	st, err := loadState(g.m)
	if err != nil {
		g.fail("Settings", err.Error())
		return nil
	}
	if st == nil {
		return nil
	}
	changed := false
	swap := func(p *string, from, to string, moved bool) {
		if !moved {
			return
		}
		if now, ok := underDir(*p, from, to); ok {
			*p, changed = now, true
		}
	}
	swap(&st.Policy, g.oldConfigDir, g.m.configDir, configMoved)
	swap(&st.DataDir, g.oldDataDir, g.m.dataDir, dataMoved)
	if changed {
		if err := saveState(g.m, st); err != nil {
			g.fail("Settings", err.Error())
			return st
		}
		g.ok("Settings", "updated the paths in "+g.m.statePath())
	}
	return st
}

// underDir returns p with its leading from replaced by to, when p is from
// or inside it.
func underDir(p, from, to string) (string, bool) {
	if from == "" {
		return "", false
	}
	sep := string(filepath.Separator)
	hasPrefix := strings.HasPrefix
	if runtime.GOOS == "windows" {
		hasPrefix = func(s, prefix string) bool {
			return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
		}
	}
	switch {
	case len(p) == len(from) && hasPrefix(p, from):
		return to, true
	case hasPrefix(p, from+sep):
		return to + p[len(from):], true
	}
	return "", false
}

func (g *migrator) moveHooks() {
	for _, a := range agentIntegrations {
		path := a.settingsPath()
		n, err := rewriteLegacyHooks(path, a.agentID, g.m.exe, a.lists)
		switch {
		case err != nil:
			g.fail(a.name, err.Error())
			g.note("Until it's changed, " + a.name + " runs the old agentguard program; once that's gone, most agents let their calls through unchecked.")
		case n > 0:
			g.ok(a.name, "its hook runs "+g.m.exe+" now (in "+path+"; the old file is kept as .vanzik-backup)")
			if a.agentID == codexAgentID {
				g.todo = append(g.todo, "Trust the changed hook in Codex: type /hooks and trust Vanzik's. Codex skips a changed hook until it's trusted, so until then its tool calls are not checked.")
			}
		}
	}
}

// restartService installs the login service again for the migrated setup,
// since the old one was removed in step 1.
func (g *migrator) restartService(st *setupState) {
	if st == nil {
		g.fail("Start at login", "AgentGuard started at login, but its setup.json is missing, so Vanzik can't do the same. Run `vanzik setup` and choose Set up.")
		return
	}
	if err := g.svc.Available(); err != nil {
		g.fail("Start at login", err.Error())
		return
	}
	spec := serviceSpec{Exe: g.m.exe, Args: serverArgs(g.m, st), WorkDir: st.DataDir, LogFile: g.m.logPath()}
	if err := g.svc.Install(spec); err != nil {
		g.fail("Start at login", err.Error())
		return
	}
	if !st.LoginStart {
		st.LoginStart = true
		_ = saveState(g.m, st)
	}
	if !waitForHealth(st.Port, 20*time.Second) {
		g.fail("Server", "Vanzik's "+g.svc.Describe()+" is installed, but the server didn't answer on "+baseURL(st.Port)+"; its log: "+g.svc.LogHint())
		return
	}
	g.ok("Server running", "Vanzik v"+serverHealth(st.Port)+" on "+baseURL(st.Port)+", started at login by its "+g.svc.Describe())
}

// checkLeftovers adds to todo what the migration doesn't change by itself:
// AGENTGUARD_* variables, MCP client configs that start the old gateway,
// and the old programs.
func (g *migrator) checkLeftovers() {
	for _, name := range legacyenv.Set() {
		g.todo = append(g.todo, name+" is set in this environment: rename it to "+legacyenv.NewName(name)+" wherever you set it (a shell startup file, a service, CI). Vanzik doesn't read it.")
	}
	for _, path := range mcpClientConfigs(g.m.goos) {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, tool := range legacyTools[1:] {
			if bytes.Contains(b, []byte(tool)) {
				g.todo = append(g.todo, path+" starts "+tool+": change it to "+strings.Replace(tool, legacyTool, "vanzik", 1)+" (in "+g.m.binDir+") and restart that client.")
				break
			}
		}
	}
	var old []string
	seen := map[string]bool{}
	for _, dir := range legacyBinDirs(g.m) {
		for _, t := range legacyTools {
			p := filepath.Join(dir, g.m.exeName(t))
			if !seen[p] && fileExists(p) {
				seen[p] = true
				old = append(old, p)
			}
		}
	}
	if len(old) > 0 {
		g.todo = append(g.todo, "The AgentGuard 1.x programs are still installed: "+strings.Join(old, ", ")+". Nothing Vanzik set up runs them; delete them once your agent sessions and MCP clients have restarted on Vanzik.")
	}
}

// legacyBinDirs are the folders AgentGuard 1.x installed its programs in:
// the installers' defaults, go install's, and this program's own folder.
func legacyBinDirs(m machine) []string {
	dirs := []string{m.binDir}
	if m.goos == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			dirs = append(dirs, filepath.Join(d, "Programs", "AgentGuard", "bin"))
		}
	} else {
		dirs = append(dirs, homeDir(".local", "bin"), "/usr/local/bin")
	}
	if d := os.Getenv("GOBIN"); d != "" {
		dirs = append(dirs, d)
	} else if d := os.Getenv("GOPATH"); d != "" {
		dirs = append(dirs, filepath.Join(d, "bin"))
	} else {
		dirs = append(dirs, homeDir("go", "bin"))
	}
	return dirs
}

// mcpClientConfigs are the MCP client config files examples/ shows the
// gateway in, for this OS.
func mcpClientConfigs(goos string) []string {
	appData, cfg := os.Getenv("APPDATA"), homeDir(".config")
	switch goos {
	case "darwin":
		appData = homeDir("Library", "Application Support")
		cfg = appData
	case "windows":
		cfg = appData
	}
	paths := []string{
		homeDir(".claude.json"),
		inDir(cursorConfigDir(), "mcp.json"),
		geminiSettingsPath(),
		inDir(codexHome(), "config.toml"),
		homeDir(".continue", "config.json"),
		homeDir(".continue", "config.yaml"),
	}
	if goos == "windows" || goos == "darwin" {
		paths = append(paths, inDir(appData, filepath.Join("Claude", "claude_desktop_config.json")))
	} else {
		paths = append(paths, inDir(cfg, filepath.Join("Claude", "claude_desktop_config.json")))
	}
	paths = append(paths,
		inDir(cfg, filepath.Join("Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")),
		inDir(cfg, filepath.Join(map[bool]string{true: "Zed", false: "zed"}[goos == "windows"], "settings.json")),
	)
	if more, err := filepath.Glob(homeDir(".continue", "mcpServers", "*")); err == nil {
		paths = append(paths, more...)
	}
	var out []string
	for _, p := range paths {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sameDir reports whether a and b are the same folder, links resolved.
func sameDir(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ra, rb)
	}
	return ra == rb
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// ── The database ────────────────────────────────────────────────────────

// errLegacyDBLeftOver is adoptLegacyDB's answer when both databases exist.
var errLegacyDBLeftOver = errors.New("both " + legacyDBFile + " and " + dbFile + " exist")

// adoptLegacyDB renames an AgentGuard 1.x database in dir, with its SQLite
// sidecar files, to the name Vanzik opens. Opening an empty database
// instead would drop the pending approvals, rate-limit state and tenant
// policies the old one holds. It does nothing when dir has no
// agentguard.db, and returns errLegacyDBLeftOver (changing nothing) when a
// vanzik.db is there too.
func adoptLegacyDB(dir string) (bool, error) {
	old, cur := filepath.Join(dir, legacyDBFile), filepath.Join(dir, dbFile)
	if !fileExists(old) {
		return false, nil
	}
	sidecars := []string{"-wal", "-shm", "-journal"}
	for _, suffix := range append([]string{""}, sidecars...) {
		if _, err := os.Lstat(cur + suffix); err == nil {
			return false, fmt.Errorf("%w in %s: Vanzik uses %s; %s was left as it was", errLegacyDBLeftOver, dir, dbFile, legacyDBFile)
		}
	}
	// The sidecars first: stopped halfway, agentguard.db is still there,
	// and the next run moves it after them.
	var moved []string
	for _, suffix := range sidecars {
		if fileExists(old + suffix) {
			if err := os.Rename(old+suffix, cur+suffix); err != nil {
				undoRenames(moved, old, cur)
				return false, err
			}
			moved = append(moved, suffix)
		}
	}
	if err := os.Rename(old, cur); err != nil {
		undoRenames(moved, old, cur)
		return false, err
	}
	return true, nil
}

func undoRenames(suffixes []string, old, cur string) {
	for _, s := range suffixes {
		_ = os.Rename(cur+s, old+s)
	}
}

// ── Root ────────────────────────────────────────────────────────────────

// reportSystemLegacy is the migration run as root: it changes nothing. A
// system-wide AgentGuard runs from a unit or plist its operator wrote,
// which names /etc/agentguard and the agentguard program; moving either
// from under it would stop the server at its next restart. It lists what
// is there instead.
func reportSystemLegacy(w io.Writer) {
	var found []string
	for _, p := range []string{
		"/etc/agentguard", "/var/lib/agentguard",
		"/etc/systemd/system/" + legacySystemdUnit, "/Library/LaunchDaemons/" + legacyLaunchdLabel + ".plist",
	} {
		if _, err := os.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	if len(found) > 0 {
		fmt.Fprintf(w, " Found a system-wide AgentGuard 1.x install: %s.\n", strings.Join(found, ", "))
		fmt.Fprintln(w, " It keeps running as it is. Move it to Vanzik by hand: see "+legacyenv.MigrationURL)
	}
	fmt.Fprintln(w, " An AgentGuard set up per user (agentguard setup) is migrated by that user: run `vanzik migrate --from-agentguard` without sudo.")
}
