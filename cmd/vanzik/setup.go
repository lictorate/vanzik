package main

// setup.go: `vanzik setup`, the interactive way to set Vanzik up on
// this computer, keep it current and remove it. It has no flags: every
// action is a menu item (see internal/tui). Scripts use the installers,
// which already install, update and uninstall.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lictorate.com/vanzik/v2/configs"
	"lictorate.com/vanzik/v2/internal/localconfig"
	"lictorate.com/vanzik/v2/internal/tui"
)

// feedbackURL is where the uninstall asks for a reason. It only prints the
// link: Vanzik sends nothing anywhere.
const feedbackURL = "https://github.com/lictorate/vanzik/issues/new?title=Uninstall+feedback"

// prompter is the terminal setup talks to: tui.Terminal, or a scripted fake
// in tests.
type prompter interface {
	Select(title string, opts []tui.Option, def int) (int, error)
	Printf(format string, a ...any)
	Style() tui.Style
}

func setupUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: vanzik setup

Set up Vanzik on this computer, keep it up to date, or remove it, from
a menu: move with the arrow keys, choose with Enter.

Setting up writes the starter policy, creates a data folder for the audit
log and database, saves an API key only you can read, and starts the
server at login (a systemd user service, a LaunchAgent, or a Task
Scheduler task; no admin rights needed). Run it again to open the
dashboard, update, see the connection settings, or uninstall.

setup needs a terminal. Scripts can use the one-line installers instead,
which install, update and uninstall too:
  `+installDocsURL()+`

Example:
  vanzik setup
`)
}

// installDocsURL is the install section of the setup guide for this
// release: the one-line installers, for scripts.
func installDocsURL() string {
	return "https://github.com/lictorate/vanzik/blob/v" + version + "/docs/SETUP.md#1-install"
}

func runSetupCmd(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	positional, code, ok := parseCommand(fs, setupUsage, args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError("setup", "unexpected argument %q (setup has no options: everything is in its menu)", positional[0])
	}
	m, err := detectMachine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanzik setup: %v\n", err)
		return 1
	}
	switch {
	case m.channel == channelContainer:
		fmt.Fprintln(os.Stderr, "vanzik setup is for a computer, not the container image. Update the image with\n  docker pull ghcr.io/lictorate/vanzik:latest\nand recreate the container; remove it with docker rm.")
		return 1
	case m.goos != "windows" && os.Geteuid() == 0:
		fmt.Fprintln(os.Stderr, "vanzik setup sets Vanzik up for your own user: run it without sudo.\nFor a system-wide server, see https://github.com/lictorate/vanzik/blob/v"+version+"/docs/DEPLOYMENT.md")
		return 1
	}

	g := newMigrator(m, os.Stdout)
	t, err := tui.Open()
	if errors.Is(err, tui.ErrNotTerminal) {
		// Without a terminal setup only prints the status; moving files and
		// rewriting hooks is left to the command made for scripts.
		if g.found() {
			fmt.Println("An AgentGuard 1.x install is here. Move it to Vanzik with: vanzik migrate --from-agentguard")
		}
		s := newSetup(m, plainPrompter{os.Stdout})
		s.printStatus()
		fmt.Println("\nvanzik setup is interactive: run it in a terminal. Scripts can use the\none-line installers instead: " + installDocsURL())
		return exitUsage
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanzik setup: %v\n", err)
		return 1
	}
	// An AgentGuard 1.x install moves over first, so the menu shows (and
	// changes) the migrated setup. Setting up beside a half-moved one would
	// start a second server and connect the agents twice.
	if g.found() {
		if !g.run() {
			t.Close()
			fmt.Println("\nvanzik setup stops here: fix what is marked ✗, then run it again.")
			return 1
		}
		fmt.Println()
	}
	s := newSetup(m, t)
	code = s.run()
	t.Close()
	if s.serveAfter != nil {
		fmt.Println()
		return runServerCmd(s.serveAfter)
	}
	return code
}

// plainPrompter prints status without a terminal; it never shows a menu.
type plainPrompter struct{ w io.Writer }

func (p plainPrompter) Select(string, []tui.Option, int) (int, error) { return tui.Back, tui.ErrQuit }
func (p plainPrompter) Printf(format string, a ...any)                { fmt.Fprintf(p.w, format, a...) }
func (p plainPrompter) Style() tui.Style                              { return tui.Style{} }

type setup struct {
	m      machine
	ui     prompter
	svc    loginService
	state  *setupState
	latest string // newest release, "" when unknown
	// checked is set once the newest release was looked up (or the lookup
	// failed); until then the menu offers "Check for updates".
	checked bool
	// serveAfter, when set, is the server command line to run in this
	// terminal after the menu closes ("Run the server in this terminal").
	serveAfter []string
}

func newSetup(m machine, ui prompter) *setup {
	s := &setup{m: m, ui: ui, svc: newLoginService(m)}
	s.state, _ = loadState(m)
	return s
}

// run is the main menu loop; it returns the exit code.
func (s *setup) run() int {
	cleanOldTools(s.m)
	st := s.ui.Style()
	s.ui.Printf("\n %s · v%s · %s\n", st.Bold("Vanzik setup"), version, s.m.binDir)
	if v := os.Getenv("VANZIK_NO_UPDATE_CHECK"); v == "" || v == "0" {
		s.checkForUpdate()
	}
	for {
		s.ui.Printf("\n")
		s.printStatus()
		s.ui.Printf("\n")
		items := s.menu()
		opts := make([]tui.Option, len(items))
		for i, it := range items {
			opts[i] = it.Option
		}
		i, err := s.ui.Select("What do you want to do?", opts, 0)
		if errors.Is(err, tui.ErrQuit) || i == tui.Back {
			return 0
		}
		if err != nil {
			s.ui.Printf(" %v\n", err)
			return 1
		}
		if done, code := items[i].run(); done {
			return code
		}
	}
}

// menuItem is a menu line and what choosing it does; run returns done=true
// to leave setup with code.
type menuItem struct {
	tui.Option
	run func() (done bool, code int)
}

func back() (bool, int) { return false, 0 }

func (s *setup) menu() []menuItem {
	var items []menuItem
	add := func(label, hint string, run func() (bool, int)) {
		items = append(items, menuItem{Option: tui.Option{Label: label, Hint: hint}, run: run})
	}
	running := s.state != nil && serverHealth(s.state.Port) != ""

	if s.state == nil {
		add("Set up Vanzik", "recommended", s.doSetup)
	} else if running {
		add("Open the dashboard", baseURL(s.state.Port)+"/dashboard", s.openDashboard)
	}
	if u := s.updateTarget(); u != "" {
		add("Update to v"+u, "you have v"+version, s.doUpdate)
	} else if !s.checked && s.m.channel != channelSource {
		add("Check for updates", "", func() (bool, int) { s.checkForUpdate(); return back() })
	}
	if s.state != nil {
		switch {
		case running && s.svc.Installed():
			add("Restart the server", "", s.restartServer)
		case !running && s.svc.Installed():
			add("Start the server", "", s.startServer)
		case !running:
			add("Run the server in this terminal", "Ctrl-C stops it", s.runHere)
		}
		add("Connection details", "URL, API key, SDK and Claude Desktop settings", s.printDetails)
		for _, a := range agentIntegrations {
			connected, _ := a.connected()
			switch {
			case connected:
				add("Disconnect "+a.name, "stop checking its tool calls", func() (bool, int) { return s.disconnectAgent(a) })
			case a.detected():
				add("Connect "+a.name, "check its tool calls against your policy", func() (bool, int) { return s.connectAgent(a) })
			}
		}
		add("Open the policy file", s.state.Policy, s.openPolicy)
		add("Change settings", "start at login, API key", s.doSetup)
		items = append(items, menuItem{Option: tui.Option{Separator: true}})
		add("Uninstall…", "", s.doUninstall)
	} else {
		items = append(items, menuItem{Option: tui.Option{Separator: true}})
		add("More options…", "", s.moreOptions)
	}
	add("Quit", "", func() (bool, int) { return true, 0 })
	return items
}

func (s *setup) moreOptions() (bool, int) {
	i, err := s.ui.Select("More options", []tui.Option{{Label: "Uninstall…"}, {Label: "Back"}}, 1)
	if err != nil {
		return true, 0
	}
	if i == 0 {
		return s.doUninstall()
	}
	return back()
}

// ── Status ──────────────────────────────────────────────────────────────

func (s *setup) printStatus() {
	st := s.ui.Style()
	row := func(label, value string) { s.ui.Printf(" %-8s %s\n", label, value) }
	if s.state == nil {
		row("Server", "not set up yet")
	} else {
		parts := []string{}
		if v := serverHealth(s.state.Port); v != "" {
			parts = append(parts, st.Good("running")+" · "+baseURL(s.state.Port))
		} else {
			parts = append(parts, st.Warn("not running"))
		}
		if s.svc.Installed() {
			parts = append(parts, "starts at login")
		}
		row("Server", strings.Join(parts, " · "))
		row("Policy", s.state.Policy)
		for _, a := range agentIntegrations {
			switch connected, failClosed := a.connected(); {
			case connected && failClosed:
				row(a.short, a.name+" is connected: its tool calls are checked (blocked while the server is down)")
			case connected:
				row(a.short, a.name+" is connected: its tool calls are checked")
			}
		}
	}
	switch {
	case s.updateTarget() != "":
		row("Update", st.Accent("v"+s.updateTarget()+" available")+" (you have v"+version+")")
	case s.m.channel == channelSource:
		row("Update", "built from source: update the checkout and rebuild")
	case s.checked && s.latest != "":
		row("Update", "up to date (v"+version+")")
	}
}

func (s *setup) checkForUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.checked = true
	if v, err := latestRelease(ctx); err == nil {
		s.latest = v
	} else {
		s.ui.Printf(" %s\n", s.ui.Style().Dim("Couldn't check for updates: "+err.Error()))
	}
}

// updateTarget is the version "Update" would install: VANZIK_VERSION
// when set (as with the installers), else a newer release; "" when there is
// nothing to install.
func (s *setup) updateTarget() string {
	if s.m.channel == channelSource || s.m.channel == channelContainer {
		return ""
	}
	if pin := strings.TrimPrefix(os.Getenv("VANZIK_VERSION"), "v"); pin != "" {
		if pin == version {
			return ""
		}
		return pin
	}
	if s.latest != "" && versionIsNewer(s.latest, version) {
		return s.latest
	}
	return ""
}

// ── Output helpers ──────────────────────────────────────────────────────

func (s *setup) ok(label, detail string) {
	s.ui.Printf(" %s %-18s %s\n", s.ui.Style().Good("✓"), label, detail)
}

func (s *setup) fail(label, detail string) {
	s.ui.Printf(" %s %-18s %s\n", s.ui.Style().Warn("✗"), label, detail)
}

func (s *setup) note(text string) {
	s.ui.Printf("   %s\n", s.ui.Style().Dim(text))
}

// ── Set up / change settings ────────────────────────────────────────────

func (s *setup) doSetup() (bool, int) {
	loginStart := false
	svcErr := s.svc.Available()
	if svcErr == nil {
		def := 0
		if s.state != nil && !s.state.LoginStart {
			def = 1
		}
		i, err := s.ui.Select("Start Vanzik when you log in?", []tui.Option{
			{Label: "Yes", Hint: "recommended: it runs in the background (" + s.svc.Describe() + ")"},
			{Label: "No", Hint: "start it yourself when you need it"},
		}, def)
		if err != nil || i == tui.Back {
			return back()
		}
		loginStart = i == 0
	}
	keyDef := 0
	if s.state != nil && !s.state.APIKey {
		keyDef = 1
	}
	i, err := s.ui.Select("Protect the server with an API key?", []tui.Option{
		{Label: "Yes", Hint: "recommended: the dashboard and approvals ask for it"},
		{Label: "No", Hint: "anything on this computer can approve actions"},
	}, keyDef)
	if err != nil || i == tui.Back {
		return back()
	}
	useKey := i == 0
	s.ui.Printf("\n")

	// A new setup seals the audit log; an existing one keeps what it had.
	st := &setupState{Port: 8080, Policy: s.m.policyPath(), DataDir: s.m.dataDir, APIKey: useKey, LoginStart: loginStart, Seal: true}
	if s.state != nil {
		st.Port, st.Policy, st.DataDir, st.Seal = s.state.Port, s.state.Policy, s.state.DataDir, s.state.Seal
	}

	// Policy: keep one that's there, write the starter policy otherwise.
	if fileExists(st.Policy) {
		s.ok("Policy", "kept "+st.Policy)
	} else {
		werr := os.MkdirAll(filepath.Dir(st.Policy), 0o700)
		if werr == nil {
			werr = os.WriteFile(st.Policy, configs.Default, 0o644)
		}
		if werr != nil {
			s.fail("Starter policy", werr.Error())
			return back()
		}
		s.ok("Starter policy", st.Policy)
	}

	if err := os.MkdirAll(st.DataDir, 0o700); err != nil {
		s.fail("Data folder", err.Error())
		return back()
	}
	s.ok("Data folder", st.DataDir+" (audit log and database)")

	if st.Seal {
		if !fileExists(sealKeyPath(st)) {
			if err := writeNewKey(sealKeyPath(st)); err != nil {
				s.fail("Audit seal key", err.Error())
				return back()
			}
		}
		s.ok("Audit seal key", sealKeyPath(st)+" (only you can read it)")
	}

	if useKey {
		if !fileExists(s.m.keyPath()) {
			if err := writeNewKey(s.m.keyPath()); err != nil {
				s.fail("API key", err.Error())
				return back()
			}
		}
		s.ok("API key", s.m.keyPath()+" (only you can read it)")
	}

	// Port: keep ours; otherwise 8080, or the next free one.
	if serverHealth(st.Port) == "" || s.state == nil {
		if p, err := freePort(st.Port); err == nil {
			st.Port = p
		}
	}

	if err := saveState(s.m, st); err != nil {
		s.fail("Settings", err.Error())
		return back()
	}
	s.state = st

	spec := serviceSpec{Exe: s.m.exe, Args: serverArgs(s.m, st), WorkDir: st.DataDir, LogFile: s.m.logPath()}
	switch {
	case loginStart:
		if err := s.svc.Install(spec); err != nil {
			s.fail("Start at login", err.Error())
			return back()
		}
		s.ok("Starts at login", s.svc.Describe())
		if waitForHealth(st.Port, 20*time.Second) {
			s.ok("Server running", baseURL(st.Port))
		} else {
			s.fail("Server", "didn't answer on "+baseURL(st.Port)+"; its log: "+s.svc.LogHint())
			return back()
		}
	case s.svc.Installed():
		if err := s.svc.Remove(); err != nil {
			s.fail("Start at login", err.Error())
			return back()
		}
		s.ok("Won't start at login", "stopped the server and removed the "+s.svc.Describe())
	}
	if svcErr != nil {
		s.note(svcErr.Error() + ". Choose \"Run the server in this terminal\" to start it.")
	}

	if loginStart {
		s.ui.Printf("\n")
		i, err := s.ui.Select("Vanzik is set up", []tui.Option{{Label: "Open the dashboard"}, {Label: "Back to the menu"}}, 0)
		if err == nil && i == 0 {
			return s.openDashboard()
		}
	}
	return back()
}

// writeNewKey saves a random 256-bit key, hex encoded, readable only by
// its owner.
func writeNewKey(path string) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(b)+"\n"), 0o600)
}

// ── Server ──────────────────────────────────────────────────────────────

func (s *setup) startServer() (bool, int) {
	if err := s.svc.Start(); err != nil {
		s.fail("Start", err.Error())
		return back()
	}
	if waitForHealth(s.state.Port, 20*time.Second) {
		s.ok("Server running", baseURL(s.state.Port))
	} else {
		s.fail("Server", "didn't answer; its log: "+s.svc.LogHint())
	}
	return back()
}

func (s *setup) restartServer() (bool, int) {
	if err := s.svc.Restart(); err != nil {
		s.fail("Restart", err.Error())
		return back()
	}
	time.Sleep(500 * time.Millisecond)
	if waitForHealth(s.state.Port, 20*time.Second) {
		s.ok("Server restarted", baseURL(s.state.Port))
	} else {
		s.fail("Server", "didn't answer after the restart; its log: "+s.svc.LogHint())
	}
	return back()
}

func (s *setup) runHere() (bool, int) {
	s.serveAfter = serverArgs(s.m, s.state)[1:] // without the "server" word
	return true, 0
}

func (s *setup) openDashboard() (bool, int) {
	url := baseURL(s.state.Port) + "/dashboard"
	if err := openURL(url); err != nil {
		s.fail("Dashboard", "couldn't open a browser; go to "+url)
	} else {
		s.ok("Dashboard", "opened "+url)
	}
	if s.state.APIKey {
		key, err := os.ReadFile(s.m.keyPath())
		switch {
		case err != nil:
			s.note("Log in with your API key from " + s.m.keyPath())
		case copyToClipboard(strings.TrimSpace(string(key))) == nil:
			s.note("Log in with your API key: it's on your clipboard.")
		default:
			s.note("Log in with your API key: " + strings.TrimSpace(string(key)))
		}
	}
	return back()
}

func (s *setup) openPolicy() (bool, int) {
	if err := editFile(s.state.Policy); err != nil {
		s.fail("Policy", "couldn't open it: "+s.state.Policy)
	} else {
		s.ok("Policy", "opened "+s.state.Policy+" (the server reloads it when you save)")
	}
	return back()
}

// ── Coding agents ───────────────────────────────────────────────────────

// connectClaude is Connect Claude Code.
func (s *setup) connectClaude() (bool, int) {
	return s.connectAgent(agentIntegrations[0])
}

// connectAgent offers to add the agent's rules to the policy, asks what
// happens while the server is down, and writes the hook into the agent's
// settings.
func (s *setup) connectAgent(a agentIntegration) (bool, int) {
	has, err := policyHasAgentRules(s.state.Policy, a.agentID)
	if err != nil {
		s.fail("Policy", err.Error())
		return back()
	}
	if !has {
		i, err := s.ui.Select("Your policy has no rules for "+a.name, []tui.Option{
			{Label: "Add Vanzik's " + a.name + " rules", Hint: "recommended: read and edit your projects; risky commands need approval"},
			{Label: "Connect without them", Hint: "the sandbox rules apply, which block most of its work"},
			{Label: "Cancel"},
		}, 0)
		if err != nil || i == tui.Back || i == 2 {
			return back()
		}
		if i == 0 {
			if err := addAgentRules(s.state.Policy, a.agentID, a.name, a.block); err != nil {
				s.fail("Policy", err.Error())
				s.note("Add the " + a.name + " block by hand: https://github.com/lictorate/vanzik/blob/v" + version + "/docs/CODING_AGENTS.md")
				return back()
			}
			s.ok("Policy", "added the "+a.name+" rules to "+s.state.Policy+" (the old file is kept as .vanzik-backup)")
		}
	}
	def := 0
	if connected, failClosed := a.connected(); connected && failClosed {
		def = 1
	}
	i, err := s.ui.Select("If Vanzik isn't running", []tui.Option{
		{Label: "Let calls through with a warning", Hint: "default: " + a.name + " keeps working, unchecked"},
		{Label: "Block them", Hint: "nothing runs unchecked; " + a.name + " can't use its tools until the server is back"},
	}, def)
	if err != nil || i == tui.Back {
		return back()
	}
	failClosed := i == 1

	path := a.settingsPath()
	if err := a.connect(path, s.m.exe, failClosed); err != nil {
		s.fail(a.name, err.Error())
		return back()
	}
	s.ok(a.name, "connected in "+path+" (the old file is kept as .vanzik-backup)")
	s.note("New " + a.name + " sessions check " + a.checks + ".")
	s.note("A call that needs approval waits up to 5 minutes: approve it at " + baseURL(s.state.Port) + "/dashboard or with 'vanzik approve <id>'.")
	switch running := serverHealth(s.state.Port) != ""; {
	case !running && failClosed:
		s.note("The server isn't running: until it is, " + a.name + "'s calls are blocked.")
	case !running:
		s.note("The server isn't running: until it is, " + a.name + "'s calls go ahead with a warning.")
	case failClosed:
		s.note("If the server stops, " + a.name + "'s calls are blocked until it's back.")
	}
	if a.note != "" {
		s.note(a.note)
	}
	return back()
}

func (s *setup) disconnectAgent(a agentIntegration) (bool, int) {
	path := a.settingsPath()
	if _, err := a.disconnect(); err != nil {
		s.fail(a.name, err.Error())
		return back()
	}
	s.ok(a.name, "disconnected: removed Vanzik's hook from "+path)
	s.note("Your policy keeps its " + a.name + " rules; they do nothing while " + a.name + " isn't connected.")
	return back()
}

// ── Connection details ──────────────────────────────────────────────────

func (s *setup) printDetails() (bool, int) {
	st := s.ui.Style()
	url := baseURL(s.state.Port)
	s.ui.Printf("\n %s\n", st.Bold("Connection details"))
	s.ui.Printf(" %-10s %s\n", "Dashboard", url+"/dashboard")
	s.ui.Printf(" %-10s %s\n", "Server", url)
	if s.state.APIKey {
		s.ui.Printf(" %-10s %s\n", "API key", s.m.keyPath())
		s.note("vanzik approve/status/audit and the MCP gateway read it from there.")
	} else {
		s.ui.Printf(" %-10s %s\n", "API key", "none: the server doesn't ask for one")
	}

	s.ui.Printf("\n %s\n", st.Bold("Python and TypeScript SDKs"))
	if s.m.goos == "windows" {
		s.ui.Printf("   $env:VANZIK_URL = '%s'\n", url)
		if s.state.APIKey {
			s.ui.Printf("   $env:VANZIK_API_KEY = Get-Content '%s'\n", s.m.keyPath())
		}
	} else {
		s.ui.Printf("   export VANZIK_URL=%s\n", url)
		if s.state.APIKey {
			s.ui.Printf("   export VANZIK_API_KEY=\"$(cat '%s')\"\n", s.m.keyPath())
		}
	}

	home, _ := os.UserHomeDir()
	entry := struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}{
		Command: filepath.Join(s.m.binDir, s.m.exeName("vanzik-mcp-gateway")),
		Args: []string{
			"--upstream", "fs:npx -y @modelcontextprotocol/server-filesystem " + home,
			"--guard-url", url,
			"--policy", s.state.Policy,
		},
	}
	b, _ := json.MarshalIndent(entry, "   ", "  ")
	s.ui.Printf("\n %s\n", st.Bold("Claude Desktop")+" — inside \"mcpServers\" in claude_desktop_config.json:")
	s.ui.Printf("   \"vanzik\": %s\n", b)
	s.note("Replace the --upstream line with the MCP servers you use; add more --upstream pairs for more.")
	if s.state.APIKey {
		s.note("No key in the file: the gateway reads it from " + s.m.keyPath() + ".")
	}
	s.note("Cursor, Cline, Continue and Zed: https://github.com/lictorate/vanzik/tree/v" + version + "/examples")

	// Wait here so the details stay on screen until the user is done with
	// them, instead of scrolling up under the status and the menu.
	s.ui.Printf("\n")
	if _, err := s.ui.Select("Connection details", []tui.Option{{Label: "Back to the menu"}}, 0); errors.Is(err, tui.ErrQuit) {
		return true, 0
	}
	return back()
}

// ── Update ──────────────────────────────────────────────────────────────

func (s *setup) doUpdate() (bool, int) {
	target := s.updateTarget()
	switch s.m.channel {
	case channelGoInstall:
		s.note("This copy was installed with go install. Update it with:")
		s.ui.Printf("   go install lictorate.com/vanzik/v2/cmd/...@v%s\n", target)
		return back()
	}
	if !writable(s.m.binDir) {
		s.fail("Update", "can't write to "+s.m.binDir)
		if s.m.goos == "windows" {
			s.note("Run the installer instead: " + updateByInstallPs1)
		} else {
			s.note("Run the installer with sudo: " + strings.Replace(updateByInstallSh, "| sh", "| sudo sh", 1))
		}
		return back()
	}
	s.ui.Printf("\n Downloading Vanzik v%s for %s/%s…\n", target, s.m.goos, s.m.goarch)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	bins, err := downloadRelease(ctx, s.m, target)
	if err != nil {
		s.fail("Download", err.Error())
		return back()
	}
	s.ok("Downloaded", releaseArchive(target, s.m.goos, s.m.goarch)+", checksum verified")
	if err := replaceTools(s.m, bins); err != nil {
		s.fail("Install", err.Error())
		return back()
	}
	s.ok("Installed", "vanzik, vanzik-mcp-gateway and vanzik-llm-proxy in "+s.m.binDir)
	if s.state != nil && s.svc.Installed() {
		if err := s.svc.Restart(); err != nil {
			s.fail("Restart", err.Error())
		} else if waitForHealth(s.state.Port, 20*time.Second) {
			s.ok("Server restarted", "running v"+serverHealth(s.state.Port))
		} else {
			s.fail("Server", "didn't answer after the restart; its log: "+s.svc.LogHint())
		}
	}
	if versionIsNewer(version, target) {
		s.ui.Printf("\n Downgraded Vanzik %s -> %s\n", version, target)
		s.note("That's older than the version you had. Unset VANZIK_VERSION to get the latest.")
	} else {
		s.ui.Printf("\n Updated Vanzik %s -> %s\n", version, target)
	}
	s.note("Run vanzik setup again to use the new version. MCP clients pick up the new gateway when they restart.")
	return true, 0
}

// ── Uninstall ───────────────────────────────────────────────────────────

func (s *setup) doUninstall() (bool, int) {
	type choice int
	const (
		stopOnly choice = iota
		keepData
		everything
	)
	var opts []tui.Option
	var choices []choice
	if s.svc.Installed() {
		opts = append(opts, tui.Option{Label: "Stop the server and don't start it at login", Hint: "Vanzik stays installed"})
		choices = append(choices, stopOnly)
	}
	opts = append(opts,
		tui.Option{Label: "Uninstall, keep my policy and data", Hint: "policy, API key, audit log and database stay"},
		tui.Option{Label: "Uninstall everything", Hint: "also deletes the policy, API key, audit log and database"},
		tui.Option{Label: "Cancel"})
	choices = append(choices, keepData, everything)
	i, err := s.ui.Select("Uninstall Vanzik", opts, 0)
	if err != nil || i == tui.Back || i >= len(choices) {
		return back()
	}
	c := choices[i]
	s.ui.Printf("\n")

	if s.svc.Installed() {
		if err := s.svc.Remove(); err != nil {
			s.fail("Login service", err.Error())
			return back()
		}
		s.ok("Server stopped", "removed the "+s.svc.Describe())
	}
	if c == stopOnly {
		if s.state != nil {
			s.state.LoginStart = false
			_ = saveState(s.m, s.state)
		}
		for _, a := range agentIntegrations {
			switch connected, failClosed := a.connected(); {
			case connected && failClosed:
				s.note(a.name + " stays connected: while the server is stopped, its tool calls are blocked.")
			case connected:
				s.note(a.name + " stays connected: while the server is stopped, its tool calls go ahead with a warning.")
			}
		}
		return back()
	}

	// Before the binaries go: a hook pointing at a deleted program would
	// show an error on every tool call of the agent (or, failing closed,
	// block them all).
	for _, a := range agentIntegrations {
		if removed, err := a.disconnect(); err != nil {
			s.fail(a.name, err.Error())
			return back()
		} else if removed {
			s.ok(a.name, "disconnected (removed Vanzik's hook from "+a.settingsPath()+")")
		}
	}

	if !writable(s.m.binDir) {
		s.fail("Uninstall", "can't write to "+s.m.binDir)
		s.note("Run the installer's uninstall with sudo: " + strings.Replace(updateByInstallSh, "| sh", "| sudo sh -s -- --uninstall", 1))
		return true, 1
	}
	pending, err := removeTools(s.m)
	if err != nil {
		s.fail("Uninstall", err.Error())
		return true, 1
	}
	s.ok("Removed", "vanzik, vanzik-mcp-gateway and vanzik-llm-proxy from "+s.m.binDir)

	var emptyDirs []string
	if s.m.goos == "windows" {
		if os.Getenv("VANZIK_NO_MODIFY_PATH") != "1" {
			if removed, err := removeFromUserPath(s.m.binDir); err != nil {
				s.fail("PATH", err.Error())
			} else if removed {
				s.ok("PATH", "removed "+s.m.binDir+" from your user PATH")
			}
		}
		if def := filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Vanzik", "bin"); strings.EqualFold(s.m.binDir, def) {
			emptyDirs = append(emptyDirs, def, filepath.Dir(def)) // the installer's own folders, once empty
		}
	}

	if c == everything {
		for _, dir := range []string{s.m.configDir, s.m.dataDir} {
			if !safeToDelete(dir) {
				s.fail("Delete", "refusing to delete unexpected folder "+dir)
				continue
			}
			if err := os.RemoveAll(dir); err != nil {
				s.fail("Delete", err.Error())
				continue
			}
			s.ok("Deleted", dir)
		}
		// The link the migration from AgentGuard left in its old config
		// folder's place points nowhere now.
		if old := localconfig.LegacyConfigDir(s.m.goos); old != "" {
			if fi, err := os.Lstat(old); err == nil && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				if _, err := os.Stat(old); err != nil {
					_ = os.Remove(old)
				}
			}
		}
		if parent := filepath.Dir(s.m.dataDir); s.m.goos == "windows" && strings.EqualFold(filepath.Base(parent), "Vanzik") {
			emptyDirs = append(emptyDirs, parent) // %LOCALAPPDATA%\Vanzik, once empty
		}
	} else {
		if s.state != nil {
			s.state.LoginStart = false
			_ = saveState(s.m, s.state)
		}
		s.note("Kept your policy and API key in " + s.m.configDir + ", and the audit log and database in " + s.m.dataDir + ".")
	}
	if len(pending) > 0 || len(emptyDirs) > 0 {
		_ = deleteAfterExit(pending, emptyDirs)
	}
	if s.m.goos != "windows" && s.m.binDir != "/usr/local/bin" && onPath(s.m.binDir) {
		s.note("If you added " + s.m.binDir + " to your PATH in a shell startup file, you can remove that line now.")
	}
	s.ui.Printf("\n Vanzik is uninstalled. If you have 30 seconds, tell us why:\n %s\n", feedbackURL)
	return true, 0
}

// removeTools deletes the three binaries and leftovers of updates. Windows
// can't delete a running .exe (this one, or a gateway an MCP client runs),
// so those are renamed to .old and returned, for deleteAfterExit.
func removeTools(m machine) (pending []string, err error) {
	for _, t := range tools {
		target := filepath.Join(m.binDir, m.exeName(t))
		_ = os.Remove(filepath.Join(m.binDir, "."+t+".new"))
		_ = os.Remove(target + ".old")
		err := os.Remove(target)
		switch {
		case err == nil || errors.Is(err, os.ErrNotExist):
		case m.goos == "windows":
			old := target + ".old"
			if rerr := os.Rename(target, old); rerr != nil {
				return pending, fmt.Errorf("can't remove %s: %w", target, err)
			}
			pending = append(pending, old)
		default:
			return pending, fmt.Errorf("can't remove %s: %w", target, err)
		}
	}
	return pending, nil
}

// safeToDelete guards RemoveAll: only Vanzik's own folders.
func safeToDelete(dir string) bool {
	base := strings.ToLower(filepath.Base(dir))
	parent := strings.ToLower(filepath.Base(filepath.Dir(dir)))
	return base == "vanzik" || (base == "data" && parent == "vanzik")
}

func onPath(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}
