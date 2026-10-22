package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof" // pprof handlers register on http.DefaultServeMux when --debug-pprof is set
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"lictorate.com/vanzik/v2/cmd/internal/buildinfo"
	"lictorate.com/vanzik/v2/internal/clihelp"
	"lictorate.com/vanzik/v2/internal/legacyenv"
	"lictorate.com/vanzik/v2/internal/localconfig"
	"lictorate.com/vanzik/v2/pkg/audit"
	"lictorate.com/vanzik/v2/pkg/migrate"
	_ "lictorate.com/vanzik/v2/pkg/migrate/v040_to_v041" // register the v0.4.0 → v0.4.1 audit schema migration
	"lictorate.com/vanzik/v2/pkg/notify"
	"lictorate.com/vanzik/v2/pkg/persist"
	"lictorate.com/vanzik/v2/pkg/policy"
	"lictorate.com/vanzik/v2/pkg/proxy"
	"lictorate.com/vanzik/v2/pkg/store"
)

var (
	version = "2.0.0"
	commit  = "dev"
)

func main() {
	// Best-effort update check (update_check.go): one line on stderr when a
	// newer release exists. Never for `server`, help, a mistyped command,
	// dev builds or VANZIK_NO_UPDATE_CHECK=1.
	updateDone := startUpdateCheck(version, commit, subcommandOf(os.Args))

	// Up to 800ms for the notice to land before the command's output; a
	// later print is harmless.
	waitForUpdateCheck(updateDone, 800*time.Millisecond)

	os.Exit(run(os.Args[1:]))
}

// run dispatches one command line (without the program name) and returns
// the exit status.
func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return exitUsage
	}
	name, ok := lookupCommand(args[0])
	if !ok {
		return unknownCommand(args[0])
	}
	rest := args[1:]
	switch name {
	case "setup":
		return runSetupCmd(rest)
	case "hook":
		return runHookCmd(rest)
	case "server":
		return runServerCmd(rest)
	case "validate":
		return runValidateCmd(rest)
	case "check":
		// runCheck owns its own flag.FlagSet: usage errors map to exit code
		// 3, not 2.
		return runCheck(rest, os.Stdin, os.Stdout, os.Stderr)
	case "test":
		return runTestCmd(rest)
	case "approve", "deny":
		return runResolveCmd(name, rest)
	case "status":
		return runStatusCmd(rest)
	case "audit":
		return runAuditCmd(rest)
	case "report":
		return runReportCmd(rest)
	case "tenant":
		return runTenant(rest)
	case "migrate":
		return runMigrateCmd(rest)
	case "version":
		if len(rest) > 0 {
			if isHelpFlag(rest[0]) {
				printVersionUsage(os.Stdout)
				return 0
			}
			fmt.Fprintf(os.Stderr, "vanzik version: unexpected argument %q\n", rest[0])
			return exitUsage
		}
		fmt.Printf("vanzik %s (%s)\n", version, buildinfo.Describe(commit))
		return 0
	case "help":
		return runHelp(rest)
	}
	return unknownCommand(args[0])
}

// runHelp implements `vanzik help [command [subcommand]]`: the command
// list, or one command's help (the same text as `<command> -h`).
func runHelp(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return 0
	}
	name, ok := lookupCommand(args[0])
	if !ok {
		return unknownCommand(args[0])
	}
	switch name {
	case "help":
		printHelpUsage(os.Stdout)
		return 0
	case "version":
		printVersionUsage(os.Stdout)
		return 0
	}
	return run(append([]string{name}, append(args[1:], "-h")...))
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "-help" || arg == "--help"
}

func printHelpUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: vanzik help [<command> [<subcommand>]]

Without a command, list every command. With one, show its help: the same
text as 'vanzik <command> -h'.

Examples:
  vanzik help server
  vanzik help tenant put
`)
}

func printVersionUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: vanzik version
       vanzik --version

Print this binary's version and the build it came from, e.g.
"vanzik 1.2.0 (abc1234)".
`)
}

// docsURL is the CLI reference for this release, so the link matches the
// installed binary rather than whatever is on master.
func docsURL() string {
	return "https://github.com/lictorate/vanzik/blob/v" + version + "/docs/CLI.md"
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Vanzik — the firewall for AI agents.

Usage:
  vanzik <command> [flags]
`)
	for _, g := range commandGroups {
		fmt.Fprintf(w, "\n%s:\n", g)
		for _, c := range commands {
			if c.Group == g {
				fmt.Fprintf(w, "  %-10s  %s\n", c.Name, c.Summary)
			}
		}
	}
	fmt.Fprint(w, `
Get started:
  vanzik setup
      Set Vanzik up to run at login, with a policy and an API key
  vanzik server --dashboard
      Or start the server yourself, then open http://localhost:8080/dashboard
  vanzik check --scope shell --command "rm -rf /"
      Try the policy on one action, no server needed

Also installed:
  vanzik-mcp-gateway   Guards the tools of an MCP client (Claude Desktop,
                           Cursor, …)
  vanzik-llm-proxy     Guards tool calls in OpenAI / Anthropic SDK code

Environment:
  VANZIK_API_KEY          API key when --api-key is not set
                              (server, approve, deny, status, audit, report)
  VANZIK_URL              Server URL when --url is not set
                              (approve, deny, status, audit)
  VANZIK_POLICY           Policy file when --policy is not set
                              (server, validate, check, test)
  VANZIK_NO_UPDATE_CHECK  Any value other than "0" turns off the check
                              for newer releases

Run 'vanzik help <command>' (or 'vanzik <command> -h') for its flags.
Flags can go before or after arguments: vanzik approve <id> --url <url>
Docs: `+docsURL()+`
`)
}

// ── server ───────────────────────────────────────────────────────────────

// serverFlags holds the parsed `vanzik server` flags.
type serverFlags struct {
	policy, bind, auditPath, apiKey, apiKeyFile, baseURL, allowedOrigin *string
	port                                                                *int
	dashboard, watch, tlsTerminated                                     *bool
	sessionCostTTL, sessionCostSweep, approvalValidity                  *time.Duration
	auditMaxSizeMB, auditMaxBackups, auditMaxAgeDays                    *int
	auditCompress, auditBuffered, auditRedact                           *bool
	auditQueueSize, auditWorkers                                        *int
	auditOverflowPath                                                   *string
	auditSeal                                                           *bool
	auditSealKeyFile                                                    *string
	auditAnchorInterval                                                 *time.Duration
	debugPprof                                                          *bool
	debugPprofPort                                                      *int
	persist                                                             *bool
	storeDSN, dataDir, auditBackend, nodeID, notifySpool                *string
	tenantPolicyRefresh, reconcileInterval                              *time.Duration
}

// newServerFlags defines the `vanzik server` flags. Names, defaults and
// meanings are frozen for 1.x (docs/COMPATIBILITY.md, frozen surface 4).
func newServerFlags() (*flag.FlagSet, *serverFlags) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	f := &serverFlags{}
	f.policy = fs.String("policy", defaultPolicyPath, "Policy file. When not given, it is looked for as described under \"Policy file\" below.")
	f.port = fs.Int("port", 8080, "Port to listen on")
	f.bind = fs.String("bind", "", "Host or IP to listen on. Empty: every interface when --api-key is set, 127.0.0.1 otherwise. A non-loopback --bind requires --api-key.")
	f.dashboard = fs.Bool("dashboard", false, "Serve the web dashboard at /dashboard (the approval UI)")
	f.watch = fs.Bool("watch", false, "Log a line each time the policy file is reloaded. The server always reloads the policy when the file changes; this flag only adds the log line.")
	f.auditPath = fs.String("audit-log", "audit.jsonl", "Path to audit log file")
	f.apiKey = fs.String("api-key", "", "Bearer token for the control and audit endpoints. Empty: no auth, and the server only listens on 127.0.0.1. Env: VANZIK_API_KEY")
	f.apiKeyFile = fs.String("api-key-file", "", "Read the API key from this file (its first line) instead of the command line, where other users could see it. --api-key wins over it; it wins over VANZIK_API_KEY. The server won't start if the file can't be read or is empty.")
	f.baseURL = fs.String("base-url", "", "External base URL for approval links (default: http://localhost:<port>)")
	f.allowedOrigin = fs.String("allowed-origin", "", "Exact CORS origin to accept (e.g. https://app.example). Empty means permissive-localhost (any http://localhost:* or http://127.0.0.1:*) for backward compat.")
	f.tlsTerminated = fs.Bool("tls-terminated-upstream", false, "Issue session cookies with Secure regardless of r.TLS — set when behind a TLS-terminating reverse proxy that does not forward X-Forwarded-Proto")
	f.sessionCostTTL = fs.Duration("session-cost-ttl", 0, "If > 0, evict session-cost accumulator entries idle longer than this duration (e.g. 24h). Zero disables eviction (entries never expire).")
	f.sessionCostSweep = fs.Duration("session-cost-sweep-interval", 0, "How often to run the session-cost sweeper. Defaults to max(session-cost-ttl/4, 1m).")
	f.approvalValidity = fs.Duration("approval-validity", 5*time.Minute, "How long a resolved approval is honored by the /v1/check approval-id retry, measured from resolution. Past the window the retry re-enters the approval flow under a new id. 0 disables the bound. Default matches the SDKs' wait_for_approval poll window.")
	// Audit log rotation; --audit-max-size-mb=0 disables it. The contract
	// is in pkg/audit/rotation.go.
	f.auditMaxSizeMB = fs.Int("audit-max-size-mb", 100, "Maximum size of the live audit log in MiB before rotation. 0 disables rotation.")
	f.auditMaxBackups = fs.Int("audit-max-backups", 5, "Maximum number of rotated archives to keep. 0 keeps all archives indefinitely.")
	f.auditMaxAgeDays = fs.Int("audit-max-age-days", 30, "Maximum age (in days) of archived audit files. Archives older than this are pruned at rotation time. 0 disables age-based pruning.")
	f.auditCompress = fs.Bool("audit-compress", true, "Gzip rotated archives. Disable to keep them as plain JSONL for grep tooling.")
	// Buffered async audit logger: bounded queue + worker pool + disk-
	// overflow durability so the /v1/check hot path does not wait on the
	// audit mutex. See pkg/audit/buffered.go for the contract.
	f.auditBuffered = fs.Bool("audit-buffered", true, "Wrap the audit logger in a bounded async queue with disk-overflow durability. Disable to write straight to FileLogger.")
	f.auditQueueSize = fs.Int("audit-queue-size", 1024, "Bounded queue size for the buffered async logger. Ignored unless --audit-buffered is set.")
	f.auditWorkers = fs.Int("audit-workers", 4, "Worker goroutines draining the buffered audit queue. Ignored unless --audit-buffered is set.")
	f.auditRedact = fs.Bool("audit-redact", true, "Mask secrets (API keys, tokens, passwords, private keys) in commands, paths, URLs and meta before they reach the audit log, GET /v1/audit, the SSE stream and the pending-approvals list. The policy's notifications.redaction.extra_patterns apply too. Set false to store requests verbatim.")
	f.auditOverflowPath = fs.String("audit-overflow-path", "", "Path to the disk-overflow spill file used when the buffered queue saturates. Defaults to <audit-log>.overflow.jsonl. Ignored unless --audit-buffered is set.")
	// Tamper-evident audit log (pkg/audit/seal.go). Off by default: it
	// changes the file format and adds cost to every write. File backend
	// only: the store keeps a subset of the entry's fields, so there is
	// nothing to chain.
	f.auditSeal = fs.Bool("audit-seal", false, "Seal the audit log into a hash chain so 'vanzik audit verify' can detect edited, removed or reordered entries. File backend only. Not encryption.")
	f.auditSealKeyFile = fs.String("audit-seal-key-file", "", "HMAC-SHA256 key for --audit-seal (the file's content, surrounding whitespace ignored). Without it the chain is plain SHA-256, which anyone who can write the file can recompute. The server won't start if the file is missing, empty or readable by every user.")
	f.auditAnchorInterval = fs.Duration("audit-anchor-interval", 5*time.Minute, "How often to log the head of the sealed chain ('audit anchor segment=... seq=... hash=...') so it can be shipped off this machine. Anchors are also logged at each rotation and at shutdown. 0 disables the periodic anchor. Ignored unless --audit-seal.")
	// Debug pprof, on a second listener bound to 127.0.0.1 only; see
	// startPprofServer for why there is no flag to widen it.
	f.debugPprof = fs.Bool("debug-pprof", false, "Expose Go pprof handlers on a separate localhost-only listener (--debug-pprof-port). Off by default; enable for performance investigations only.")
	f.debugPprofPort = fs.Int("debug-pprof-port", 6060, "Port for the localhost-only pprof listener. Ignored unless --debug-pprof is set.")
	// Durable persistence. Zero-config by default: runtime state
	// (approvals, rate-limit buckets, cost accumulators) is written behind to a
	// SQLite database so it survives restarts. The store is NEVER on the
	// /v1/check hot path — a background syncer flushes snapshots on a ≥1s tick
	// and hydrates the in-memory maps on boot.
	f.persist = fs.Bool("persist", true, "Persist runtime state (approvals, rate-limit buckets, cost accumulators) to a durable store so it survives restarts. Set false for pure in-memory.")
	f.storeDSN = fs.String("store-dsn", "", "Durable store DSN. Empty => zero-config SQLite at <data-dir>/vanzik.db; a sqlite file path is also accepted. A postgres:// or postgresql:// DSN selects the PostgreSQL backend (required for multi-node deployments).")
	f.dataDir = fs.String("data-dir", ".", "Directory for the zero-config SQLite database (vanzik.db). Ignored when --store-dsn is set or --persist=false.")
	f.auditBackend = fs.String("audit-backend", "file", `Audit storage: "file" (JSONL, default) or "store" (the SQLite store — unifies state+audit in one DB with indexed queries). "store" requires --persist.`)
	// Non-local tenant policies are cached in memory and served from that cache
	// on the hot path. Without a periodic rebuild the cache is whatever the
	// process loaded at boot, so `vanzik tenant put` on an EXISTING tenant
	// would never reach a running server. This ticker is that rebuild; the swap
	// is a single pointer assignment under the provider's write lock, off the
	// request path. Ignored unless --persist (the multi-tenant provider only
	// exists in persistence mode).
	f.tenantPolicyRefresh = fs.Duration("tenant-policy-refresh-interval", 30*time.Second, "How often to rebuild the non-local tenant policy cache from the store, so 'vanzik tenant put' reaches a running server without a restart. 0 disables the rebuild (boot-time cache only). Ignored unless --persist.")
	// Multi-node reconciliation. When multiple Vanzik nodes share a
	// durable store, a background reconcile loop converges each node's local
	// rate-limit / session-cost view toward the cluster-wide total (bounded
	// overshoot ~= reconcile-interval x rate x nodes). It is off the /v1/check hot
	// path (Snapshot-diff + chunked write-back). On a single node the "others"
	// sum is always zero, so this is a behavioral no-op regardless of interval.
	f.nodeID = fs.String("node-id", defaultNodeID(), "Stable identifier for THIS node in multi-node reconciliation. Defaults to the OS hostname. Each node MUST have a distinct id; an empty value disables reconciliation.")
	f.reconcileInterval = fs.Duration("reconcile-interval", 2*time.Second, "Cadence of the background multi-node rate-limit/cost reconciliation loop. Takes effect ONLY with a Postgres --store-dsn (multi-node topology); on the zero-config single-node SQLite backend reconciliation never starts regardless of this value. 0 disables it.")
	f.notifySpool = fs.String("notify-spool", "", "Path to a JSONL spool file for notification events that overflow the dispatch queue (retried by a recovery loop instead of dropped). Empty disables (drop-on-full).")
	return fs, f
}

// serverFlagGroups is the layout of `vanzik server -h`. Every server
// flag must appear in exactly one group (TestServerHelp_GroupsEveryFlag).
var serverFlagGroups = []clihelp.Group{
	{Title: "Network", Names: []string{"port", "bind", "dashboard", "base-url"}},
	{Title: "Security", Names: []string{"api-key", "api-key-file", "allowed-origin", "tls-terminated-upstream"}},
	{Title: "Policy", Names: []string{"policy", "watch", "approval-validity", "session-cost-ttl", "session-cost-sweep-interval", "tenant-policy-refresh-interval"}},
	{Title: "Audit log", Names: []string{"audit-log", "audit-redact", "audit-backend", "audit-max-size-mb", "audit-max-backups", "audit-max-age-days", "audit-compress", "audit-buffered", "audit-queue-size", "audit-workers", "audit-overflow-path"}},
	{Title: "Audit sealing", Names: []string{"audit-seal", "audit-seal-key-file", "audit-anchor-interval"}},
	{Title: "Storage", Names: []string{"persist", "store-dsn", "data-dir"}},
	{Title: "Multi-node (PostgreSQL store)", Names: []string{"node-id", "reconcile-interval"}},
	{Title: "Notifications", Names: []string{"notify-spool"}},
	{Title: "Debugging", Names: []string{"debug-pprof", "debug-pprof-port"}},
}

func serverUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `Usage: vanzik server [flags]
       (also runs as 'vanzik serve')

Start the Vanzik server: policy engine, approval queue, audit log and,
with --dashboard, the web dashboard. Agents reach it through the SDKs, the
MCP gateway or the LLM API proxy, which all call its /v1/check endpoint.

`)
	clihelp.WriteGroups(w, fs, serverFlagGroups, serverHelp)
	fmt.Fprint(w, `
Policy file, when --policy is not given: VANZIK_POLICY, then
configs/default.yaml in the current folder, then the starter policy the
installer wrote (~/.config/vanzik/default.yaml, %APPDATA%\vanzik\
on Windows, /etc/vanzik/default.yaml for a root install).

Environment:
  VANZIK_API_KEY   Used when --api-key is not set.
  VANZIK_POLICY    Used when --policy is not set.

Examples:
  vanzik server --dashboard
  vanzik server --policy ./policy.yaml --api-key "$KEY" --port 9090
`)
}

func runServerCmd(args []string) int {
	fs, f := newServerFlags()
	positional, code, ok := parseCommand(fs, func(w io.Writer) { serverUsage(w, fs) }, args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError("server", "unexpected argument %q (the server takes flags only)", positional[0])
	}
	policyPath, _, err := findPolicy(*f.policy, flagWasSet(fs, "policy"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanzik server: %v\n", err)
		return 1
	}
	apiKey, err := serverAPIKey(*f.apiKey, *f.apiKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanzik server: %v\n", err)
		return 1
	}
	sealOpts, code, err := auditSealFromFlags(f)
	if err != nil {
		if code == exitUsage {
			return usageError("server", "%v", err)
		}
		fmt.Fprintf(os.Stderr, "vanzik server: %v\n", err)
		return code
	}
	// Applied by main with os.Exit, after runServe returns: os.Exit skips
	// defers, and every teardown in runServe has already run by then.
	return runServe(policyPath, *f.port, *f.dashboard, *f.watch, *f.auditPath, apiKey, *f.baseURL, *f.allowedOrigin, *f.tlsTerminated, *f.sessionCostTTL, *f.sessionCostSweep, *f.approvalValidity, auditRotationOpts{
		MaxSizeMB:  *f.auditMaxSizeMB,
		MaxBackups: *f.auditMaxBackups,
		MaxAgeDays: *f.auditMaxAgeDays,
		Compress:   *f.auditCompress,
	}, auditBufferedOpts{
		Enabled:      *f.auditBuffered,
		QueueSize:    *f.auditQueueSize,
		Workers:      *f.auditWorkers,
		OverflowPath: *f.auditOverflowPath,
	}, sealOpts, pprofOpts{
		Enabled: *f.debugPprof,
		Port:    *f.debugPprofPort,
	}, persistOpts{
		Enabled:             *f.persist,
		DSN:                 *f.storeDSN,
		DataDir:             *f.dataDir,
		AuditBackend:        *f.auditBackend,
		NodeID:              *f.nodeID,
		ReconcileInterval:   *f.reconcileInterval,
		TenantPolicyRefresh: *f.tenantPolicyRefresh,
	}, *f.notifySpool, *f.auditRedact, *f.bind)
}

// ── validate ─────────────────────────────────────────────────────────────

func runValidateCmd(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	file := fs.String("policy", defaultPolicyPath, "Policy file to validate (you can also give it as an argument)")
	strict := fs.Bool("strict", false, "Exit with status 1 if the policy loads with warnings (merged scope blocks, likely-misspelled scope names, recursive path globs)")
	usage := func(w io.Writer) {
		fmt.Fprint(w, `Usage: vanzik validate [<policy.yaml>] [flags]

Validate a policy YAML file: load it, check rule syntax, and print the
rule/scope counts. Exits non-zero when the policy does not load.

Without a file it validates the one 'vanzik server' would load:
VANZIK_POLICY, then configs/default.yaml, then the installer's
starter policy.

`)
		clihelp.WriteFlags(w, fs, policyHelp)
		fmt.Fprint(w, `
Examples:
  vanzik validate my-policy.yaml
  vanzik validate --strict        # the policy the server would load

Exit status: 0 valid, 1 invalid (or has warnings, with --strict),
2 command-line mistake.
`)
	}
	positional, code, ok := parseCommand(fs, usage, args)
	if !ok {
		return code
	}
	explicit := flagWasSet(fs, "policy")
	switch {
	case len(positional) > 1:
		return usageError("validate", "unexpected argument %q (validate checks one file at a time)", positional[1])
	case len(positional) == 1 && explicit && positional[0] != *file:
		return usageError("validate", "give the policy file as an argument or with --policy, not both")
	case len(positional) == 1:
		*file, explicit = positional[0], true
	}
	path, note, err := findPolicy(*file, explicit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanzik validate: %v\n", err)
		return 1
	}
	if note != "" {
		fmt.Fprintf(os.Stderr, "Using policy file %s (%s).\n", path, note)
	}
	return runValidate(path, *strict)
}

// ── approve / deny ───────────────────────────────────────────────────────

func runResolveCmd(action string, args []string) int {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	serverFlag := addServerURLFlags(fs)
	key := fs.String("api-key", "", "Bearer token. Env: VANZIK_API_KEY, then the key vanzik setup saved")
	verb := map[string]string{"approve": "Approve", "deny": "Deny"}[action]
	usage := func(w io.Writer) {
		fmt.Fprintf(w, `Usage: vanzik %s <approval-id> [flags]

%s a pending action on a running Vanzik server. Approval IDs appear
in 'vanzik status', the dashboard and approval notifications.

`, action, verb)
		clihelp.WriteFlags(w, fs, urlAlias)
		fmt.Fprintf(w, `
Examples:
  vanzik %[1]s ap_7f3a
  vanzik %[1]s ap_7f3a --url http://guard.internal:8080 --api-key "$KEY"

Exit status: 0 %[2]s, 1 the server refused or couldn't be reached,
2 command-line mistake.
`, action, map[string]string{"approve": "approved", "deny": "denied"}[action])
	}
	positional, code, ok := parseCommand(fs, usage, args)
	if !ok {
		return code
	}
	switch {
	case len(positional) == 0:
		return usageError(action, "missing the approval ID (find it with 'vanzik status' or in the dashboard)")
	case len(positional) > 1:
		return usageError(action, "unexpected argument %q (%s takes one approval ID)", positional[1], action)
	}
	base, err := serverURL(fs, *serverFlag)
	if err != nil {
		return usageError(action, "%v", err)
	}
	return runResolve(os.Stdout, os.Stderr, base, positional[0], action, resolveClientAPIKey(*key))
}

// ── status ───────────────────────────────────────────────────────────────

func runStatusCmd(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	serverFlag := addServerURLFlags(fs)
	key := fs.String("api-key", "", "Bearer token. Env: VANZIK_API_KEY, then the key vanzik setup saved")
	usage := func(w io.Writer) {
		fmt.Fprint(w, `Usage: vanzik status [flags]

Show the health of a running Vanzik server and its pending-approval
queue. The queue is listed only when the server runs with --dashboard.

`)
		clihelp.WriteFlags(w, fs, urlAlias)
		fmt.Fprint(w, `
Examples:
  vanzik status
  vanzik status --url http://guard.internal:8080 --api-key "$KEY"

Exit status: 0 the server is up, 1 it can't be reached (so status works as
a health check), 2 command-line mistake.
`)
	}
	positional, code, ok := parseCommand(fs, usage, args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError("status", "unexpected argument %q", positional[0])
	}
	base, err := serverURL(fs, *serverFlag)
	if err != nil {
		return usageError("status", "%v", err)
	}
	return statusReport(os.Stdout, os.Stderr, base, resolveClientAPIKey(*key))
}

// ── audit ────────────────────────────────────────────────────────────────

func runAuditCmd(args []string) int {
	// `audit verify` works on files, not on a server, and has flags of its
	// own; it is told apart before the query flags are parsed (which would
	// reject "verify" as an unexpected argument).
	if len(args) > 0 && args[0] == "verify" {
		return runAuditVerifyCmd(args[1:])
	}
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	serverFlag := addServerURLFlags(fs)
	var q auditQuery
	fs.StringVar(&q.Agent, "agent", "", "Filter by agent ID")
	fs.StringVar(&q.Decision, "decision", "", "Filter by decision (ALLOW, DENY, REQUIRE_APPROVAL)")
	fs.StringVar(&q.Scope, "scope", "", "Filter by scope (shell, filesystem, network, browser, data, cost, mcp_tool)")
	fs.StringVar(&q.Transport, "transport", "", "Filter by integration path (sdk|mcp_gateway|llm_api_proxy, or a coding-agent hook: claude_code|cursor|gemini_cli|codex_cli)")
	fs.StringVar(&q.Session, "session", "", "Filter by session ID")
	fs.StringVar(&q.ParentSession, "parent-session", "", "Only the calls of sessions started by this session")
	sinceFlag := fs.String("since", "", "Entries at or after this time: a duration back from now (2h, 30m) or an RFC 3339 time")
	untilFlag := fs.String("until", "", "Entries before this time, same forms as --since")
	fs.IntVar(&q.Limit, "limit", 50, "Max entries to return")
	fs.StringVar(&q.Order, "order", "desc", "Entry order: desc (newest first) or asc (oldest first)")
	key := fs.String("api-key", "", "Bearer token. Env: VANZIK_API_KEY, then the key vanzik setup saved")
	usage := func(w io.Writer) {
		fmt.Fprint(w, `Usage: vanzik audit [flags]
       vanzik audit verify [flags]

Query the audit log of a running Vanzik server (newest first),
optionally filtered by agent, session, decision, scope, transport or time.

'vanzik audit verify' checks a sealed audit log (server --audit-seal)
for tampering, offline; see 'vanzik audit verify -h'.

`)
		clihelp.WriteGroups(w, fs, auditFlagGroups, urlAlias)
		fmt.Fprint(w, `
Examples:
  vanzik audit --decision DENY --limit 20
  vanzik audit --agent my-bot --scope shell --order asc
  vanzik audit --session sess-42 --since 2h --order asc
  vanzik audit --parent-session sess-42 --since 2026-10-14T09:00:00Z
  vanzik audit verify --audit-log audit.jsonl --key-file seal.key

Exit status: 0 success (also when nothing matches), 1 the server refused or
couldn't be reached, 2 command-line mistake.
`)
	}
	positional, code, ok := parseCommand(fs, usage, args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError("audit", "unexpected argument %q (filters are flags, e.g. --agent %s)", positional[0], positional[0])
	}
	now := time.Now()
	var err error
	if q.Since, err = parseAuditTime(*sinceFlag, now); err != nil {
		return usageError("audit", "--since: %v", err)
	}
	if q.Until, err = parseAuditTime(*untilFlag, now); err != nil {
		return usageError("audit", "--until: %v", err)
	}
	base, err := serverURL(fs, *serverFlag)
	if err != nil {
		return usageError("audit", "%v", err)
	}
	return runAuditQuery(os.Stdout, os.Stderr, base, q, resolveClientAPIKey(*key))
}

// auditFlagGroups lays out `vanzik audit -h`.
var auditFlagGroups = []clihelp.Group{
	{Title: "Filters", Names: []string{"agent", "session", "parent-session", "decision", "scope", "transport"}},
	{Title: "Time window", Names: []string{"since", "until"}},
	{Title: "Output", Names: []string{"limit", "order"}},
	{Title: "Server", Names: []string{"url", "api-key"}},
}

// parseAuditTime reads --since / --until: a duration back from now ("2h",
// "90m") or an RFC 3339 time. It returns the time in RFC 3339 (UTC) for the
// server's since/until parameters, or "" when raw is empty.
func parseAuditTime(raw string, now time.Time) (string, error) {
	if raw == "" {
		return "", nil
	}
	if d, err := time.ParseDuration(raw); err == nil {
		if d < 0 {
			return "", fmt.Errorf("%q is negative; give how long ago, e.g. 2h", raw)
		}
		return now.Add(-d).UTC().Format(time.RFC3339Nano), nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return "", fmt.Errorf("%q is neither a duration (2h, 30m) nor an RFC 3339 time (2026-10-14T09:00:00Z)", raw)
	}
	return t.UTC().Format(time.RFC3339Nano), nil
}

// ── migrate ──────────────────────────────────────────────────────────────

func runMigrateCmd(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	var o migrateCmdOpts
	fs.StringVar(&o.AuditPath, "audit-log", "audit.jsonl", "The audit log to migrate (the server's --audit-log)")
	fs.StringVar(&o.CheckpointPath, "checkpoint", "", "The replay checkpoint the server reads at startup (default: <audit-log>"+audit.CheckpointSuffix+", the file the server writes)")
	fs.StringVar(&o.BackupDir, "backup-dir", "", "Where to keep a copy of each file before changing it, for rollback (default: the audit log's folder)")
	fs.BoolVar(&o.DryRun, "dry-run", false, "Show what would change without writing anything")
	fs.BoolVar(&o.List, "list", false, "List the known migrations and exit")
	fs.StringVar(&o.ID, "id", "", "Run only this migration, even if it finds nothing to migrate")
	fs.BoolVar(&o.ResetCheckpoint, "reset-checkpoint", false, "Delete the replay checkpoint first, so the next server start replays the whole audit log")
	fromAgentGuard := fs.Bool("from-agentguard", false, "Move this user's AgentGuard 1.x install to Vanzik: its login service, config and data folders, database and coding-agent hooks. Takes no other flag.")
	usage := func(w io.Writer) {
		fmt.Fprint(w, `Usage: vanzik migrate [flags]
       vanzik migrate --from-agentguard

Upgrade the audit log's on-disk format to the one this version writes.

You rarely need this: the server applies these migrations itself when it
starts. Use migrate to run them ahead of an upgrade, to preview them
(--dry-run), or to reset a damaged replay checkpoint (--reset-checkpoint).

--from-agentguard moves an install from before the rename to Vanzik (2.0):
it stops and removes AgentGuard's login service, moves ~/.config/agentguard
and the data folder to Vanzik's (files unchanged, agentguard.db renamed to
vanzik.db), points the Claude Code, Cursor, Gemini CLI and Codex hooks at
vanzik (keeping each old file as .vanzik-backup), and starts the server at
login again. The installers and vanzik setup run it for you. Run as root, it
only lists a system-wide install to move by hand.

`)
		clihelp.WriteFlags(w, fs, clihelp.Options{})
		fmt.Fprint(w, `
Examples:
  vanzik migrate --list
  vanzik migrate --audit-log /var/lib/vanzik/audit.jsonl --dry-run
  vanzik migrate --audit-log /var/lib/vanzik/audit.jsonl
  vanzik migrate --from-agentguard
`)
	}
	positional, code, ok := parseCommand(fs, usage, args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError("migrate", "unexpected argument %q (use --audit-log <file> to name the audit log)", positional[0])
	}
	if *fromAgentGuard {
		var others []string
		fs.Visit(func(f *flag.Flag) {
			if f.Name != "from-agentguard" {
				others = append(others, "--"+f.Name)
			}
		})
		if len(others) > 0 {
			return usageError("migrate", "--from-agentguard takes no other flag (got %s)", strings.Join(others, ", "))
		}
		return runMigrateFromAgentGuard(os.Stdout)
	}
	return executeMigrate(o, os.Stdout, os.Stderr)
}

// runMigrateFromAgentGuard is `vanzik migrate --from-agentguard`; it
// returns 1 when a step failed.
func runMigrateFromAgentGuard(w io.Writer) int {
	if goos != "windows" && os.Geteuid() == 0 {
		reportSystemLegacy(w)
		return 0
	}
	m, err := detectMachine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanzik migrate: %v\n", err)
		return 1
	}
	if !newMigrator(m, w).run() {
		return 1
	}
	return 0
}

// auditRotationOpts mirrors the --audit-* rotation flags; runServe turns
// it into an audit.RotationConfig.
type auditRotationOpts struct {
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	Compress   bool
}

// auditBufferedOpts mirrors the --audit-buffered* CLI flags; runServe
// turns it into an audit.BufferedAsyncOpts.
//
// Enabled=false makes writes go straight to the FileLogger and /v1/check
// waits on the audit mutex. Enabled=true (the default) decouples the
// request path from audit I/O via a bounded queue + worker pool + disk-
// overflow durability.
type auditBufferedOpts struct {
	Enabled      bool
	QueueSize    int
	Workers      int
	OverflowPath string
}

// auditSealOpts mirrors the --audit-seal* flags, with the key already read.
// Key is empty for a plain SHA-256 chain. NodeID is the server's --node-id,
// recorded in each audit file header.
type auditSealOpts struct {
	Enabled        bool
	Key            []byte
	NodeID         string
	AnchorInterval time.Duration
}

// auditSealFromFlags checks the --audit-seal flags and reads the key. A
// combination that can't work is a usage mistake (exitUsage); a key file
// that can't be used is a startup error (1), like --api-key-file.
func auditSealFromFlags(f *serverFlags) (auditSealOpts, int, error) {
	o := auditSealOpts{Enabled: *f.auditSeal, NodeID: *f.nodeID, AnchorInterval: *f.auditAnchorInterval}
	switch {
	case !o.Enabled && *f.auditSealKeyFile != "":
		return o, exitUsage, errors.New("--audit-seal-key-file needs --audit-seal")
	case !o.Enabled:
		return o, 0, nil
	case *f.auditBackend == "store":
		return o, exitUsage, errors.New("--audit-seal works with the file audit backend only; drop --audit-backend=store or --audit-seal")
	case o.AnchorInterval < 0:
		return o, exitUsage, errors.New("--audit-anchor-interval can't be negative (0 turns the periodic anchor off)")
	}
	if *f.auditSealKeyFile != "" {
		key, err := audit.LoadSealKey(*f.auditSealKeyFile, true)
		if err != nil {
			return o, 1, err
		}
		o.Key = key
	}
	return o, 0, nil
}

// pprofOpts mirrors the --debug-pprof* CLI flags. The listener starts only
// when Enabled is true, and always on 127.0.0.1 (see startPprofServer).
type pprofOpts struct {
	Enabled bool
	Port    int
}

// persistOpts mirrors the persistence CLI flags.
type persistOpts struct {
	Enabled      bool
	DSN          string
	DataDir      string
	AuditBackend string // "file" | "store"

	// Multi-node reconciliation. NodeID identifies this node; empty or a
	// zero ReconcileInterval disables reconciliation (single-node behavior).
	NodeID            string
	ReconcileInterval time.Duration

	// TenantPolicyRefresh is how often the non-local tenant policy cache is
	// rebuilt from the store. Zero keeps the boot-time cache forever, which
	// means a tenant policy updated in the store never reaches this process.
	TenantPolicyRefresh time.Duration
}

// defaultNodeID returns the OS hostname as the default multi-node node id,
// falling back to "node" when the hostname is unavailable. Operators override it
// with --node-id; each node in a cluster MUST have a distinct value.
func defaultNodeID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "node"
}

// persistentStore is the internal backend contract openStore returns: the
// durable store.Store PLUS the tenant-policy methods its consumers depend on —
// policy.PolicySource (for the MultiTenantProvider) and PutPolicy/DeletePolicy
// (for the `tenant` CLI). Both *store.SQLiteStore and *store.PostgresStore
// satisfy it. Unexported, so not part of the frozen v1.0 surface.
type persistentStore interface {
	store.Store
	policy.PolicySource
	PutPolicy(ctx context.Context, tenantID string, policyYAML []byte) error
	DeletePolicy(ctx context.Context, tenantID string) (bool, error)
}

// isPostgresDSN reports whether dsn selects the multi-node PostgresStore (a
// postgres:// / postgresql:// URL). Used both to pick the backend in openStore
// and to gate multi-node reconciliation, which is a Postgres-only feature: the
// zero-config single-node SQLite default does no reconciliation I/O.
func isPostgresDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// dbFile is the zero-config SQLite database's name in --data-dir.
const dbFile = "vanzik.db"

// openStore opens the durable store described by cfg: a postgres:// or
// postgresql:// DSN selects the multi-node PostgresStore, an empty DSN the
// zero-config SQLite database <data-dir>/vanzik.db, and any other DSN is a
// SQLite path. It also returns the resolved DSN/path for logging.
func openStore(cfg persistOpts) (persistentStore, string, error) {
	if isPostgresDSN(cfg.DSN) {
		s, err := store.NewPostgresStore(cfg.DSN)
		if err != nil {
			return nil, "", err
		}
		return s, cfg.DSN, nil
	}
	path := cfg.DSN
	if path == "" {
		dir := cfg.DataDir
		if dir == "" {
			dir = "."
		}
		path = filepath.Join(dir, dbFile)
		// A data folder an AgentGuard 1.x server used holds agentguard.db.
		// Starting on an empty vanzik.db beside it would drop its approvals,
		// rate-limit state and tenant policies, so it is renamed first; if
		// that fails the server doesn't start.
		switch adopted, err := adoptLegacyDB(dir); {
		case errors.Is(err, errLegacyDBLeftOver):
			log.Printf("WARNING: %v", err)
		case err != nil:
			return nil, "", fmt.Errorf("renaming the AgentGuard 1.x database in %s to %s: %w", dir, dbFile, err)
		case adopted:
			log.Printf("Renamed the AgentGuard 1.x database %s to %s", filepath.Join(dir, legacyDBFile), path)
		}
	}
	s, err := store.NewSQLiteStore(path)
	if err != nil {
		return nil, "", err
	}
	return s, path, nil
}

// runServe returns the process exit code: 0 on a clean signal-driven shutdown,
// 1 when the listener failed. The caller applies it with os.Exit AFTER this
// function returns, so every deferred teardown here (persist flush, audit
// drain, store close) has already run — os.Exit skips defers.
func runServe(policyFile string, port int, dashboardEnabled bool, watch bool, auditPath string, apiKey string, baseURL string, allowedOrigin string, tlsTerminatedUpstream bool, sessionCostTTL time.Duration, sessionCostSweep time.Duration, approvalValidity time.Duration, rotOpts auditRotationOpts, bufOpts auditBufferedOpts, sealOpts auditSealOpts, pprofCfg pprofOpts, persistCfg persistOpts, notifySpoolPath string, auditRedact bool, bindHost string) int {
	if err := validateBind(bindHost, apiKey); err != nil {
		log.Printf("ERROR: %v", err)
		return 2
	}
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}

	// LOUD security warning: with no API key configured (flag empty AND
	// VANZIK_API_KEY empty), the control- and audit-plane endpoints are
	// unauthenticated (requireAuthOrSession in pkg/proxy/auth.go allows on an
	// empty key). The server still binds localhost-only in this mode
	// (proxy.Server.Start), but a reverse proxy or --tls-terminated-upstream
	// can expose them without an auth gate. Visibility only: the server still
	// starts, and no endpoint is gated differently.
	if apiKey == "" {
		fmt.Fprint(os.Stderr, "\n"+
			"================================ SECURITY WARNING ================================\n"+
			"  No API key is set (--api-key empty and VANZIK_API_KEY empty).\n"+
			"  The control and audit endpoints are UNAUTHENTICATED:\n"+
			"      POST /v1/approve   POST /v1/deny   GET /v1/status\n"+
			"      GET  /v1/audit     POST /v1/audit  GET /v1/audit/head\n"+
			"      /api/* (dashboard, when --dashboard)\n"+
			"  Anyone who can reach this server can approve or deny pending actions and\n"+
			"  read or write the audit trail. The server binds to 127.0.0.1 only in this\n"+
			"  mode; if you place it behind a reverse proxy or TLS terminator, set\n"+
			"  --api-key (or VANZIK_API_KEY) FIRST.\n"+
			"=================================================================================\n\n")
	}

	// Warn the operator when session-cost TTL is disabled. The engine
	// accumulator grows one entry per distinct session_id forever when
	// the sweeper is off, and operators who never set --session-cost-ttl
	// usually do not realise it.
	if sessionCostTTL <= 0 {
		log.Println("WARNING: --session-cost-ttl is 0; session-cost accumulator will grow unbounded. Set e.g. --session-cost-ttl 24h to bound memory.")
	}

	// Optional pprof debug listener, loopback only (see startPprofServer).
	pprofSrv := startPprofServer(pprofCfg)
	if pprofSrv != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = pprofSrv.Shutdown(ctx)
		}()
	}
	provider, err := policy.NewFilePolicyProvider(policyFile)
	if err != nil {
		log.Fatalf("Failed to load policy %s: %v", policyFile, err)
	}
	defer provider.Close()
	pol, err := provider.Get(policy.LocalTenantID)
	if err != nil {
		// NewFilePolicyProvider already validated that the local policy
		// loaded; this is a defensive read for the rule-count log line.
		log.Fatalf("Failed to read policy from provider: %v", err)
	}
	log.Printf("Loaded policy: %s from %s (%d rules across %d scopes)", pol.Name, policyFile, pol.RuleCount(), pol.ScopeCount())

	// Audit redaction: mask secrets in requests before they reach the
	// audit trail, the SSE stream and the pending-approvals list. It runs in
	// the audit workers and the SSE writers, not on the /v1/check goroutine
	// (except with --audit-buffered=false, where the write itself is
	// synchronous). The approval store keeps the original request: replay
	// matching compares it field by field.
	var redactor *notify.Redactor
	var auditTransform audit.EntryTransform
	if auditRedact {
		r, rerr := notify.DefaultRedactor().WithExtraPatterns(pol.Notifications.Redaction.ExtraPatterns)
		if rerr != nil {
			log.Printf("WARNING: audit redaction: ignoring notifications.redaction.extra_patterns (%v); built-in patterns only", rerr)
		}
		redactor = r
		auditTransform = func(e audit.Entry) audit.Entry {
			e.Request = redactor.RedactRequest(e.Request)
			e.Result.Reason = redactor.RedactString(e.Result.Reason)
			return e
		}
	} else {
		log.Printf("WARNING: --audit-redact=false: the audit trail, SSE stream and pending list show requests verbatim, including any secrets they contain.")
	}

	// Open the durable store. Zero-config by default: a SQLite database
	// at <data-dir>/vanzik.db. Deferred Close is registered HERE (early) so
	// — via Go's LIFO defer order — the store is the LAST thing torn down, after
	// the syncer's final flush and the buffered audit logger's drain (both
	// registered later) have written through it.
	var st persistentStore
	var storePath string
	storeAudit := persistCfg.Enabled && persistCfg.AuditBackend == "store"
	if persistCfg.Enabled {
		st, storePath, err = openStore(persistCfg)
		if err != nil {
			log.Fatalf("Failed to open store: %v", err)
		}
		defer func() { _ = st.Close() }()
	} else if persistCfg.AuditBackend == "store" {
		log.Fatalf("--audit-backend=store requires --persist (the store is disabled)")
	}

	// Audit pipeline: the "file" backend is the JSONL FileLogger, "store" the
	// store's indexed audit_entries table. Either way the BufferedAsyncLogger
	// keeps the audit write off the /v1/check hot path. buildAuditPipeline
	// (audit_setup.go) has the construction and forced-buffering rules.
	pipeline, err := buildAuditPipeline(auditPath, storeAudit, st, rotOpts, bufOpts, sealOpts, auditTransform)
	if err != nil {
		log.Fatalf("Failed to initialize audit pipeline: %v", err)
	}
	// Registered after the store's deferred Close, so by LIFO the pipeline
	// drains and closes BEFORE the store goes away. The internal cleanup
	// order (buffer drain, then base logger) is explicit in
	// auditPipeline.Close.
	defer pipeline.Close()
	if storeAudit {
		log.Printf("Audit backend: store (%s)", storePath)
	}
	auditLogger := pipeline.Logger

	// In persistence mode, wrap the file provider (which serves the local
	// tenant) with a MultiTenantProvider that serves OTHER tenants' policies
	// from the store (registered via `vanzik tenant put`). Non-local
	// policies are parsed once and cached in memory, so per-tenant evaluation
	// never hits the DB on the /v1/check hot path. The file provider's own
	// Close (deferred above) still owns the watcher lifecycle.
	var engineProvider policy.PolicyProvider = provider
	if persistCfg.Enabled {
		mtp, mtErr := policy.NewMultiTenantProvider(provider, st)
		if mtErr != nil {
			log.Fatalf("Failed to initialize multi-tenant policy provider: %v", mtErr)
		}
		// Non-local tenants have no Watch channel, so only this rebuild brings
		// in a `vanzik tenant put` on an existing tenant. mtp.Close() also stops
		// the ticker; the explicit stop keeps the lifetime obvious.
		if persistCfg.TenantPolicyRefresh > 0 {
			stopRefresh := mtp.StartAutoRefresh(persistCfg.TenantPolicyRefresh)
			defer stopRefresh()
			log.Printf("Tenant policy refresh: every %s", persistCfg.TenantPolicyRefresh)
		} else {
			log.Printf("WARNING: --tenant-policy-refresh-interval is 0; tenant policy updates will NOT reach this process until restart")
		}
		engineProvider = mtp
	}

	// Initialize policy engine. The engine subscribes to the provider's
	// Watch stream so hot-reloads land automatically — no second watcher.
	engine, err := policy.NewEngine(engineProvider)
	if err != nil {
		log.Fatalf("Failed to initialize policy engine: %v", err)
	}
	defer engine.Close()

	// Initialize notifier from policy config. The dispatcher owns background
	// worker goroutines and MUST be Close()'d on shutdown to stop them.
	// --notify-spool adds queue-overflow durability (events spill to a
	// JSONL file and are retried instead of dropped).
	notifier := notify.NewDispatcherWithOptions(pol.Notifications, notify.DispatcherOptions{
		Workers:   notify.DefaultWorkers,
		QueueSize: notify.DefaultQueueSize,
		SpoolPath: notifySpoolPath,
	})
	defer notifier.Close()

	// Log every successful provider update (`Policy reloaded: ...`). The
	// engine's own Watch subscription swaps the policy, and the file watcher
	// is always on inside FilePolicyProvider; --watch, kept for
	// compatibility, only gates this log line.
	if watch {
		stop, err := provider.Watch(policy.LocalTenantID, func(updated *policy.Policy) {
			log.Printf("Policy reloaded: %s (%d rules)", updated.Name, updated.RuleCount())
		})
		if err != nil {
			log.Fatalf("Failed to subscribe to policy reloads: %v", err)
		}
		defer stop()
	}

	// Policy-driven tunables (session TTL, request body cap, audit query
	// bounds) go through Policy accessors, which apply the documented
	// defaults when the YAML key is absent.
	srv := proxy.NewServer(proxy.Config{
		Port:                     port,
		Engine:                   engine,
		Logger:                   auditLogger,
		DashboardEnabled:         dashboardEnabled,
		Notifier:                 notifier,
		Redactor:                 redactor,
		APIKey:                   apiKey,
		BindHost:                 bindHost,
		BaseURL:                  baseURL,
		AllowedOrigin:            allowedOrigin,
		Version:                  version,
		TLSTerminatedUpstream:    tlsTerminatedUpstream,
		SessionCostTTL:           sessionCostTTL,
		SessionCostSweepInterval: sessionCostSweep,
		ApprovalValidity:         approvalValidity,
		SessionTTL:               pol.SessionTTL(),
		MaxRequestBodyBytes:      pol.MaxRequestBodyBytes(),
		AuditDefaultLimit:        pol.AuditDefaultLimit(),
		AuditMaxLimit:            pol.AuditMaxLimit(),
	})

	// Wire the write-behind persistence syncer. It hydrates the
	// in-memory state from the store on boot, then flushes snapshots on a ≥1s
	// background tick. It NEVER runs on the request path. The deferred Close
	// performs a final flush; registered AFTER store.Close (defer LIFO) so the
	// final flush writes through a still-open store.
	if persistCfg.Enabled {
		// Multi-node reconciliation is POSTGRES-ONLY. The zero-config
		// single-node SQLite backend must do no reconciliation I/O, so the
		// interval is forced to 0 for SQLite: the syncer's `ReconcileInterval>0`
		// gate keeps the reconcile ticker off (no consumption-table writes, no
		// GC). Tests arm reconcile on SQLite by setting Config.ReconcileInterval
		// directly; only this production wiring is gated.
		reconcileInterval := persistCfg.ReconcileInterval
		if !isPostgresDSN(persistCfg.DSN) {
			reconcileInterval = 0
		}
		syncer := persist.New(persist.Config{
			Store:       st,
			Engine:      engine,
			Limiter:     srv.Limiter(),
			Approvals:   srv.ApprovalQueue(),
			CostTTL:     sessionCostTTL, // matches in-memory sweeper (0 = keep)
			ApprovalTTL: 24 * time.Hour, // resolved approvals retained 24h
			BucketTTL:   time.Hour,      // fully-refilled buckets reaped after 1h
			// Multi-node reconciliation. Armed only when the interval is >0
			// (Postgres backend) AND the store supports it; SQLite => 0 => disabled.
			NodeID:            persistCfg.NodeID,
			ReconcileInterval: reconcileInterval,
		})
		hctx, hcancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := syncer.Hydrate(hctx); err != nil {
			log.Printf("WARNING: state hydration failed (%v); starting with empty in-memory state", err)
		}
		hcancel()
		syncer.Start()
		defer syncer.Close()
		log.Printf("Persistence: enabled (store=%s, audit-backend=%s)", storePath, persistCfg.AuditBackend)
		if reconcileInterval > 0 && persistCfg.NodeID != "" {
			log.Printf("Multi-node reconciliation: enabled (node-id=%s interval=%s, Postgres backend)", persistCfg.NodeID, reconcileInterval)
		}
	} else {
		log.Printf("Persistence: disabled (--persist=false); runtime state is in-memory only")
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Buffered so the serve goroutine never blocks handing off its error.
	serveErr := make(chan error, 1)

	go func() {
		log.Printf("Vanzik v%s listening on :%d", version, port)
		if dashboardEnabled {
			log.Printf("Dashboard: http://localhost:%d/dashboard", port)
		}
		log.Printf("Health:    http://localhost:%d/health", port)
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Hand the error to main rather than log.Fatalf here:
			// Fatalf calls os.Exit, which skips every defer in main — including
			// `defer syncer.Close()` (the final persist flush) and the buffered
			// audit drain. Losing those on a listener failure is exactly when
			// the durable record matters most.
			serveErr <- err
		}
	}()

	exitCode := 0
	select {
	case <-stop:
		log.Println("Shutting down...")
	case err := <-serveErr:
		log.Printf("Server error: %v", err)
		log.Println("Shutting down...")
		// Non-zero so a supervisor (systemd, Kubernetes) still sees a failed
		// listener as a failure and restarts us. main applies it with os.Exit
		// only AFTER this function returns, so every defer above has run.
		exitCode = 1
	}
	srv.Shutdown()
	return exitCode
}

// startPprofServer starts a localhost-bound listener for the pprof
// handlers the net/http/pprof import registers. It returns nil when
// --debug-pprof is unset.
//
// Security: addr is hard-coded to 127.0.0.1 — there is no flag to widen
// the bind. Pprof leaks goroutine stacks, heap shapes, and CPU samples
// that an attacker can use to fingerprint the binary or extract secrets
// from in-flight strings, so the only correct default is "loopback only,
// no override". Operators who need remote access must tunnel.
func startPprofServer(opts pprofOpts) *http.Server {
	if !opts.Enabled {
		return nil
	}
	addr := fmt.Sprintf("127.0.0.1:%d", opts.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux, // pprof handlers register here via net/http/pprof init()
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("pprof debug server listening on http://%s/debug/pprof/", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("pprof server error: %v", err)
		}
	}()
	return srv
}

func runValidate(policyFile string, strict bool) int {
	pol, warnings, err := policy.LoadFromFileWithWarnings(policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		return 1
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "WARN: %s\n", w)
	}
	if strict && len(warnings) > 0 {
		fmt.Fprintf(os.Stderr, "INVALID (--strict): %s loads, but with %d warning(s)\n", pol.Name, len(warnings))
		return 1
	}
	fmt.Printf("VALID: %s — %d rules across %d scopes\n", pol.Name, pol.RuleCount(), pol.ScopeCount())
	return 0
}

// resolveAPIKey returns the first non-empty of: explicit flag, env var.
func resolveAPIKey(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("VANZIK_API_KEY")
}

// resolveClientAPIKey is resolveAPIKey for the commands that talk to a
// server (approve, deny, status, audit), with one more fallback: the key
// `vanzik setup` saved, so they work against the server setup runs
// without exporting anything.
func resolveClientAPIKey(flagVal string) string {
	if k := resolveAPIKey(flagVal); k != "" {
		return k
	}
	return localconfig.ReadAPIKey(goos)
}

// serverAPIKey is the server's key: --api-key, else the first line of
// --api-key-file, else VANZIK_API_KEY. A key file that was asked for
// but can't be read, or is empty, is an error: starting without the key
// would open the control endpoints the operator meant to protect.
func serverAPIKey(flagVal, file string) (string, error) {
	if flagVal != "" || file == "" {
		// A server that ignored a key the operator set would accept every
		// request; it doesn't start instead.
		if flagVal == "" {
			if err := legacyenv.Check("API_KEY"); err != nil {
				return "", err
			}
		}
		return resolveAPIKey(flagVal), nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("--api-key-file: %w", err)
	}
	key := localconfig.FirstLine(b)
	if key == "" {
		return "", fmt.Errorf("--api-key-file %s is empty", file)
	}
	return key, nil
}

// attachAuth adds a Bearer header when the key is non-empty.
func attachAuth(req *http.Request, key string) {
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
}

// runResolve approves or denies one pending action on the server at baseURL
// and returns the exit code. The server answers errors as JSON (409, already
// resolved) or plain text (401, 404), so both are read.
func runResolve(stdout, stderr io.Writer, baseURL, approvalID, action, apiKey string) int {
	endpoint := fmt.Sprintf("%s/v1/%s/%s", baseURL, action, url.PathEscape(approvalID))
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		fmt.Fprintf(stderr, "vanzik %s: %v\n", action, err)
		return 1
	}
	attachAuth(req, apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		cannotConnect(stderr, baseURL, err)
		return 1
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var body map[string]string
	_ = json.Unmarshal(raw, &body)

	switch {
	case resp.StatusCode == http.StatusOK:
		done := map[string]string{"approve": "Approved", "deny": "Denied"}[action]
		fmt.Fprintf(stdout, "%s %s\n", done, approvalID)
		return 0
	case resp.StatusCode == http.StatusConflict && body["status"] != "":
		fmt.Fprintf(stderr, "vanzik %s: %s was already %s\n", action, approvalID, body["status"])
	case resp.StatusCode == http.StatusUnauthorized:
		fmt.Fprintf(stderr, "vanzik %s: %s\n", action, authFailure(apiKey))
	case resp.StatusCode == http.StatusNotFound:
		fmt.Fprintf(stderr, "vanzik %s: no pending approval %s on %s (%s)\n", action, approvalID, baseURL, serverMessage(body, raw))
	default:
		fmt.Fprintf(stderr, "vanzik %s: the server answered HTTP %d: %s\n", action, resp.StatusCode, serverMessage(body, raw))
	}
	return 1
}

// authFailure explains an HTTP 401 from the server.
func authFailure(apiKey string) string {
	if apiKey == "" {
		return "the server requires an API key (HTTP 401). Set --api-key or VANZIK_API_KEY."
	}
	return "the server rejected the API key (HTTP 401). Check --api-key or VANZIK_API_KEY."
}

// serverMessage is the readable part of an error response: the JSON
// "error" field when there is one, otherwise the first line of the body.
// An HTML page means the URL points at something other than Vanzik.
func serverMessage(body map[string]string, raw []byte) string {
	if msg := body["error"]; msg != "" {
		return msg
	}
	msg := strings.TrimSpace(string(raw))
	switch {
	case msg == "":
		return "no details"
	case strings.HasPrefix(msg, "<"):
		return "an HTML page; is this a Vanzik server?"
	}
	msg, _, _ = strings.Cut(msg, "\n")
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

// statusReport is the testable core of `vanzik status`: it writes the
// report to stdout/stderr and returns the process exit code (1 only when the
// server can't be reached at all; the pending list is best-effort).
func statusReport(stdout, stderr io.Writer, baseURL, apiKey string) int {
	url := strings.TrimRight(baseURL, "/")
	client := &http.Client{Timeout: 10 * time.Second}

	// Health check (unauthenticated)
	resp, err := client.Get(url + "/health")
	if err != nil {
		cannotConnect(stderr, baseURL, err)
		return 1
	}
	resp.Body.Close()
	fmt.Fprintf(stdout, "Vanzik server: OK (%s)\n", baseURL)

	// Pending approvals (requires auth when server has --api-key)
	pendingReq, err := http.NewRequest(http.MethodGet, url+"/api/pending", nil)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 0
	}
	attachAuth(pendingReq, apiKey)
	resp, err = client.Do(pendingReq)
	if err != nil {
		fmt.Fprintf(stdout, "Pending approvals: unavailable (%v)\n", err)
		return 0
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		fmt.Fprintln(stdout, "Pending approvals: unauthorized (set --api-key or VANZIK_API_KEY)")
		return 0
	case resp.StatusCode == http.StatusNotFound:
		// /api/pending is registered only when the server runs --dashboard.
		fmt.Fprintln(stdout, "Pending approvals: unavailable (the server was started without --dashboard)")
		return 0
	case resp.StatusCode != http.StatusOK:
		fmt.Fprintf(stdout, "Pending approvals: unavailable (HTTP %d)\n", resp.StatusCode)
		return 0
	}

	var pending []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		fmt.Fprintf(stderr, "Error decoding pending list: %v\n", err)
		return 0
	}

	if len(pending) == 0 {
		fmt.Fprintln(stdout, "Pending approvals: none")
		return 0
	}
	fmt.Fprintf(stdout, "Pending approvals: %d\n", len(pending))
	for _, p := range pending {
		id, _ := p["id"].(string)
		req, ok := p["request"].(map[string]interface{})
		if !ok {
			fmt.Fprintf(stdout, "  [%s] (unable to parse request)\n", id)
			continue
		}
		scope, _ := req["scope"].(string)
		cmd, _ := req["command"].(string)
		agent, _ := req["agent_id"].(string)
		if cmd == "" {
			cmd, _ = req["domain"].(string)
		}
		if cmd == "" {
			cmd, _ = req["path"].(string)
		}
		fmt.Fprintf(stdout, "  [%s] scope=%s action=%q agent=%s\n", id, scope, cmd, agent)
	}
	return 0
}

// auditQuery is the parsed `vanzik audit` filter set.
type auditQuery struct {
	Agent, Decision, Scope, Transport, Order string
	Limit                                    int
	// Session and ParentSession filter by session_id and
	// parent_session_id; Since and Until are RFC 3339 times (already
	// resolved from a duration by the flag parser).
	Session, ParentSession, Since, Until string
}

// serverIgnoresTimeFilters reports whether the server would ignore the
// since, until and parent_session_id parameters, as servers before 1.4
// do. It asks /v1/audit with a since that isn't a time: a server that
// reads since answers 400, one that ignores it answers 200.
//
// Asking the server what it does, rather than comparing the version from
// /health, keeps working for dev builds and for a build of the 1.4 code
// before its version string is bumped. Any other answer (401, an error, no
// answer) counts as not ignoring: the query that follows reports it.
// version is /health's, best effort, for the message.
func serverIgnoresTimeFilters(baseURL, apiKey string) (ignores bool, version string) {
	base := strings.TrimRight(baseURL, "/")
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, base+"/v1/audit?limit=1&since=probe", nil)
	if err != nil {
		return false, ""
	}
	attachAuth(req, apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, ""
	}
	if h, err := client.Get(base + "/health"); err == nil {
		var body struct {
			Version string `json:"version"`
		}
		_ = json.NewDecoder(io.LimitReader(h.Body, 64<<10)).Decode(&body)
		h.Body.Close()
		version = body.Version
	}
	return true, version
}

// runAuditQuery prints the audit entries matching q from the server at
// baseURL and returns the exit code.
func runAuditQuery(stdout, stderr io.Writer, baseURL string, q auditQuery, apiKey string) int {
	// A server before 1.4 ignores the parameters it doesn't know and
	// returns every entry, which would read as a filtered answer.
	if q.ParentSession != "" || q.Since != "" || q.Until != "" {
		if ignores, v := serverIgnoresTimeFilters(baseURL, apiKey); ignores {
			running := "a version before 1.4"
			if v != "" {
				running = "Vanzik " + v
			}
			fmt.Fprintf(stderr, "vanzik audit: the server at %s runs %s, which ignores --since, --until and --parent-session (added in 1.4) and would return every entry; upgrade the server, or leave those flags out\n", baseURL, running)
			return 1
		}
	}
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", q.Limit))
	if q.Order != "" {
		params.Set("order", q.Order)
	}
	if q.Agent != "" {
		params.Set("agent_id", q.Agent)
	}
	if q.Decision != "" {
		params.Set("decision", q.Decision)
	}
	if q.Scope != "" {
		params.Set("scope", q.Scope)
	}
	if q.Transport != "" {
		params.Set("transport", q.Transport)
	}
	if q.Session != "" {
		params.Set("session_id", q.Session)
	}
	if q.ParentSession != "" {
		params.Set("parent_session_id", q.ParentSession)
	}
	if q.Since != "" {
		params.Set("since", q.Since)
	}
	if q.Until != "" {
		params.Set("until", q.Until)
	}
	queryURL := fmt.Sprintf("%s/v1/audit?%s", baseURL, params.Encode())

	req, err := http.NewRequest(http.MethodGet, queryURL, nil)
	if err != nil {
		fmt.Fprintf(stderr, "vanzik audit: %v\n", err)
		return 1
	}
	attachAuth(req, apiKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		cannotConnect(stderr, baseURL, err)
		return 1
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		fmt.Fprintf(stderr, "vanzik audit: %s\n", authFailure(apiKey))
		return 1
	case resp.StatusCode != http.StatusOK:
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		fmt.Fprintf(stderr, "vanzik audit: the server answered HTTP %d: %s\n", resp.StatusCode, serverMessage(nil, raw))
		return 1
	}

	var entries []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		fmt.Fprintf(stderr, "vanzik audit: unreadable answer from %s (is it a Vanzik server?): %v\n", baseURL, err)
		return 1
	}

	if len(entries) == 0 {
		fmt.Fprintln(stdout, "No audit entries found.")
		return 0
	}

	fmt.Fprintf(stdout, "Showing %d audit entries:\n\n", len(entries))
	for _, e := range entries {
		ts, _ := e["timestamp"].(string)
		agentID, _ := e["agent_id"].(string)
		req, _ := e["request"].(map[string]interface{})
		result, _ := e["result"].(map[string]interface{})
		reqScope, _ := req["scope"].(string)
		dec, _ := result["decision"].(string)
		reason, _ := result["reason"].(string)
		// Transport is omitempty on the wire — older entries lack the
		// field. Fall back to "sdk" so columns stay aligned.
		tport, _ := e["transport"].(string)
		if tport == "" {
			tport = "sdk"
		}
		cmd, _ := req["command"].(string)
		if cmd == "" {
			cmd, _ = req["domain"].(string)
		}
		if cmd == "" {
			cmd, _ = req["path"].(string)
		}
		fmt.Fprintf(stdout, "  %s  %-18s  transport=%-12s  scope=%-12s  agent=%-15s  %s\n", ts, dec, tport, reqScope, agentID, cmd)
		if reason != "" {
			fmt.Fprintf(stdout, "    reason: %s\n", reason)
		}
	}
	return 0
}

// migrateCmdOpts carries the parsed `vanzik migrate` flags.
type migrateCmdOpts struct {
	AuditPath       string
	CheckpointPath  string // empty => defaultCheckpointPath(AuditPath)
	BackupDir       string // empty => directory of AuditPath
	DryRun          bool
	List            bool
	ID              string
	ResetCheckpoint bool
}

// defaultCheckpointPath is the checkpoint file `vanzik server` actually
// reads and writes for a given audit log. It MUST go through
// audit.CheckpointPath: with any other path `--reset-checkpoint` deletes
// a file that never existed and reports success.
func defaultCheckpointPath(auditPath string) string {
	return audit.CheckpointPath(auditPath)
}

// executeMigrate is the testable core of `vanzik migrate`. Returns the
// process exit code: 0 on success, 1 on any failure.
//
// The --reset-checkpoint flag deletes the replay checkpoint before running
// any migration, forcing the next server start to do a full replay. This is
// the escape hatch for operators who suspect the checkpoint is corrupt or
// was written by an incompatible build. It reports honestly: "removed" only
// when a file was actually deleted, "no checkpoint found" otherwise.
func executeMigrate(o migrateCmdOpts, stdout, stderr io.Writer) int {
	if o.AuditPath == "" {
		fmt.Fprintln(stderr, "migrate: --audit-log is required")
		return 1
	}
	if o.CheckpointPath == "" {
		o.CheckpointPath = defaultCheckpointPath(o.AuditPath)
	}
	if o.BackupDir == "" {
		o.BackupDir = filepath.Dir(o.AuditPath)
	}

	if o.ResetCheckpoint {
		switch err := os.Remove(o.CheckpointPath); {
		case err == nil:
			fmt.Fprintf(stdout, "migrate: checkpoint removed (%s)\n", o.CheckpointPath)
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintf(stdout, "migrate: no checkpoint found at %s (nothing to reset)\n", o.CheckpointPath)
		default:
			fmt.Fprintf(stderr, "migrate: could not remove checkpoint %s: %v\n", o.CheckpointPath, err)
			return 1
		}
	}

	env := migrate.Env{
		AuditLogPath:   o.AuditPath,
		CheckpointPath: o.CheckpointPath,
		BackupDir:      o.BackupDir,
		Logger:         log.New(stderr, "", log.LstdFlags),
		Stdout:         stdout,
	}
	opts := migrate.CLIOptions{
		DryRun: o.DryRun,
		ID:     o.ID,
		List:   o.List,
	}
	if err := migrate.RunCLI(context.Background(), env, opts); err != nil {
		fmt.Fprintf(stderr, "migrate: %v\n", err)
		return 1
	}
	return 0
}

// subcommandOf returns the subcommand token of a CLI argv ("" when absent).
func subcommandOf(args []string) string {
	if len(args) < 2 {
		return ""
	}
	return args[1]
}

// runTenant implements `vanzik tenant <put|list|rm>` — the operator
// interface for registering per-tenant policies in the durable store (
// multi-tenancy). It opens the store directly (the server need not be running;
// SQLite WAL permits a concurrent writer, and a running server picks up a new
// tenant on its next lookup).
func runTenant(args []string) int {
	if len(args) == 0 {
		printTenantUsage(os.Stderr)
		return exitUsage
	}
	sub := args[0]
	switch sub {
	case "-h", "-help", "--help", "help":
		printTenantUsage(os.Stdout)
		return 0
	case "put", "list", "rm":
	default:
		// Checked before the store is opened, so a typo never creates an
		// empty vanzik.db in the current folder.
		fmt.Fprintf(os.Stderr, "vanzik tenant: unknown subcommand %q.", sub)
		if s := closest(sub, []string{"put", "list", "rm"}); s != "" {
			fmt.Fprintf(os.Stderr, " Did you mean 'vanzik tenant %s'?", s)
		}
		fmt.Fprintln(os.Stderr, "\nRun 'vanzik tenant -h' for help.")
		return exitUsage
	}

	name := "tenant " + sub
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	storeDSN := fs.String("store-dsn", "", "The server's --store-dsn, if it uses one (empty: <data-dir>/vanzik.db)")
	dataDir := fs.String("data-dir", ".", "The server's --data-dir: the folder holding vanzik.db")
	var policyPath *string
	if sub == "put" {
		policyPath = fs.String("policy", "", "Policy YAML file to register (required)")
	}
	usage := func(w io.Writer) {
		switch sub {
		case "put":
			fmt.Fprint(w, `Usage: vanzik tenant put <tenant-id> --policy <file.yaml> [flags]

Validate a policy YAML file and register it for a tenant in the durable
store. Running it again replaces the tenant's policy.

`)
		case "list":
			fmt.Fprint(w, `Usage: vanzik tenant list [flags]

List tenant IDs with a policy registered in the durable store. (The
"local" tenant is always served from the server's --policy file.)

`)
		case "rm":
			fmt.Fprint(w, `Usage: vanzik tenant rm <tenant-id> [flags]

Remove a tenant's policy from the durable store.

`)
		}
		clihelp.WriteFlags(w, fs, clihelp.Options{})
		fmt.Fprint(w, tenantStoreWarning)
		switch sub {
		case "put":
			fmt.Fprint(w, `
Examples:
  vanzik tenant put acme --policy acme.yaml
  vanzik tenant put acme --policy acme.yaml --data-dir /var/lib/vanzik
`)
		case "list":
			fmt.Fprint(w, `
Example:
  vanzik tenant list --data-dir /var/lib/vanzik
`)
		case "rm":
			fmt.Fprint(w, `
Example:
  vanzik tenant rm acme --data-dir /var/lib/vanzik
`)
		}
	}
	positional, code, ok := parseCommand(fs, usage, args[1:])
	if !ok {
		return code
	}
	var tenant string
	if sub == "list" {
		if len(positional) > 0 {
			return usageError(name, "unexpected argument %q", positional[0])
		}
	} else {
		switch {
		case len(positional) == 0:
			return usageError(name, "missing the tenant ID")
		case len(positional) > 1:
			return usageError(name, "unexpected argument %q (one tenant ID at a time)", positional[1])
		}
		tenant = positional[0]
	}
	if sub == "put" && *policyPath == "" {
		return usageError(name, "--policy is required (the policy file to register)")
	}

	st, path, err := openStore(persistOpts{DSN: *storeDSN, DataDir: *dataDir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanzik tenant: cannot open store: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	switch sub {
	case "put":
		// Validate before storing so a malformed policy is never registered.
		pol, err := policy.LoadFromFile(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vanzik tenant put: INVALID policy %s: %v\n", *policyPath, err)
			return 1
		}
		raw, err := os.ReadFile(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vanzik tenant put: read %s: %v\n", *policyPath, err)
			return 1
		}
		if err := st.PutPolicy(ctx, tenant, raw); err != nil {
			fmt.Fprintf(os.Stderr, "vanzik tenant put: %v\n", err)
			return 1
		}
		fmt.Printf("Registered tenant %q: %s (%d rules across %d scopes) in %s\n",
			tenant, pol.Name, pol.RuleCount(), pol.ScopeCount(), path)
		fmt.Println("A server sees it only if it uses this same store (the same --data-dir or --store-dsn).")

	case "list":
		tenants, err := st.ListPolicyTenants(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vanzik tenant list: %v\n", err)
			return 1
		}
		if len(tenants) == 0 {
			fmt.Println("No tenant policies registered. (The 'local' tenant is served from --policy.)")
			return 0
		}
		fmt.Printf("Registered tenants (%d):\n", len(tenants))
		for _, t := range tenants {
			fmt.Printf("  %s\n", t)
		}

	case "rm":
		ok, err := st.DeletePolicy(ctx, tenant)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vanzik tenant rm: %v\n", err)
			return 1
		}
		if ok {
			fmt.Printf("Removed tenant %q\n", tenant)
		} else {
			fmt.Printf("Tenant %q not found\n", tenant)
		}
	}
	return 0
}

// tenantStoreWarning is in every tenant help page: a tenant written to one
// store and a server reading another fail silently, the tenant simply
// never exists for that server.
const tenantStoreWarning = `
Use the same --data-dir (or --store-dsn) as the server. Otherwise the
server never sees these tenants, and nothing reports an error.
`

// printTenantUsage is the `vanzik tenant` dispatcher-level help —
// each subcommand prints its own (see usage in runTenant).
func printTenantUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: vanzik tenant <put|list|rm> [flags]

Manage per-tenant policies in the durable store (multi-tenancy). The
server need not be running. A running server sees a new tenant on its
next lookup (within --tenant-policy-refresh-interval if that tenant ID
was queried before it was registered); replacements and removals reach
it within --tenant-policy-refresh-interval (default 30s).

Subcommands:
  put <tenant-id> --policy <file.yaml>   Validate and register a tenant policy
  list                                   List registered tenant IDs
  rm <tenant-id>                         Remove a tenant policy
`+tenantStoreWarning+`
Example:
  vanzik tenant put acme --policy acme.yaml --data-dir /var/lib/vanzik

Run 'vanzik tenant <subcommand> -h' for details on each subcommand.
`)
}

// validateBind refuses a non-loopback --bind without an API key: without a
// key the approve/deny endpoints are open, which is only safe on loopback.
func validateBind(bindHost, apiKey string) error {
	if bindHost == "" || apiKey != "" || proxy.IsLoopbackHost(bindHost) {
		return nil
	}
	return fmt.Errorf("--bind %q is not a loopback address; refusing to listen without --api-key (set --api-key, or use --bind 127.0.0.1)", bindHost)
}
