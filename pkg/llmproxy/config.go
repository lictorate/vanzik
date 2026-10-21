// Package llmproxy implements the Vanzik LLM API Proxy: an HTTP
// server that speaks OpenAI Chat Completions and Anthropic Messages
// wire formats, forwards requests to the real upstreams, and gates
// any tool calls the model emits through the central Vanzik
// policy engine.
//
// Files: server.go (server, hooks), forward.go (non-streaming),
// streaming.go with openai_parser.go and anthropic_parser.go (SSE
// gating), gate.go (/v1/check client), scope_map.go, refusal.go.
// Design: docs/LLM_API_PROXY.md and docs/PROXY_ARCHITECTURE.md.
package llmproxy

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"lictorate.com/vanzik/v2/internal/clihelp"
	"lictorate.com/vanzik/v2/pkg/internal/gateclient"
)

// Default flag values.
const (
	// DefaultListen is loopback; Validate refuses non-loopback binds
	// without --proxy-api-key.
	DefaultListen = "127.0.0.1:8081"

	// Gate-side defaults are shared with the MCP gateway.
	DefaultUpstreamOpenAI    = "https://api.openai.com"
	DefaultUpstreamAnthropic = "https://api.anthropic.com"
	DefaultGuardURL          = gateclient.DefaultGuardURL
	DefaultTenantID          = gateclient.DefaultTenantID
	DefaultFailMode          = gateclient.DefaultFailMode
	DefaultLogLevel          = gateclient.DefaultLogLevel

	// DefaultMaxBufferBytes is the per-stream tool-call buffer cap. It
	// matches the central server's MaxRequestBodySize so /v1/check
	// payloads always fit.
	DefaultMaxBufferBytes = 1024 * 1024 // 1 MiB

	// MaxConfigurableBufferBytes is the largest accepted
	// --max-buffer-bytes.
	MaxConfigurableBufferBytes = 64 * 1024 * 1024 // 64 MiB

	// DefaultMaxConcurrentStreams caps simultaneous streams; 0 disables
	// the cap. Each stream holds up to ~2x --max-buffer-bytes, so this
	// cap is what bounds memory under fan-out: 100 streams at 1 MiB is
	// about 200 MiB, while typical SDK concurrency is under 10.
	DefaultMaxConcurrentStreams = 100
)

// Config is the proxy's parsed flag/env configuration, immutable after
// startup.
type Config struct {
	// Listen is the bind address. Non-loopback requires ProxyAPIKey; an
	// empty host (":8081") binds every interface and counts as
	// non-loopback.
	Listen string

	// UpstreamOpenAI is the base URL for OpenAI-shape requests
	// (/v1/chat/completions, /v1/completions, /v1/embeddings, /v1/models).
	UpstreamOpenAI string

	// UpstreamAnthropic is the base URL for Anthropic-shape requests
	// (/v1/messages).
	UpstreamAnthropic string

	// GuardURL is the central Vanzik server's base URL.
	GuardURL string

	// APIKey is the bearer for /v1/check and /v1/audit (falls back to
	// VANZIK_API_KEY). Unrelated to the upstream Authorization header,
	// which is forwarded unread.
	APIKey string

	// ProxyAPIKey, if set, is enforced on inbound requests via
	// ProxyAuthHeader. Empty disables proxy auth (loopback only).
	ProxyAPIKey string

	// TenantID is sent to /v1/check and recorded in audit entries.
	TenantID string

	// FailMode is "deny", "allow" or "fail-closed-with-audit"
	// (docs/PROXY_ARCHITECTURE.md § 6.1).
	FailMode string

	// FailAuditLog is the local JSONL file for denials made while
	// /v1/check is unreachable in fail-closed-with-audit mode. Empty
	// disables it.
	FailAuditLog string

	// MaxBufferBytes caps the per-stream tool-call buffer.
	MaxBufferBytes int

	// MaxConcurrentStreams caps simultaneous streams process-wide;
	// excess requests get 503 + Retry-After: 5. 0 disables the cap.
	MaxConcurrentStreams int

	// LogLevel is "info" or "debug".
	LogLevel string

	// PolicyPath is the policy YAML (the central server's) read for
	// tool_scope_map overrides. Unset means DefaultLLMToolScopeMap only
	// and no hot-reload. Cross-host deployments must share or replicate
	// the file so both sides agree.
	PolicyPath string
}

// ParseConfig parses CLI args (without the binary name) and validates
// the result. --api-key wins over VANZIK_API_KEY.
func ParseConfig(args []string) (*Config, error) {
	return ParseConfigWithOutput(args, os.Stderr)
}

// proxyFlagGroups is the layout of `vanzik-llm-proxy -h`. Every flag
// must be in one group (TestConfig_HelpGroupsEveryFlag).
var proxyFlagGroups = []clihelp.Group{
	{Title: "Listening", Names: []string{"listen", "proxy-api-key", "max-concurrent-streams", "max-buffer-bytes"}},
	{Title: "Model providers", Names: []string{"upstream-openai", "upstream-anthropic"}},
	{Title: "Vanzik server", Names: []string{"guard-url", "api-key", "tenant-id"}},
	{Title: "Policy", Names: []string{"policy"}},
	{Title: "When the Vanzik server is unreachable", Names: []string{"fail-mode", "fail-audit-log"}},
	{Title: "Logging", Names: []string{"log-level"}},
}

// ParseConfigWithOutput is ParseConfig with usage written to errOut.
func ParseConfigWithOutput(args []string, errOut io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("vanzik-llm-proxy", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprintf(errOut, `Usage: vanzik-llm-proxy [flags]

vanzik-llm-proxy is a drop-in OpenAI/Anthropic base URL: it speaks
the OpenAI Chat Completions and Anthropic Messages wire formats,
forwards traffic to the real upstreams, and gates every tool call the
model emits through a central Vanzik server's /v1/check endpoint.

Example:
  vanzik-llm-proxy --guard-url http://127.0.0.1:8080 \
      --policy /etc/vanzik/policy.yaml
  # then point the agent's SDK at the proxy:
  #   OPENAI_BASE_URL=http://127.0.0.1:8081/v1
  #   ANTHROPIC_BASE_URL=http://127.0.0.1:8081

`)
		clihelp.WriteGroups(errOut, fs, proxyFlagGroups, clihelp.Options{})
		fmt.Fprint(errOut, `
Other:
  --version  Print the version and exit (checked before any other flag)

Environment:
  VANZIK_URL       Used when --guard-url is not set.
  VANZIK_API_KEY   Used when --api-key is not set.
`)
	}

	gate := gateclient.RegisterGateFlags(fs,
		"Path to policy YAML for tool→scope mapping; empty falls back to DefaultLLMToolScopeMap with no operator overrides")
	listen := fs.String("listen", DefaultListen, "Address to bind (host:port)")
	upstreamOpenAI := fs.String("upstream-openai", DefaultUpstreamOpenAI, "Base URL for OpenAI-shape requests")
	upstreamAnthropic := fs.String("upstream-anthropic", DefaultUpstreamAnthropic, "Base URL for Anthropic-shape requests")
	proxyAPIKey := fs.String("proxy-api-key", "", "Optional bearer the proxy itself enforces on inbound requests (X-Vanzik-Proxy-Auth). Empty = no proxy auth.")
	maxBufferBytes := fs.Int("max-buffer-bytes", DefaultMaxBufferBytes, "Per-stream tool-call buffer cap in bytes")
	maxConcurrentStreams := fs.Int("max-concurrent-streams", DefaultMaxConcurrentStreams, "Global cap on simultaneous streaming requests; 0 disables the cap. Excess requests are refused with 503 + Retry-After: 5.")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if err := gateclient.RejectArgs(fs.Args(), ""); err != nil {
		return nil, err
	}
	if err := gate.ApplyEnv(); err != nil {
		return nil, err
	}

	cfg := &Config{
		Listen:               *listen,
		UpstreamOpenAI:       *upstreamOpenAI,
		UpstreamAnthropic:    *upstreamAnthropic,
		GuardURL:             *gate.GuardURL,
		APIKey:               *gate.APIKey,
		ProxyAPIKey:          *proxyAPIKey,
		TenantID:             *gate.TenantID,
		FailMode:             *gate.FailMode,
		FailAuditLog:         *gate.FailAuditLog,
		MaxBufferBytes:       *maxBufferBytes,
		MaxConcurrentStreams: *maxConcurrentStreams,
		LogLevel:             *gate.LogLevel,
		PolicyPath:           *gate.PolicyPath,
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks a Config, including one built without ParseConfig.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("--listen must not be empty")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("--listen %q is not a valid host:port: %w", c.Listen, err)
	}
	if port == "" {
		return fmt.Errorf("--listen %q is missing port", c.Listen)
	}

	if err := gateclient.ValidateBaseURL("--upstream-openai", c.UpstreamOpenAI); err != nil {
		return err
	}
	if err := gateclient.ValidateBaseURL("--upstream-anthropic", c.UpstreamAnthropic); err != nil {
		return err
	}
	if err := gateclient.ValidateGateConfig(c.GuardURL, c.TenantID, c.FailMode, c.LogLevel); err != nil {
		return err
	}

	if c.MaxBufferBytes <= 0 {
		return fmt.Errorf("--max-buffer-bytes must be > 0, got %d", c.MaxBufferBytes)
	}
	if c.MaxBufferBytes > MaxConfigurableBufferBytes {
		return fmt.Errorf("--max-buffer-bytes %d exceeds maximum %d", c.MaxBufferBytes, MaxConfigurableBufferBytes)
	}

	// Negative max-concurrent-streams is a typo; 0 disables the cap.
	if c.MaxConcurrentStreams < 0 {
		return fmt.Errorf("--max-concurrent-streams must be >= 0, got %d", c.MaxConcurrentStreams)
	}

	if c.TenantID == "" {
		return errors.New("--tenant-id must not be empty")
	}

	// No unauthenticated non-loopback binds (docs/LLM_API_PROXY.md § 8.1).
	if !isLoopbackHost(host) && c.ProxyAPIKey == "" {
		if strings.TrimSpace(host) == "" {
			return fmt.Errorf("--listen %q has no host, so it binds every interface (non-loopback) without --proxy-api-key; refuse to start to avoid exposing an unauthenticated proxy (use 127.0.0.1:%s for loopback only)", c.Listen, port)
		}
		return fmt.Errorf("--listen %q binds non-loopback host %q without --proxy-api-key; refuse to start to avoid exposing an unauthenticated proxy", c.Listen, host)
	}

	return nil
}

// isLoopbackHost reports whether host is localhost or a loopback IP.
// An empty host is not: ":8081" listens on every interface.
func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	// Brackets are normally stripped by net.SplitHostPort already.
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
