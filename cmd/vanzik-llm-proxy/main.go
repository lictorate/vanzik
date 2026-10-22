// Command vanzik-llm-proxy is the Vanzik LLM API Proxy: an
// HTTP server that speaks the OpenAI Chat Completions and Anthropic
// Messages wire formats, forwards traffic to the real upstream, and
// gates any tool calls the model emits through the central
// Vanzik policy engine.
//
// Usage:
//
//	vanzik-llm-proxy \
//	    --listen 127.0.0.1:8081 \
//	    --upstream-openai https://api.openai.com \
//	    --upstream-anthropic https://api.anthropic.com \
//	    --guard-url http://127.0.0.1:8080 \
//	    --api-key $VANZIK_API_KEY \
//	    --proxy-api-key $PROXY_AUTH_TOKEN \
//	    --policy /etc/vanzik/policy.yaml \
//	    --tenant-id local \
//	    --fail-mode deny \
//	    --max-buffer-bytes 1048576 \
//	    --log-level info
//
// Point the agent's SDK at the proxy. Only the OpenAI base URL takes
// `/v1`; the Anthropic SDK appends `/v1/messages` to the origin itself:
//
//	OPENAI_BASE_URL=http://127.0.0.1:8081/v1
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8081
//
// See docs/LLM_API_PROXY.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"lictorate.com/vanzik/v2/cmd/internal/buildinfo"
	"lictorate.com/vanzik/v2/pkg/llmproxy"
	"lictorate.com/vanzik/v2/pkg/policy"
)

// Set at link time via -ldflags.
var (
	version = "2.0.0"
	commit  = "dev"
)

func main() {
	args := os.Args[1:]

	// --version is checked before flag parsing so it needs no config.
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Printf("vanzik-llm-proxy %s (%s)\n", version, buildinfo.Describe(commit))
			return
		}
	}

	cfg, err := llmproxy.ParseConfig(args)
	if err != nil {
		// -h already printed usage; exit 0 like the vanzik subcommands.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "vanzik-llm-proxy: %v\n", err)
		os.Exit(2)
	}

	// Advertised by /healthz and the upstream User-Agent.
	llmproxy.BuildVersion = version

	// Without --api-key, /v1/check still works against an unkeyed
	// central server (loopback dev), but production should set it.
	if cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "vanzik-llm-proxy: WARNING --api-key not set: /v1/check calls are unauthenticated, and if the central server is keyed, forced-refusal audits fall back to the lower-fidelity /v1/check path (POST /v1/audit is auth-gated). Set --api-key or VANZIK_API_KEY.")
	}
	if cfg.ProxyAPIKey == "" {
		fmt.Fprintf(os.Stderr, "vanzik-llm-proxy: WARNING --proxy-api-key not set; %s header will not be enforced\n", llmproxy.ProxyAuthHeader)
	}

	server, err := llmproxy.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanzik-llm-proxy: %v\n", err)
		os.Exit(1)
	}

	// --policy is the central server's YAML, read here only for
	// tool_scope_map overrides. Without it the gate uses the bundled
	// defaults; /v1/check still gates every tool call.
	var (
		gate      *llmproxy.HTTPPolicyClient
		stopWatch func()
	)
	if cfg.PolicyPath != "" {
		provider, perr := policy.NewFilePolicyProvider(cfg.PolicyPath)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "vanzik-llm-proxy: policy load: %v\n", perr)
			os.Exit(1)
		}
		defer provider.Close()

		pol, perr := provider.Get(cfg.TenantID)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "vanzik-llm-proxy: policy get for tenant %q: %v\n", cfg.TenantID, perr)
			os.Exit(1)
		}

		gate = llmproxy.NewHTTPPolicyClient(cfg, pol)

		// Hot-reload the tool_scope_map on YAML edits.
		stop, werr := provider.Watch(cfg.TenantID, gate.SetPolicy)
		if werr != nil {
			fmt.Fprintf(os.Stderr, "vanzik-llm-proxy: policy watch: %v\n", werr)
			os.Exit(1)
		}
		stopWatch = stop
	} else {
		fmt.Fprintln(os.Stderr, "vanzik-llm-proxy: WARNING --policy not set; tool→scope mapping will use bundled defaults only (no operator overrides)")
		gate = llmproxy.NewHTTPPolicyClient(cfg, nil)
	}
	if stopWatch != nil {
		defer stopWatch()
	}

	// Hooks must be set before Run.
	server.PolicyCheck = gate.Check
	server.ScopeMap = gate.MapScope
	server.BuildRefusal = llmproxy.BuildRefusalRich
	// The proxy writes no audit entries itself: /v1/check records each
	// gated call, and refusals the proxy manufactures go to /v1/audit
	// with the DENY the client actually received.
	server.RecordForcedAudit = gate.RecordForcedAudit

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "vanzik-llm-proxy: signal received, shutting down")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "vanzik-llm-proxy %s listening on %s (upstream-openai=%s upstream-anthropic=%s guard=%s)\n",
		version, cfg.Listen, cfg.UpstreamOpenAI, cfg.UpstreamAnthropic, cfg.GuardURL)

	if err := server.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "vanzik-llm-proxy: %v\n", err)
		os.Exit(1)
	}
}
