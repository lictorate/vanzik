package llmproxy

// Concurrency contract (per-request isolation, shared pooled
// http.Client, no global mutable state): docs/LLM_API_PROXY.md § 6.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lictorate.com/vanzik/v2/pkg/internal/gateclient"
	"lictorate.com/vanzik/v2/pkg/metrics"
)

// BuildVersion is overridden via -ldflags by the binary entry point.
// Defaults to "dev" for `go test` / `go run`.
var BuildVersion = "dev"

// ProxyAuthHeader is the inbound-auth header the proxy enforces when
// --proxy-api-key is set. It is separate from Authorization, which
// carries the upstream's bearer token verbatim; callers send both.
const ProxyAuthHeader = "X-Vanzik-Proxy-Auth"

// ParentSessionHeader names the session that started the caller's session
// (X-Session-ID): an orchestrator's session for a sub-agent. The proxy sends
// it to /v1/check as parent_session_id; like X-Session-ID it is also
// forwarded upstream unchanged.
const ParentSessionHeader = "X-Vanzik-Parent-Session"

// ApprovalIDHeader carries an approval id from an earlier
// REQUIRE_APPROVAL refusal. The proxy sends it to /v1/check as
// approval_id on every gated tool call in the request; the server
// honors it only for the action that was approved (its replay checks
// still apply) and evaluates anything else fresh. Like ProxyAuthHeader
// it is inbound-only and never forwarded upstream.
const ApprovalIDHeader = "X-Vanzik-Approval-ID"

// ----- Hook input/output types -----

// ToolCallCheck is the shape passed to PolicyCheck, which turns it
// into a /v1/check call. It mirrors mcpgw.ToolsCallRequest so both
// proxies share one model.
type ToolCallCheck struct {
	// Provider is "openai" or "anthropic"; it selects the refusal shape.
	Provider string

	// ToolName is the tool name as the model emitted it (no namespace
	// prefix, unlike MCP).
	ToolName string

	// ToolCallID is the upstream-assigned id (OpenAI call_xxx,
	// Anthropic toolu_xxx), surfaced in audit meta for correlation
	// with provider logs.
	ToolCallID string

	// Arguments holds the parsed arguments: for OpenAI the JSON inside
	// the tool_calls[*].function.arguments string, for Anthropic the
	// input object. nil if the model emitted invalid JSON; the policy
	// hook decides how to handle that.
	Arguments map[string]interface{}

	// RawArguments is the unparsed arguments, for inspection or
	// redaction before re-marshalling.
	RawArguments json.RawMessage

	// AgentID comes from X-Agent-ID (default "llm-proxy"), TenantID
	// from cfg.TenantID, ApprovalID from ApprovalIDHeader on a retry.
	AgentID    string
	SessionID  string
	TenantID   string
	ApprovalID string

	// ParentSessionID is the X-Vanzik-Parent-Session header: the
	// session that started this one, recorded in the audit log so the
	// sessions API can group them. Policy ignores it.
	ParentSessionID string

	// Model is the request body's model name, surfaced in audit meta.
	Model string

	// Stream reports whether the request was streaming (audit meta).
	Stream bool

	// UpstreamStatus is the upstream HTTP status; 0 means no upstream
	// call yet.
	UpstreamStatus int
}

// Decision is the verdict returned by PolicyCheck. Alias of the shared
// gateclient.Decision so both proxies speak one verdict shape.
type Decision = gateclient.Decision

// ----- Server -----

// Server is the HTTP server. Hooks (PolicyCheck, ScopeMap,
// BuildRefusal, RecordForcedAudit) are nil-safe and wired by main.go
// before Run.
//
// Concurrency: Server is read-only after construction; per-request
// state is never shared between requests.
type Server struct {
	cfg *Config

	// httpClient is shared so connections pool per upstream host.
	httpClient *http.Client

	openaiURL    *url.URL
	anthropicURL *url.URL

	// PolicyCheck is the policy hook; nil means ALLOW (tests). The
	// wired hook POSTs to <guard-url>/v1/check with
	// meta["transport"]="llm_api_proxy". /v1/check writes the audit
	// entry and SSE event; the proxy itself writes no audit entries.
	PolicyCheck func(ctx context.Context, req *ToolCallCheck) (Decision, error)

	// ScopeMap resolves a tool name to a policy scope. nil returns
	// "unmapped", which the engine fails closed on unless an
	// "unmapped" scope rule exists.
	ScopeMap func(toolName string) string

	// BuildRefusal builds the synthetic-refusal bytes for a denied
	// tool call (OpenAI: assistant text + [DONE]; Anthropic: a text
	// block at the tool_use's index + stop_reason rewrite). nil uses
	// defaultRefusalBytes. Never use `role: "tool"`: it hangs SDKs.
	BuildRefusal func(provider string, decision Decision, ctx *RefusalContext) []byte

	// RecordForcedAudit, when non-nil, records a proxy-manufactured
	// fail-closed refusal (e.g. the malformed-tool-call DENY) in the
	// central audit trail with the verdict the client actually
	// received, via the gate's /v1/audit ingest. nil falls back to
	// auditDeniedToolCalls, which logs the engine verdict instead. Only
	// the malformed-completion path calls it, never the ALLOW path.
	RecordForcedAudit func(ctx context.Context, req *ToolCallCheck, decision Decision)

	// running prevents concurrent Run calls on one Server.
	running   sync.Mutex
	startTime time.Time

	// streamingActive counts in-flight streams process-wide, checked
	// against cfg.MaxConcurrentStreams by admitStream.
	streamingActive atomic.Int64
}

// NewServer constructs a Server from a Config already checked by
// Config.Validate.
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	openai, err := url.Parse(cfg.UpstreamOpenAI)
	if err != nil {
		return nil, fmt.Errorf("parse upstream-openai: %w", err)
	}
	anthropic, err := url.Parse(cfg.UpstreamAnthropic)
	if err != nil {
		return nil, fmt.Errorf("parse upstream-anthropic: %w", err)
	}

	client := &http.Client{
		// No end-to-end timeout: streams last as long as upstream and
		// client agree. The request context (client disconnect)
		// cancels.
		Timeout: 0,
	}

	return &Server{
		cfg:          cfg,
		httpClient:   client,
		openaiURL:    openai,
		anthropicURL: anthropic,
	}, nil
}

// Run serves until ctx is cancelled (graceful shutdown, returns nil)
// or ListenAndServe fails.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.TryLock() {
		return errors.New("server already running")
	}
	defer s.running.Unlock()

	mux := s.routes()

	srv := &http.Server{
		Addr:    s.cfg.Listen,
		Handler: mux,
		// Slowloris guard on headers only; bodies are capped by
		// max-buffer-bytes, not by time.
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.startTime = time.Now()

	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		close(shutdownDone)
	}()

	err := srv.ListenAndServe()
	<-shutdownDone

	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// routes builds the request multiplexer. Every handler is wrapped in
// recoverPanic so a per-request panic cannot crash the process.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/chat/completions", s.recoverPanic(s.authMiddleware(s.handleChatCompletions)))
	mux.HandleFunc("POST /v1/completions", s.recoverPanic(s.authMiddleware(s.handleLegacyCompletions)))

	mux.HandleFunc("POST /v1/messages", s.recoverPanic(s.authMiddleware(s.handleAnthropicMessages)))

	// Pass-through: these responses carry no tool calls, so nothing is gated.
	mux.HandleFunc("POST /v1/embeddings", s.recoverPanic(s.authMiddleware(s.handlePassThroughOpenAI)))
	mux.HandleFunc("GET /v1/models", s.recoverPanic(s.authMiddleware(s.handlePassThroughOpenAI)))

	// Not auth-gated, so health checks work with --proxy-api-key set.
	mux.HandleFunc("GET /healthz", s.recoverPanic(s.handleHealth))

	return mux
}

// committedWriter records whether the status line has been sent, so a
// late error path knows whether an error envelope is still safe.
// net/http drops a second WriteHeader but still writes the body after
// it, which would append an error object to a partial response.
// forwardTo's io.Copy uses errResponseCommitted for the same reason.
//
// Flush is forwarded explicitly: the streaming loops type-assert to
// http.Flusher, which an embedded-only wrapper would fail.
type committedWriter struct {
	http.ResponseWriter
	committed bool
}

func (c *committedWriter) WriteHeader(status int) {
	c.committed = true
	c.ResponseWriter.WriteHeader(status)
}

func (c *committedWriter) Write(b []byte) (int, error) {
	// An implicit 200 from a bare Write commits the response just as
	// surely as an explicit WriteHeader.
	c.committed = true
	return c.ResponseWriter.Write(b)
}

func (c *committedWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (c *committedWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// recoverPanic logs a handler panic and returns a JSON 500 if nothing
// has been written yet. Once the response is committed it writes
// nothing, so the client sees a truncated stream rather than an error
// envelope appended to partial bytes. Mirrors pkg/proxy's recoverPanic.
func (s *Server) recoverPanic(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cw := &committedWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("llmproxy: PANIC %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				if cw.committed {
					// SDKs treat the truncated body as a disconnect.
					log.Printf("llmproxy: response already committed; closing without an error envelope")
					return
				}
				cw.Header().Set("Content-Type", "application/json")
				cw.WriteHeader(http.StatusInternalServerError)
				_, _ = cw.Write([]byte(`{"error":{"message":"internal server error","type":"vanzik_error"}}`))
			}
		}()
		next(cw, r)
	}
}

// admitStream acquires a streaming slot. On true the caller must
// defer releaseStream; on false it has already written 503 +
// Retry-After. MaxConcurrentStreams <= 0 disables the cap.
func (s *Server) admitStream(w http.ResponseWriter) bool {
	cap := s.cfg.MaxConcurrentStreams
	if cap <= 0 {
		// Still count, so the gauge shows in-flight streams when uncapped.
		s.streamingActive.Add(1)
		metrics.AddLLMProxyStreamsActive(1)
		return true
	}
	// Optimistic add-then-check keeps this lock-free; if we overshoot we
	// decrement and refuse, at the cost of one extra atomic in the rare
	// overflow case.
	n := s.streamingActive.Add(1)
	if n > int64(cap) {
		s.streamingActive.Add(-1)
		// Gauge not bumped for a rejected stream, so nothing to roll back.
		metrics.IncLLMProxyStreamsRejected()
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"server overloaded; too many concurrent streams","type":"vanzik_error"}}`))
		return false
	}
	metrics.AddLLMProxyStreamsActive(1)
	return true
}

// releaseStream releases a slot; call it once per admitStream that
// returned true, never after a false.
func (s *Server) releaseStream() {
	s.streamingActive.Add(-1)
	metrics.AddLLMProxyStreamsActive(-1)
}

// handleHealth reports the proxy process's liveness, not the central
// server's (docs/PROXY_ARCHITECTURE.md § 8).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]interface{}{
		"status":    "ok",
		"version":   BuildVersion,
		"transport": "llm_api_proxy",
		"uptime_s":  int(time.Since(s.startTime).Seconds()),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// authMiddleware enforces ProxyAuthHeader when --proxy-api-key is set
// and is a no-op otherwise. The compare is constant-time.
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	if s.cfg.ProxyAPIKey == "" {
		return next
	}
	expected := []byte(s.cfg.ProxyAPIKey)
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(ProxyAuthHeader)
		// "Bearer <key>" and bare "<key>" are both accepted.
		got = strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
		if got == "" || subtle.ConstantTimeCompare([]byte(got), expected) != 1 {
			writeJSONError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized: %s missing or invalid", ProxyAuthHeader))
			return
		}
		next(w, r)
	}
}

// ----- OpenAI handlers -----

// handleChatCompletions routes /v1/chat/completions to the streaming
// pipeline or to forwardChatCompletion; both gate every tool call.
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r, s.cfg.MaxBufferBytes)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	var req ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if isStreamingRequest(r, req.Stream) {
		s.handleStreamingChatCompletion(w, r, body, &req)
		return
	}

	if err := s.forwardChatCompletion(r.Context(), w, r, body, &req); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Errorf("upstream error: %w", err))
	}
}

// handleLegacyCompletions routes /v1/completions. Legacy completions
// carry no tool calls; streaming still goes through the SSE runner.
func (s *Server) handleLegacyCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r, s.cfg.MaxBufferBytes)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	var probe struct {
		Stream bool `json:"stream,omitempty"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if isStreamingRequest(r, probe.Stream) {
		s.handleStreamingLegacyCompletion(w, r, body)
		return
	}

	if err := s.forwardOpenAI(r.Context(), w, r, body, "/v1/completions"); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Errorf("upstream error: %w", err))
	}
}

// handleStreamingLegacyCompletion streams /v1/completions through the
// OpenAI SSE runner. No tool_call deltas arrive, so every event passes
// through, with the same byte-identity and flush semantics as chat.
func (s *Server) handleStreamingLegacyCompletion(w http.ResponseWriter, r *http.Request, body []byte) {
	if !s.admitStream(w) {
		return
	}
	defer s.releaseStream()

	upstreamResp, err := s.dispatchStreamingUpstream(r.Context(), s.openaiURL, "/v1/completions", r.Header, body)
	if err != nil {
		s.streamingForwardError(w, err)
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode < 200 || upstreamResp.StatusCode >= 300 {
		s.copyStreamingResponseHeaders(w, upstreamResp)
		_, _ = io.Copy(w, upstreamResp.Body)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.streamingForwardError(w, errors.New("response writer does not support flushing"))
		return
	}
	s.copyStreamingResponseHeaders(w, upstreamResp)
	flusher.Flush()
	s.runOpenAIStreamLoop(w, flusher, r, upstreamResp.Body)
}

// handlePassThroughOpenAI forwards /v1/embeddings and /v1/models to
// the OpenAI upstream verbatim, ungated (no tool calls). The body is
// still capped by max-buffer-bytes; GET has none.
func (s *Server) handlePassThroughOpenAI(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r, s.cfg.MaxBufferBytes)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	if err := s.forwardOpenAI(r.Context(), w, r, body, r.URL.Path); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Errorf("upstream error: %w", err))
	}
}

// ----- Anthropic handler -----

// handleAnthropicMessages routes /v1/messages; it mirrors
// handleChatCompletions.
func (s *Server) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r, s.cfg.MaxBufferBytes)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	var req AnthropicMessagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if isStreamingRequest(r, req.Stream) {
		s.handleStreamingAnthropicMessages(w, r, body, &req)
		return
	}

	if err := s.forwardAnthropicMessages(r.Context(), w, r, body, &req); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Errorf("upstream error: %w", err))
	}
}

// ----- Helpers -----

// isStreamingRequest reports whether the body sets `stream: true` or
// Accept includes text/event-stream. SDKs differ in which one they
// set, so either suffices (docs/LLM_API_PROXY.md § 3.2).
func isStreamingRequest(r *http.Request, bodyStream bool) bool {
	if bodyStream {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(strings.ToLower(accept), "text/event-stream")
}

// errResponseCommitted tags an error raised after the status and part
// of the body were written. The only correct move is to stop writing
// and let the truncated body close; writeJSONError honors the tag.
var errResponseCommitted = errors.New("response already committed")

// writeJSONError writes an OpenAI/Anthropic-shaped error envelope so
// SDK error handling engages. It no-ops for errResponseCommitted,
// which would otherwise append the envelope to a partial body.
func writeJSONError(w http.ResponseWriter, status int, err error) {
	if errors.Is(err, errResponseCommitted) {
		log.Printf("llmproxy: %v (response already committed; closing without an error envelope)", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": err.Error(),
			"type":    "vanzik_error",
		},
	})
}

// writeBodyReadError maps readRequestBody errors to 413 (over cap) or 400.
func writeBodyReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		writeJSONError(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	writeJSONError(w, http.StatusBadRequest, fmt.Errorf("read request body: %w", err))
}

// readRequestBody returns errBodyTooLarge when the body exceeds
// maxBytes. It reads maxBytes+1 so "fits exactly" and "truncated" are
// distinguishable. A request with no body yields nil.
func readRequestBody(r *http.Request, maxBytes int) ([]byte, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, int64(maxBytes)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}

var errBodyTooLarge = errors.New("request body exceeds --max-buffer-bytes")

// Run builds a Server from cfg and runs it until ctx is cancelled.
func Run(ctx context.Context, cfg *Config) error {
	srv, err := NewServer(cfg)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}
