package llmproxy

// SSE pause/resume/rewrite orchestrator (docs/LLM_API_PROXY.md § 5).
// Content deltas pass through byte-identical; tool-call deltas are held
// until the call is assembled and gated, then replayed byte-identical on
// ALLOW or replaced by a synthetic refusal. Each request owns its
// accumulator; nothing is shared between requests.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

// RefusalContext is the input to Server.BuildRefusal.
type RefusalContext struct {
	// Provider is "openai" or "anthropic".
	Provider string

	// OriginalToolCall is the denied call; zero when the refusal has no
	// single call (e.g. buffer overflow before one assembled).
	OriginalToolCall ToolCallCheck

	// AnthropicToolUseIndex is the content_block index of the tool_use
	// being replaced; -1 when unknown or for OpenAI.
	AnthropicToolUseIndex int

	// NonStreaming asks for one JSON response object instead of SSE
	// events; only the non-streaming forwarders set it.
	//
	// Model is the request's model, echoed so SDKs that index by model
	// don't fail on ""; empty becomes "vanzik-refusal".
	NonStreaming bool
	Model        string
}

// dispatchStreamingUpstream POSTs body upstream and returns the live
// response; the caller closes resp.Body.
func (s *Server) dispatchStreamingUpstream(
	ctx context.Context,
	upstream *url.URL,
	path string,
	srcHeader http.Header,
	body []byte,
) (*http.Response, error) {
	if upstream == nil {
		return nil, errors.New("upstream URL not configured")
	}
	target := *upstream
	target.Path = joinPath(upstream.Path, path)

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build streaming upstream request: %w", err)
	}
	copyForwardableHeaders(srcHeader, req.Header)
	rewriteUserAgent(req.Header, srcHeader.Get("User-Agent"))
	req.Host = upstream.Host

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("streaming upstream %s: %w", target.String(), err)
	}
	return resp, nil
}

// copyStreamingResponseHeaders writes the filtered upstream headers and
// status. X-Accel-Buffering: no stops intermediaries such as nginx from
// buffering SSE.
func (s *Server) copyStreamingResponseHeaders(w http.ResponseWriter, upstream *http.Response) {
	copyForwardableHeaders(upstream.Header, w.Header())
	if w.Header().Get("X-Accel-Buffering") == "" {
		w.Header().Set("X-Accel-Buffering", "no")
	}
	w.WriteHeader(upstream.StatusCode)
}

// streamingForwardError writes a 502 envelope. Only valid before any
// bytes are sent; after that it would corrupt the SSE stream.
func (s *Server) streamingForwardError(w http.ResponseWriter, err error) {
	writeJSONError(w, http.StatusBadGateway, fmt.Errorf("streaming proxy: %w", err))
}

// readSSEEvent returns the raw bytes of one SSE event, through its
// blank-line terminator. A partial trailing event comes back with
// io.EOF; callers should still dispatch it.
//
// Not bufio.Scanner: events can exceed its 64 KiB default. Not
// ReadBytes: it buffers a whole line before returning, so a giant
// newline-free blob would grow memory before the cap check. ReadSlice
// returns at most one buffer per call, so maxEventBytes is enforced
// every few KiB.
func readSSEEvent(r *bufio.Reader, maxEventBytes int) ([]byte, error) {
	var buf bytes.Buffer
	atLineStart := true
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			buf.Write(chunk)
			if maxEventBytes > 0 && buf.Len() > maxEventBytes {
				return buf.Bytes(), errSSEEventTooLarge
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			// Line longer than the reader's buffer; keep draining it.
			atLineStart = false
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && buf.Len() > 0 {
				return buf.Bytes(), io.EOF
			}
			return buf.Bytes(), err
		}
		// A blank line ends the event, but only when the chunk is the
		// whole line: the tail of an over-length line can be exactly "\n".
		wasLineStart := atLineStart
		atLineStart = true
		if wasLineStart && (bytes.Equal(chunk, []byte("\n")) || bytes.Equal(chunk, []byte("\r\n"))) {
			return buf.Bytes(), nil
		}
	}
}

var errSSEEventTooLarge = errors.New("sse event exceeded buffer cap")

// absoluteMaxBufferBytes bounds the streaming buffers when a Config
// built directly (tests, embedders) has MaxBufferBytes == 0, which
// ParseConfig would reject. Without it, an upstream that never ends an
// SSE event grows memory without bound. Any positive operator cap is
// used as-is.
const absoluteMaxBufferBytes = MaxConfigurableBufferBytes

// hardCappedBufferBytes maps a cap <= 0 to absoluteMaxBufferBytes.
func hardCappedBufferBytes(computed int) int {
	if computed <= 0 {
		return absoluteMaxBufferBytes
	}
	return computed
}

// runPolicyCheck invokes Server.PolicyCheck; nil means ALLOW.
func (s *Server) runPolicyCheck(ctx context.Context, tc ToolCallCheck) (Decision, error) {
	// SECURITY: refuse duplicate JSON keys. The gate sees a Go map
	// (last wins) while ALLOW replays the raw bytes, so a first-wins
	// executor would act on a value that was never gated. This is a
	// deny with nil error, so --fail-mode allow cannot override it.
	if hasDuplicateJSONKeys(tc.RawArguments) {
		return Decision{
			Allow:  false,
			Reason: "tool call arguments contain duplicate JSON keys (ambiguous to gate; refused)",
			Rule:   "deny:llm_api_proxy:duplicate_argument_key",
		}, nil
	}
	if s.PolicyCheck == nil {
		return Decision{Allow: true, Rule: "allow:llm_api_proxy:no_hook"}, nil
	}
	return s.PolicyCheck(ctx, &tc)
}

// buildRefusal calls Server.BuildRefusal, or defaultRefusalBytes if nil.
func (s *Server) buildRefusal(provider string, decision Decision, ctx *RefusalContext) []byte {
	if s.BuildRefusal != nil {
		return s.BuildRefusal(provider, decision, ctx)
	}
	return defaultRefusalBytes(provider, decision, ctx)
}

// defaultRefusalBytes is the minimal refusal used when
// Server.BuildRefusal is nil (tests); production wires BuildRefusalRich.
// It still closes the stream cleanly so SDKs don't hang. The OpenAI
// shape is assistant text + [DONE]: `role: "tool"` is not in the
// response schema and SDKs hang on the missing tool_call_id.
func defaultRefusalBytes(provider string, decision Decision, ctx *RefusalContext) []byte {
	msg := decision.Reason
	if msg == "" {
		msg = "tool call denied by Vanzik policy"
	}
	full := "Vanzik denied this action: " + msg

	if ctx != nil && ctx.NonStreaming {
		return defaultRefusalNonStreamingBytes(provider, full, ctx.Model)
	}

	switch provider {
	case "openai":
		quoted, _ := json.Marshal(full)
		event := fmt.Sprintf(
			`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":%s},"finish_reason":"stop"}]}`,
			string(quoted),
		)
		return []byte(event + "\n\n" + "data: [DONE]\n\n")

	case "anthropic":
		idx := 0
		if ctx != nil && ctx.AnthropicToolUseIndex >= 0 {
			idx = ctx.AnthropicToolUseIndex
		}
		quoted, _ := json.Marshal(full)
		// A text block at the tool_use's index, then stop_reason
		// "end_turn" so the SDK doesn't wait for a tool result.
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n", idx)
		fmt.Fprintf(&buf, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":%d,\"delta\":{\"type\":\"text_delta\",\"text\":%s}}\n\n", idx, string(quoted))
		fmt.Fprintf(&buf, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", idx)
		fmt.Fprintf(&buf, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n")
		fmt.Fprintf(&buf, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		return buf.Bytes()

	default:
		return []byte("data: {\"error\":\"vanzik refusal\"}\n\n")
	}
}

// defaultRefusalNonStreamingBytes is defaultRefusalBytes' single-JSON
// form: BuildRefusalRich's non-streaming shape with only the bare
// reason. Empty model becomes "vanzik-refusal".
func defaultRefusalNonStreamingBytes(provider, full, model string) []byte {
	if model == "" {
		model = "vanzik-refusal"
	}
	switch provider {
	case "openai":
		payload := map[string]interface{}{
			"id":      "vanzik-refusal",
			"object":  "chat.completion",
			"created": 0,
			"model":   model,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": full,
					},
					"finish_reason": "stop",
				},
			},
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return []byte(`{"id":"vanzik-refusal","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Vanzik refusal"},"finish_reason":"stop"}]}`)
		}
		return b
	case "anthropic":
		payload := map[string]interface{}{
			"id":    "vanzik-refusal",
			"type":  "message",
			"role":  "assistant",
			"model": model,
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": full,
				},
			},
			"stop_reason": "end_turn",
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return []byte(`{"id":"vanzik-refusal","type":"message","role":"assistant","content":[{"type":"text","text":"Vanzik refusal"}],"stop_reason":"end_turn"}`)
		}
		return b
	default:
		return []byte(`{"error":{"message":"vanzik refusal","type":"vanzik_error"}}`)
	}
}

// handleStreamingChatCompletion streams OpenAI chat completions. On
// ALLOW the client gets upstream's bytes unchanged: no JSON
// re-encoding, no whitespace changes, only hop-by-hop header
// filtering. admitStream refuses over-cap streams before upstream is
// contacted.
func (s *Server) handleStreamingChatCompletion(w http.ResponseWriter, r *http.Request, body []byte, _ *ChatCompletionRequest) {
	if !s.admitStream(w) {
		return
	}
	defer s.releaseStream()

	upstreamResp, err := s.dispatchStreamingUpstream(r.Context(), s.openaiURL, "/v1/chat/completions", r.Header, body)
	if err != nil {
		s.streamingForwardError(w, err)
		return
	}
	defer upstreamResp.Body.Close()

	// Non-2xx: pass the upstream error envelope through verbatim.
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
	flusher.Flush() // EventSource.onopen fires immediately

	s.runOpenAIStreamLoop(w, flusher, r, upstreamResp.Body)
}

// handleStreamingAnthropicMessages mirrors handleStreamingChatCompletion.
func (s *Server) handleStreamingAnthropicMessages(w http.ResponseWriter, r *http.Request, body []byte, _ *AnthropicMessagesRequest) {
	if !s.admitStream(w) {
		return
	}
	defer s.releaseStream()

	upstreamResp, err := s.dispatchStreamingUpstream(r.Context(), s.anthropicURL, "/v1/messages", r.Header, body)
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

	s.runAnthropicStreamLoop(w, flusher, r, upstreamResp.Body)
}

// runOpenAIStreamLoop reads upstream SSE events into a per-request
// accumulator and flushes, gates, or refuses per FeedResult.
func (s *Server) runOpenAIStreamLoop(w http.ResponseWriter, flusher http.Flusher, r *http.Request, body io.Reader) {
	acc := NewOpenAIToolCallAccumulator(hardCappedBufferBytes(s.cfg.MaxBufferBytes))
	reader := bufio.NewReader(body)

	for {
		event, err := readSSEEvent(reader, hardCappedBufferBytes(s.cfg.MaxBufferBytes*2))
		isEOF := errors.Is(err, io.EOF)
		isTooLarge := errors.Is(err, errSSEEventTooLarge)

		if isTooLarge {
			// A single event exceeded 2x the buffer cap.
			metrics.IncLLMProxyBufferOverflow("openai")
			decision := bufferOverflowDecision()
			refusal := s.buildRefusal("openai", decision,
				&RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
			_, _ = w.Write(refusal)
			flusher.Flush()
			name, id := acc.pendingIdentity()
			s.auditStreamRefusal(r, "openai", decision, name, id)
			return
		}

		if len(event) > 0 {
			result, ferr := acc.FeedEvent(event)
			if ferr != nil && !result.Completed && !isEOF {
				// Malformed non-completion delta: drop it rather than inject
				// bytes. Corruption that affects a decision surfaces at
				// completion, which fails closed below.
				continue
			}
			switch {
			case ferr != nil && result.Completed:
				// Completed call with invalid argument JSON (max_tokens
				// cutoff, or attacker-induced). Must deny, never drop:
				// dropping skips the gate and audit and strands the
				// accumulator, so every later event is lost at EOF.
				s.denyMalformedOpenAI(w, flusher, r, acc, result.CompletedToolCalls)
				// The refusal ended with its own [DONE]; the client must
				// not see a second one when upstream closes.
				w = dropDoneWriter{w}

			case result.ProtocolViolation:
				// A stream that cannot be gated without risking a bypass
				// (e.g. tool_calls on more than one choice): fail closed,
				// naming the defect.
				metrics.IncLLMProxyProtocolViolation("openai")
				decision := protocolViolationDecision("openai", result.violation)
				refusal := s.buildRefusal("openai", decision,
					&RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
				_, _ = w.Write(refusal)
				flusher.Flush()
				name, id := acc.pendingIdentity()
				s.auditStreamRefusal(r, "openai", decision, name, id)
				return

			case result.OverflowBufferBytes:
				metrics.IncLLMProxyBufferOverflow("openai")
				decision := bufferOverflowDecision()
				refusal := s.buildRefusal("openai", decision,
					&RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
				_, _ = w.Write(refusal)
				flusher.Flush()
				name, id := acc.pendingIdentity()
				s.auditStreamRefusal(r, "openai", decision, name, id)
				return

			case result.Completed:
				if !s.gateAndFlushOpenAI(w, flusher, r, acc, result.CompletedToolCalls) {
					return // refused; orchestrator stops reading
				}

			case result.PassThrough:
				_, _ = w.Write(event)
				flusher.Flush()

			case result.Accumulating:
				// Held in acc.bufferedEvents; closeOpenAIStreamAtEOF
				// finalizes them if the stream ends first.
			}
		}

		if isEOF {
			s.closeOpenAIStreamAtEOF(w, flusher, r, acc)
			return
		}
		if err != nil {
			// Bytes may already be sent, so no error envelope.
			return
		}
		if r.Context().Err() != nil {
			return
		}
	}
}

// gateAndFlushOpenAI gates each completed call. On all-ALLOW it replays
// the buffered events and returns true; otherwise it writes a refusal
// and returns false (the loop stops).
func (s *Server) gateAndFlushOpenAI(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *OpenAIToolCallAccumulator, calls []ToolCallCheck) bool {
	for i := range calls {
		calls[i].TenantID = s.cfg.TenantID
		calls[i].AgentID = strings.TrimSpace(r.Header.Get("X-Agent-ID"))
		if calls[i].AgentID == "" {
			calls[i].AgentID = "llm-proxy"
		}
		calls[i].SessionID = strings.TrimSpace(r.Header.Get("X-Session-ID"))
		calls[i].ParentSessionID = strings.TrimSpace(r.Header.Get(ParentSessionHeader))
		calls[i].ApprovalID = strings.TrimSpace(r.Header.Get(ApprovalIDHeader))
		calls[i].Stream = true
		decision, err := s.runPolicyCheck(r.Context(), calls[i])
		if err != nil {
			// The wired gate returns a Decision shaped by --fail-mode
			// (failModeDecision) alongside err; pass it on verbatim so the
			// operator's mode reaches the client-visible rule string.
			if s.cfg.FailMode == "allow" {
				continue
			}
			refusalDecision := decision
			if refusalDecision.Rule == "" {
				// Bare error (test shim): synthesise a decision that still
				// distinguishes the two closed modes.
				refusalDecision = Decision{
					Allow:  false,
					Reason: fmt.Sprintf("policy check unavailable: %v", err),
					Rule:   fallbackFailModeRule(s.cfg.FailMode),
				}
			}
			refusal := s.buildRefusal("openai", refusalDecision, &RefusalContext{Provider: "openai", OriginalToolCall: calls[i], AnthropicToolUseIndex: -1})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return false
		}
		if !decision.Allow {
			refusal := s.buildRefusal("openai", decision, &RefusalContext{
				Provider:              "openai",
				OriginalToolCall:      calls[i],
				AnthropicToolUseIndex: -1,
			})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return false
		}
	}
	for _, ev := range acc.BufferedEvents() {
		_, _ = w.Write(ev)
	}
	flusher.Flush()
	acc.Reset()
	return true
}

// bufferOverflowDecision is the verdict for buffered tool-call bytes
// exceeding --max-buffer-bytes. The Rule is stable for alerting.
func bufferOverflowDecision() Decision {
	return Decision{
		Allow:  false,
		Reason: "tool call arguments exceed gating buffer",
		Rule:   "deny:llm_api_proxy:buffer_overflow",
	}
}

// protocolViolationDecision names the accumulator-reported defect in
// Reason and Rule. The zero kind's per-provider text is a wire
// contract: keep it byte-identical.
func protocolViolationDecision(provider string, kind protocolViolationKind) Decision {
	switch kind {
	case violationOrphanedToolInput:
		return Decision{
			Allow:  false,
			Reason: "upstream tool_use stream is malformed (tool input outside any tool_use block); refused",
			Rule:   "deny:llm_api_proxy:orphaned_tool_input",
		}
	case violationMultiChoiceToolCalls:
		return Decision{
			Allow:  false,
			Reason: "upstream returned tool calls on multiple choices; refused",
			Rule:   "deny:llm_api_proxy:multi_choice_tool_calls",
		}
	default:
		if provider == "anthropic" {
			return Decision{
				Allow:  false,
				Reason: "upstream tool_use stream is malformed (interleaved or conflicting tool_use blocks); refused",
				Rule:   "deny:llm_api_proxy:tool_use_interleaved",
			}
		}
		return Decision{
			Allow:  false,
			Reason: "upstream tool_call stream is malformed; refused",
			Rule:   "deny:llm_api_proxy:tool_use_interleaved",
		}
	}
}

// closeOpenAIStreamAtEOF finalizes a tool call still buffered at EOF
// (dropped connection, or no terminal finish_reason). The buffered
// bytes are ungated: dropping them skips gate and audit, flushing them
// is a bypass. So they take the same path a finish_reason would:
// truncated arguments get the malformed refusal, complete ones are
// gated and replayed only on ALLOW.
func (s *Server) closeOpenAIStreamAtEOF(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *OpenAIToolCallAccumulator) {
	result, ferr := acc.CloseAtEOF()
	if !result.Completed {
		return
	}
	if ferr != nil {
		s.denyMalformedOpenAI(w, flusher, r, acc, result.CompletedToolCalls)
		return
	}
	s.gateAndFlushOpenAI(w, flusher, r, acc, result.CompletedToolCalls)
}

// closeAnthropicStreamAtEOF mirrors closeOpenAIStreamAtEOF for a
// tool_use block still open at EOF.
func (s *Server) closeAnthropicStreamAtEOF(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *AnthropicAccumulator) {
	result, ferr := acc.CloseAtEOF()
	if !result.Completed {
		return
	}
	if ferr != nil {
		s.denyMalformedAnthropic(w, flusher, r, acc, result.CompletedToolCalls)
		return
	}
	s.gateAndFlushAnthropic(w, flusher, r, acc, result.CompletedToolCalls)
}

// auditStreamRefusal records a structural refusal (ungateable stream
// shape, buffer cap) in the central audit trail. The gate never ran for
// these, so without this the only trace is a process-local counter with
// no scrape endpoint. The tool identity is often empty (no call
// assembled); rule, tenant, agent and provider still make it
// diagnosable.
//
// Called after the client is served, so no refusal waits on the audit
// round trip (the malformed-completion path audits first). Best-effort:
// a failure never changes what the client received.
func (s *Server) auditStreamRefusal(r *http.Request, provider string, decision Decision, toolName, toolCallID string) {
	call := ToolCallCheck{
		Provider:        provider,
		ToolName:        toolName,
		ToolCallID:      toolCallID,
		TenantID:        s.cfg.TenantID,
		AgentID:         strings.TrimSpace(r.Header.Get("X-Agent-ID")),
		SessionID:       strings.TrimSpace(r.Header.Get("X-Session-ID")),
		ParentSessionID: strings.TrimSpace(r.Header.Get(ParentSessionHeader)),
		Stream:          true,
	}
	if call.AgentID == "" {
		call.AgentID = "llm-proxy"
	}
	if s.RecordForcedAudit != nil {
		s.RecordForcedAudit(r.Context(), &call, decision)
		return
	}
	// No hook (tests, embedders): /v1/check still writes an entry, but
	// with the engine verdict rather than the refusal.
	_, _ = s.runPolicyCheck(r.Context(), call)
}

// malformedToolCallDecision is the verdict for a completed tool call
// whose arguments are not valid JSON (max_tokens truncation, or
// attacker-induced). The Rule is stable for alerting.
func malformedToolCallDecision() Decision {
	return Decision{
		Allow:  false,
		Reason: "malformed tool call arguments — refused",
		Rule:   "deny:llm_api_proxy:malformed_tool_call",
	}
}

// auditMalformedToolCalls records the malformed_tool_call DENY the
// client received via RecordForcedAudit, not the engine verdict
// /v1/check would log for the garbage arguments. With a nil hook it
// falls back to auditDeniedToolCalls. Identity fields match
// gateAndFlush* so the entry is attributed like a normal deny.
func (s *Server) auditMalformedToolCalls(r *http.Request, calls []ToolCallCheck) {
	if s.RecordForcedAudit == nil {
		s.auditDeniedToolCalls(r, calls)
		return
	}
	decision := malformedToolCallDecision()
	for i := range calls {
		calls[i].TenantID = s.cfg.TenantID
		calls[i].AgentID = strings.TrimSpace(r.Header.Get("X-Agent-ID"))
		if calls[i].AgentID == "" {
			calls[i].AgentID = "llm-proxy"
		}
		calls[i].SessionID = strings.TrimSpace(r.Header.Get("X-Session-ID"))
		calls[i].ParentSessionID = strings.TrimSpace(r.Header.Get(ParentSessionHeader))
		calls[i].Stream = true
		s.RecordForcedAudit(r.Context(), &calls[i], decision)
	}
}

// auditDeniedToolCalls is auditMalformedToolCalls' nil-hook fallback.
// It runs PolicyCheck only for the audit entry /v1/check writes; the
// verdict is ignored because the caller refuses regardless. That entry
// carries the engine verdict (often ALLOW), not the client's DENY.
func (s *Server) auditDeniedToolCalls(r *http.Request, calls []ToolCallCheck) {
	for i := range calls {
		calls[i].TenantID = s.cfg.TenantID
		calls[i].AgentID = strings.TrimSpace(r.Header.Get("X-Agent-ID"))
		if calls[i].AgentID == "" {
			calls[i].AgentID = "llm-proxy"
		}
		calls[i].SessionID = strings.TrimSpace(r.Header.Get("X-Session-ID"))
		calls[i].ParentSessionID = strings.TrimSpace(r.Header.Get(ParentSessionHeader))
		calls[i].Stream = true
		_, _ = s.runPolicyCheck(r.Context(), calls[i])
	}
}

// denyMalformedOpenAI handles a completed tool call with invalid
// argument JSON: audit, write the malformed_tool_call refusal in place
// of the buffered events, and reset the accumulator. Unlike other
// denies it keeps reading upstream, so a later valid call is still
// gated.
func (s *Server) denyMalformedOpenAI(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *OpenAIToolCallAccumulator, calls []ToolCallCheck) {
	s.auditMalformedToolCalls(r, calls)
	var original ToolCallCheck
	if len(calls) > 0 {
		original = calls[0]
	}
	refusal := s.buildRefusal("openai", malformedToolCallDecision(), &RefusalContext{
		Provider:              "openai",
		OriginalToolCall:      original,
		AnthropicToolUseIndex: -1,
	})
	_, _ = w.Write(refusal)
	flusher.Flush()
	acc.Reset()
}

// dropDoneWriter swallows a write that is exactly one OpenAI `[DONE]`
// event. After a malformed-tool-call refusal (which ends in its own
// `[DONE]`) the loop keeps reading, and upstream's terminator would be
// a second one. Upstream events are written one per Write, so the
// match is exact.
type dropDoneWriter struct {
	http.ResponseWriter
}

func (d dropDoneWriter) Write(p []byte) (int, error) {
	if _, isDone, _ := extractOpenAIDataLine(p); isDone {
		return len(p), nil
	}
	return d.ResponseWriter.Write(p)
}

// dropAnthropicCloseWriter is dropDoneWriter for Anthropic: it swallows
// a single `message_delta` or `message_stop` event. A synthetic refusal
// is one Write of several events, so it never matches.
type dropAnthropicCloseWriter struct {
	http.ResponseWriter
}

func (d dropAnthropicCloseWriter) Write(p []byte) (int, error) {
	if dataLine, hasData := extractAnthropicDataLine(p); hasData {
		var env anthropicEventEnvelope
		if json.Unmarshal(dataLine, &env) == nil && (env.Type == "message_delta" || env.Type == "message_stop") {
			return len(p), nil
		}
	}
	return d.ResponseWriter.Write(p)
}

// fallbackFailModeRule gives the rule when PolicyCheck returns an error
// with no Decision (test shims; the wired gate uses failModeDecision).
// It uses the FailModeRule* constants so the dashboard sees the same
// rule strings either way.
func fallbackFailModeRule(failMode string) string {
	switch strings.ToLower(failMode) {
	case "fail-closed-with-audit":
		return FailModeRuleClosedAudit
	default:
		return FailModeRuleClosed
	}
}

// runAnthropicStreamLoop mirrors runOpenAIStreamLoop.
func (s *Server) runAnthropicStreamLoop(w http.ResponseWriter, flusher http.Flusher, r *http.Request, body io.Reader) {
	acc := NewAnthropicAccumulator(hardCappedBufferBytes(s.cfg.MaxBufferBytes))
	reader := bufio.NewReader(body)

	for {
		event, err := readSSEEvent(reader, hardCappedBufferBytes(s.cfg.MaxBufferBytes*2))
		isEOF := errors.Is(err, io.EOF)
		isTooLarge := errors.Is(err, errSSEEventTooLarge)

		if isTooLarge {
			metrics.IncLLMProxyBufferOverflow("anthropic")
			decision := bufferOverflowDecision()
			refusal := s.buildRefusal("anthropic", decision,
				&RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: acc.ActiveToolUseIndex()})
			_, _ = w.Write(refusal)
			flusher.Flush()
			name, id := acc.pendingIdentity()
			s.auditStreamRefusal(r, "anthropic", decision, name, id)
			return
		}

		if len(event) > 0 {
			result, ferr := acc.FeedEvent(event)
			if ferr != nil && !result.Completed && !isEOF {
				// As in the OpenAI loop: drop malformed non-completion deltas.
				continue
			}
			switch {
			case ferr != nil && result.Completed:
				s.denyMalformedAnthropic(w, flusher, r, acc, result.CompletedToolCalls)
				// The refusal ended with its own message_delta and
				// message_stop; the client must not see upstream's too.
				w = dropAnthropicCloseWriter{w}

			case result.ProtocolViolation:
				// SECURITY: interleaved tool_use, start input conflicting
				// with deltas, or input with no block open cannot be gated
				// safely: discard the buffer and refuse.
				metrics.IncLLMProxyProtocolViolation("anthropic")
				decision := protocolViolationDecision("anthropic", result.violation)
				refusal := s.buildRefusal("anthropic", decision,
					&RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: acc.ActiveToolUseIndex()})
				_, _ = w.Write(refusal)
				flusher.Flush()
				name, id := acc.pendingIdentity()
				s.auditStreamRefusal(r, "anthropic", decision, name, id)
				return

			case result.OverflowBufferBytes:
				metrics.IncLLMProxyBufferOverflow("anthropic")
				decision := bufferOverflowDecision()
				refusal := s.buildRefusal("anthropic", decision,
					&RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: acc.ActiveToolUseIndex()})
				_, _ = w.Write(refusal)
				flusher.Flush()
				name, id := acc.pendingIdentity()
				s.auditStreamRefusal(r, "anthropic", decision, name, id)
				return

			case result.Completed:
				if !s.gateAndFlushAnthropic(w, flusher, r, acc, result.CompletedToolCalls) {
					return
				}

			case result.PassThrough:
				_, _ = w.Write(event)
				flusher.Flush()

			case result.Accumulating:
				// Held; closeAnthropicStreamAtEOF finalizes them.
			}
		}

		if isEOF {
			s.closeAnthropicStreamAtEOF(w, flusher, r, acc)
			return
		}
		if err != nil {
			return
		}
		if r.Context().Err() != nil {
			return
		}
	}
}

// gateAndFlushAnthropic mirrors gateAndFlushOpenAI for Anthropic.
func (s *Server) gateAndFlushAnthropic(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *AnthropicAccumulator, calls []ToolCallCheck) bool {
	for i := range calls {
		calls[i].TenantID = s.cfg.TenantID
		calls[i].AgentID = strings.TrimSpace(r.Header.Get("X-Agent-ID"))
		if calls[i].AgentID == "" {
			calls[i].AgentID = "llm-proxy"
		}
		calls[i].SessionID = strings.TrimSpace(r.Header.Get("X-Session-ID"))
		calls[i].ParentSessionID = strings.TrimSpace(r.Header.Get(ParentSessionHeader))
		calls[i].ApprovalID = strings.TrimSpace(r.Header.Get(ApprovalIDHeader))
		calls[i].Stream = true
		decision, err := s.runPolicyCheck(r.Context(), calls[i])
		if err != nil {
			// Fail-mode handling as in gateAndFlushOpenAI.
			if s.cfg.FailMode == "allow" {
				continue
			}
			refusalDecision := decision
			if refusalDecision.Rule == "" {
				refusalDecision = Decision{
					Allow:  false,
					Reason: fmt.Sprintf("policy check unavailable: %v", err),
					Rule:   fallbackFailModeRule(s.cfg.FailMode),
				}
			}
			refusal := s.buildRefusal("anthropic", refusalDecision, &RefusalContext{Provider: "anthropic", OriginalToolCall: calls[i], AnthropicToolUseIndex: acc.ActiveToolUseIndex()})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return false
		}
		if !decision.Allow {
			refusal := s.buildRefusal("anthropic", decision, &RefusalContext{
				Provider:              "anthropic",
				OriginalToolCall:      calls[i],
				AnthropicToolUseIndex: acc.ActiveToolUseIndex(),
			})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return false
		}
	}
	for _, ev := range acc.BufferedEvents() {
		_, _ = w.Write(ev)
	}
	flusher.Flush()
	acc.Reset()
	return true
}

// denyMalformedAnthropic mirrors denyMalformedOpenAI. The refusal
// reuses the tool_use's block index, read before the reset.
func (s *Server) denyMalformedAnthropic(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *AnthropicAccumulator, calls []ToolCallCheck) {
	s.auditMalformedToolCalls(r, calls)
	var original ToolCallCheck
	if len(calls) > 0 {
		original = calls[0]
	}
	refusal := s.buildRefusal("anthropic", malformedToolCallDecision(), &RefusalContext{
		Provider:              "anthropic",
		OriginalToolCall:      original,
		AnthropicToolUseIndex: acc.ActiveToolUseIndex(),
	})
	_, _ = w.Write(refusal)
	flusher.Flush()
	acc.Reset()
}
