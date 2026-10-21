package llmproxy

// Non-streaming forward path. The gated forwarders buffer the upstream
// response (bounded by --max-buffer-bytes), gate every tool call, and
// either forward the upstream bytes unchanged (all ALLOW) or replace the
// whole response with a 200 synthetic refusal. Nothing of a denied
// response is kept: partial content would leak the model's reasoning
// behind the denied call.

import (
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

// hopByHopHeaders are never forwarded (RFC 7230 § 6.1). Host is also
// dropped (an explicit Host breaks upstream routing) and Content-Length
// (net/http computes its own; sending both confuses chunked-vs-fixed
// negotiation on some intermediaries).
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	"Host":                {},
	"Content-Length":      {},
}

// forwardOpenAI forwards body verbatim to the OpenAI upstream at path,
// ungated. Only for endpoints without tool calls (/v1/embeddings,
// /v1/models, /v1/completions); chat goes through forwardChatCompletion.
func (s *Server) forwardOpenAI(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, path string) error {
	return s.forwardTo(ctx, w, r, body, s.openaiURL, path)
}

// forwardChatCompletion is the gated non-streaming /v1/chat/completions
// forwarder.
func (s *Server) forwardChatCompletion(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, req *ChatCompletionRequest) error {
	return s.forwardWithToolCallGating(ctx, w, r, body, s.openaiURL, "/v1/chat/completions", "openai", req.Model)
}

// forwardAnthropicMessages is the gated non-streaming /v1/messages
// forwarder.
func (s *Server) forwardAnthropicMessages(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, req *AnthropicMessagesRequest) error {
	return s.forwardWithToolCallGating(ctx, w, r, body, s.anthropicURL, "/v1/messages", "anthropic", req.Model)
}

// forwardWithToolCallGating is the shared gated forwarder. provider
// ("openai" or "anthropic") selects the parser and refusal shape;
// reqModel is echoed in a synthetic refusal. Errors are returned only
// before anything is written (the caller sends 502); after that they
// are swallowed.
func (s *Server) forwardWithToolCallGating(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	body []byte,
	upstream *url.URL,
	path string,
	provider string,
	reqModel string,
) error {
	if upstream == nil {
		return errors.New("upstream URL not configured")
	}

	target := *upstream
	target.Path = joinPath(upstream.Path, path)
	target.RawQuery = r.URL.RawQuery

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("build upstream request: %w", err)
	}
	copyForwardableHeaders(r.Header, upstreamReq.Header)
	rewriteUserAgent(upstreamReq.Header, r.Header.Get("User-Agent"))
	upstreamReq.Host = upstream.Host

	resp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("upstream %s: %w", target.String(), err)
	}
	defer resp.Body.Close()

	// Non-2xx passes through verbatim so SDK retry/rate-limit logic sees
	// the upstream's error envelope.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		copyForwardableHeaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)
		if _, copyErr := io.Copy(w, resp.Body); copyErr != nil {
			return fmt.Errorf("copy upstream error body: %w", copyErr)
		}
		return nil
	}

	// Read cap+1 bytes so "exactly cap" and "overflowed" differ.
	cap := s.cfg.MaxBufferBytes
	if cap <= 0 {
		cap = DefaultMaxBufferBytes
	}
	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(cap)+1))
	if readErr != nil {
		return fmt.Errorf("read upstream body: %w", readErr)
	}

	if len(bodyBytes) > cap {
		// Too large to inspect for tool calls: refuse rather than
		// forward ungated.
		metrics.IncLLMProxyNonStreamingOverflow(provider)
		decision := Decision{
			Allow:  false,
			Reason: fmt.Sprintf("upstream non-streaming response exceeds gating buffer (--max-buffer-bytes=%d)", cap),
			Rule:   "deny:llm_api_proxy:non_streaming_buffer_overflow",
		}
		writeNonStreamingRefusal(s, w, resp.Header, provider, decision, ToolCallCheck{Provider: provider}, reqModel)
		return nil
	}

	// Malformed JSON passes through verbatim with the upstream status,
	// except a body that still carries a tool call: Go rejects a
	// type-mismatched field that a lenient client SDK ignores, so "we
	// can't decode it" does not mean "the client can't execute it".
	// hasLenientToolCall runs only on this failure branch, so normal
	// bodies pay nothing for it.
	switch provider {
	case "openai":
		var parsed ChatCompletionResponse
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			if hasLenientToolCall(bodyBytes, "openai") {
				metrics.IncLLMProxyUndecodableToolCall("openai")
				s.auditUndecodableToolCall(r, "openai", reqModel)
				decision := undecodableToolCallDecision("openai")
				writeNonStreamingRefusal(s, w, resp.Header, "openai", decision, ToolCallCheck{Provider: "openai"}, reqModel)
				return nil
			}
			passThroughResponse(w, resp.Header, resp.StatusCode, bodyBytes)
			return nil
		}
		decision, denied, denyCall := s.gateOpenAINonStreaming(ctx, r, &parsed)
		if denied {
			writeNonStreamingRefusal(s, w, resp.Header, "openai", decision, denyCall, reqModel)
			return nil
		}
	case "anthropic":
		var parsed AnthropicMessagesResponse
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			if hasLenientToolCall(bodyBytes, "anthropic") {
				metrics.IncLLMProxyUndecodableToolCall("anthropic")
				s.auditUndecodableToolCall(r, "anthropic", reqModel)
				decision := undecodableToolCallDecision("anthropic")
				writeNonStreamingRefusal(s, w, resp.Header, "anthropic", decision, ToolCallCheck{Provider: "anthropic"}, reqModel)
				return nil
			}
			passThroughResponse(w, resp.Header, resp.StatusCode, bodyBytes)
			return nil
		}
		decision, denied, denyCall := s.gateAnthropicNonStreaming(ctx, r, &parsed)
		if denied {
			writeNonStreamingRefusal(s, w, resp.Header, "anthropic", decision, denyCall, reqModel)
			return nil
		}
	}

	// All ALLOW: forward byte-identical (no re-encoding).
	passThroughResponse(w, resp.Header, resp.StatusCode, bodyBytes)
	return nil
}

// passThroughResponse writes the upstream status and body byte-identical,
// with headers filtered by copyForwardableHeaders.
func passThroughResponse(w http.ResponseWriter, srcHeader http.Header, status int, body []byte) {
	copyForwardableHeaders(srcHeader, w.Header())
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeNonStreamingRefusal writes a provider-shaped synthetic refusal
// with HTTP 200. Not 4xx/5xx: SDKs turn non-2xx into client-side errors
// that never show the refusal text to the agent. The deny is carried by
// the assistant text and finish_reason=stop / stop_reason=end_turn.
func writeNonStreamingRefusal(
	s *Server,
	w http.ResponseWriter,
	srcHeader http.Header,
	provider string,
	decision Decision,
	originalCall ToolCallCheck,
	model string,
) {
	// The refusal's length differs from the upstream body's.
	copyForwardableHeaders(srcHeader, w.Header())
	w.Header().Del("Content-Length")
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}

	refusal := s.buildRefusal(provider, decision, &RefusalContext{
		Provider:              provider,
		OriginalToolCall:      originalCall,
		AnthropicToolUseIndex: -1,
		NonStreaming:          true,
		Model:                 model,
	})

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(refusal)
}

// gateOpenAINonStreaming gates choices[*].message.tool_calls and stops
// at the first non-ALLOW, returning denied=true and that call. The
// caller then replaces the whole response, so no ALLOWed sibling's
// arguments reach the agent.
func (s *Server) gateOpenAINonStreaming(
	ctx context.Context,
	r *http.Request,
	resp *ChatCompletionResponse,
) (Decision, bool, ToolCallCheck) {
	for _, choice := range resp.Choices {
		for i := range choice.Message.ToolCalls {
			tc := &choice.Message.ToolCalls[i]
			check := buildOpenAINonStreamingCheck(s, r, resp, tc)
			decision, err := s.runPolicyCheck(ctx, check)
			if err != nil {
				if strings.EqualFold(s.cfg.FailMode, "allow") {
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
				return refusalDecision, true, check
			}
			if !decision.Allow {
				return decision, true, check
			}
		}
	}
	return Decision{Allow: true}, false, ToolCallCheck{}
}

// buildOpenAINonStreamingCheck matches the streaming path's check
// (gateAndFlushOpenAI) so PolicyCheck sees identical inputs either way.
func buildOpenAINonStreamingCheck(s *Server, r *http.Request, resp *ChatCompletionResponse, tc *ChatCompletionToolCallEcho) ToolCallCheck {
	var args map[string]interface{}
	if len(tc.Function.Arguments) > 0 {
		// Invalid JSON leaves args nil, as in the streaming accumulator.
		_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
	}
	agent := strings.TrimSpace(r.Header.Get("X-Agent-ID"))
	if agent == "" {
		agent = "llm-proxy"
	}
	return ToolCallCheck{
		Provider:        "openai",
		ToolName:        tc.Function.Name,
		ToolCallID:      tc.ID,
		Arguments:       args,
		RawArguments:    json.RawMessage(tc.Function.Arguments),
		AgentID:         agent,
		SessionID:       strings.TrimSpace(r.Header.Get("X-Session-ID")),
		ParentSessionID: strings.TrimSpace(r.Header.Get(ParentSessionHeader)),
		ApprovalID:      strings.TrimSpace(r.Header.Get(ApprovalIDHeader)),
		TenantID:        s.cfg.TenantID,
		Model:           resp.Model,
		Stream:          false,
	}
}

// gateAnthropicNonStreaming gates content[] tool_use blocks, stopping
// at the first non-ALLOW like gateOpenAINonStreaming.
func (s *Server) gateAnthropicNonStreaming(
	ctx context.Context,
	r *http.Request,
	resp *AnthropicMessagesResponse,
) (Decision, bool, ToolCallCheck) {
	for i := range resp.Content {
		block := &resp.Content[i]
		if block.Type != "tool_use" {
			continue
		}
		check := buildAnthropicNonStreamingCheck(s, r, resp, block)
		decision, err := s.runPolicyCheck(ctx, check)
		if err != nil {
			if strings.EqualFold(s.cfg.FailMode, "allow") {
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
			return refusalDecision, true, check
		}
		if !decision.Allow {
			return decision, true, check
		}
	}
	return Decision{Allow: true}, false, ToolCallCheck{}
}

// buildAnthropicNonStreamingCheck builds the check for one tool_use block.
func buildAnthropicNonStreamingCheck(s *Server, r *http.Request, resp *AnthropicMessagesResponse, block *AnthropicContentBlock) ToolCallCheck {
	var args map[string]interface{}
	if len(block.Input) > 0 {
		_ = json.Unmarshal(block.Input, &args)
	}
	agent := strings.TrimSpace(r.Header.Get("X-Agent-ID"))
	if agent == "" {
		agent = "llm-proxy"
	}
	return ToolCallCheck{
		Provider:        "anthropic",
		ToolName:        block.Name,
		ToolCallID:      block.ID,
		Arguments:       args,
		RawArguments:    block.Input,
		AgentID:         agent,
		SessionID:       strings.TrimSpace(r.Header.Get("X-Session-ID")),
		ParentSessionID: strings.TrimSpace(r.Header.Get(ParentSessionHeader)),
		ApprovalID:      strings.TrimSpace(r.Header.Get(ApprovalIDHeader)),
		TenantID:        s.cfg.TenantID,
		Model:           resp.Model,
		Stream:          false,
	}
}

// forwardTo is the ungated verbatim forwarder (header rules:
// docs/LLM_API_PROXY.md § 3.1).
func (s *Server) forwardTo(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, upstream *url.URL, path string) error {
	if upstream == nil {
		return errors.New("upstream URL not configured")
	}

	target := *upstream
	target.Path = joinPath(upstream.Path, path)
	target.RawQuery = r.URL.RawQuery

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("build upstream request: %w", err)
	}

	copyForwardableHeaders(r.Header, req.Header)
	rewriteUserAgent(req.Header, r.Header.Get("User-Agent"))

	req.Host = upstream.Host

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("upstream %s: %w", target.String(), err)
	}
	defer resp.Body.Close()

	copyForwardableHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		// Headers and part of the body are already sent; the tag makes
		// writeJSONError skip the envelope.
		return fmt.Errorf("copy response body: %w: %w", errResponseCommitted, err)
	}
	return nil
}

// copyForwardableHeaders copies src into dst minus hop-by-hop headers
// and the inbound-only ProxyAuthHeader and ApprovalIDHeader.
// Authorization is forwarded; the proxy never reads it.
func copyForwardableHeaders(src, dst http.Header) {
	for k, vs := range src {
		if _, hop := hopByHopHeaders[http.CanonicalHeaderKey(k)]; hop {
			continue
		}
		if http.CanonicalHeaderKey(k) == http.CanonicalHeaderKey(ProxyAuthHeader) {
			continue
		}
		if http.CanonicalHeaderKey(k) == http.CanonicalHeaderKey(ApprovalIDHeader) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// rewriteUserAgent prefixes the proxy's identity, keeping the original
// UA as a suffix for upstream logs.
func rewriteUserAgent(h http.Header, original string) {
	original = strings.TrimSpace(original)
	if original == "" {
		h.Set("User-Agent", "vanzik-llm-proxy/"+BuildVersion)
		return
	}
	h.Set("User-Agent", "vanzik-llm-proxy/"+BuildVersion+" "+original)
}

// joinPath joins URL paths without doubling "/"; both empty gives "/".
func joinPath(base, route string) string {
	switch {
	case base == "" || base == "/":
		if route == "" {
			return "/"
		}
		return route
	case route == "":
		return base
	default:
		bTrim := strings.TrimSuffix(base, "/")
		rTrim := route
		if !strings.HasPrefix(rTrim, "/") {
			rTrim = "/" + rTrim
		}
		return bTrim + rTrim
	}
}
