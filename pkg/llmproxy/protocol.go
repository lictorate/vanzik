package llmproxy

// Request/response types for inspection only: bodies are forwarded as
// the original bytes and never re-encoded, so untyped fields survive.
// Streaming shapes live in the SSE parsers.
//
// References:
//   - https://platform.openai.com/docs/api-reference/chat/create
//   - https://platform.claude.com/docs/en/api/messages

import (
	"encoding/json"
)

// ----- OpenAI Chat Completions -----

// ChatCompletionRequest is the OpenAI /v1/chat/completions request
// body, typed only as deep as the proxy reads.
type ChatCompletionRequest struct {
	Model    string               `json:"model"`
	Stream   bool                 `json:"stream,omitempty"`
	Messages []json.RawMessage    `json:"messages,omitempty"`
	Tools    []ChatCompletionTool `json:"tools,omitempty"`
}

// ChatCompletionTool is one element of the request's `tools` array.
type ChatCompletionTool struct {
	Type     string                 `json:"type"`
	Function ChatCompletionToolFunc `json:"function"`
}

// ChatCompletionToolFunc is a function-tool definition.
type ChatCompletionToolFunc struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ChatCompletionResponse is the non-streaming chat response.
type ChatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []ChatCompletionChoice `json:"choices"`
	Usage   *ChatCompletionUsage   `json:"usage,omitempty"`
}

// ChatCompletionChoice is one candidate in the response.
type ChatCompletionChoice struct {
	Index        int                   `json:"index"`
	Message      ChatCompletionMessage `json:"message"`
	FinishReason string                `json:"finish_reason"`
}

// ChatCompletionMessage is the assistant turn; Content is null when
// there are tool calls.
type ChatCompletionMessage struct {
	Role      string                       `json:"role"`
	Content   *string                      `json:"content,omitempty"`
	ToolCalls []ChatCompletionToolCallEcho `json:"tool_calls,omitempty"`
}

// ChatCompletionToolCallEcho is a tool call in a response.
type ChatCompletionToolCallEcho struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function ChatCompletionToolEcho `json:"function"`
}

// ChatCompletionToolEcho is a tool call's function. Arguments is a
// string holding JSON, parsed only at the gate.
type ChatCompletionToolEcho struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatCompletionUsage is the token-usage report.
type ChatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ----- Anthropic Messages -----

// AnthropicMessagesRequest is the /v1/messages request body, typed
// only as deep as the proxy reads.
type AnthropicMessagesRequest struct {
	Model    string            `json:"model"`
	Stream   bool              `json:"stream,omitempty"`
	Messages []json.RawMessage `json:"messages,omitempty"`
	Tools    []AnthropicTool   `json:"tools,omitempty"`
}

// AnthropicTool describes one tool the model can call.
type AnthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// AnthropicMessagesResponse is the non-streaming messages response.
type AnthropicMessagesResponse struct {
	ID         string                  `json:"id"`
	Type       string                  `json:"type"`
	Role       string                  `json:"role"`
	Model      string                  `json:"model"`
	Content    []AnthropicContentBlock `json:"content"`
	StopReason string                  `json:"stop_reason"`
	Usage      *AnthropicUsage         `json:"usage,omitempty"`
}

// AnthropicContentBlock is one content block; only tool_use is gated.
type AnthropicContentBlock struct {
	Type string `json:"type"`

	// type=="text"
	Text string `json:"text,omitempty"`

	// type=="tool_use"
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

// AnthropicUsage mirrors the Anthropic billing report.
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
