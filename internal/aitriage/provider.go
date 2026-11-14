package aitriage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/netguard"
)

// Prompt is exactly what is sent to the model.
type Prompt struct {
	System string `json:"system"`
	User   string `json:"user"`
}

// Provider asks a model to complete a prompt and returns its raw text answer.
type Provider interface {
	// Name is the AI_PROVIDER value; Model the model asked.
	Name() string
	Model() string
	Complete(ctx context.Context, p Prompt) (string, error)
}

// maxAnswerBytes bounds what is read from a provider.
const maxAnswerBytes = 1 << 20

// RemoteError is a provider failure. Its detail (the remote's own words) is
// shown to instance admins only; everyone else sees Public().
type RemoteError struct{ msg, detail string }

func (e RemoteError) Error() string {
	if e.detail == "" {
		return e.msg
	}
	return e.msg + ": " + e.detail
}

// Public is the message without the remote's own words.
func (e RemoteError) Public() string { return e.msg }

// NewProvider builds the configured provider; outbound calls go through
// netguard.
func NewProvider(c config.AI) (Provider, error) {
	client := netguard.NewClient(c.Timeout)
	switch c.Provider {
	case config.AIProviderOpenAI:
		return &OpenAI{BaseURL: c.BaseURL, ModelName: c.Model, APIKey: c.APIKey, Client: client}, nil
	case config.AIProviderAnthropic:
		base := c.BaseURL
		if base == "" {
			base = "https://api.anthropic.com"
		}
		return &Anthropic{BaseURL: base, ModelName: c.Model, APIKey: c.APIKey, Client: client}, nil
	}
	return nil, fmt.Errorf("unknown AI provider %q", c.Provider)
}

// post sends a JSON request and decodes a 2xx JSON answer into out.
func post(ctx context.Context, client *http.Client, url string, headers map[string]string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return RemoteError{msg: "the AI provider URL is invalid"}
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return RemoteError{msg: "the AI provider could not be reached", detail: err.Error()}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		return RemoteError{msg: "reading the AI provider's answer failed", detail: err.Error()}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return RemoteError{msg: fmt.Sprintf("the AI provider answered HTTP %d", resp.StatusCode), detail: snippet(data)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return RemoteError{msg: "the AI provider's answer is not the expected JSON", detail: snippet(data)}
	}
	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return s
}

// OpenAI speaks the OpenAI chat-completions protocol (POST
// {BaseURL}/chat/completions), which most hosted and self-hosted model
// servers implement. APIKey is optional (a local server may need none).
type OpenAI struct {
	BaseURL, ModelName, APIKey string
	Client                     *http.Client
}

// Name implements Provider.
func (o *OpenAI) Name() string { return config.AIProviderOpenAI }

// Model implements Provider.
func (o *OpenAI) Model() string { return o.ModelName }

// Complete implements Provider.
func (o *OpenAI) Complete(ctx context.Context, p Prompt) (string, error) {
	headers := map[string]string{}
	if o.APIKey != "" {
		headers["Authorization"] = "Bearer " + o.APIKey
	}
	body := map[string]any{
		"model": o.ModelName,
		"messages": []map[string]string{
			{"role": "system", "content": p.System},
			{"role": "user", "content": p.User},
		},
		"temperature":     0,
		"response_format": map[string]string{"type": "json_object"},
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := post(ctx, o.Client, o.BaseURL+"/chat/completions", headers, body, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", RemoteError{msg: "the AI provider returned no answer"}
	}
	return out.Choices[0].Message.Content, nil
}

// Anthropic speaks the Anthropic Messages API (POST {BaseURL}/v1/messages).
type Anthropic struct {
	BaseURL, ModelName, APIKey string
	Client                     *http.Client
}

// anthropicVersion is the Messages API version header.
const anthropicVersion = "2023-06-01"

// Name implements Provider.
func (a *Anthropic) Name() string { return config.AIProviderAnthropic }

// Model implements Provider.
func (a *Anthropic) Model() string { return a.ModelName }

// Complete implements Provider.
func (a *Anthropic) Complete(ctx context.Context, p Prompt) (string, error) {
	body := map[string]any{
		"model":       a.ModelName,
		"max_tokens":  2048,
		"temperature": 0,
		"system":      p.System,
		"messages":    []map[string]string{{"role": "user", "content": p.User}},
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	headers := map[string]string{"x-api-key": a.APIKey, "anthropic-version": anthropicVersion}
	if err := post(ctx, a.Client, a.BaseURL+"/v1/messages", headers, body, &out); err != nil {
		return "", err
	}
	var text strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	if text.Len() == 0 {
		return "", RemoteError{msg: "the AI provider returned no answer"}
	}
	return text.String(), nil
}

// Fake is a Provider for tests: it records every prompt and answers with
// Answer (or fails with Err) without any network.
type Fake struct {
	ModelName string
	Answer    string
	Err       error

	mu      sync.Mutex
	Prompts []Prompt
}

// Name implements Provider.
func (f *Fake) Name() string { return "fake" }

// Model implements Provider.
func (f *Fake) Model() string { return f.ModelName }

// Complete implements Provider.
func (f *Fake) Complete(_ context.Context, p Prompt) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Prompts = append(f.Prompts, p)
	if f.Err != nil {
		return "", f.Err
	}
	return f.Answer, nil
}

// Sent returns the prompts sent so far.
func (f *Fake) Sent() []Prompt {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Prompt(nil), f.Prompts...)
}
