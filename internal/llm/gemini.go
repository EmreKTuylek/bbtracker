// Package llm is a minimal native Gemini client: one generateContent call that
// returns JSON text. The API key travels in the x-goog-api-key header, never in
// the URL, so net/http errors (which embed the URL) can't leak it, and it is
// scrubbed from any error message anyway.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BaseURL is a var so tests can point it at httptest.
var BaseURL = "https://generativelanguage.googleapis.com/v1beta"

// RetryError marks a transient failure (429 / 5xx). After is the server's
// retry hint (0 if none given); callers apply their own backoff on top.
type RetryError struct {
	After time.Duration
	Msg   string
}

func (e *RetryError) Error() string { return e.Msg }

const maxResponseBytes = 4 << 20

// GenerateJSON asks model for a JSON object (responseMimeType application/json)
// and returns the raw JSON text. The schema is described in the prompt and
// validated by the caller: the docs conflict on responseSchema vs
// responseJsonSchema, so the native schema parameter is deliberately not used.
// Request/response bodies are never logged.
func GenerateJSON(ctx context.Context, apiKey, model, system, user string) (string, error) {
	model = strings.TrimPrefix(strings.TrimSpace(model), "models/")
	if apiKey == "" || model == "" {
		return "", fmt.Errorf("gemini api key and model name are required")
	}
	body, _ := json.Marshal(map[string]any{
		"systemInstruction": map[string]any{"parts": []map[string]string{{"text": system}}},
		"contents":          []map[string]any{{"role": "user", "parts": []map[string]string{{"text": user}}}},
		"generationConfig":  map[string]any{"responseMimeType": "application/json"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		BaseURL+"/models/"+url.PathEscape(model)+":generateContent", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)

	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
	if err != nil {
		return "", scrub(err.Error(), apiKey)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", scrub(err.Error(), apiKey)
	}

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Message string `json:"message"`
				Details []struct {
					RetryDelay string `json:"retryDelay"`
				} `json:"details"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := fmt.Sprintf("gemini: %s: %s", resp.Status, truncate(e.Error.Message, 300))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			after := time.Duration(0)
			for _, d := range e.Error.Details {
				if v, err := time.ParseDuration(d.RetryDelay); err == nil && v > after {
					after = v
				}
			}
			return "", &RetryError{After: after, Msg: scrub(msg, apiKey).Error()}
		}
		return "", scrub(msg, apiKey)
	}

	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		PromptFeedback struct {
			BlockReason string `json:"blockReason"`
		} `json:"promptFeedback"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("gemini: decode response: %w", err)
	}
	if len(out.Candidates) == 0 {
		return "", fmt.Errorf("gemini: no candidates (blockReason=%q)", out.PromptFeedback.BlockReason)
	}
	var sb strings.Builder
	for _, p := range out.Candidates[0].Content.Parts {
		sb.WriteString(p.Text)
	}
	text := strings.TrimSpace(sb.String())
	if text == "" {
		return "", fmt.Errorf("gemini: empty response (finishReason=%q)", out.Candidates[0].FinishReason)
	}
	return stripFence(text), nil
}

// stripFence removes a ```json ... ``` wrapper some models add despite the
// JSON mime type.
func stripFence(s string) string {
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

func scrub(msg, key string) error {
	if key != "" {
		msg = strings.ReplaceAll(msg, key, "****")
	}
	return fmt.Errorf("%s", msg)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
