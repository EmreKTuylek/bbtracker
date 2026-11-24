package llm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fake(t *testing.T, status int, body string) func() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-goog-api-key") != "SECRET" || r.URL.RawQuery != "" {
			t.Errorf("key must be in header only; query=%q", r.URL.RawQuery)
		}
		if !strings.HasSuffix(r.URL.Path, "/models/m1:generateContent") {
			t.Errorf("bad path %s", r.URL.Path)
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	old := BaseURL
	BaseURL = srv.URL
	return func() { BaseURL = old; srv.Close() }
}

func TestGenerateJSONOK(t *testing.T) {
	defer fake(t, 200, "{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"```json\\n{\\\"a\\\":1}\\n```\"}]}}]}")()
	got, err := GenerateJSON(context.Background(), "SECRET", "models/m1", "sys", "user")
	if err != nil || got != `{"a":1}` {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestGenerateJSONRateLimit(t *testing.T) {
	defer fake(t, 429, `{"error":{"message":"quota SECRET","details":[{"retryDelay":"12s"}]}}`)()
	_, err := GenerateJSON(context.Background(), "SECRET", "m1", "s", "u")
	var re *RetryError
	if !errors.As(err, &re) || re.After != 12*time.Second {
		t.Fatalf("want RetryError 12s, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("key leaked in error: %v", err)
	}
}

func TestGenerateJSONAuthErrorNotRetryable(t *testing.T) {
	defer fake(t, 400, `{"error":{"message":"API key not valid"}}`)()
	_, err := GenerateJSON(context.Background(), "SECRET", "m1", "s", "u")
	var re *RetryError
	if err == nil || errors.As(err, &re) {
		t.Fatalf("want non-retryable error, got %v", err)
	}
}

func TestGenerateJSONNoCandidates(t *testing.T) {
	defer fake(t, 200, `{"promptFeedback":{"blockReason":"SAFETY"}}`)()
	if _, err := GenerateJSON(context.Background(), "SECRET", "m1", "s", "u"); err == nil || !strings.Contains(err.Error(), "SAFETY") {
		t.Fatalf("want block error, got %v", err)
	}
}
