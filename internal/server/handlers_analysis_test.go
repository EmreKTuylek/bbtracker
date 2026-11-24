package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"bbtracker/internal/analysis"
	"bbtracker/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewServer(st, nil)
}

func do(s *Server, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:8787"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestGeminiKeyValidatedBeforeSave(t *testing.T) {
	s := newTestServer(t)
	old := geminiCheck
	defer func() { geminiCheck = old }()

	geminiCheck = func(context.Context, string, string, string, string) (string, error) {
		return "", errors.New("gemini: 400 Bad Request: API key not valid")
	}
	rec := do(s, "PUT", "/api/settings", `{"gemini_api_key":"BAD","gemini_triage_model":"m"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "key check failed") {
		t.Fatalf("want 400 key check failed, got %d %s", rec.Code, rec.Body)
	}
	if set, _ := s.st.GetSettings(); set.GeminiAPIKey != "" {
		t.Fatal("a rejected key must not be stored")
	}

	geminiCheck = func(context.Context, string, string, string, string) (string, error) { return `{"ok":true}`, nil }
	rec = do(s, "PUT", "/api/settings", `{"gemini_api_key":"GOOD","gemini_triage_model":"m","gemini_analysis_model":"m2"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "GOOD") {
		t.Fatalf("want 200 without echoing the key, got %d %s", rec.Code, rec.Body)
	}
	if set, _ := s.st.GetSettings(); set.GeminiAPIKey != "GOOD" {
		t.Fatal("valid key not stored")
	}

	// A blank key on a later save keeps it without re-checking.
	geminiCheck = func(context.Context, string, string, string, string) (string, error) {
		t.Error("blank key must not trigger a check")
		return "", nil
	}
	do(s, "PUT", "/api/settings", `{"gemini_triage_model":"m","gemini_analysis_model":"m2"}`)
	if set, _ := s.st.GetSettings(); set.GeminiAPIKey != "GOOD" {
		t.Fatal("blank key wiped the saved one")
	}
}

func TestAnalyzeEndToEnd(t *testing.T) {
	s := newTestServer(t)
	if _, err := s.st.SaveWriteup(store.Writeup{Source: "hackerone", ExternalID: "1", URL: "u", Title: "t",
		RawText: "TOP-SECRET-BODY", ContentHash: "h", QualityFlag: "ok"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.st.ListWriteups("all", 1)
	id := rows[0].ID
	path := "/api/writeups/" + strconv.FormatInt(id, 10)

	if rec := do(s, "POST", path+"/analyze", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("no key saved: want 400, got %d", rec.Code)
	}
	if err := s.st.UpdateGeminiSettings("K", "tm", "am"); err != nil {
		t.Fatal(err)
	}
	if rec := do(s, "POST", "/api/writeups/9999/analyze", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown writeup: want 404, got %d", rec.Code)
	}
	if rec := do(s, "POST", path+"/analyze", ""); rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d %s", rec.Code, rec.Body)
	}
	// Second call dedupes onto the queued job.
	var again struct{ Queued bool }
	json.Unmarshal(do(s, "POST", path+"/analyze", "").Body.Bytes(), &again)
	if again.Queued {
		t.Fatal("duplicate analyze must not enqueue a second job")
	}

	w := &analysis.Worker{St: s.st, Gen: func(_ context.Context, _, model, _, user string) (string, error) {
		if !strings.Contains(user, "TOP-SECRET-BODY") {
			t.Error("worker must feed raw_text to the model")
		}
		return `{"vuln_class":"IDOR","summary":"s","root_cause":"r","attack_flow":[{"step":1,"action":"a","why_it_works":"w"}],
			"fix":{"wrong":"x","right":"y"},"test_checklist":["c"]}`, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go w.Run(ctx)
	var body string
	for i := 0; i < 50; i++ {
		rec := do(s, "GET", path+"/analysis", "")
		if strings.Contains(rec.Body.String(), `"root_cause"`) {
			body = rec.Body.String()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if body == "" {
		t.Fatal("analysis never appeared")
	}
	if strings.Contains(body, "TOP-SECRET-BODY") || strings.Contains(do(s, "GET", "/api/writeups", "").Body.String(), "TOP-SECRET-BODY") {
		t.Fatal("raw_text leaked through the API")
	}
	if !strings.Contains(body, `"stage":"done"`) {
		t.Fatalf("job should be done: %s", body)
	}
}
