package analysis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"bbtracker/internal/llm"
	"bbtracker/internal/store"
)

const goodDeep = `{"vuln_class":"IDOR","summary":"s","root_cause":"rc",
 "attack_flow":[{"step":1,"action":"a","why_it_works":"w"}],
 "fix":{"wrong":"x","right":"y","code_hint":null},
 "detection":{"signals":["sig"],"where":"log"},
 "test_checklist":["Kendi hedefinde x kontrol et"],"tech_tags":["rest"],"unknowns":["u"]}`

type call struct{ model string }

// setup returns a store with one writeup, Gemini settings saved, and a worker
// whose Gen replays the given responses (each a text or an error).
func setup(t *testing.T, triage bool, resp ...any) (*Worker, int64, *[]call) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpdateGeminiSettings("KEY", "triage-m", "deep-m"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveWriteup(store.Writeup{Source: "hackerone", ExternalID: "1", URL: "u", Title: "t",
		RawText: "some text", ContentHash: "h", QualityFlag: "ok"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListWriteups("all", 1)
	if _, ok, err := st.EnqueueAnalysis(rows[0].ID, triage); err != nil || !ok {
		t.Fatalf("enqueue: ok=%v err=%v", ok, err)
	}
	var calls []call
	i := 0
	w := &Worker{St: st, Pace: 0, Gen: func(_ context.Context, key, model, _, _ string) (string, error) {
		calls = append(calls, call{model})
		r := resp[i]
		i++
		if e, ok := r.(error); ok {
			return "", e
		}
		return r.(string), nil
	}}
	return w, rows[0].ID, &calls
}

func TestBulkTriageThenDeep(t *testing.T) {
	w, id, calls := setup(t, true, `{"quality_score":7,"vuln_class":"IDOR","reason":"ok"}`, goodDeep)
	w.step(context.Background())
	a, _ := w.St.GetAnalysis(id, "tr")
	if a == nil || a.QualityScore == nil || *a.QualityScore != 7 || a.VulnClass != "IDOR" || a.Model != "deep-m" {
		t.Fatalf("bad analysis: %+v", a)
	}
	if len(*calls) != 2 || (*calls)[0].model != "triage-m" || (*calls)[1].model != "deep-m" {
		t.Fatalf("want triage then deep model, got %+v", *calls)
	}
	if j, _ := w.St.LatestJob(id); j.Stage != "done" {
		t.Fatalf("job stage %s", j.Stage)
	}
}

func TestLowTriageSkipsDeep(t *testing.T) {
	w, id, calls := setup(t, true, `{"quality_score":3,"vuln_class":"XSS","reason":"no detail"}`)
	w.step(context.Background())
	if a, _ := w.St.GetAnalysis(id, "tr"); a != nil {
		t.Fatal("analysis must not exist")
	}
	j, _ := w.St.LatestJob(id)
	if j.Stage != "skipped" || !strings.Contains(j.Error, "no detail") || len(*calls) != 1 {
		t.Fatalf("job %+v calls %d", j, len(*calls))
	}
}

func TestRateLimitRequeuesWithBackoff(t *testing.T) {
	w, id, _ := setup(t, false, &llm.RetryError{After: time.Minute, Msg: "429"})
	w.step(context.Background())
	j, _ := w.St.LatestJob(id)
	if j.Stage != "queued" || j.Attempts != 1 {
		t.Fatalf("want queued/1, got %s/%d", j.Stage, j.Attempts)
	}
	if next, _ := w.St.ClaimDueJob(); next != nil {
		t.Fatal("job must not be due during backoff")
	}
}

func TestRateLimitGivesUp(t *testing.T) {
	w, id, _ := setup(t, false, &llm.RetryError{Msg: "429"})
	// Pretend 4 attempts already happened.
	if err := w.St.FinishJob(1, "queued", maxAttempts-1, "", 0); err != nil {
		t.Fatal(err)
	}
	w.step(context.Background())
	if j, _ := w.St.LatestJob(id); j.Stage != "failed" {
		t.Fatalf("stage %s", j.Stage)
	}
}

func TestInvalidOutputRetriedOnce(t *testing.T) {
	w, id, calls := setup(t, false, `{"summary":""}`, goodDeep)
	w.step(context.Background())
	if a, _ := w.St.GetAnalysis(id, "tr"); a == nil || a.QualityScore != nil || len(*calls) != 2 {
		t.Fatalf("retry should succeed: a=%+v calls=%d", a, len(*calls))
	}

	w2, id2, calls2 := setup(t, false, `not json`, `{"summary":""}`)
	w2.step(context.Background())
	j, _ := w2.St.LatestJob(id2)
	if j.Stage != "failed" || len(*calls2) != 2 {
		t.Fatalf("want failed after 2 invalid, got %s calls=%d", j.Stage, len(*calls2))
	}
}

func TestNonRetryableErrorFailsImmediately(t *testing.T) {
	w, id, _ := setup(t, false, errors.New("gemini: 400 Bad Request: API key not valid"))
	w.step(context.Background())
	if j, _ := w.St.LatestJob(id); j.Stage != "failed" || !strings.Contains(j.Error, "API key") {
		t.Fatalf("job %+v", j)
	}
}

func TestMissingKeyFails(t *testing.T) {
	w, id, calls := setup(t, false)
	if err := w.St.UpdateGeminiSettings("", "", ""); err != nil {
		t.Fatal(err)
	}
	w.step(context.Background())
	if j, _ := w.St.LatestJob(id); j.Stage != "failed" || len(*calls) != 0 {
		t.Fatalf("job %+v calls %d", j, len(*calls))
	}
}

func TestParseDeepRejectsIncomplete(t *testing.T) {
	for _, bad := range []string{
		`{}`,
		`{"vuln_class":"x","summary":"s","root_cause":"r","attack_flow":[],"fix":{"wrong":"a","right":"b"},"test_checklist":["c"]}`,
		`{"vuln_class":"x","summary":"s","root_cause":"r","attack_flow":[{"step":1,"action":"a","why_it_works":""}],"fix":{"wrong":"a","right":"b"},"test_checklist":["c"]}`,
	} {
		if _, err := parseDeep(bad); err == nil {
			t.Errorf("accepted bad input: %s", bad)
		}
	}
	if _, err := parseDeep(goodDeep); err != nil {
		t.Errorf("rejected good input: %v", err)
	}
}
