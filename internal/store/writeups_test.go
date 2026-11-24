package store

import "testing"

func TestSaveWriteupDedupe(t *testing.T) {
	st, err := Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	w := Writeup{Source: "hackerone", ExternalID: "1", URL: "u", Title: "a", ContentHash: "h1", QualityFlag: "ok", RawText: "secret"}
	if isNew, err := st.SaveWriteup(w); err != nil || !isNew {
		t.Fatalf("first save: isNew=%v err=%v", isNew, err)
	}
	if isNew, err := st.SaveWriteup(w); err != nil || isNew {
		t.Fatalf("same hash: isNew=%v err=%v", isNew, err)
	}
	w.ContentHash, w.Title = "h2", "b"
	if isNew, err := st.SaveWriteup(w); err != nil || isNew {
		t.Fatalf("changed hash: isNew=%v err=%v", isNew, err)
	}
	rows, err := st.ListWriteups("all", 10)
	if err != nil || len(rows) != 1 || rows[0].Title != "b" {
		t.Fatalf("list: %+v err=%v", rows, err)
	}
}

func TestListWriteupsAnalysisState(t *testing.T) {
	st, err := Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SaveWriteup(Writeup{Source: "hackerone", ExternalID: "1", URL: "u", Title: "a", ContentHash: "h", QualityFlag: "ok"})
	rows, _ := st.ListWriteups("all", 10)
	id := rows[0].ID
	if rows[0].AnalysisStatus != "" || len(rows[0].TechTags) != 0 {
		t.Fatalf("fresh row: %+v", rows[0])
	}
	jobID, _, err := st.EnqueueAnalysis(id, false)
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ = st.ListWriteups("all", 10); rows[0].AnalysisStatus != "queued" {
		t.Fatalf("want queued, got %q", rows[0].AnalysisStatus)
	}
	if err := st.FinishJob(jobID, "failed", 1, "boom", 0); err != nil {
		t.Fatal(err)
	}
	if rows, _ = st.ListWriteups("all", 10); rows[0].AnalysisStatus != "failed" || rows[0].AnalysisError != "boom" {
		t.Fatalf("want failed/boom, got %q/%q", rows[0].AnalysisStatus, rows[0].AnalysisError)
	}
	if err := st.SaveAnalysis(Analysis{WriteupID: id, Provider: "gemini", Model: "m", VulnClass: "IDOR", Summary: "s",
		RootCause: "r", AttackFlow: []byte("[]"), Fix: []byte("{}"), TestChecklist: []byte("[]"),
		TechTags: []byte(`["rest","jwt"]`), Detection: []byte("null"), Unknowns: []byte("[]"), Lang: "tr"}); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.ListWriteups("all", 10)
	if r := rows[0]; r.AnalysisStatus != "done" || r.VulnClass != "IDOR" || len(r.TechTags) != 2 {
		t.Fatalf("analyzed row: %+v", r)
	}
}
