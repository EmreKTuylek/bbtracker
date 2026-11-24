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
