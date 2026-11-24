package store

import (
	"strconv"
	"testing"
	"time"
)

func TestWeeklyPatterns(t *testing.T) {
	st, err := Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	recent := now.AddDate(0, 0, -2).Format(time.RFC3339)
	old := now.AddDate(0, 0, -30).Format(time.RFC3339)
	add := func(id, weakness, disclosed string) int64 {
		if _, err := st.SaveWriteup(Writeup{Source: "hackerone", ExternalID: id, URL: "u", Title: "t" + id,
			Weakness: weakness, DisclosedAt: disclosed, ContentHash: id, QualityFlag: "ok"}); err != nil {
			t.Fatal(err)
		}
		rows, _ := st.ListWriteups("all", 50)
		for _, r := range rows {
			if r.ExternalID == id {
				return r.ID
			}
		}
		t.Fatal("not found")
		return 0
	}
	analyze := func(id int64, class, tags string) {
		if err := st.SaveAnalysis(Analysis{WriteupID: id, Provider: "gemini", Model: "m", VulnClass: class, Summary: "s",
			RootCause: "rc-" + strconv.FormatInt(id, 10), AttackFlow: []byte("[]"), Fix: []byte("{}"),
			TestChecklist: []byte("[]"), TechTags: []byte(tags), Detection: []byte("null"), Unknowns: []byte("[]"), Lang: "tr"}); err != nil {
			t.Fatal(err)
		}
	}

	a := add("1", "Insecure Direct Object Reference", recent)
	b := add("2", "", recent)
	add("3", "XSS", recent)
	add("4", "", old) // outside the window
	analyze(a, "IDOR", `["rest","jwt"]`)
	analyze(b, "idor", `["rest"]`) // same class, different case

	sum, err := st.WeeklyPatterns(7)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 3 {
		t.Fatalf("old report must be excluded: total=%d", sum.Total)
	}
	if len(sum.Classes) != 2 || sum.Classes[0].Count != 2 || sum.Classes[0].Analyzed != 2 || sum.Classes[1].Class != "XSS" {
		t.Fatalf("classes (case-insensitive grouping): %+v", sum.Classes)
	}
	if sum.TopClass != "IDOR" && sum.TopClass != "idor" {
		t.Fatalf("top class %q", sum.TopClass)
	}
	if len(sum.TopTech) != 2 || sum.TopTech[0] != "rest" {
		t.Fatalf("top tech (rest appears twice): %v", sum.TopTech)
	}
	if len(sum.Examples) != 2 {
		t.Fatalf("examples: %+v", sum.Examples)
	}

	empty, err := st.WeeklyPatterns(0)
	if err != nil || empty.TopClass != "" || len(empty.Classes) != 0 {
		t.Fatalf("empty window: %+v err=%v", empty, err)
	}
}
