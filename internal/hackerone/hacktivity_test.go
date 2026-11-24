package hackerone

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchHacktivity(t *testing.T) {
	pages := map[string]string{
		"1": `{"data":[
			{"id":42,"attributes":{"title":"IDOR","url":"https://hackerone.com/reports/42","disclosed_at":"2026-01-02","severity_rating":"high","cwe":"IDOR","total_awarded_amount":"500.5","disclosed":true},
			 "relationships":{"program":{"data":{"attributes":{"handle":"acme","name":"Acme"}}},"report_generated_content":{"data":{"attributes":{"hacktivity_summary":"sum"}}}}},
			{"id":43,"attributes":{"title":"hidden","disclosed":false}}]}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, _, ok := r.BasicAuth(); !ok || u != "u" {
			t.Errorf("missing basic auth")
		}
		body, ok := pages[r.URL.Query().Get("page[number]")]
		if !ok {
			body = `{"data":[]}`
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()
	old := hacktivityURL
	hacktivityURL = srv.URL
	defer func() { hacktivityURL = old }()

	got, err := FetchHacktivity(context.Background(), "u", "t", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 disclosed item (empty page stops, non-disclosed dropped), got %d", len(got))
	}
	g := got[0]
	if g.ID != "42" || g.Program != "Acme" || g.Bounty != 500.5 || g.Summary != "sum" || g.Severity != "high" {
		t.Fatalf("bad parse: %+v", g)
	}
}
