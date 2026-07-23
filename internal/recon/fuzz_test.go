package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestFuzzSoftNotFound verifies that a target which returns 200 with
// identical content for every unknown path (a "soft 404") produces zero
// hits, while a real hit whose response differs from the baseline still
// gets reported.
func TestFuzzSoftNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/admin") {
			w.Write([]byte("real admin panel"))
			return
		}
		w.Write([]byte("soft 404 page")) // same body for baseline path and every wordlist miss
	}))
	defer srv.Close()

	dir := t.TempDir()
	wordlistPath := dir + "/words.txt"
	if err := os.WriteFile(wordlistPath, []byte("admin\nmissing\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := NewSimpleFuzzer()
	results, err := f.Fuzz(context.Background(), []string{srv.URL}, wordlistPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Path != "admin" {
		t.Errorf("got %+v, want exactly one hit for \"admin\"", results)
	}
}
