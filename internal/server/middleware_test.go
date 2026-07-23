package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8787": true,
		"127.0.0.1":      true,
		"localhost:8787": true,
		"LOCALHOST":      true,
		"[::1]:8787":     true,
		"::1":            true,
		"evil.com:8787":  false,
		"evil.com":       false,
		"0.0.0.0:8787":   false,
		"":               false,
	}
	for in, want := range cases {
		if got := isLoopbackHost(in); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestHostOriginCheck(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := hostOriginCheck(ok)

	do := func(method, host, origin string) int {
		req := httptest.NewRequest(method, "/api/programs", nil)
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	cases := []struct {
		name                 string
		method, host, origin string
		want                 int
	}{
		{"legit GET", http.MethodGet, "127.0.0.1:8787", "", http.StatusOK},
		{"rebound Host on GET", http.MethodGet, "evil.com:8787", "", http.StatusForbidden},
		{"legit POST no origin (curl)", http.MethodPost, "127.0.0.1:8787", "", http.StatusOK},
		{"legit POST same-origin", http.MethodPost, "127.0.0.1:8787", "http://127.0.0.1:8787", http.StatusOK},
		{"cross-origin POST", http.MethodPost, "127.0.0.1:8787", "http://evil.com", http.StatusForbidden},
		{"rebound Host POST", http.MethodPost, "evil.com:8787", "http://evil.com", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := do(c.method, c.host, c.origin); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}
