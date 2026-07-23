package hackerone

import "testing"

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":            "example.com",
		"*.example.com":          "example.com",
		"https://example.com":    "example.com",
		"http://example.com/api": "example.com",
		"example.com:8443":       "example.com",
		"EXAMPLE.COM":            "example.com",
		"":                       "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
