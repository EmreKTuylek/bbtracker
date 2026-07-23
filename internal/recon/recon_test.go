package recon

import "testing"

func TestHostInScopeSuffix(t *testing.T) {
	domains := []string{"example.com", "test.io"}
	cases := map[string]bool{
		"example.com":      true,
		"api.example.com":  true,
		"test.io":          true,
		"a.b.test.io":      true,
		"notexample.com":   false,
		"example.com.evil": false,
		"evil.com":         false,
	}
	for host, want := range cases {
		if got := hostInScopeSuffix(host, domains); got != want {
			t.Errorf("hostInScopeSuffix(%q) = %v, want %v", host, got, want)
		}
	}
}
