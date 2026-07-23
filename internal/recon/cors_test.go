package recon

import "testing"

func TestSubdomainBypassOrigins(t *testing.T) {
	got := subdomainBypassOrigins("https://example.com/path")
	want := []string{"https://evilexample.com", "https://example.com.evil.test"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if got := subdomainBypassOrigins("not a url"); got != nil {
		t.Errorf("expected nil for unparseable target, got %v", got)
	}
}
