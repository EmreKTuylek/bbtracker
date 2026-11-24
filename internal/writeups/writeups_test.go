package writeups

import (
	"strings"
	"testing"
)

func TestQualityFlag(t *testing.T) {
	long := strings.Repeat("x", 300)
	cases := []struct{ name, in, want string }{
		{"empty", "", "low"},
		{"short with marker", "curl https://x", "low"},
		{"long no marker", long, "low"},
		{"long with payload", long + " payload", "ok"},
		{"long with url", long + " https://a.b", "ok"},
	}
	for _, c := range cases {
		if got := QualityFlag(c.in); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}
