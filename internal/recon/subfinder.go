package recon

import (
	"context"
	"fmt"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// LibSubfinder implements Subfinder using subfinder as a Go library
// (github.com/projectdiscovery/subfinder/v2/pkg/runner), so no external
// binary is required at runtime.
type LibSubfinder struct {
	Threads            int // concurrent resolver goroutines
	TimeoutSeconds     int // per-source HTTP timeout
	MaxEnumerationTime int // minutes to wait for enumeration to finish
}

// NewLibSubfinder returns a LibSubfinder with sane defaults.
func NewLibSubfinder() *LibSubfinder {
	return &LibSubfinder{Threads: 10, TimeoutSeconds: 30, MaxEnumerationTime: 5}
}

// Enumerate runs passive subdomain enumeration for each domain and returns
// the discovered hosts that actually resolve. It satisfies the
// recon.Subfinder interface.
//
// RemoveWildcard is enabled so subfinder resolves every candidate host
// (via its own resolver pool, seeded with resolve.DefaultResolvers/public
// DNS, bypassing the system resolver) and strips out wildcard DNS noise.
// Results are collected through ResultCallback rather than the sourceMap
// returned by EnumerateSingleDomainWithCtx, because with RemoveWildcard set
// that return value is unpopulated per-domain until the whole call
// completes - the callback is what actually fires per resolved host.
func (l *LibSubfinder) Enumerate(ctx context.Context, domains []string) ([]SubResult, error) {
	var (
		mu  sync.Mutex
		out []SubResult
	)

	opts := &runner.Options{
		Threads:            valOrDefault(l.Threads, 10),
		Timeout:            valOrDefault(l.TimeoutSeconds, 30),
		MaxEnumerationTime: valOrDefault(l.MaxEnumerationTime, 5),
		Silent:             true,
		DisableUpdateCheck: true,
		RemoveWildcard:     true,
		ResultCallback: func(result *resolve.HostEntry) {
			mu.Lock()
			out = append(out, SubResult{Host: result.Host, Source: result.Source})
			mu.Unlock()
		},
	}

	r, err := runner.NewRunner(opts)
	if err != nil {
		return nil, fmt.Errorf("subfinder: init runner: %w", err)
	}

	for _, domain := range domains {
		if domain == "" {
			continue
		}
		// Return value (sourceMap) is intentionally ignored: with
		// RemoveWildcard=true results are collected via ResultCallback above.
		if _, err := r.EnumerateSingleDomainWithCtx(ctx, domain, nil); err != nil {
			return nil, fmt.Errorf("subfinder: enumerate %s: %w", domain, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	return out, nil
}

func valOrDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
