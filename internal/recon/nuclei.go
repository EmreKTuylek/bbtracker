package recon

import (
	"context"
	"sync"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// LibNuclei implements VulnScanner using nuclei as a Go library
// (github.com/projectdiscovery/nuclei/v3/lib), so no external binary is
// required at runtime - same pattern as LibSubfinder/LibHTTPProbe.
//
// Safety defaults: dos/intrusive-tagged templates are excluded, and only
// http-protocol templates run (ProtocolTypes: "http"). bbtracker only ever
// points this at the live HTTP(S) URLs httpx already probed - it never hands
// nuclei a bare host - so non-http template categories (network/tcp, dns)
// would otherwise have nuclei independently connecting to other, unrelated
// ports on the target (some default templates probe specific non-standard
// ports for known services) to run raw protocol checks unrelated to what
// httpx found. Restricting to http keeps every request on the same surface
// the user already scoped in, and also cuts the template count drastically
// (see nucleiPhaseTimeout's comment on how slow the full set is).
type LibNuclei struct{}

// NewLibNuclei returns a LibNuclei with its safety defaults.
func NewLibNuclei() *LibNuclei {
	return &LibNuclei{}
}

// Scan runs nuclei's default template set (minus dos/intrusive tags) against
// urls and returns one VulnResult per match. It satisfies recon.VulnScanner.
//
// nuclei downloads and caches nuclei-templates from GitHub the first time
// it's ever run on this machine (see nucleiPhaseTimeout in recon.go for the
// generous deadline that accounts for this); later runs reuse the cache.
func (l *LibNuclei) Scan(ctx context.Context, urls []string) ([]VulnResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			ExcludeTags:   []string{"dos", "intrusive"},
			ProtocolTypes: "http",
		}),
	)
	if err != nil {
		return nil, err
	}
	defer ne.Close()

	ne.LoadTargets(urls, false)

	var (
		mu      sync.Mutex
		results []VulnResult
	)
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		mu.Lock()
		results = append(results, VulnResult{
			Host:       event.Host,
			TemplateID: event.TemplateID,
			Name:       event.Info.Name,
			Severity:   event.Info.SeverityHolder.Severity.String(),
			MatchedAt:  event.Matched,
		})
		mu.Unlock()
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}
