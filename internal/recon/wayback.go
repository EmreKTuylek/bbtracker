package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// waybackTimeout bounds a single domain's CDX query - the public API can be
// slow for domains with a very large archive footprint.
const waybackTimeout = 20 * time.Second

// LibWayback implements URLArchive by querying the Wayback Machine's public
// CDX API directly (a single HTTP GET + JSON parse per domain) - no library
// dependency, since waybackurls/gau are CLI tools, not SDKs, and the CDX API
// itself is this simple. Matches the SimpleFuzzer precedent in fuzz.go.
type LibWayback struct {
	Client *http.Client
}

// NewLibWayback returns a LibWayback with a sane HTTP client.
func NewLibWayback() *LibWayback {
	return &LibWayback{Client: &http.Client{Timeout: waybackTimeout}}
}

// Fetch queries the CDX API for each domain and returns every archived URL
// found, deduplicated, with out-of-scope hosts already excluded by the
// caller (Engine.Run passes only in-scope domains; this function has no
// scope knowledge of its own).
func (l *LibWayback) Fetch(ctx context.Context, domains []string) ([]ArchivedURL, error) {
	seen := map[string]bool{}
	var out []ArchivedURL
	for _, domain := range domains {
		urls, err := l.fetchDomain(ctx, domain)
		if err != nil {
			continue // one domain's CDX hiccup shouldn't fail the whole phase
		}
		for _, u := range urls {
			if seen[u] {
				continue
			}
			seen[u] = true
			host := u
			if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
				host = parsed.Hostname()
			}
			out = append(out, ArchivedURL{URL: u, Host: strings.ToLower(host)})
		}
	}
	return out, nil
}

func (l *LibWayback) fetchDomain(ctx context.Context, domain string) ([]string, error) {
	endpoint := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=5000",
		url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := l.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cdx api: unexpected status %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, nil // first row is the header ("original"); no data rows means no results
	}
	urls := make([]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		if len(row) > 0 && row[0] != "" {
			urls = append(urls, row[0])
		}
	}
	return urls, nil
}
