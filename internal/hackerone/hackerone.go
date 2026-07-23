// Package hackerone fetches a program's public structured scope from
// HackerOne's API, for bbtracker's scope-import feature - an alternative to
// typing scope domains in one at a time.
package hackerone

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiBase = "https://api.hackerone.com/v1/hackers/programs/%s/structured_scopes?page%%5Bsize%%5D=100"

// ScopeItem is one normalized domain from a HackerOne program's structured
// scope, ready to insert as a bbtracker scope entry.
type ScopeItem struct {
	Domain  string
	InScope bool
}

type scopeResponse struct {
	Data []struct {
		Attributes struct {
			AssetType             string `json:"asset_type"`
			AssetIdentifier       string `json:"asset_identifier"`
			EligibleForSubmission bool   `json:"eligible_for_submission"`
		} `json:"attributes"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// FetchStructuredScopes returns every domain-shaped ("URL" asset type) entry
// from a HackerOne program's public structured scope, paginating through the
// full result set. Requires the account's own username + API token -
// HackerOne's API has no unauthenticated access, even for public programs
// (see Settings.HackerOneUsername/HackerOneAPIToken). Only asset_type "URL"
// entries are returned; CIDR ranges, mobile app store IDs, source code,
// hardware, and other non-domain asset types are silently skipped, not
// treated as errors.
func FetchStructuredScopes(ctx context.Context, username, apiToken, handle string) ([]ScopeItem, error) {
	if username == "" || apiToken == "" {
		return nil, fmt.Errorf("hackerone username and api token are required")
	}
	if handle == "" {
		return nil, fmt.Errorf("hackerone program handle is required")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	next := fmt.Sprintf(apiBase, url.PathEscape(handle))

	var out []ScopeItem
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(username, apiToken)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("hackerone api: %s (check the program handle and your API token)", resp.Status)
		}
		var parsed scopeResponse
		err = json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode hackerone response: %w", err)
		}

		for _, d := range parsed.Data {
			if d.Attributes.AssetType != "URL" {
				continue
			}
			domain := normalizeDomain(d.Attributes.AssetIdentifier)
			if domain == "" {
				continue
			}
			out = append(out, ScopeItem{Domain: domain, InScope: d.Attributes.EligibleForSubmission})
		}
		next = parsed.Links.Next
	}
	return out, nil
}

// normalizeDomain strips a HackerOne "URL" scope's asset_identifier (which
// may be a bare domain, a wildcard like "*.example.com", or a full URL with
// scheme/path/port) down to a bare lowercase hostname.
//
// ponytail: url.Parse-based, not a full domain-grammar validator - a
// malformed asset_identifier is silently dropped (empty return) rather than
// reported per-entry, matching FetchStructuredScopes' "skip non-domain
// entries" behavior.
func normalizeDomain(identifier string) string {
	s := strings.TrimSpace(identifier)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(u.Hostname(), "*."))
}
