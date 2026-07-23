package recon

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/go-github/v30/github"
	"golang.org/x/oauth2"
)

// githubDorkQueries is a small, curated set of GitHub code-search qualifiers
// targeting filenames/extensions commonly associated with leaked secrets -
// the same idea as GitDorker's dork list, kept short (a hardcoded slice, not
// an embedded wordlist file - unlike fuzz/param-fuzz) to bound request
// volume against GitHub's code-search rate limit (see githubQueryDelay).
var githubDorkQueries = []string{
	"filename:.env",
	"filename:.npmrc",
	"filename:.git-credentials",
	"filename:credentials",
	"filename:id_rsa",
	"extension:pem",
	"filename:wp-config.php",
	"filename:.htpasswd",
	"extension:sql password",
	"filename:settings.py SECRET_KEY",
}

// githubQueryDelay paces requests between GitHub code-search calls: the
// code-search endpoint has historically had a much stricter secondary rate
// limit (~10 requests/minute) than the Search API's general 30/minute, even
// for authenticated requests. A fixed inter-request delay is simpler and
// safer than trying to parse GitHub's rate-limit headers precisely.
const githubQueryDelay = 6 * time.Second

// maxGithubResultsPerQuery caps how many code-search hits are read per dork
// query - GitHub only returns the first 1000 results total anyway; a bug
// bounty recon pass just needs the first page of hits per dork.
const maxGithubResultsPerQuery = 20

// maxGithubSnippetBytes bounds how much of an unmatched fragment is kept as
// context for a "dork_match" finding.
const maxGithubSnippetBytes = 200

// LibGitHubDorker implements GitHubDorker using google/go-github (already a
// vendored, transitively-required dependency of nuclei's own GitHub
// integrations - see vendor/github.com/projectdiscovery/nuclei/v3/pkg/external/
// customtemplates and pkg/reporting/trackers/github - so this adds no new
// go.mod footprint) against GitHub's Code Search API. Requires a GitHub
// personal access token - unauthenticated requests cannot use code search at
// all. The token needs no special scopes: code search only ever indexes
// public repositories, so this can never read a user's private repos.
type LibGitHubDorker struct {
	// BaseURL overrides the GitHub API base URL, for tests only (empty means
	// the real https://api.github.com/) - mirrors LibHTTPProbe's
	// UseInstalledChrome field: a small, deliberate testability hook.
	BaseURL string
}

// NewLibGitHubDorker returns a LibGitHubDorker using the real GitHub API.
func NewLibGitHubDorker() *LibGitHubDorker {
	return &LibGitHubDorker{}
}

func (d *LibGitHubDorker) Scan(ctx context.Context, token string, domains []string) ([]GitHubFinding, error) {
	if token == "" || len(domains) == 0 {
		return nil, nil
	}

	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	client := github.NewClient(httpClient)
	if d.BaseURL != "" {
		u, err := url.Parse(d.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid BaseURL: %w", err)
		}
		client.BaseURL = u
	}

	var findings []GitHubFinding
	seen := map[string]bool{} // dedupe (repo, path, kind, value) within this single run
	addFinding := func(repo, path, htmlURL, dork, kind, value string) {
		key := repo + "|" + path + "|" + kind + "|" + value
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, GitHubFinding{Repo: repo, Path: path, HTMLURL: htmlURL, Dork: dork, Kind: kind, Value: value})
	}

	first := true
	for _, domain := range domains {
		for _, dork := range githubDorkQueries {
			if ctx.Err() != nil {
				return findings, nil
			}
			if !first {
				select {
				case <-time.After(githubQueryDelay):
				case <-ctx.Done():
					return findings, nil
				}
			}
			first = false

			query := fmt.Sprintf("%q %s", domain, dork)
			result, _, err := client.Search.Code(ctx, query, &github.SearchOptions{
				TextMatch:   true,
				ListOptions: github.ListOptions{PerPage: maxGithubResultsPerQuery},
			})
			if err != nil {
				var rateErr *github.RateLimitError
				var abuseErr *github.AbuseRateLimitError
				if errors.As(err, &rateErr) || errors.As(err, &abuseErr) {
					return findings, nil // stop early, keep whatever we've already found
				}
				continue // skip this one dork query, keep going
			}

			for _, item := range result.CodeResults {
				repo := item.GetRepository().GetFullName()
				path := item.GetPath()
				htmlURL := item.GetHTMLURL()

				matchedSecret := false
				for _, tm := range item.TextMatches {
					frag := tm.GetFragment()
					if frag == "" {
						continue
					}
					for _, re := range secretPatterns {
						for _, m := range re.FindAllString(frag, -1) {
							addFinding(repo, path, htmlURL, dork, "secret", m)
							matchedSecret = true
						}
					}
				}
				if !matchedSecret {
					snippet := path
					if len(item.TextMatches) > 0 {
						if frag := item.TextMatches[0].GetFragment(); frag != "" {
							snippet = frag
						}
					}
					if len(snippet) > maxGithubSnippetBytes {
						snippet = snippet[:maxGithubSnippetBytes]
					}
					addFinding(repo, path, htmlURL, dork, "dork_match", snippet)
				}
			}
		}
	}

	return findings, nil
}
