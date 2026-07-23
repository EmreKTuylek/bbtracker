package recon

import (
	"context"
	"embed"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

//go:embed wordlists/cors_paths.txt
var embeddedCorsPathsWordlist embed.FS

// corsWorkers caps concurrent CORS probe requests across the whole phase.
const corsWorkers = 10

// corsProbeOrigin is the "attacker" origin sent to test whether a server
// reflects arbitrary origins back in Access-Control-Allow-Origin.
const corsProbeOrigin = "https://bbtracker-cors-probe.invalid"

// SimpleCORSScanner implements CORSScanner: for each URL it sends a small,
// fixed set of GET requests with crafted Origin headers and inspects the
// Access-Control-Allow-Origin / Access-Control-Allow-Credentials response
// headers for common misconfigurations (arbitrary-origin reflection,
// wildcard + credentials, null-origin allowance, naive subdomain prefix/
// suffix matching). No request-smuggling-style malformed requests - every
// probe is a normal, idempotent GET.
//
// The same probe set also runs against a small, curated list of extra paths
// per host (wordlists/cors_paths.txt, or a user-supplied override file,
// same "empty path => use the embedded default" convention as fuzz/params) -
// not just the single root URL httpx already probed. CORS misconfigurations
// are frequently on an authenticated/API endpoint rather than the homepage;
// this scanner still doesn't crawl or log in (that's a materially bigger
// feature - see CLAUDE.md), so it can't discover arbitrary endpoints, but
// trying common naming conventions for this class of endpoint catches a
// meaningful share of them for free.
type SimpleCORSScanner struct{}

// NewSimpleCORSScanner returns a SimpleCORSScanner.
func NewSimpleCORSScanner() *SimpleCORSScanner {
	return &SimpleCORSScanner{}
}

// corsJob is one URL to actually send probes to. root is the original
// httpx-probed asset URL - carried through unchanged so Engine.Run can map
// a finding back to its asset id (via CORSFinding.Host) even when target is
// root plus an extra path, not root itself.
type corsJob struct{ root, target string }

func (c *SimpleCORSScanner) Scan(ctx context.Context, urls []string, pathsWordlistPath string) ([]CORSFinding, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	paths, err := loadWordlistFile(pathsWordlistPath, embeddedCorsPathsWordlist, "wordlists/cors_paths.txt")
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: skipVerifyTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	jobs := make(chan corsJob)
	resultsCh := make(chan CORSFinding)

	var wg sync.WaitGroup
	for i := 0; i < corsWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				for _, f := range probeCORS(ctx, client, j.root, j.target) {
					select {
					case resultsCh <- f:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, u := range urls {
			select {
			case jobs <- corsJob{root: u, target: u}:
			case <-ctx.Done():
				return
			}
			trimmed := strings.TrimRight(u, "/")
			for _, p := range paths {
				select {
				case jobs <- corsJob{root: u, target: trimmed + "/" + p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var out []CORSFinding
	for r := range resultsCh {
		out = append(out, r)
	}
	return out, nil
}

// probeCORS runs the fixed probe set against one URL (target) and returns
// any findings, tagged with root - the original asset URL httpx discovered
// - so Engine.Run can look up the right asset id even when target is
// root plus an extra path (see CORSFinding.Host's doc comment in recon.go).
func probeCORS(ctx context.Context, client *http.Client, root, target string) []CORSFinding {
	var findings []CORSFinding

	// Probe 1+2: arbitrary-origin reflection, and wildcard+credentials (a
	// spec-violating combination some servers still send).
	if acao, acac, ok := doGetWithOrigin(ctx, client, target, corsProbeOrigin); ok {
		if acao == corsProbeOrigin {
			findings = append(findings, CORSFinding{
				Host: root, URL: target, Issue: "reflects_arbitrary_origin",
				OriginSent: corsProbeOrigin, ACAOValue: acao, ACACAllowed: acac,
			})
		}
		if acao == "*" && acac {
			findings = append(findings, CORSFinding{
				Host: root, URL: target, Issue: "wildcard_with_credentials",
				OriginSent: corsProbeOrigin, ACAOValue: acao, ACACAllowed: acac,
			})
		}
	}

	// Probe 3: null origin (sandboxed iframes / file:// origins send this).
	if acao, acac, ok := doGetWithOrigin(ctx, client, target, "null"); ok && acao == "null" {
		findings = append(findings, CORSFinding{
			Host: root, URL: target, Issue: "null_origin_allowed",
			OriginSent: "null", ACAOValue: acao, ACACAllowed: acac,
		})
	}

	// Probe 4+5: naive subdomain-prefix/suffix bypass, derived from the
	// target's own host. One confirmed hit is enough evidence for this URL.
	for _, bypass := range subdomainBypassOrigins(target) {
		if acao, acac, ok := doGetWithOrigin(ctx, client, target, bypass); ok && acao == bypass {
			findings = append(findings, CORSFinding{
				Host: root, URL: target, Issue: "subdomain_bypass",
				OriginSent: bypass, ACAOValue: acao, ACACAllowed: acac,
			})
			break
		}
	}

	return findings
}

// subdomainBypassOrigins derives naive origin-matching bypass candidates
// from target's own host: a prefix bypass (no separator, so a substring
// check on "example.com" would wrongly match "evilexample.com") and a
// suffix bypass (a subdomain-suffix check without an anchoring dot would
// wrongly match "example.com.evil.test").
func subdomainBypassOrigins(target string) []string {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	host := u.Hostname()
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return []string{
		scheme + "://evil" + host,
		scheme + "://" + host + ".evil.test",
	}
}

// doGetWithOrigin sends a GET with the given Origin header and returns the
// Access-Control-Allow-Origin value and whether Access-Control-Allow-Credentials
// is "true". ok is false only when the request itself failed (network error),
// not when CORS headers are simply absent.
func doGetWithOrigin(ctx context.Context, client *http.Client, target, origin string) (acao string, acac bool, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", false, false
	}
	req.Header.Set("Origin", origin)
	resp, err := client.Do(req)
	if err != nil {
		return "", false, false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxFuzzBodyBytes))
	acao = resp.Header.Get("Access-Control-Allow-Origin")
	acac = strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	return acao, acac, true
}
