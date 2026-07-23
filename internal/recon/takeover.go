package recon

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// takeoverWorkers caps concurrent takeover checks across the whole phase - one
// CNAME lookup plus (at most) one GET per host, so a modest pool is plenty.
const takeoverWorkers = 10

// takeoverFingerprint pairs a CNAME target suffix (a service's own hosting
// domain) with a body substring that service returns when the CNAME points at
// a slot nobody has claimed - the same idea as the community-maintained
// "can-i-take-over-xyz" fingerprint list, kept as a small hardcoded Go slice
// (like githubDorkQueries) rather than an embedded wordlist file, since it's
// a fixed, curated set rather than something a user would want to extend.
type takeoverFingerprint struct {
	Service       string
	CNAMESuffix   string
	BodySignature string
}

var takeoverFingerprints = []takeoverFingerprint{
	{"GitHub Pages", "github.io", "There isn't a GitHub Pages site here"},
	{"Heroku", "herokuapp.com", "no such app"},
	{"AWS S3", "s3.amazonaws.com", "NoSuchBucket"},
	{"AWS S3 (website)", "s3-website", "NoSuchBucket"},
	{"Azure Web App", "azurewebsites.net", "Error 404 - Web app not found"},
	{"Azure Blob", "blob.core.windows.net", "BlobNotFound"},
	{"Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"},
	{"Fastly", "fastly.net", "Fastly error: unknown domain"},
	{"Surge.sh", "surge.sh", "project not found"},
	{"Unbounce", "unbounceapp.com", "The requested URL was not found on this server"},
	{"Pantheon", "pantheonsite.io", "The gods are wise"},
	{"Zendesk", "zendesk.com", "Help Center Closed"},
	{"UserVoice", "uservoice.com", "This UserVoice subdomain is currently available"},
	{"Tumblr", "tumblr.com", "There's nothing here"},
	{"WordPress.com", "wordpress.com", "Do you want to register"},
	{"Bitbucket Pages", "bitbucket.io", "Repository not found"},
	{"Cargo Collective", "cargocollective.com", "404 Not Found"},
	{"StatusPage", "statuspage.io", "You are being"},
	{"Netlify", "netlify.app", "Not Found - Request ID"},
	{"CloudFront", "cloudfront.net", "ERROR: The request could not be satisfied"},
	{"Help Scout", "helpscoutdocs.com", "No settings were found for this company"},
	{"Ghost", "ghost.io", "The thing you were looking for is no longer here"},
}

// SimpleTakeoverScanner implements TakeoverScanner: for each host it resolves
// the CNAME chain, checks whether the apex still resolves at all (the
// strongest signal - a dangling CNAME to *anything*), and if the CNAME
// matches a known hosting provider's domain, fetches the page once to look
// for that provider's own "nothing claimed here" body text.
type SimpleTakeoverScanner struct{}

// NewSimpleTakeoverScanner returns a SimpleTakeoverScanner.
func NewSimpleTakeoverScanner() *SimpleTakeoverScanner {
	return &SimpleTakeoverScanner{}
}

func (t *SimpleTakeoverScanner) Scan(ctx context.Context, hosts []string) ([]TakeoverFinding, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	client := &http.Client{
		Transport: skipVerifyTransport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	jobs := make(chan string)
	resultsCh := make(chan TakeoverFinding)

	var wg sync.WaitGroup
	for i := 0; i < takeoverWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				if f, ok := checkTakeover(ctx, client, h); ok {
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
		for _, h := range hosts {
			select {
			case jobs <- h:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var out []TakeoverFinding
	for f := range resultsCh {
		out = append(out, f)
	}
	return out, nil
}

// checkTakeover resolves host's CNAME chain and classifies it. ok is false
// when there is nothing worth reporting (no CNAME, or the host resolves fine
// with no known-vulnerable-provider CNAME match).
func checkTakeover(ctx context.Context, client *http.Client, host string) (TakeoverFinding, bool) {
	cname, err := net.DefaultResolver.LookupCNAME(ctx, host)
	if err != nil {
		return TakeoverFinding{}, false
	}
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	if cname == strings.ToLower(strings.TrimSuffix(host, ".")) {
		return TakeoverFinding{}, false // no real CNAME, just the host's own name
	}

	if _, err := net.DefaultResolver.LookupHost(ctx, host); err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return TakeoverFinding{Host: host, CNAME: cname, Kind: "nxdomain",
				Evidence: "apex does not resolve (NXDOMAIN)"}, true
		}
		return TakeoverFinding{}, false // transient/other DNS error, not signal
	}

	var service string
	for _, fp := range takeoverFingerprints {
		if strings.HasSuffix(cname, fp.CNAMESuffix) {
			service = fp.Service
			body := fetchBody(ctx, client, host)
			if body != "" {
				for _, fp2 := range takeoverFingerprints {
					if fp2.Service == service && strings.Contains(body, fp2.BodySignature) {
						return TakeoverFinding{Host: host, CNAME: cname, Service: service,
							Kind: "fingerprint_match", Evidence: fp2.BodySignature}, true
					}
				}
			}
			return TakeoverFinding{Host: host, CNAME: cname, Service: service,
				Kind: "cname_match", Evidence: "CNAME points at " + fp.CNAMESuffix + "; body not confirmed"}, true
		}
	}
	return TakeoverFinding{}, false
}

// fetchBody does a best-effort GET (https then http) and returns a bounded
// prefix of the response body, or "" on any failure.
func fetchBody(ctx context.Context, client *http.Client, host string) string {
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+host+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxFuzzBodyBytes))
		resp.Body.Close()
		if len(body) > 0 {
			return string(body)
		}
	}
	return ""
}
