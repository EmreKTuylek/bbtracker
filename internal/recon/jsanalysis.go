package recon

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// scriptSrcRe extracts <script src="..."> references from an HTML body.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"'>]+)["']`)

// endpointRe is a LinkFinder-style heuristic: quoted strings that look like
// an absolute path (starting with /, at least one more path segment) or a
// full URL. Intentionally broad - false positives (CSS classes, etc.) are
// an accepted v1 tradeoff, same spirit as fuzz's "only skip 404s".
var endpointRe = regexp.MustCompile(`["']((?:/[a-zA-Z0-9_\-.]+){2,}(?:\?[^"']*)?|https?://[^\s"'<>]{8,})["']`)

// secretPatterns are a small, curated set of common secret formats.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                                 // AWS access key ID
	regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),                                           // Google API key
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,48}`),                                  // Slack token
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), // JWT
	regexp.MustCompile(`(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([0-9a-zA-Z\-_]{16,})["']`),
}

// maxJSFileBytes bounds how much of each linked .js file is read.
const maxJSFileBytes = 2 * 1024 * 1024 // 2 MiB

// jsFetchWorkers caps concurrent .js file downloads.
const jsFetchWorkers = 10

// SimpleJSAnalyzer implements JSAnalyzer with plain regexes over page bodies
// httpx already captured (via ProbeOptions.CaptureBody) plus any linked .js
// files it discovers and fetches itself - no library dependency, since
// LinkFinder/SecretFinder/Mantra are Python/CLI tools, not Go SDKs.
type SimpleJSAnalyzer struct{}

// NewSimpleJSAnalyzer returns a SimpleJSAnalyzer.
func NewSimpleJSAnalyzer() *SimpleJSAnalyzer {
	return &SimpleJSAnalyzer{}
}

func (a *SimpleJSAnalyzer) Analyze(ctx context.Context, pages map[string]string) ([]JSFinding, error) {
	if len(pages) == 0 {
		return nil, nil
	}

	client := &http.Client{Transport: skipVerifyTransport}
	var findings []JSFinding
	seen := map[string]bool{} // dedupe (host, kind, value) within this single run

	addFinding := func(host, sourceURL, kind, value string) {
		key := host + "|" + kind + "|" + value
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, JSFinding{Host: host, SourceURL: sourceURL, Kind: kind, Value: value})
	}

	scanText := func(host, sourceURL, text string) {
		for _, m := range endpointRe.FindAllStringSubmatch(text, -1) {
			addFinding(host, sourceURL, "endpoint", m[1])
		}
		for _, re := range secretPatterns {
			for _, m := range re.FindAllString(text, -1) {
				addFinding(host, sourceURL, "secret", m)
			}
		}
	}

	// Collect linked .js URLs per host before fetching, so fetches can be
	// capped/parallelized independently of how many seed pages there are.
	type jsJob struct{ host, jsURL string }
	var jsJobs []jsJob
	for pageURL, body := range pages {
		if body == "" {
			continue
		}
		scanText(pageURL, pageURL, body)

		base, err := url.Parse(pageURL)
		if err != nil {
			continue
		}
		for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
			src := m[1]
			if !strings.Contains(strings.ToLower(src), ".js") {
				continue
			}
			resolved, err := base.Parse(src)
			if err != nil {
				continue
			}
			jsJobs = append(jsJobs, jsJob{host: pageURL, jsURL: resolved.String()})
		}
	}

	if len(jsJobs) == 0 {
		return findings, nil
	}

	type jsResult struct {
		host, jsURL, body string
	}
	jobs := make(chan jsJob)
	results := make(chan jsResult)
	done := make(chan struct{})

	for i := 0; i < jsFetchWorkers; i++ {
		go func() {
			for j := range jobs {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.jsURL, nil)
				if err != nil {
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, maxJSFileBytes))
				resp.Body.Close()
				select {
				case results <- jsResult{host: j.host, jsURL: j.jsURL, body: string(body)}:
				case <-ctx.Done():
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, j := range jsJobs {
			select {
			case jobs <- j:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for i := 0; i < len(jsJobs); i++ {
			select {
			case r := <-results:
				scanText(r.host, r.jsURL, r.body)
			case <-ctx.Done():
				close(done)
				return
			}
		}
		close(done)
	}()

	<-done
	return findings, nil
}
