package recon

import (
	"bufio"
	"context"
	"crypto/tls"
	"embed"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

//go:embed wordlists/common.txt
var embeddedWordlist embed.FS

// fuzzWorkers caps how many fuzz requests run concurrently across the whole
// phase (not per host) - a flat cap keeps total request volume predictable
// regardless of how many live URLs are being fuzzed, which matters since
// fuzzing is by far the most request-heavy tool this project runs (host
// count x wordlist size requests, versus one request per host for httpx).
const fuzzWorkers = 20

// maxFuzzBodyBytes bounds how much of each response body is read (just to
// measure content length) - fuzz responses are discarded, never stored, so
// there's no reason to buffer an arbitrarily large body.
const maxFuzzBodyBytes = 1 << 20 // 1 MiB

// skipVerifyTransport is shared by every recon tool in this package that
// makes its own follow-up HTTP requests to a host httpx already discovered
// (fuzz, param-fuzz, CORS, JS-linked-file fetches, takeover fingerprinting,
// cloud enum). httpx's own initial probe already tolerates invalid/
// self-signed certificates (InsecureSkipVerify, set in several places in
// vendor/github.com/projectdiscovery/httpx/common/httpx/httpx.go) - a host
// httpx reports as live must stay probeable by these follow-up tools too,
// or they silently produce zero findings for it with no error anywhere,
// indistinguishable from "this host has no issues" (confirmed as a real
// bug via live reproduction: a self-signed HTTPS target with a genuine
// CORS misconfiguration was correctly discovered as a live asset by httpx,
// but cors.go's own un-configured http.Client failed every probe against
// it and reported zero findings). Not a new security concern: these are
// outbound requests to the user's own authorized bug-bounty target, the
// standard posture for recon/security tooling (nuclei, Burp, httpx itself
// all skip verification the same way) - see tlsinfo.go's
// SimpleTLSScanner for the same precedent already established in this
// codebase. http.Transport is safe for concurrent reuse across multiple
// http.Client values (stdlib-documented), so one shared instance is
// correct here, not just convenient.
var skipVerifyTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

// SimpleFuzzer implements Fuzzer as a plain concurrent net/http directory/file
// brute-forcer: for every (url, wordlist entry) pair it requests url+"/"+entry
// and reports anything that doesn't come back 404. There's no library
// dependency here - see fuzz.go's package doc comment in CLAUDE.md for why
// ffuf's pkg/ffuf (the obvious off-the-shelf option) was passed over: it's
// the CLI's own internal package split, not a documented SDK, and wiring it
// up (matcher manager, input/output/runner providers, a scraper directory)
// would have been substantially more code and fragility than this project's
// actual v1 need - "try each wordlist entry, report non-404s" - warrants.
type SimpleFuzzer struct{}

// NewSimpleFuzzer returns a SimpleFuzzer.
func NewSimpleFuzzer() *SimpleFuzzer {
	return &SimpleFuzzer{}
}

// Fuzz tries every wordlistPath entry (or the embedded default, if empty)
// against every url and returns one FuzzResult per non-404 response. It
// satisfies recon.Fuzzer.
func (f *SimpleFuzzer) Fuzz(ctx context.Context, urls []string, wordlistPath string) ([]FuzzResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	words, err := loadWordlistFile(wordlistPath, embeddedWordlist, "wordlists/common.txt")
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, nil
	}

	type job struct{ url, word string }
	jobs := make(chan job)
	resultsCh := make(chan FuzzResult)

	client := &http.Client{
		Transport: skipVerifyTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // report the redirect itself, don't follow it
		},
	}

	baselines := fetchBaselines(ctx, client, urls)

	var wg sync.WaitGroup
	for i := 0; i < fuzzWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				target := strings.TrimRight(j.url, "/") + "/" + j.word
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxFuzzBodyBytes))
				resp.Body.Close()
				if resp.StatusCode == http.StatusNotFound {
					continue
				}
				if b, ok := baselines[j.url]; ok && resp.StatusCode == b.status && int(n) == b.length {
					continue // soft-404: identical to this host's baseline for a random nonexistent path
				}
				select {
				case resultsCh <- FuzzResult{Host: j.url, Path: j.word, URL: target, StatusCode: resp.StatusCode, ContentLength: int(n)}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, u := range urls {
			for _, w := range words {
				select {
				case jobs <- job{u, w}:
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

	var out []FuzzResult
	for r := range resultsCh {
		out = append(out, r)
	}
	return out, nil
}

// fuzzBaseline is one host's response shape for a path that can't legitimately
// exist, used to recognize soft-404s (servers that return 200 for anything).
type fuzzBaseline struct {
	status int
	length int
}

// fuzzBaselinePath is deliberately unguessable-looking so it doesn't collide
// with a wordlist entry or a real route.
const fuzzBaselinePath = "bbtracker-baseline-check-39fa2716"

// fetchBaselines requests fuzzBaselinePath against every url once (concurrently,
// capped at fuzzWorkers) and returns each host's response shape. A host whose
// baseline request fails is simply absent from the map, so its results fall
// back to the plain 404-only filter.
//
// ponytail: match is exact (status+length) rather than a size-delta threshold
// or word-count heuristic like ffuf/wfuf use - upgrade to a tolerance if a
// target's soft-404 page includes byte-varying content (e.g. a timestamp).
func fetchBaselines(ctx context.Context, client *http.Client, urls []string) map[string]fuzzBaseline {
	out := make(map[string]fuzzBaseline, len(urls))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, fuzzWorkers)
	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			target := strings.TrimRight(u, "/") + "/" + fuzzBaselinePath
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxFuzzBodyBytes))
			resp.Body.Close()
			mu.Lock()
			out[u] = fuzzBaseline{status: resp.StatusCode, length: int(n)}
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return out
}

// loadWordlistFile reads newline-separated entries from path, or from
// embeddedName within fallbackFS if path is empty. Blank lines and "#"
// comments are skipped. Shared by fuzz.go (paths) and paramfuzz.go
// (parameter names) - each embeds its own default wordlist file.
func loadWordlistFile(path string, fallbackFS embed.FS, embeddedName string) ([]string, error) {
	var r io.ReadCloser
	if path == "" {
		f, err := fallbackFS.Open(embeddedName)
		if err != nil {
			return nil, err
		}
		r = f
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		r = f
	}
	defer r.Close()

	var words []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, strings.TrimPrefix(line, "/"))
	}
	return words, sc.Err()
}
