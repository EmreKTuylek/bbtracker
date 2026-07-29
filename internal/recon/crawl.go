package recon

import (
	"context"
	"net/url"
	"sync"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

// crawlWorkers bounds how many root URLs are crawled concurrently against a
// single shared *standard.Crawler instance. This mirrors katana's own CLI
// (internal/runner/executer.go), which wraps a sizedwaitgroup around one
// shared crawler and calls Crawl() from multiple goroutines concurrently -
// confirmed via the vendored source, not an assumption about thread-safety.
const crawlWorkers = 5

// maxCrawledURLs caps how many URLs this phase returns in total, across every
// asset. Unbounded crawling, followed by nuclei/cors/params/jsanalysis each
// running over every discovered URL, could turn a routine scan into one that
// runs for hours.
const maxCrawledURLs = 500

// CrawlResult is one URL katana discovered while crawling a probed asset.
type CrawlResult struct {
	Host string // the root URL that was crawled (httpx's probed URL - matches assetIDByURL's key)
	URL  string // the discovered URL
}

// Crawler crawls live probed URLs for additional in-scope URLs (linked
// pages, forms, JS-referenced endpoints). Results feed back into
// assetIDByURL in runAssetChain, so nuclei/cors/params/jsanalysis see the
// wider URL set without any change to those four phases themselves.
type Crawler interface {
	Crawl(ctx context.Context, urls []string) ([]CrawlResult, error)
}

// LibKatana implements Crawler using ProjectDiscovery's katana
// (github.com/projectdiscovery/katana) in its standard (non-headless) mode.
// Headless mode uses go-rod, which would reintroduce the Leakless/Windows
// Defender false-positive problem httpx's screenshot capture already works
// around - see CLAUDE.md's Leakless section; standard mode has no such
// dependency.
type LibKatana struct{}

// NewLibKatana returns a LibKatana.
func NewLibKatana() *LibKatana {
	return &LibKatana{}
}

func (k *LibKatana) Crawl(ctx context.Context, urls []string) ([]CrawlResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	// katana's OnResult callback identifies a result by RootHostname (a bare
	// hostname, e.g. "sub.example.com"), not the original root URL string -
	// this map recovers the exact input URL (matching assetIDByURL's key) for
	// each hostname, so CrawlResult.Host stays a lookup-compatible value.
	hostnameToRootURL := map[string]string{}
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		hostnameToRootURL[parsed.Hostname()] = u
	}

	var (
		mu  sync.Mutex
		out []CrawlResult
	)
	opts := &types.Options{
		MaxDepth:     3,
		FieldScope:   "rdn", // root domain name - stay within the same registered domain
		BodyReadSize: 2 << 20,
		Timeout:      10,
		Concurrency:  10,
		Parallelism:  10,
		RateLimit:    150,
		Strategy:     "depth-first",
		OnResult: func(r output.Result) {
			if r.Request == nil {
				return
			}
			rootURL, ok := hostnameToRootURL[r.Request.RootHostname]
			if !ok {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if len(out) >= maxCrawledURLs {
				return
			}
			out = append(out, CrawlResult{Host: rootURL, URL: r.Request.URL})
		},
	}

	crawlerOptions, err := types.NewCrawlerOptions(opts)
	if err != nil {
		return nil, err
	}
	defer crawlerOptions.Close()

	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		return nil, err
	}
	defer crawler.Close()

	sem := make(chan struct{}, crawlWorkers)
	var wg sync.WaitGroup
	for _, u := range urls {
		mu.Lock()
		full := len(out) >= maxCrawledURLs
		mu.Unlock()
		if full {
			break
		}
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(rootURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			_ = crawler.Crawl(rootURL) // per-host crawl errors are non-fatal - one bad host shouldn't fail the whole phase
		}(u)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return out, err
	}
	return out, nil
}
