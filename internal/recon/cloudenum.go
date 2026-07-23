package recon

import (
	"context"
	"embed"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

//go:embed wordlists/cloud_suffixes.txt
var embeddedCloudSuffixes embed.FS

// cloudEnumWorkers caps concurrent bucket-check requests across the whole
// phase - a flat cap like fuzzWorkers, since candidate count (keywords x
// suffixes x providers) can get large.
const cloudEnumWorkers = 20

// maxCloudBodyBytes bounds how much of each response body is read - bodies
// are discarded, only the status code matters for classification.
const maxCloudBodyBytes = 1 << 16 // 64 KiB

// azureAccountNameRe matches Azure Storage's account-naming rules (lowercase
// letters/digits only, 3-24 chars) - used to skip Azure checks for
// candidates that could never be a valid account name (e.g. a full domain
// containing dots), rather than wasting a doomed request.
var azureAccountNameRe = regexp.MustCompile(`^[a-z0-9]{3,24}$`)

// cloudProvider describes one cloud storage provider's public, read-only
// HTTP existence/listing check.
type cloudProvider struct {
	name   string
	urlFor func(bucket string) string
	valid  func(bucket string) bool // nil means "always valid"
}

func defaultCloudProviders() []cloudProvider {
	return []cloudProvider{
		{
			name: "s3",
			urlFor: func(bucket string) string {
				// Path-style avoids TLS SNI/cert mismatches that break
				// virtual-hosted-style URLs for bucket names containing
				// dots (e.g. a full domain used for static website hosting).
				if strings.Contains(bucket, ".") {
					return "https://s3.amazonaws.com/" + bucket + "/"
				}
				return "https://" + bucket + ".s3.amazonaws.com/"
			},
		},
		{
			name: "gcs",
			urlFor: func(bucket string) string {
				return "https://storage.googleapis.com/" + bucket + "/"
			},
		},
		{
			name: "azure",
			urlFor: func(bucket string) string {
				return "https://" + bucket + ".blob.core.windows.net/?comp=list"
			},
			valid: azureAccountNameRe.MatchString,
		},
	}
}

// SimpleCloudEnumerator implements CloudEnumerator: for each in-scope
// domain it derives a candidate keyword (see deriveCloudKeywords), expands
// that into a small set of candidate bucket/container names (the keyword
// itself, plus the keyword combined with a curated suffix/prefix list -
// wordlists/cloud_suffixes.txt), and checks each read-only against AWS S3,
// Google Cloud Storage, and Azure Blob's public HTTP endpoints. No library
// dependency - cloud_enum/S3Scanner are Python/Go-binary CLIs, not Go SDKs.
// Deliberately read-only: it never attempts to write/upload anything (a
// write-permission check was considered and explicitly declined - see
// CLAUDE.md).
type SimpleCloudEnumerator struct {
	providers []cloudProvider // overridable in tests; nil means the real providers
}

// NewSimpleCloudEnumerator returns a SimpleCloudEnumerator using the real
// AWS/GCP/Azure endpoints.
func NewSimpleCloudEnumerator() *SimpleCloudEnumerator {
	return &SimpleCloudEnumerator{}
}

func (e *SimpleCloudEnumerator) Enumerate(ctx context.Context, domains []string) ([]CloudFinding, error) {
	keywords := deriveCloudKeywords(domains)
	if len(keywords) == 0 {
		return nil, nil
	}
	suffixes, err := loadWordlistFile("", embeddedCloudSuffixes, "wordlists/cloud_suffixes.txt")
	if err != nil {
		return nil, err
	}

	providers := e.providers
	if providers == nil {
		providers = defaultCloudProviders()
	}

	seen := map[string]bool{}
	var candidates []string
	addCandidate := func(n string) {
		n = strings.ToLower(n)
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		candidates = append(candidates, n)
	}
	for _, kw := range keywords {
		addCandidate(kw)
		for _, suf := range suffixes {
			addCandidate(kw + "-" + suf)
			addCandidate(suf + "-" + kw)
		}
	}

	type job struct {
		provider cloudProvider
		bucket   string
	}
	var jobs []job
	for _, p := range providers {
		for _, c := range candidates {
			if p.valid != nil && !p.valid(c) {
				continue
			}
			jobs = append(jobs, job{p, c})
		}
	}
	if len(jobs) == 0 {
		return nil, nil
	}

	client := &http.Client{}
	jobsCh := make(chan job)
	resultsCh := make(chan CloudFinding)

	var wg sync.WaitGroup
	for i := 0; i < cloudEnumWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				target := j.provider.urlFor(j.bucket)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCloudBodyBytes))
				resp.Body.Close()

				var kind string
				switch resp.StatusCode {
				case http.StatusOK:
					kind = "open_listable"
				case http.StatusForbidden:
					kind = "exists_private"
				default:
					continue // 404/other: doesn't exist or inconclusive - not worth reporting
				}
				select {
				case resultsCh <- CloudFinding{Provider: j.provider.name, Bucket: j.bucket, URL: target, Kind: kind}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobsCh)
		for _, j := range jobs {
			select {
			case jobsCh <- j:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var out []CloudFinding
	for r := range resultsCh {
		out = append(out, r)
	}
	return out, nil
}

// deriveCloudKeywords extracts candidate base names from in-scope domains:
// the full domain (a common literal bucket-naming convention for static
// website hosting, e.g. a bucket literally named "www.example.com") and its
// leftmost label (a stand-in for "company name", since bbtracker's scope
// model has no separate company-name field).
func deriveCloudKeywords(domains []string) []string {
	seen := map[string]bool{}
	var keywords []string
	add := func(k string) {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		keywords = append(keywords, k)
	}
	for _, d := range domains {
		add(d)
		if i := strings.Index(d, "."); i > 0 {
			add(d[:i])
		}
	}
	return keywords
}
