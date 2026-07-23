package recon

import (
	"context"
	"embed"
	"io"
	"net/http"
	"strings"
	"sync"
)

//go:embed wordlists/params.txt
var embeddedParamsWordlist embed.FS

// paramProbeValue is appended as the candidate parameter's value - distinct
// enough that it's very unlikely to collide with a real value the
// application expects, while still being a plausible short string for
// parameters that get echoed back or used in simple comparisons.
const paramProbeValue = "bbtracker_probe"

// paramLengthThreshold is the minimum content-length delta (in bytes) from
// baseline to count as a hit, alongside a relative threshold - guards
// against flagging every parameter on a page with naturally fluctuating
// content (timestamps, CSRF tokens, etc).
const paramLengthThreshold = 20

// SimpleParamFuzzer implements ParamFuzzer: for each URL it takes a
// baseline (no extra param) request, then tries each wordlist entry as a
// query parameter name with a fixed marker value, flagging any that shift
// the status code or meaningfully change the response size versus baseline.
// This is a deliberately simple v1 heuristic (no Arjun-style batching/binary
// search) - one request per candidate parameter, easy to reason about.
type SimpleParamFuzzer struct{}

// NewSimpleParamFuzzer returns a SimpleParamFuzzer.
func NewSimpleParamFuzzer() *SimpleParamFuzzer {
	return &SimpleParamFuzzer{}
}

func (f *SimpleParamFuzzer) FuzzParams(ctx context.Context, urls []string, wordlistPath string) ([]ParamResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	words, err := loadWordlistFile(wordlistPath, embeddedParamsWordlist, "wordlists/params.txt")
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, nil
	}

	client := &http.Client{
		Transport: skipVerifyTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type job struct{ url, param string }
	jobs := make(chan job)
	resultsCh := make(chan ParamResult)

	baselines := map[string]struct {
		status int
		length int
	}{}
	var baselineMu sync.Mutex
	baseline := func(u string) (int, int, bool) {
		baselineMu.Lock()
		b, ok := baselines[u]
		baselineMu.Unlock()
		if ok {
			return b.status, b.length, true
		}
		status, length, err := doGet(ctx, client, u)
		if err != nil {
			return 0, 0, false
		}
		baselineMu.Lock()
		baselines[u] = struct {
			status int
			length int
		}{status, length}
		baselineMu.Unlock()
		return status, length, true
	}

	var wg sync.WaitGroup
	for i := 0; i < fuzzWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				baseStatus, baseLength, ok := baseline(j.url)
				if !ok {
					continue
				}
				target := j.url
				if strings.Contains(target, "?") {
					target += "&" + j.param + "=" + paramProbeValue
				} else {
					target += "?" + j.param + "=" + paramProbeValue
				}
				status, length, err := doGet(ctx, client, target)
				if err != nil {
					continue
				}
				lengthDelta := length - baseLength
				if lengthDelta < 0 {
					lengthDelta = -lengthDelta
				}
				threshold := baseLength / 10
				if threshold < paramLengthThreshold {
					threshold = paramLengthThreshold
				}
				if status == baseStatus && lengthDelta <= threshold {
					continue
				}
				select {
				case resultsCh <- ParamResult{
					Host: j.url, URL: j.url, Param: j.param,
					BaselineStatus: baseStatus, BaselineLength: baseLength,
					HitStatus: status, HitLength: length,
				}:
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

	var out []ParamResult
	for r := range resultsCh {
		out = append(out, r)
	}
	return out, nil
}

// doGet issues a GET and returns the status code and response body length,
// discarding the body (capped, like the fuzzer, to bound memory use).
func doGet(ctx context.Context, client *http.Client, target string) (int, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxFuzzBodyBytes))
	return resp.StatusCode, int(n), nil
}
