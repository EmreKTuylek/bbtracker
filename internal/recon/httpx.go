package recon

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

// Screenshot capture has its own timing knobs (page navigation idle wait,
// overall capture deadline) that httpx's CLI only defaults via ParseOptions'
// flag registration. Since we build runner.Options directly (never call
// ParseOptions), these must be set explicitly or they're zero, which makes
// every capture fail instantly with "context deadline exceeded".
const (
	screenshotTimeout = 10 * time.Second
	screenshotIdle    = 1 * time.Second
)

// maxProbeBodyBytes bounds how much of each page's response body httpx keeps
// (for JS-analysis's endpoint/secret regex scanning) - must be set
// explicitly and non-zero, since runner.Options.MaxResponseBodySizeToSave
// defaults to the zero value when built directly (not via ParseOptions),
// which would truncate every captured body to empty.
//
// This bounds two DIFFERENT httpx knobs, both required: MaxResponseBodySizeToSave
// (how much of the body ends up in Result.ResponseBody) and
// MaxResponseBodySizeToRead (how many bytes httpx reads off the wire at all -
// see vendor/.../httpx/common/httpx/httpx.go's io.LimitReader(httpresp.Body,
// h.Options.MaxResponseBodySizeToRead)). Missing the Read one is worse than
// missing Save: runner.go's own New() clamps Save down to Read when Read is
// smaller ("if MaxResponseBodySizeToSave > MaxResponseBodySizeToRead {
// MaxResponseBodySizeToSave = MaxResponseBodySizeToRead }"), so a zero Read
// value zeroes Save too - httpx reads zero bytes of every response body
// regardless of CaptureBody/ResponseInStdout, and JS analysis silently gets
// nothing to scan on every single scan, not just large pages. Confirmed by
// reproduction: a live scan against a target with a guaranteed JS secret
// returned zero js_findings until this was added.
const maxProbeBodyBytes = 2 * 1024 * 1024 // 2 MiB

// LibHTTPProbe implements HTTPProbe using httpx as a Go library
// (github.com/projectdiscovery/httpx/runner), so no external binary is
// required at runtime.
type LibHTTPProbe struct {
	Threads            int
	TimeoutSeconds     int
	UseInstalledChrome bool // desktop tool: prefer the user's installed Chrome over go-rod's ~100+MB auto-download
}

// NewLibHTTPProbe returns a LibHTTPProbe with sane defaults.
func NewLibHTTPProbe() *LibHTTPProbe {
	return &LibHTTPProbe{Threads: 50, TimeoutSeconds: 10, UseInstalledChrome: true}
}

// Probe runs an HTTP(S) probe against the given hosts and returns one result
// per successfully probed host. It satisfies the recon.HTTPProbe interface.
func (l *LibHTTPProbe) Probe(ctx context.Context, hosts []string, opts ProbeOptions) ([]HTTPResult, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	threads := valOrDefault(l.Threads, 50)
	if opts.Screenshot {
		threads = 10 // screenshot capture runs synchronously per target on this pool (headless Chrome tabs); cap concurrency
	}

	var storeDir string
	if opts.Screenshot {
		var err error
		storeDir, err = os.MkdirTemp("", "bbtracker-httpx-*")
		if err != nil {
			return nil, fmt.Errorf("create screenshot scratch dir: %w", err)
		}
		defer os.RemoveAll(storeDir) // Screenshot forces httpx's StoreResponse side effect (full response bodies + PNGs); we only want ScreenshotBytes, discard the files
	}

	var (
		mu      sync.Mutex
		results []HTTPResult
	)

	runnerOpts := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           goflags.StringSlice(hosts),
		Threads:                   threads,
		Timeout:                   valOrDefault(l.TimeoutSeconds, 10),
		StatusCode:                true,
		ExtractTitle:              true,
		TechDetect:                true,
		OutputServerHeader:        true,
		ContentLength:             true,
		Screenshot:                opts.Screenshot,
		ScreenshotTimeout:         screenshotTimeout,
		ScreenshotIdle:            screenshotIdle,
		UseInstalledChrome:        l.UseInstalledChrome,
		StoreResponseDir:          storeDir,
		ResponseInStdout:          opts.CaptureBody,
		MaxResponseBodySizeToSave: maxProbeBodyBytes,
		MaxResponseBodySizeToRead: maxProbeBodyBytes,
		Silent:                    true,
		DisableStdin:              true,
		DisableUpdateCheck:        true,
		OnResult: func(r runner.Result) {
			if r.Err != nil {
				return
			}
			mu.Lock()
			results = append(results, HTTPResult{
				Input:           r.Input,
				URL:             r.URL,
				StatusCode:      r.StatusCode,
				Title:           r.Title,
				Tech:            strings.Join(r.Technologies, ","),
				ContentLength:   r.ContentLength,
				Webserver:       r.WebServer,
				IP:              r.HostIP,
				ScreenshotBytes: append([]byte(nil), r.ScreenshotBytes...),
				Body:            r.ResponseBody,
			})
			mu.Unlock()
		},
	}

	h, err := runner.New(&runnerOpts)
	if err != nil {
		return nil, err
	}
	defer h.Close()

	h.RunEnumeration()

	return results, nil
}
