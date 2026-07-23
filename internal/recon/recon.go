// Package recon orchestrates subdomain discovery (subfinder) and HTTP probing (httpx),
// persisting results through the store. The concrete tools sit behind small interfaces
// so the implementation can swap between Go-library and exec backends without touching
// the orchestrator or the server.
package recon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"bbtracker/internal/store"
	"bbtracker/internal/telegram"
)

// Hard ceilings on each phase of a scan. subfinder/httpx are expected to
// respect ctx cancellation and their own internal timeouts, but in practice
// a single misbehaving source (e.g. a passive source whose HTTP client
// ignores context under restrictive network conditions) can block its
// goroutine forever, which prevents the library call from ever returning
// even past its own configured timeout. Racing the call against a local
// timer guarantees Run always reaches FinishScan, so a stuck scan can never
// permanently block future scans for the program. The leaked goroutine (if
// the library truly never returns) is an acceptable tradeoff for that
// guarantee - Go cannot forcibly cancel it.
const (
	subfinderPhaseTimeout        = 4 * time.Minute
	httpxBaseTimeout             = 2 * time.Minute
	httpxPerHostBudget           = 200 * time.Millisecond
	httpxPerHostBudgetScreenshot = 4 * time.Second
	httpxMaxTimeout              = 15 * time.Minute
	// nucleiPhaseTimeout is generous relative to the httpx phase: nuclei
	// downloads and caches nuclei-templates from GitHub on its very first
	// run (a one-time cost borne by whichever scan enables it first), on
	// top of running many templates per URL. LibNuclei restricts to
	// http-protocol templates only (see nuclei.go), which cut this down a
	// lot, but a program with many live URLs can still take a while.
	nucleiPhaseTimeout = 30 * time.Minute
	// fuzzPhaseTimeout scales with host count like the httpx phase, but with
	// a much larger per-host budget: fuzzing is host-count x wordlist-size
	// requests (versus one request per host for httpx), the most
	// request-heavy tool this project runs.
	fuzzBaseTimeout   = 2 * time.Minute
	fuzzPerHostBudget = 45 * time.Second
	fuzzMaxTimeout    = 25 * time.Minute
	// waybackPhaseTimeout is flat (not host-scaled): LibWayback makes one
	// CDX request per in-scope domain, not per host, and each domain query
	// already has its own internal waybackTimeout (see wayback.go).
	waybackPhaseTimeout = 3 * time.Minute
	// paramsPhaseTimeout follows the same host-scaled shape as fuzz - one
	// baseline request plus one request per wordlist entry, per URL.
	paramsBaseTimeout   = 2 * time.Minute
	paramsPerHostBudget = 30 * time.Second
	paramsMaxTimeout    = 20 * time.Minute
	// jsAnalysisPhaseTimeout is flat: work is bounded by the number of
	// linked .js files per page (typically small), not by a wordlist.
	jsAnalysisPhaseTimeout = 5 * time.Minute
	// corsPhaseTimeout follows the same host-scaled shape as httpx. Budget
	// bumped from the original 5s/host (a fixed 5-probe set, no extra paths)
	// to cover the CORS paths wordlist added later: the same 5-probe set now
	// also runs against each extra path per host (embedded default ~24
	// entries, or a larger user-supplied override file), a flat generous
	// per-host budget rather than counting the wordlist first - same
	// approach fuzzPerHostBudget already takes for its (much larger)
	// wordlist.
	corsBaseTimeout   = 1 * time.Minute
	corsPerHostBudget = 30 * time.Second
	corsMaxTimeout    = 20 * time.Minute
	// githubDorkPhaseTimeout scales with domain count, not host count: each
	// domain runs the full (small, fixed) dork list with a 6s inter-query
	// delay to respect GitHub's code-search rate limit (see githubQueryDelay
	// in githubdork.go), so the per-domain budget must cover the whole list.
	githubDorkBaseTimeout     = 1 * time.Minute
	githubDorkPerDomainBudget = 90 * time.Second
	githubDorkMaxTimeout      = 20 * time.Minute
	// cloudEnumPhaseTimeout scales with domain count: each domain expands
	// into ~2x the suffix-list size candidate names x 3 providers, run
	// through a flat cloudEnumWorkers-sized pool (see cloudenum.go) - a
	// generous per-domain budget covers that without needing to model exact
	// candidate counts here.
	cloudEnumBaseTimeout     = 1 * time.Minute
	cloudEnumPerDomainBudget = 2 * time.Minute
	cloudEnumMaxTimeout      = 20 * time.Minute
	// takeoverPhaseTimeout follows the same host-scaled shape as CORS - one
	// CNAME lookup plus at most one GET per host, the lightest per-host
	// request volume alongside CORS.
	takeoverBaseTimeout   = 1 * time.Minute
	takeoverPerHostBudget = 5 * time.Second
	takeoverMaxTimeout    = 10 * time.Minute
	// tlsPhaseTimeout follows the same host-scaled shape - one TLS dial per
	// host, no wordlist.
	tlsBaseTimeout   = 1 * time.Minute
	tlsPerHostBudget = 5 * time.Second
	tlsMaxTimeout    = 10 * time.Minute
)

// httpxTimeoutFor scales the probe deadline with the number of hosts
// discovered, so a program with a large passive footprint doesn't spuriously
// time out before httpx has a real chance to get through the list. Screenshot
// capture (headless Chrome per host) is far slower than a plain HTTP probe,
// so it gets its own, much larger, per-host budget.
func httpxTimeoutFor(hostCount int, screenshot bool) time.Duration {
	budget := httpxPerHostBudget
	if screenshot {
		budget = httpxPerHostBudgetScreenshot
	}
	d := httpxBaseTimeout + time.Duration(hostCount)*budget
	if d > httpxMaxTimeout {
		return httpxMaxTimeout
	}
	return d
}

// hostInScopeSuffix reports whether host equals, or is a subdomain of, any
// domain in domains. Used to drop hosts that fall under an out-of-scope
// domain before they're persisted or probed.
func hostInScopeSuffix(host string, domains []string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// SubResult is one discovered subdomain.
type SubResult struct {
	Host   string
	Source string
}

// Subfinder discovers subdomains for a set of root domains.
type Subfinder interface {
	Enumerate(ctx context.Context, domains []string) ([]SubResult, error)
}

// HTTPResult is one httpx probe result.
type HTTPResult struct {
	Input           string // the host that was probed
	URL             string
	StatusCode      int
	Title           string
	Tech            string
	ContentLength   int
	Webserver       string
	IP              string
	ScreenshotBytes []byte
	Body            string // only populated when ProbeOptions.CaptureBody is set
}

// ProbeOptions tunes one HTTPProbe.Probe call.
type ProbeOptions struct {
	Screenshot  bool
	CaptureBody bool // capture each page's response body, for JS/secret analysis
}

// HTTPProbe probes hosts over HTTP(S).
type HTTPProbe interface {
	Probe(ctx context.Context, hosts []string, opts ProbeOptions) ([]HTTPResult, error)
}

// VulnResult is one nuclei template match.
type VulnResult struct {
	Host       string // the URL nuclei scanned
	TemplateID string
	Name       string
	Severity   string
	MatchedAt  string
}

// VulnScanner runs nuclei templates against live URLs.
type VulnScanner interface {
	Scan(ctx context.Context, urls []string) ([]VulnResult, error)
}

// FuzzResult is one non-404 response a directory/file fuzz scan found.
type FuzzResult struct {
	Host          string // the URL fuzzed (without the path appended)
	Path          string // the wordlist entry that was appended
	URL           string // the full URL that was requested
	StatusCode    int
	ContentLength int
}

// Fuzzer tries wordlist entries as paths against live URLs.
type Fuzzer interface {
	Fuzz(ctx context.Context, urls []string, wordlistPath string) ([]FuzzResult, error)
}

// ArchivedURL is one URL the Wayback Machine's CDX API has archived.
type ArchivedURL struct {
	URL  string
	Host string
}

// URLArchive fetches historically archived URLs for a set of domains.
type URLArchive interface {
	Fetch(ctx context.Context, domains []string) ([]ArchivedURL, error)
}

// ParamResult is one candidate hidden query parameter a param-fuzz scan found.
type ParamResult struct {
	Host           string // the URL fuzzed
	URL            string
	Param          string
	BaselineStatus int
	BaselineLength int
	HitStatus      int
	HitLength      int
}

// ParamFuzzer tries wordlist entries as query parameter names against live URLs.
type ParamFuzzer interface {
	FuzzParams(ctx context.Context, urls []string, wordlistPath string) ([]ParamResult, error)
}

// JSFinding is one endpoint-like string or matched secret pattern a JS
// analysis scan found.
type JSFinding struct {
	Host      string // which probed asset URL this finding belongs to
	SourceURL string // the exact page or .js file the match came from
	Kind      string // "endpoint" | "secret"
	Value     string
}

// JSAnalyzer scans seed pages (URL -> body) and any linked .js files for
// endpoint-like strings and known secret patterns.
type JSAnalyzer interface {
	Analyze(ctx context.Context, pages map[string]string) ([]JSFinding, error)
}

// CORSFinding is one CORS misconfiguration a CORS scan found for a probed URL.
type CORSFinding struct {
	Host        string // the original httpx-probed asset URL, for asset-id lookup - NOT necessarily what was requested, see URL
	URL         string // the exact URL probed: Host itself, or Host plus an extra path from the CORS paths wordlist
	Issue       string // reflects_arbitrary_origin | wildcard_with_credentials | null_origin_allowed | subdomain_bypass
	OriginSent  string
	ACAOValue   string
	ACACAllowed bool
}

// CORSScanner probes live URLs (plus a small set of extra per-host paths,
// pathsWordlistPath empty => the embedded default) for common CORS
// misconfigurations using a fixed set of crafted Origin headers - no
// malformed/ambiguous requests (unlike e.g. HTTP request smuggling
// detection, which was considered and explicitly deferred - see CLAUDE.md).
type CORSScanner interface {
	Scan(ctx context.Context, urls []string, pathsWordlistPath string) ([]CORSFinding, error)
}

// GitHubFinding is one leaked-secret/sensitive-file hit a GitHub code-search
// dork found for an in-scope domain.
type GitHubFinding struct {
	Repo, Path, HTMLURL, Dork string
	Kind                      string // "secret" | "dork_match"
	Value                     string
}

// GitHubDorker searches public GitHub repositories for files/secrets
// associated with a set of in-scope domains (GitDorker/TruffleHog/Gitleaks-
// style recon). Requires a GitHub token, supplied per call rather than held
// on the implementation, since it comes from app-wide settings that can
// change between scans.
type GitHubDorker interface {
	Scan(ctx context.Context, token string, domains []string) ([]GitHubFinding, error)
}

// CloudFinding is one cloud storage bucket/container a cloud enumeration
// scan found for an in-scope domain-derived keyword.
type CloudFinding struct {
	Provider string // "s3" | "gcs" | "azure"
	Bucket   string
	URL      string
	Kind     string // "open_listable" | "exists_private"
}

// CloudEnumerator checks cloud storage providers (AWS S3, Google Cloud
// Storage, Azure Blob) for buckets/containers named after a set of in-scope
// domains (cloud_enum/S3Scanner-style recon) - read-only existence/listing
// checks only, never a write-permission test (see CLAUDE.md).
type CloudEnumerator interface {
	Enumerate(ctx context.Context, domains []string) ([]CloudFinding, error)
}

// TakeoverFinding is one subdomain-takeover signal found for a host: either a
// dangling CNAME that doesn't resolve at all ("nxdomain"), a CNAME pointing
// at a known hosting provider confirmed by that provider's own "unclaimed"
// page body ("fingerprint_match"), or the same CNAME match without body
// confirmation ("cname_match" - needs manual review).
type TakeoverFinding struct {
	Host     string
	CNAME    string
	Service  string // empty for "nxdomain"
	Kind     string // "nxdomain" | "fingerprint_match" | "cname_match"
	Evidence string
}

// TakeoverScanner checks hosts for dangling CNAMEs / subdomain takeover
// candidates. Depends only on DNS + one GET per host - no httpx URLs needed.
type TakeoverScanner interface {
	Scan(ctx context.Context, hosts []string) ([]TakeoverFinding, error)
}

// TLSFinding is one certificate issue (or informational SAN entry) found for
// a host's TLS listener on port 443.
type TLSFinding struct {
	Host   string
	Issue  string // expired | expiring_soon | self_signed | hostname_mismatch | weak_protocol | new_san_subdomain
	Detail string
}

// TLSScanner inspects each host's TLS certificate (expiry, self-signed,
// hostname mismatch, weak protocol version, SAN entries). Depends only on a
// direct TLS dial to each host - no httpx URLs needed.
type TLSScanner interface {
	Scan(ctx context.Context, hosts []string) ([]TLSFinding, error)
}

// Engine runs a full recon pass and writes results to the store.
type Engine struct {
	st         *store.Store
	subs       Subfinder
	http       HTTPProbe
	vuln       VulnScanner
	fuzz       Fuzzer
	archive    URLArchive
	params     ParamFuzzer
	jsAnalyzer JSAnalyzer
	cors       CORSScanner
	github     GitHubDorker
	cloud      CloudEnumerator
	takeover   TakeoverScanner
	tlsScan    TLSScanner

	mu      sync.Mutex
	cancels map[int64]context.CancelFunc

	phaseMu      sync.Mutex
	activePhases map[int64]map[string]bool
}

// NewEngine wires the recon engine.
func NewEngine(st *store.Store, subs Subfinder, http HTTPProbe, vuln VulnScanner, fuzz Fuzzer,
	archive URLArchive, params ParamFuzzer, jsAnalyzer JSAnalyzer, cors CORSScanner, github GitHubDorker,
	cloud CloudEnumerator, takeover TakeoverScanner, tlsScan TLSScanner) *Engine {
	return &Engine{
		st: st, subs: subs, http: http, vuln: vuln, fuzz: fuzz,
		archive: archive, params: params, jsAnalyzer: jsAnalyzer, cors: cors, github: github, cloud: cloud,
		takeover: takeover, tlsScan: tlsScan,
		cancels:      map[int64]context.CancelFunc{},
		activePhases: map[int64]map[string]bool{},
	}
}

// startPhase/endPhase/ActivePhases track which named phases are currently
// running for a scan, purely in memory (not persisted). Unlike a single
// current_phase DB column, this correctly represents that several phases can
// be genuinely running at once - Run launches wayback/github/cloud/takeover/
// tls concurrently with the httpx-dependent asset chain (see Run). Called
// from multiple goroutines per scan, so guarded by phaseMu.
func (e *Engine) startPhase(scanID int64, name string) {
	e.phaseMu.Lock()
	defer e.phaseMu.Unlock()
	set, ok := e.activePhases[scanID]
	if !ok {
		set = map[string]bool{}
		e.activePhases[scanID] = set
	}
	set[name] = true
}

func (e *Engine) endPhase(scanID int64, name string) {
	e.phaseMu.Lock()
	defer e.phaseMu.Unlock()
	if set, ok := e.activePhases[scanID]; ok {
		delete(set, name)
		if len(set) == 0 {
			delete(e.activePhases, scanID)
		}
	}
}

// ActivePhases returns the names of phases currently running for scanID, in
// no particular order. Empty (nil) once the scan has no in-flight phases.
func (e *Engine) ActivePhases(scanID int64) []string {
	e.phaseMu.Lock()
	defer e.phaseMu.Unlock()
	set, ok := e.activePhases[scanID]
	if !ok || len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	return out
}

func (e *Engine) registerCancel(scanID int64, cancel context.CancelFunc) {
	e.mu.Lock()
	e.cancels[scanID] = cancel
	e.mu.Unlock()
}

func (e *Engine) unregisterCancel(scanID int64) {
	e.mu.Lock()
	delete(e.cancels, scanID)
	e.mu.Unlock()
}

// Cancel requests that a running scan stop. It returns whether a running
// scan was found; the scan's own goroutine observes ctx.Done() and marks
// the row "cancelled" via FinishScan asynchronously - this call does not
// block on that.
func (e *Engine) Cancel(scanID int64) bool {
	e.mu.Lock()
	cancel, ok := e.cancels[scanID]
	e.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// Run executes a scan synchronously: optionally subfinder over in-scope domains
// (upserting assets and counting new ones), then optionally httpx over the
// resulting hosts, saving probes. It updates the scan row's status on
// completion. Intended to be called from a goroutine.
func (e *Engine) Run(ctx context.Context, programID, scanID int64, opts store.ScanOptions) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.registerCancel(scanID, cancel)
	defer e.unregisterCancel(scanID)

	if !opts.AnyToolEnabled() {
		e.st.FinishScan(scanID, "error", 0, "no tools selected")
		return
	}

	assetIDByHost := map[string]int64{}
	newHosts := []string{}
	newCount := 0

	if opts.RunSubfinder {
		domains, err := e.st.InScopeDomains(programID)
		if err != nil {
			e.finishFailed(scanID, 0, "read scope", err)
			return
		}
		if len(domains) == 0 {
			e.st.FinishScan(scanID, "error", 0, "no in-scope domains")
			return
		}
		outDomains, err := e.st.OutScopeDomains(programID)
		if err != nil {
			e.finishFailed(scanID, 0, "read scope", err)
			return
		}

		subs, err := e.enumerateWithDeadline(ctx, domains)
		if err != nil {
			e.finishFailed(scanID, 0, "subfinder", err)
			return
		}

		for _, sres := range subs {
			host := strings.ToLower(strings.TrimSpace(sres.Host))
			if host == "" || hostInScopeSuffix(host, outDomains) {
				continue
			}
			id, isNew, err := e.st.UpsertAsset(programID, host, sres.Source)
			if err != nil {
				e.finishFailed(scanID, newCount, "save asset", err)
				return
			}
			assetIDByHost[host] = id
			if isNew {
				newCount++
				newHosts = append(newHosts, host)
				_ = e.st.SaveScanEvent(scanID, id, "new_asset", "", sres.Source)
			}
		}
	} else if opts.RunHTTPX || opts.RunTakeover || opts.RunTLS {
		// Probing known assets without re-running subfinder. Domain-only
		// tools (wayback/github/cloud) need no assets at all, so this branch
		// only applies to tools that work over hosts: httpx (URLs) and
		// takeover/TLS (host-only - see runTakeoverPhase/runTLSPhase).
		hostIDs, err := e.st.AssetHosts(programID)
		if err != nil {
			e.finishFailed(scanID, 0, "read assets", err)
			return
		}
		if len(hostIDs) == 0 {
			e.st.FinishScan(scanID, "error", 0, "no known assets to probe; run subfinder first")
			return
		}
		assetIDByHost = hostIDs
	}

	if err := ctx.Err(); err != nil {
		e.finishFailed(scanID, newCount, "", err)
		return
	}

	// Domain-only phases (wayback, GitHub dorking, cloud enum) need only the
	// in-scope domains, not the asset chain's results, and are independent of
	// each other - run them concurrently with the asset chain (httpx →
	// nuclei/cors/fuzz/params/jsanalysis) so their network-bound work overlaps
	// instead of running end to end. All store writes serialize safely through
	// the single DB connection (store.Open sets MaxOpenConns(1)). The first
	// fatal error from any phase is recorded and cancels the rest, so the scan
	// still finishes exactly once with a single status.
	var (
		phaseMu   sync.Mutex
		phaseErr  error
		phaseName string
	)
	recordErr := func(name string, err error) {
		phaseMu.Lock()
		if phaseErr == nil {
			phaseErr, phaseName = err, name
		}
		phaseMu.Unlock()
		cancel() // stop the other in-flight phases
	}

	var wg sync.WaitGroup
	if opts.RunWayback {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.runWaybackPhase(ctx, programID, scanID, assetIDByHost); err != nil {
				recordErr("wayback", err)
			}
		}()
	}
	if opts.RunGithubDork {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.runGithubPhase(ctx, programID, scanID); err != nil {
				recordErr("github dork", err)
			}
		}()
	}
	if opts.RunCloudEnum {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.runCloudPhase(ctx, programID, scanID); err != nil {
				recordErr("cloud enum", err)
			}
		}()
	}
	if opts.RunTakeover {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.runTakeoverPhase(ctx, scanID, assetIDByHost); err != nil {
				recordErr("takeover", err)
			}
		}()
	}
	if opts.RunTLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.runTLSPhase(ctx, scanID, assetIDByHost); err != nil {
				recordErr("tls", err)
			}
		}()
	}

	hostIPs, changedAssets, newVulns, phase, err := e.runAssetChain(ctx, scanID, opts, assetIDByHost)
	if err != nil {
		recordErr(phase, err)
	}

	wg.Wait()

	if phaseErr != nil {
		e.finishFailed(scanID, newCount, phaseName, phaseErr)
		return
	}

	e.st.FinishScan(scanID, "done", newCount, "")

	if settings, err := e.st.GetSettings(); err == nil && settings.ScanRetentionCount > 0 {
		if _, err := e.st.PruneOldScans(programID, settings.ScanRetentionCount); err != nil {
			log.Printf("prune old scans: %v", err)
		}
	}

	programName := ""
	if p, err := e.st.GetProgram(programID); err == nil && p != nil {
		programName = p.Name
	}
	if len(newHosts) > 0 {
		assets := make([]telegram.Asset, len(newHosts))
		for i, h := range newHosts {
			assets[i] = telegram.Asset{Host: h, IP: hostIPs[h]}
		}
		if err := telegram.NotifyNewAssets(e.st, programName, assets); err != nil {
			log.Printf("telegram notify: %v", err)
		}
	}
	if len(changedAssets) > 0 {
		if err := telegram.NotifyChangedAssets(e.st, programName, changedAssets); err != nil {
			log.Printf("telegram notify: %v", err)
		}
	}
	if len(newVulns) > 0 {
		if err := telegram.NotifyNewVulnerabilities(e.st, programName, newVulns); err != nil {
			log.Printf("telegram notify: %v", err)
		}
	}
}

// runAssetChain runs the asset-dependent phases in sequence - httpx, then
// nuclei/cors/fuzz/params/jsanalysis over the URLs httpx probed. It returns
// the data Run needs for Telegram notifications (resolved IPs, changed
// assets, new vulns) plus the name of the phase that failed and its error
// (empty name / nil error on success). Meant to run on the main goroutine
// concurrently with the domain-only phases; see Run.
func (e *Engine) runAssetChain(ctx context.Context, scanID int64, opts store.ScanOptions,
	assetIDByHost map[string]int64) (map[string]string, []telegram.AssetChange, []telegram.Vuln, string, error) {

	hostIPs := map[string]string{}
	assetIDByURL := map[string]int64{}
	changedAssets := []telegram.AssetChange{}
	newVulns := []telegram.Vuln{}
	pages := map[string]string{}

	if opts.RunHTTPX {
		e.startPhase(scanID, "httpx")
		hosts := make([]string, 0, len(assetIDByHost))
		for h := range assetIDByHost {
			hosts = append(hosts, h)
		}

		probes, err := e.probeWithDeadline(ctx, hosts, ProbeOptions{Screenshot: opts.Screenshot, CaptureBody: opts.RunJSAnalysis})
		e.endPhase(scanID, "httpx")
		if err != nil {
			return hostIPs, changedAssets, newVulns, "httpx", err
		}
		for _, p := range probes {
			host := strings.ToLower(strings.TrimSpace(p.Input))
			id, ok := assetIDByHost[host]
			if !ok {
				continue
			}
			if p.IP != "" {
				hostIPs[host] = p.IP
			}
			if p.URL != "" {
				assetIDByURL[p.URL] = id
				if opts.RunJSAnalysis && p.Body != "" {
					pages[p.URL] = p.Body
				}
			}

			if old, err := e.st.GetProbe(id); err == nil && old != nil &&
				(old.StatusCode != p.StatusCode || old.Title != p.Title) {
				changedAssets = append(changedAssets, telegram.AssetChange{
					Host: host, OldStatus: old.StatusCode, NewStatus: p.StatusCode,
					OldTitle: old.Title, NewTitle: p.Title,
				})
				_ = e.st.SaveScanEvent(scanID, id, "changed_asset",
					fmt.Sprintf("%d · %s", old.StatusCode, old.Title),
					fmt.Sprintf("%d · %s", p.StatusCode, p.Title))
			}

			_ = e.st.SaveProbe(id, store.Probe{
				URL:           p.URL,
				StatusCode:    p.StatusCode,
				Title:         p.Title,
				Tech:          p.Tech,
				ContentLength: p.ContentLength,
				Webserver:     p.Webserver,
				IP:            p.IP,
				Screenshot:    p.ScreenshotBytes,
			})
		}
	}

	if opts.RunNuclei && len(assetIDByURL) > 0 {
		e.startPhase(scanID, "nuclei")
		urls := make([]string, 0, len(assetIDByURL))
		for u := range assetIDByURL {
			urls = append(urls, u)
		}
		results, err := e.scanVulnsWithDeadline(ctx, urls)
		e.endPhase(scanID, "nuclei")
		if err != nil {
			return hostIPs, changedAssets, newVulns, "nuclei", err
		}
		for _, v := range results {
			assetID, ok := assetIDByURL[v.Host]
			if !ok {
				continue
			}
			isNew, err := e.st.SaveVulnerability(store.Vulnerability{
				AssetID: assetID, ScanID: scanID, TemplateID: v.TemplateID,
				Name: v.Name, Severity: v.Severity, MatchedAt: v.MatchedAt,
			})
			if err != nil {
				continue
			}
			if isNew {
				newVulns = append(newVulns, telegram.Vuln{
					Host: v.Host, TemplateID: v.TemplateID, Name: v.Name,
					Severity: v.Severity, MatchedAt: v.MatchedAt,
				})
				_ = e.st.SaveScanEvent(scanID, assetID, "new_vuln", "",
					fmt.Sprintf("%s (%s)", v.Name, v.Severity))
			}
		}
	}

	if opts.RunCORS && len(assetIDByURL) > 0 {
		e.startPhase(scanID, "cors")
		urls := make([]string, 0, len(assetIDByURL))
		for u := range assetIDByURL {
			urls = append(urls, u)
		}
		results, err := e.corsWithDeadline(ctx, urls, opts.CORSWordlistPath)
		e.endPhase(scanID, "cors")
		if err != nil {
			return hostIPs, changedAssets, newVulns, "cors", err
		}
		for _, r := range results {
			assetID, ok := assetIDByURL[r.Host]
			if !ok {
				continue
			}
			isNew, err := e.st.SaveCORSFinding(store.CORSFinding{
				AssetID: assetID, ScanID: scanID, URL: r.URL, Issue: r.Issue,
				OriginSent: r.OriginSent, ACAOValue: r.ACAOValue, ACACAllowed: r.ACACAllowed,
			})
			if err != nil {
				continue
			}
			if isNew {
				_ = e.st.SaveScanEvent(scanID, assetID, "new_cors_finding", "",
					fmt.Sprintf("%s (origin=%s)", r.Issue, r.OriginSent))
			}
		}
	}

	if opts.RunFuzz && len(assetIDByURL) > 0 {
		e.startPhase(scanID, "fuzz")
		urls := make([]string, 0, len(assetIDByURL))
		for u := range assetIDByURL {
			urls = append(urls, u)
		}
		results, err := e.fuzzWithDeadline(ctx, urls, opts.FuzzWordlistPath)
		e.endPhase(scanID, "fuzz")
		if err != nil {
			return hostIPs, changedAssets, newVulns, "fuzz", err
		}
		for _, r := range results {
			assetID, ok := assetIDByURL[r.Host]
			if !ok {
				continue
			}
			isNew, err := e.st.SaveFuzzHit(store.FuzzHit{
				AssetID: assetID, ScanID: scanID, Path: r.Path, URL: r.URL,
				StatusCode: r.StatusCode, ContentLength: r.ContentLength,
			})
			if err != nil {
				continue
			}
			if isNew {
				_ = e.st.SaveScanEvent(scanID, assetID, "new_fuzz_hit", "",
					fmt.Sprintf("%d · %s", r.StatusCode, r.Path))
			}
		}
	}

	if opts.RunParams && len(assetIDByURL) > 0 {
		e.startPhase(scanID, "params")
		urls := make([]string, 0, len(assetIDByURL))
		for u := range assetIDByURL {
			urls = append(urls, u)
		}
		results, err := e.paramsWithDeadline(ctx, urls, opts.ParamsWordlistPath)
		e.endPhase(scanID, "params")
		if err != nil {
			return hostIPs, changedAssets, newVulns, "params", err
		}
		for _, r := range results {
			assetID, ok := assetIDByURL[r.Host]
			if !ok {
				continue
			}
			isNew, err := e.st.SaveParamHit(store.ParamHit{
				AssetID: assetID, ScanID: scanID, URL: r.URL, Param: r.Param,
				BaselineStatus: r.BaselineStatus, BaselineLength: r.BaselineLength,
				HitStatus: r.HitStatus, HitLength: r.HitLength,
			})
			if err != nil {
				continue
			}
			if isNew {
				_ = e.st.SaveScanEvent(scanID, assetID, "new_param_hit", "",
					fmt.Sprintf("%s (%d, %d bytes)", r.Param, r.HitStatus, r.HitLength))
			}
		}
	}

	if opts.RunJSAnalysis && len(pages) > 0 {
		e.startPhase(scanID, "jsanalysis")
		results, err := e.jsAnalysisWithDeadline(ctx, pages)
		e.endPhase(scanID, "jsanalysis")
		if err != nil {
			return hostIPs, changedAssets, newVulns, "jsanalysis", err
		}
		for _, f := range results {
			assetID, ok := assetIDByURL[f.Host]
			if !ok {
				continue
			}
			isNew, err := e.st.SaveJSFinding(store.JSFinding{
				AssetID: assetID, ScanID: scanID, Kind: f.Kind, SourceURL: f.SourceURL, Value: f.Value,
			})
			if err != nil {
				continue
			}
			if isNew {
				kind := "new_endpoint"
				if f.Kind == "secret" {
					kind = "new_secret"
				}
				_ = e.st.SaveScanEvent(scanID, assetID, kind, "", f.Value)
			}
		}
	}

	return hostIPs, changedAssets, newVulns, "", nil
}

// runWaybackPhase fetches archived URLs for the program's in-scope domains
// and persists them. Domain-only (no asset chain dependency); see Run.
func (e *Engine) runWaybackPhase(ctx context.Context, programID, scanID int64, assetIDByHost map[string]int64) error {
	e.startPhase(scanID, "wayback")
	defer e.endPhase(scanID, "wayback")
	domains, err := e.st.InScopeDomains(programID)
	if err != nil || len(domains) == 0 {
		return nil
	}
	outDomains, _ := e.st.OutScopeDomains(programID)
	results, err := e.waybackWithDeadline(ctx, domains)
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Host != "" && hostInScopeSuffix(r.Host, outDomains) {
			continue
		}
		isNew, err := e.st.SaveArchivedURL(store.ArchivedURL{
			ProgramID: programID, ScanID: scanID, URL: r.URL, Host: r.Host,
		})
		if err != nil {
			continue
		}
		if isNew {
			if assetID, ok := assetIDByHost[r.Host]; ok {
				_ = e.st.SaveScanEvent(scanID, assetID, "new_archived_url", "", r.URL)
			}
		}
	}
	return nil
}

// runGithubPhase runs GitHub code-search dorks for the program's in-scope
// domains, if a token is configured. Domain-only; see Run. No scan_events
// entry (GitHub findings have no asset_id, and that column is NOT NULL).
func (e *Engine) runGithubPhase(ctx context.Context, programID, scanID int64) error {
	e.startPhase(scanID, "github dork")
	defer e.endPhase(scanID, "github dork")
	domains, err := e.st.InScopeDomains(programID)
	if err != nil || len(domains) == 0 {
		return nil
	}
	settings, sErr := e.st.GetSettings()
	if sErr != nil || settings.GithubToken == "" {
		return nil
	}
	results, err := e.githubDorkWithDeadline(ctx, settings.GithubToken, domains)
	if err != nil {
		return err
	}
	for _, f := range results {
		_, _ = e.st.SaveGitHubFinding(store.GitHubFinding{
			ProgramID: programID, ScanID: scanID, Repo: f.Repo, Path: f.Path,
			HTMLURL: f.HTMLURL, Dork: f.Dork, Kind: f.Kind, Value: f.Value,
		})
	}
	return nil
}

// runCloudPhase enumerates cloud storage buckets for the program's in-scope
// domains. Domain-only; see Run. No scan_events entry (cloud findings have no
// asset_id, and that column is NOT NULL).
func (e *Engine) runCloudPhase(ctx context.Context, programID, scanID int64) error {
	e.startPhase(scanID, "cloud enum")
	defer e.endPhase(scanID, "cloud enum")
	domains, err := e.st.InScopeDomains(programID)
	if err != nil || len(domains) == 0 {
		return nil
	}
	results, err := e.cloudEnumWithDeadline(ctx, domains)
	if err != nil {
		return err
	}
	for _, f := range results {
		_, _ = e.st.SaveCloudFinding(store.CloudFinding{
			ProgramID: programID, ScanID: scanID, Provider: f.Provider,
			Bucket: f.Bucket, URL: f.URL, Kind: f.Kind,
		})
	}
	return nil
}

// runTakeoverPhase checks known hosts for subdomain-takeover candidates.
// Host-only (needs assetIDByHost, not httpx's live URLs) - runs in the same
// concurrent group as the domain-only phases; see Run.
func (e *Engine) runTakeoverPhase(ctx context.Context, scanID int64, assetIDByHost map[string]int64) error {
	e.startPhase(scanID, "takeover")
	defer e.endPhase(scanID, "takeover")
	if len(assetIDByHost) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(assetIDByHost))
	for h := range assetIDByHost {
		hosts = append(hosts, h)
	}
	results, err := e.takeoverWithDeadline(ctx, hosts)
	if err != nil {
		return err
	}
	for _, f := range results {
		assetID, ok := assetIDByHost[f.Host]
		if !ok {
			continue
		}
		isNew, err := e.st.SaveTakeoverFinding(store.TakeoverFinding{
			AssetID: assetID, ScanID: scanID, Host: f.Host, CNAME: f.CNAME,
			Service: f.Service, Kind: f.Kind, Evidence: f.Evidence,
		})
		if err != nil {
			continue
		}
		if isNew {
			_ = e.st.SaveScanEvent(scanID, assetID, "new_takeover_finding", "",
				fmt.Sprintf("%s (%s)", f.Kind, f.CNAME))
		}
	}
	return nil
}

// runTLSPhase inspects known hosts' TLS certificates. Host-only (needs
// assetIDByHost, not httpx's live URLs) - runs in the same concurrent group
// as the domain-only phases; see Run.
func (e *Engine) runTLSPhase(ctx context.Context, scanID int64, assetIDByHost map[string]int64) error {
	e.startPhase(scanID, "tls")
	defer e.endPhase(scanID, "tls")
	if len(assetIDByHost) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(assetIDByHost))
	for h := range assetIDByHost {
		hosts = append(hosts, h)
	}
	results, err := e.tlsWithDeadline(ctx, hosts)
	if err != nil {
		return err
	}
	for _, f := range results {
		assetID, ok := assetIDByHost[f.Host]
		if !ok {
			continue
		}
		isNew, err := e.st.SaveTLSFinding(store.TLSFinding{
			AssetID: assetID, ScanID: scanID, Host: f.Host, Issue: f.Issue, Detail: f.Detail,
		})
		if err != nil {
			continue
		}
		if isNew {
			_ = e.st.SaveScanEvent(scanID, assetID, "new_tls_finding", "",
				fmt.Sprintf("%s: %s", f.Issue, f.Detail))
		}
	}
	return nil
}

// finishFailed marks scanID "cancelled" if err originated from the scan's
// own context being cancelled (see Cancel), or "error" otherwise.
func (e *Engine) finishFailed(scanID int64, newCount int, phase string, err error) {
	if errors.Is(err, context.Canceled) {
		e.st.FinishScan(scanID, "cancelled", newCount, "")
		return
	}
	msg := err.Error()
	if phase != "" {
		msg = phase + ": " + msg
	}
	e.st.FinishScan(scanID, "error", newCount, msg)
}

// enumerateWithDeadline runs Subfinder.Enumerate on its own goroutine and
// races it against subfinderPhaseTimeout, so a source that ignores ctx
// cancellation can never hang the scan forever. See the timeout constants'
// doc comment for why this is necessary.
func (e *Engine) enumerateWithDeadline(ctx context.Context, domains []string) ([]SubResult, error) {
	ctx, cancel := context.WithTimeout(ctx, subfinderPhaseTimeout)
	defer cancel()

	type outcome struct {
		subs []SubResult
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		subs, err := e.subs.Enumerate(ctx, domains)
		done <- outcome{subs, err}
	}()

	select {
	case o := <-done:
		return o.subs, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for subdomain enumeration", subfinderPhaseTimeout)
	}
}

// scanVulnsWithDeadline is the nuclei equivalent of enumerateWithDeadline,
// with its own (much larger) timeout - see nucleiPhaseTimeout's doc comment.
func (e *Engine) scanVulnsWithDeadline(ctx context.Context, urls []string) ([]VulnResult, error) {
	ctx, cancel := context.WithTimeout(ctx, nucleiPhaseTimeout)
	defer cancel()

	type outcome struct {
		results []VulnResult
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.vuln.Scan(ctx, urls)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for nuclei scan of %d urls", nucleiPhaseTimeout, len(urls))
	}
}

// fuzzTimeoutFor is the fuzz-phase equivalent of httpxTimeoutFor.
func fuzzTimeoutFor(hostCount int) time.Duration {
	d := fuzzBaseTimeout + time.Duration(hostCount)*fuzzPerHostBudget
	if d > fuzzMaxTimeout {
		return fuzzMaxTimeout
	}
	return d
}

// fuzzWithDeadline is the fuzz equivalent of scanVulnsWithDeadline.
func (e *Engine) fuzzWithDeadline(ctx context.Context, urls []string, wordlistPath string) ([]FuzzResult, error) {
	timeout := fuzzTimeoutFor(len(urls))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		results []FuzzResult
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.fuzz.Fuzz(ctx, urls, wordlistPath)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for fuzz scan of %d urls", timeout, len(urls))
	}
}

// waybackWithDeadline races URLArchive.Fetch against waybackPhaseTimeout.
func (e *Engine) waybackWithDeadline(ctx context.Context, domains []string) ([]ArchivedURL, error) {
	ctx, cancel := context.WithTimeout(ctx, waybackPhaseTimeout)
	defer cancel()

	type outcome struct {
		results []ArchivedURL
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.archive.Fetch(ctx, domains)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for wayback lookup of %d domains", waybackPhaseTimeout, len(domains))
	}
}

// paramsTimeoutFor is the param-fuzz equivalent of httpxTimeoutFor/fuzzTimeoutFor.
func paramsTimeoutFor(hostCount int) time.Duration {
	d := paramsBaseTimeout + time.Duration(hostCount)*paramsPerHostBudget
	if d > paramsMaxTimeout {
		return paramsMaxTimeout
	}
	return d
}

// paramsWithDeadline is the param-fuzz equivalent of fuzzWithDeadline.
func (e *Engine) paramsWithDeadline(ctx context.Context, urls []string, wordlistPath string) ([]ParamResult, error) {
	timeout := paramsTimeoutFor(len(urls))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		results []ParamResult
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.params.FuzzParams(ctx, urls, wordlistPath)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for param fuzz of %d urls", timeout, len(urls))
	}
}

// jsAnalysisWithDeadline races JSAnalyzer.Analyze against jsAnalysisPhaseTimeout.
func (e *Engine) jsAnalysisWithDeadline(ctx context.Context, pages map[string]string) ([]JSFinding, error) {
	ctx, cancel := context.WithTimeout(ctx, jsAnalysisPhaseTimeout)
	defer cancel()

	type outcome struct {
		results []JSFinding
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.jsAnalyzer.Analyze(ctx, pages)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for JS analysis of %d pages", jsAnalysisPhaseTimeout, len(pages))
	}
}

// corsTimeoutFor is the CORS-scan equivalent of httpxTimeoutFor/fuzzTimeoutFor.
func corsTimeoutFor(hostCount int) time.Duration {
	d := corsBaseTimeout + time.Duration(hostCount)*corsPerHostBudget
	if d > corsMaxTimeout {
		return corsMaxTimeout
	}
	return d
}

// corsWithDeadline races CORSScanner.Scan against a host-scaled timeout, the
// same deadline-race pattern as fuzzWithDeadline/paramsWithDeadline.
func (e *Engine) corsWithDeadline(ctx context.Context, urls []string, pathsWordlistPath string) ([]CORSFinding, error) {
	timeout := corsTimeoutFor(len(urls))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		results []CORSFinding
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.cors.Scan(ctx, urls, pathsWordlistPath)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for CORS scan of %d urls", timeout, len(urls))
	}
}

// githubDorkTimeoutFor scales the deadline with domain count (each domain
// runs the full dork list, paced by githubQueryDelay).
func githubDorkTimeoutFor(domainCount int) time.Duration {
	d := githubDorkBaseTimeout + time.Duration(domainCount)*githubDorkPerDomainBudget
	if d > githubDorkMaxTimeout {
		return githubDorkMaxTimeout
	}
	return d
}

// githubDorkWithDeadline races GitHubDorker.Scan against a domain-scaled
// timeout, the same deadline-race pattern as the other *WithDeadline methods.
func (e *Engine) githubDorkWithDeadline(ctx context.Context, token string, domains []string) ([]GitHubFinding, error) {
	timeout := githubDorkTimeoutFor(len(domains))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		results []GitHubFinding
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.github.Scan(ctx, token, domains)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for GitHub dork scan of %d domains", timeout, len(domains))
	}
}

// cloudEnumTimeoutFor is the cloud-enum equivalent of httpxTimeoutFor/fuzzTimeoutFor.
func cloudEnumTimeoutFor(domainCount int) time.Duration {
	d := cloudEnumBaseTimeout + time.Duration(domainCount)*cloudEnumPerDomainBudget
	if d > cloudEnumMaxTimeout {
		return cloudEnumMaxTimeout
	}
	return d
}

// cloudEnumWithDeadline races CloudEnumerator.Enumerate against a
// domain-scaled timeout, the same deadline-race pattern as the other
// *WithDeadline methods.
func (e *Engine) cloudEnumWithDeadline(ctx context.Context, domains []string) ([]CloudFinding, error) {
	timeout := cloudEnumTimeoutFor(len(domains))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		results []CloudFinding
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.cloud.Enumerate(ctx, domains)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for cloud enum of %d domains", timeout, len(domains))
	}
}

// probeWithDeadline is the httpx equivalent of enumerateWithDeadline. The
// deadline scales with len(hosts) since a program with a large passive
// footprint can easily have far more candidate hosts than a fixed timeout
// could ever probe through.
func (e *Engine) probeWithDeadline(ctx context.Context, hosts []string, opts ProbeOptions) ([]HTTPResult, error) {
	timeout := httpxTimeoutFor(len(hosts), opts.Screenshot)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		probes []HTTPResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		probes, err := e.http.Probe(ctx, hosts, opts)
		done <- outcome{probes, err}
	}()

	select {
	case o := <-done:
		return o.probes, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for HTTP probing of %d hosts", timeout, len(hosts))
	}
}

// takeoverTimeoutFor is the takeover-scan equivalent of corsTimeoutFor.
func takeoverTimeoutFor(hostCount int) time.Duration {
	d := takeoverBaseTimeout + time.Duration(hostCount)*takeoverPerHostBudget
	if d > takeoverMaxTimeout {
		return takeoverMaxTimeout
	}
	return d
}

// takeoverWithDeadline races TakeoverScanner.Scan against a host-scaled
// timeout, the same deadline-race pattern as corsWithDeadline.
func (e *Engine) takeoverWithDeadline(ctx context.Context, hosts []string) ([]TakeoverFinding, error) {
	timeout := takeoverTimeoutFor(len(hosts))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		results []TakeoverFinding
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.takeover.Scan(ctx, hosts)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for takeover scan of %d hosts", timeout, len(hosts))
	}
}

// tlsTimeoutFor is the TLS-scan equivalent of corsTimeoutFor.
func tlsTimeoutFor(hostCount int) time.Duration {
	d := tlsBaseTimeout + time.Duration(hostCount)*tlsPerHostBudget
	if d > tlsMaxTimeout {
		return tlsMaxTimeout
	}
	return d
}

// tlsWithDeadline races TLSScanner.Scan against a host-scaled timeout, the
// same deadline-race pattern as corsWithDeadline.
func (e *Engine) tlsWithDeadline(ctx context.Context, hosts []string) ([]TLSFinding, error) {
	timeout := tlsTimeoutFor(len(hosts))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		results []TLSFinding
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := e.tlsScan.Scan(ctx, hosts)
		done <- outcome{results, err}
	}()

	select {
	case o := <-done:
		return o.results, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for TLS scan of %d hosts", timeout, len(hosts))
	}
}
