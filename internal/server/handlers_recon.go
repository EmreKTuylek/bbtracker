package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"bbtracker/internal/store"
)

// scanRequest selects which recon tools a scan should run. A nil field means
// "use the default"; only an explicit false/true overrides it.
type scanRequest struct {
	RunSubfinder       *bool   `json:"run_subfinder"`
	RunHTTPX           *bool   `json:"run_httpx"`
	Screenshot         *bool   `json:"screenshot"`
	RunNuclei          *bool   `json:"run_nuclei"`
	RunFuzz            *bool   `json:"run_fuzz"`
	FuzzWordlistPath   *string `json:"fuzz_wordlist_path"`
	RunWayback         *bool   `json:"run_wayback"`
	RunParams          *bool   `json:"run_params"`
	ParamsWordlistPath *string `json:"params_wordlist_path"`
	RunJSAnalysis      *bool   `json:"run_jsanalysis"`
	RunCORS            *bool   `json:"run_cors"`
	CORSWordlistPath   *string `json:"cors_wordlist_path"`
	RunGithubDork      *bool   `json:"run_github_dork"`
	RunCloudEnum       *bool   `json:"run_cloud_enum"`
	RunTakeover        *bool   `json:"run_takeover"`
	RunTLS             *bool   `json:"run_tls"`
	RunDNS             *bool   `json:"run_dns"`
	RunUncover         *bool   `json:"run_uncover"`
	RunCrawl           *bool   `json:"run_crawl"`
}

func stringOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// maxWordlistBytes caps how large a user-supplied wordlist file may be.
//
// ponytail: a flat size cap, not a directory allowlist - the fuzz/params
// wordlist path is a documented feature for pointing at any wordlist file on
// disk (e.g. a local SecLists checkout, see CLAUDE.md), so confining it to a
// fixed directory would break that. The cap alone stops the worst abuse (the
// API opening and line-scanning an arbitrary huge or binary file) without
// touching the intended use; even SecLists' biggest raft lists are a few MB.
const maxWordlistBytes = 20 << 20 // 20 MiB

// validateWordlistPath checks a user-supplied wordlist path - empty means
// "use the embedded default" and is always fine - exists, is a regular file,
// and isn't implausibly large. Called at scan-start/schedule-save time so a
// bad path is a clear 400 immediately, not a confusing failure deep inside
// fuzz.go/paramfuzz.go's loadWordlistFile mid-scan.
func validateWordlistPath(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("wordlist path %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("wordlist path %q is not a regular file", path)
	}
	if info.Size() > maxWordlistBytes {
		return fmt.Errorf("wordlist path %q is too large (%d bytes, max %d)", path, info.Size(), maxWordlistBytes)
	}
	return nil
}

// handleStartScan starts a new recon scan for a program, unless one is
// already running. The scan itself runs asynchronously in a goroutine;
// the client polls GET /api/scans/{id} for completion.
func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}

	program, err := s.st.GetProgram(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if program == nil {
		writeError(w, http.StatusNotFound, "program not found")
		return
	}

	running, err := s.st.RunningScanForProgram(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if running > 0 {
		writeError(w, http.StatusConflict, "a scan is already running for this program")
		return
	}

	var req scanRequest
	if err := readJSON(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	opts := store.ScanOptions{
		RunSubfinder:       boolOr(req.RunSubfinder, true),
		RunHTTPX:           boolOr(req.RunHTTPX, true),
		Screenshot:         boolOr(req.Screenshot, false),
		RunNuclei:          boolOr(req.RunNuclei, false),
		RunFuzz:            boolOr(req.RunFuzz, false),
		FuzzWordlistPath:   stringOr(req.FuzzWordlistPath, ""),
		RunWayback:         boolOr(req.RunWayback, false),
		RunParams:          boolOr(req.RunParams, false),
		ParamsWordlistPath: stringOr(req.ParamsWordlistPath, ""),
		RunJSAnalysis:      boolOr(req.RunJSAnalysis, false),
		RunCORS:            boolOr(req.RunCORS, false),
		CORSWordlistPath:   stringOr(req.CORSWordlistPath, ""),
		RunGithubDork:      boolOr(req.RunGithubDork, false),
		RunCloudEnum:       boolOr(req.RunCloudEnum, false),
		RunTakeover:        boolOr(req.RunTakeover, false),
		RunTLS:             boolOr(req.RunTLS, false),
		RunDNS:             boolOr(req.RunDNS, false),
		RunUncover:         boolOr(req.RunUncover, false),
		RunCrawl:           boolOr(req.RunCrawl, false),
	}
	if !opts.AnyToolEnabled() {
		writeError(w, http.StatusBadRequest, "select at least one tool to run")
		return
	}
	if err := validateWordlistPath(opts.FuzzWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateWordlistPath(opts.ParamsWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateWordlistPath(opts.CORSWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if opts.Screenshot && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "screenshot requires the HTTP probe tool")
		return
	}
	if opts.RunNuclei && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "nuclei requires the HTTP probe tool")
		return
	}
	if opts.RunFuzz && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "fuzzing requires the HTTP probe tool")
		return
	}
	if opts.RunParams && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "hidden parameter discovery requires the HTTP probe tool")
		return
	}
	if opts.RunJSAnalysis && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "JS analysis requires the HTTP probe tool")
		return
	}
	if opts.RunCORS && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "CORS scanning requires the HTTP probe tool")
		return
	}
	if opts.RunCrawl && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "crawling requires the HTTP probe tool")
		return
	}
	if opts.RunGithubDork {
		settings, err := s.st.GetSettings()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if settings.GithubToken == "" {
			writeError(w, http.StatusBadRequest, "GitHub dorking requires a GitHub token in Settings")
			return
		}
	}

	scanID, err := s.st.CreateScan(programID, opts, "manual")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	go s.engine.Run(context.Background(), programID, scanID, opts)

	writeJSON(w, http.StatusAccepted, map[string]int64{"scan_id": scanID})
}

// assetScanRequest is the body for POST /api/assets/{id}/scan - the Assets
// tab's "Rescan" button. Deliberately a narrower subset of scanRequest: it
// omits subfinder/uncover/wayback/github-dork/cloud-enum, which are
// domain-scoped tools that don't make sense targeted at a single asset.
type assetScanRequest struct {
	RunHTTPX           *bool   `json:"run_httpx"`
	Screenshot         *bool   `json:"screenshot"`
	RunNuclei          *bool   `json:"run_nuclei"`
	RunFuzz            *bool   `json:"run_fuzz"`
	FuzzWordlistPath   *string `json:"fuzz_wordlist_path"`
	RunParams          *bool   `json:"run_params"`
	ParamsWordlistPath *string `json:"params_wordlist_path"`
	RunJSAnalysis      *bool   `json:"run_jsanalysis"`
	RunCORS            *bool   `json:"run_cors"`
	CORSWordlistPath   *string `json:"cors_wordlist_path"`
	RunTakeover        *bool   `json:"run_takeover"`
	RunTLS             *bool   `json:"run_tls"`
	RunDNS             *bool   `json:"run_dns"`
	RunCrawl           *bool   `json:"run_crawl"`
}

// handleStartAssetScan starts a scan scoped to a single known asset (opts.AssetID),
// reusing the exact same Engine.Run/CreateScan path as a whole-program scan -
// see the AssetID branch in Engine.Run. Rejected the same way as a
// whole-program scan if one is already running for the asset's program
// (RunningScanForProgram has no asset-level granularity; only one scan runs
// per program at a time regardless of scope).
func (s *Server) handleStartAssetScan(w http.ResponseWriter, r *http.Request) {
	assetID, ok := pathID(w, r)
	if !ok {
		return
	}
	asset, err := s.st.GetAsset(assetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if asset == nil {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}

	running, err := s.st.RunningScanForProgram(asset.ProgramID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if running > 0 {
		writeError(w, http.StatusConflict, "a scan is already running for this program")
		return
	}

	var req assetScanRequest
	if err := readJSON(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	opts := store.ScanOptions{
		RunHTTPX:           boolOr(req.RunHTTPX, true),
		Screenshot:         boolOr(req.Screenshot, false),
		RunNuclei:          boolOr(req.RunNuclei, false),
		RunFuzz:            boolOr(req.RunFuzz, false),
		FuzzWordlistPath:   stringOr(req.FuzzWordlistPath, ""),
		RunParams:          boolOr(req.RunParams, false),
		ParamsWordlistPath: stringOr(req.ParamsWordlistPath, ""),
		RunJSAnalysis:      boolOr(req.RunJSAnalysis, false),
		RunCORS:            boolOr(req.RunCORS, false),
		CORSWordlistPath:   stringOr(req.CORSWordlistPath, ""),
		RunTakeover:        boolOr(req.RunTakeover, false),
		RunTLS:             boolOr(req.RunTLS, false),
		RunDNS:             boolOr(req.RunDNS, false),
		RunCrawl:           boolOr(req.RunCrawl, false),
		AssetID:            assetID,
	}
	if !opts.AnyToolEnabled() {
		writeError(w, http.StatusBadRequest, "select at least one tool to run")
		return
	}
	if err := validateWordlistPath(opts.FuzzWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateWordlistPath(opts.ParamsWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateWordlistPath(opts.CORSWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if opts.Screenshot && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "screenshot requires the HTTP probe tool")
		return
	}
	if opts.RunNuclei && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "nuclei requires the HTTP probe tool")
		return
	}
	if opts.RunFuzz && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "fuzzing requires the HTTP probe tool")
		return
	}
	if opts.RunParams && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "hidden parameter discovery requires the HTTP probe tool")
		return
	}
	if opts.RunJSAnalysis && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "JS analysis requires the HTTP probe tool")
		return
	}
	if opts.RunCORS && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "CORS scanning requires the HTTP probe tool")
		return
	}
	if opts.RunCrawl && !opts.RunHTTPX {
		writeError(w, http.StatusBadRequest, "crawling requires the HTTP probe tool")
		return
	}

	scanID, err := s.st.CreateScan(asset.ProgramID, opts, "manual")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	go s.engine.Run(context.Background(), asset.ProgramID, scanID, opts)

	writeJSON(w, http.StatusAccepted, map[string]int64{"scan_id": scanID})
}

// handleStopScan requests cancellation of a running scan. The scan's own
// goroutine observes the cancellation and marks the row "cancelled"
// asynchronously; this handler does not wait for that to happen.
func (s *Server) handleStopScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	scan, err := s.st.GetScan(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if scan == nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if scan.Status != "running" {
		writeError(w, http.StatusConflict, "scan is not running")
		return
	}
	if !s.engine.Cancel(id) {
		writeError(w, http.StatusConflict, "scan is not currently cancellable")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancelling"})
}

// handleListScans returns the scan history for a program, most recent first.
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	scans, err := s.st.ListScans(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// scanWithProgress adds the engine's live in-memory view of which phases are
// currently running to a Scan - this isn't stored in the DB (see
// Engine.ActivePhases: several phases can be genuinely active at once now
// that domain/host-only phases run concurrently with the httpx chain, so a
// single current_phase column would be misleading).
type scanWithProgress struct {
	*store.Scan
	ActivePhases []string `json:"active_phases,omitempty"`
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	scan, err := s.st.GetScan(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if scan == nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	out := scanWithProgress{Scan: scan}
	if scan.Status == "running" {
		out.ActivePhases = s.engine.ActivePhases(id)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleListScanEvents returns what a scan found (new assets, changed
// assets, new vulnerabilities) - the scan-diff view.
func (s *Server) handleListScanEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	events, err := s.st.ListScanEvents(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}
