package server

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"bbtracker/internal/hackerone"
	"bbtracker/internal/store"
)

// domainRe matches a bare, dotted hostname (at least two labels), the shape
// subfinder expects. It rejects raw URLs/paths so scans don't silently find
// nothing for a scope entry like "https://example.com/path".
var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// normalizeDomain extracts a bare hostname from user input that may include
// a scheme, path, port, leading wildcard, or trailing dot (e.g.
// "https://*.example.com/foo:8080" -> "example.com"), so pasting a URL or a
// wildcard scope entry (the common "*.example.com" scope-page format) still
// works. A leading wildcard is dropped rather than rejected because this
// codebase's scope matching already treats an in-scope apex domain as
// covering all its subdomains (see hostInScopeSuffix in internal/recon).
func normalizeDomain(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", fmt.Errorf("domain is required")
	}
	candidate := s
	if !strings.Contains(candidate, "://") {
		candidate = "//" + candidate // scheme-relative so url.Parse still extracts Host
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("%q doesn't look like a domain", s)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	host = strings.TrimPrefix(host, "*.")
	if !domainRe.MatchString(host) {
		return "", fmt.Errorf("%q doesn't look like a domain", s)
	}
	return host, nil
}

// pathID parses the {id} path value as an int64, writing a 400 on failure.
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func (s *Server) handleListPrograms(w http.ResponseWriter, r *http.Request) {
	programs, err := s.st.ListPrograms()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, programs)
}

func (s *Server) handleCreateProgram(w http.ResponseWriter, r *http.Request) {
	var p store.Program
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if p.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	created, err := s.st.CreateProgram(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleGetProgram(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.st.GetProgram(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p == nil {
		writeError(w, http.StatusNotFound, "program not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleUpdateProgram(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var p store.Program
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	existing, err := s.st.GetProgram(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "program not found")
		return
	}
	updated, err := s.st.UpdateProgram(id, p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteProgram(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteProgram(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// scheduleRequest is the body for PUT /api/programs/{id}/schedule.
type scheduleRequest struct {
	Enabled            bool   `json:"enabled"`
	IntervalDays       int    `json:"interval_days"`
	TimeOfDay          string `json:"time_of_day"`
	RunSubfinder       bool   `json:"run_subfinder"`
	RunHTTPX           bool   `json:"run_httpx"`
	Screenshot         bool   `json:"screenshot"`
	RunNuclei          bool   `json:"run_nuclei"`
	RunFuzz            bool   `json:"run_fuzz"`
	FuzzWordlistPath   string `json:"fuzz_wordlist_path"`
	RunWayback         bool   `json:"run_wayback"`
	RunParams          bool   `json:"run_params"`
	ParamsWordlistPath string `json:"params_wordlist_path"`
	RunJSAnalysis      bool   `json:"run_jsanalysis"`
	RunCORS            bool   `json:"run_cors"`
	CORSWordlistPath   string `json:"cors_wordlist_path"`
	RunGithubDork      bool   `json:"run_github_dork"`
	RunCloudEnum       bool   `json:"run_cloud_enum"`
	RunTakeover        bool   `json:"run_takeover"`
	RunTLS             bool   `json:"run_tls"`
	RunDNS             bool   `json:"run_dns"`
	RunUncover         bool   `json:"run_uncover"`
	RunCrawl           bool   `json:"run_crawl"`
}

// handleUpdateSchedule sets a program's recurring auto-scan configuration.
// The schedule is evaluated by internal/scheduler while the app is running.
func (s *Server) handleUpdateSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	program, err := s.st.GetProgram(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if program == nil {
		writeError(w, http.StatusNotFound, "program not found")
		return
	}
	var req scheduleRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.Enabled && req.IntervalDays < 1 {
		writeError(w, http.StatusBadRequest, "interval_days must be at least 1")
		return
	}
	if err := validateWordlistPath(req.FuzzWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateWordlistPath(req.ParamsWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateWordlistPath(req.CORSWordlistPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	anyTool := req.RunSubfinder || req.RunHTTPX || req.RunNuclei || req.RunFuzz ||
		req.RunWayback || req.RunParams || req.RunJSAnalysis || req.RunCORS ||
		req.RunGithubDork || req.RunCloudEnum || req.RunTakeover || req.RunTLS || req.RunDNS || req.RunUncover || req.RunCrawl
	if req.Enabled && !anyTool {
		writeError(w, http.StatusBadRequest, "select at least one tool to run")
		return
	}
	if req.Enabled && req.RunNuclei && !req.RunHTTPX {
		writeError(w, http.StatusBadRequest, "nuclei requires the HTTP probe tool")
		return
	}
	if req.Enabled && req.RunFuzz && !req.RunHTTPX {
		writeError(w, http.StatusBadRequest, "fuzzing requires the HTTP probe tool")
		return
	}
	if req.Enabled && req.RunParams && !req.RunHTTPX {
		writeError(w, http.StatusBadRequest, "hidden parameter discovery requires the HTTP probe tool")
		return
	}
	if req.Enabled && req.RunJSAnalysis && !req.RunHTTPX {
		writeError(w, http.StatusBadRequest, "JS analysis requires the HTTP probe tool")
		return
	}
	if req.Enabled && req.RunCORS && !req.RunHTTPX {
		writeError(w, http.StatusBadRequest, "CORS scanning requires the HTTP probe tool")
		return
	}
	if req.Enabled && req.RunCrawl && !req.RunHTTPX {
		writeError(w, http.StatusBadRequest, "crawling requires the HTTP probe tool")
		return
	}
	if req.Enabled && req.RunGithubDork {
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
	if req.Enabled {
		if _, err := time.Parse("15:04", req.TimeOfDay); err != nil {
			writeError(w, http.StatusBadRequest, "time_of_day must be HH:MM")
			return
		}
	}
	updated, err := s.st.UpdateSchedule(id, req.Enabled, req.IntervalDays, req.TimeOfDay, req.RunSubfinder, req.RunHTTPX,
		req.Screenshot, req.RunNuclei, req.RunFuzz, req.FuzzWordlistPath,
		req.RunWayback, req.RunParams, req.ParamsWordlistPath, req.RunJSAnalysis, req.RunCORS, req.CORSWordlistPath,
		req.RunGithubDork, req.RunCloudEnum, req.RunTakeover, req.RunTLS, req.RunDNS, req.RunUncover, req.RunCrawl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleListScopes(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	scopes, err := s.st.ListScopes(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scopes)
}

func (s *Server) handleCreateScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var sc store.Scope
	if err := readJSON(r, &sc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	domain, err := normalizeDomain(sc.Domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sc.Domain = domain
	sc.ProgramID = id
	created, err := s.st.CreateScope(sc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeleteScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteScope(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// handleImportScopes bulk-adds scope entries from pasted text, one domain
// per line (blank lines and "#" comments skipped) - works for any platform,
// including ones with no scope API (e.g. Bugcrowd), since it's just parsing
// whatever the user copy-pasted from the program page.
func (s *Server) handleImportScopes(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Text string `json:"text"`
		Type string `json:"type"` // "in" or "out"
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	scType := "in"
	if req.Type == "out" {
		scType = "out"
	}

	var entries []store.Scope
	for _, line := range strings.Split(req.Text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain, err := normalizeDomain(line)
		if err != nil {
			continue // skip unparseable lines rather than failing the whole paste
		}
		entries = append(entries, store.Scope{Domain: domain, Type: scType})
	}

	imported, skipped, err := s.st.ImportScopes(id, entries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"imported": imported, "skipped": skipped})
}

// handleImportHackerOneScope imports a HackerOne program's structured scope
// (in-scope and out-of-scope domains) via HackerOne's API. Requires
// hackerone_username/hackerone_api_token to already be saved in Settings.
func (s *Server) handleImportHackerOneScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Handle string `json:"handle"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.Handle == "" {
		writeError(w, http.StatusBadRequest, "hackerone program handle is required")
		return
	}

	settings, err := s.st.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if settings.HackerOneUsername == "" || settings.HackerOneAPIToken == "" {
		writeError(w, http.StatusBadRequest, "save a HackerOne username and API token in Settings first")
		return
	}

	items, err := hackerone.FetchStructuredScopes(r.Context(), settings.HackerOneUsername, settings.HackerOneAPIToken, req.Handle)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	entries := make([]store.Scope, 0, len(items))
	for _, it := range items {
		scType := "out"
		if it.InScope {
			scType = "in"
		}
		entries = append(entries, store.Scope{Domain: it.Domain, Type: scType})
	}

	imported, skipped, err := s.st.ImportScopes(id, entries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"imported": imported, "skipped": skipped})
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	assets, err := s.st.ListAssets(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, assets)
}

// handleGetAssetScreenshot serves the raw PNG bytes captured for an asset's
// latest probe, if any.
func (s *Server) handleGetAssetScreenshot(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	png, err := s.st.GetScreenshot(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(png) == 0 {
		writeError(w, http.StatusNotFound, "no screenshot for this asset")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

// handleUpdateAssetNotes sets an asset's free-text notes.
func (s *Server) handleUpdateAssetNotes(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Notes string `json:"notes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := s.st.UpdateAssetNotes(id, req.Notes); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
