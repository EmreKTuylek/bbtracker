// Package server exposes bbtracker's HTTP API and static frontend.
package server

import (
	"encoding/json"
	"io/fs"
	"net/http"

	"bbtracker/internal/recon"
	"bbtracker/internal/store"
)

// Server wires the store, the recon engine, and the HTTP handlers together.
type Server struct {
	st     *store.Store
	engine *recon.Engine
	mux    *http.ServeMux
}

// NewServer builds a Server backed by st and engine. engine is constructed
// by the caller (see cmd/bbtracker/main.go) and shared with
// internal/scheduler, so a scan started by the scheduler and one started via
// the API use the same cancel registry - "Stop scan" works regardless of
// which triggered it.
func NewServer(st *store.Store, engine *recon.Engine) *Server {
	s := &Server{st: st, engine: engine, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the root http.Handler for the server, wrapped with the
// Host/Origin check (middleware.go) that keeps the unauthenticated local API
// from being reachable via DNS rebinding or cross-origin requests.
func (s *Server) Handler() http.Handler {
	return hostOriginCheck(s.mux)
}

func (s *Server) routes() {
	// Static frontend.
	staticRoot, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // programmer error: static dir must be embedded
	}
	// embed.FS reports a fixed zero-value ModTime for every file, so
	// http.FileServerFS's Last-Modified/ETag validators never change across
	// rebuilds - browsers can keep serving a stale cached app.js/index.html
	// indefinitely even after the binary is rebuilt. no-cache forces a
	// revalidation request every load instead.
	s.mux.Handle("/", noCache(http.FileServerFS(staticRoot)))

	// Dashboard (cross-program overview).
	s.mux.HandleFunc("GET /api/dashboard", s.handleDashboard)

	// Programs & scopes.
	s.mux.HandleFunc("GET /api/programs", s.handleListPrograms)
	s.mux.HandleFunc("POST /api/programs", s.handleCreateProgram)
	s.mux.HandleFunc("GET /api/programs/{id}", s.handleGetProgram)
	s.mux.HandleFunc("PUT /api/programs/{id}", s.handleUpdateProgram)
	s.mux.HandleFunc("DELETE /api/programs/{id}", s.handleDeleteProgram)
	s.mux.HandleFunc("PUT /api/programs/{id}/schedule", s.handleUpdateSchedule)
	s.mux.HandleFunc("GET /api/programs/{id}/scopes", s.handleListScopes)
	s.mux.HandleFunc("POST /api/programs/{id}/scopes", s.handleCreateScope)
	s.mux.HandleFunc("DELETE /api/scopes/{id}", s.handleDeleteScope)
	s.mux.HandleFunc("POST /api/programs/{id}/scopes/import", s.handleImportScopes)
	s.mux.HandleFunc("POST /api/programs/{id}/scopes/import-hackerone", s.handleImportHackerOneScope)
	s.mux.HandleFunc("GET /api/programs/{id}/assets", s.handleListAssets)
	s.mux.HandleFunc("GET /api/assets/{id}/screenshot", s.handleGetAssetScreenshot)
	s.mux.HandleFunc("PATCH /api/assets/{id}/notes", s.handleUpdateAssetNotes)
	s.mux.HandleFunc("POST /api/assets/{id}/scan", s.handleStartAssetScan)

	// Recon.
	s.mux.HandleFunc("POST /api/programs/{id}/scans", s.handleStartScan)
	s.mux.HandleFunc("GET /api/programs/{id}/scans", s.handleListScans)
	s.mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	s.mux.HandleFunc("GET /api/scans/{id}/events", s.handleListScanEvents)
	s.mux.HandleFunc("POST /api/scans/{id}/stop", s.handleStopScan)

	// Bounties & earnings.
	s.mux.HandleFunc("GET /api/programs/{id}/bounties", s.handleListBounties)
	s.mux.HandleFunc("POST /api/programs/{id}/bounties", s.handleCreateBounty)
	s.mux.HandleFunc("PUT /api/bounties/{id}", s.handleUpdateBounty)
	s.mux.HandleFunc("DELETE /api/bounties/{id}", s.handleDeleteBounty)
	s.mux.HandleFunc("GET /api/earnings", s.handleGetEarnings)

	// App-wide settings (Telegram new-asset notifications).
	s.mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	s.mux.HandleFunc("PUT /api/settings", s.handleUpdateSettings)
	s.mux.HandleFunc("POST /api/settings/test", s.handleTestTelegram)

	// Write-ups (disclosed HackerOne reports)
	s.mux.HandleFunc("GET /api/writeups", s.handleListWriteups)
	s.mux.HandleFunc("POST /api/writeups/sync", s.handleSyncWriteups)
	s.mux.HandleFunc("GET /api/writeups/weekly", s.handleWeeklyWriteups)
	s.mux.HandleFunc("POST /api/writeups/analyze-bulk", s.handleAnalyzeBulk)
	s.mux.HandleFunc("POST /api/writeups/{id}/analyze", s.handleAnalyzeWriteup)
	s.mux.HandleFunc("GET /api/writeups/{id}/analysis", s.handleGetAnalysis)

	// Vulnerabilities (nuclei findings).
	s.mux.HandleFunc("GET /api/programs/{id}/vulnerabilities", s.handleListVulnerabilities)

	// Fuzzing (directory/file discovery hits).
	s.mux.HandleFunc("GET /api/programs/{id}/fuzz-hits", s.handleListFuzzHits)

	// Archived URLs (Wayback), hidden parameters, and JS-analysis findings.
	s.mux.HandleFunc("GET /api/programs/{id}/archived-urls", s.handleListArchivedURLs)
	s.mux.HandleFunc("GET /api/programs/{id}/param-hits", s.handleListParamHits)
	s.mux.HandleFunc("GET /api/programs/{id}/js-findings", s.handleListJSFindings)

	// CORS misconfiguration findings.
	s.mux.HandleFunc("GET /api/programs/{id}/cors-findings", s.handleListCORSFindings)

	// GitHub dorking findings.
	s.mux.HandleFunc("GET /api/programs/{id}/github-findings", s.handleListGitHubFindings)

	// Cloud storage enumeration findings.
	s.mux.HandleFunc("GET /api/programs/{id}/cloud-findings", s.handleListCloudFindings)

	// Subdomain takeover findings.
	s.mux.HandleFunc("GET /api/programs/{id}/takeover-findings", s.handleListTakeoverFindings)

	// TLS certificate findings.
	s.mux.HandleFunc("GET /api/programs/{id}/tls-findings", s.handleListTLSFindings)

	// DNS/infrastructure findings (records, zone-transfer, WAF/CDN/cloud/ASN).
	s.mux.HandleFunc("GET /api/programs/{id}/dns-findings", s.handleListDNSFindings)

	// Katana-crawled URLs.
	s.mux.HandleFunc("GET /api/programs/{id}/crawled-urls", s.handleListCrawledURLs)

	// Findings triage (status/notes) - one generic endpoint across all findings tables.
	s.mux.HandleFunc("PATCH /api/findings/{kind}/{id}", s.handleUpdateFindingTriage)

	// CSV export of a program's tables (?type=assets|bounties|vulnerabilities|...).
	s.mux.HandleFunc("GET /api/programs/{id}/export", s.handleExportCSV)
}

// writeJSON encodes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error body: {"error": msg}.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes the request body into v, returning a 400-worthy error on failure.
func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
