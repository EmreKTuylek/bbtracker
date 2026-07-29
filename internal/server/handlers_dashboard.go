package server

import (
	"net/http"

	"bbtracker/internal/store"
)

// Each dashboard* type below tags one finding type's row with which program
// it came from, so the cross-program dashboard can return one merged list
// per finding type without a new query shape - it's the same rows each
// per-program List* endpoint already returns, just stamped with
// program_id/program_name. (A generic wrapper was tried first, but Go
// doesn't allow embedding a bare type parameter - these are the concrete
// equivalent, one per finding type, matching this codebase's existing
// "repeat the shape once per finding type" convention.) Severity/title/
// detail derivation for display stays entirely in app.js's FINDING_SOURCES
// (reused, not duplicated, for the dashboard's findings inbox) - these
// types only carry data, not presentation logic.
type dashboardVuln struct {
	store.VulnerabilityRow
	ProgramID   int64  `json:"program_id"`
	ProgramName string `json:"program_name"`
}
type dashboardFuzzHit struct {
	store.FuzzHitRow
	ProgramID   int64  `json:"program_id"`
	ProgramName string `json:"program_name"`
}
type dashboardParamHit struct {
	store.ParamHitRow
	ProgramID   int64  `json:"program_id"`
	ProgramName string `json:"program_name"`
}
type dashboardJSFinding struct {
	store.JSFindingRow
	ProgramID   int64  `json:"program_id"`
	ProgramName string `json:"program_name"`
}
type dashboardCORSFinding struct {
	store.CORSFindingRow
	ProgramID   int64  `json:"program_id"`
	ProgramName string `json:"program_name"`
}
type dashboardGitHubFinding struct {
	store.GitHubFinding        // already carries ProgramID; shadowed below
	ProgramID           int64  `json:"program_id"`
	ProgramName         string `json:"program_name"`
}
type dashboardCloudFinding struct {
	store.CloudFinding        // already carries ProgramID; shadowed below
	ProgramID          int64  `json:"program_id"`
	ProgramName        string `json:"program_name"`
}
type dashboardTakeoverFinding struct {
	store.TakeoverFindingRow
	ProgramID   int64  `json:"program_id"`
	ProgramName string `json:"program_name"`
}
type dashboardTLSFinding struct {
	store.TLSFindingRow
	ProgramID   int64  `json:"program_id"`
	ProgramName string `json:"program_name"`
}
type dashboardDNSFinding struct {
	store.DNSFindingRow
	ProgramID   int64  `json:"program_id"`
	ProgramName string `json:"program_name"`
}

// dashboardProgramSummary is one program's row in the dashboard's program
// list: enough to render a per-program card without a second request per
// program (asset count via the lightweight Store.CountAssets, not the full
// ListAssets join; most recent scan via ListScans[0]).
type dashboardProgramSummary struct {
	store.Program
	AssetCount int         `json:"asset_count"`
	LastScan   *store.Scan `json:"last_scan,omitempty"`
}

// dashboardResponse is GET /api/dashboard's body. It merges what every
// program's own tabs already expose (asset count, last scan, all 9 findings
// types) into one response, so the frontend's cross-program dashboard loads
// in a single request instead of fanning out to N programs x 9+ endpoints.
type dashboardResponse struct {
	Programs         []dashboardProgramSummary  `json:"programs"`
	Vulnerabilities  []dashboardVuln            `json:"vulnerabilities"`
	FuzzHits         []dashboardFuzzHit         `json:"fuzz_hits"`
	ParamHits        []dashboardParamHit        `json:"param_hits"`
	JSFindings       []dashboardJSFinding       `json:"js_findings"`
	CORSFindings     []dashboardCORSFinding     `json:"cors_findings"`
	GitHubFindings   []dashboardGitHubFinding   `json:"github_findings"`
	CloudFindings    []dashboardCloudFinding    `json:"cloud_findings"`
	TakeoverFindings []dashboardTakeoverFinding `json:"takeover_findings"`
	TLSFindings      []dashboardTLSFinding      `json:"tls_findings"`
	DNSFindings      []dashboardDNSFinding      `json:"dns_findings"`
}

// handleDashboard serves the cross-program overview: per-program summaries
// plus every finding across every program, for the "Dashboard" nav view.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	programs, err := s.st.ListPrograms()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := dashboardResponse{Programs: make([]dashboardProgramSummary, 0, len(programs))}
	for _, p := range programs {
		assetCount, err := s.st.CountAssets(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		scans, err := s.st.ListScans(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		summary := dashboardProgramSummary{Program: p, AssetCount: assetCount}
		if len(scans) > 0 {
			summary.LastScan = &scans[0]
		}
		resp.Programs = append(resp.Programs, summary)

		vulns, err := s.st.ListVulnerabilities(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, v := range vulns {
			resp.Vulnerabilities = append(resp.Vulnerabilities, dashboardVuln{VulnerabilityRow: v, ProgramID: p.ID, ProgramName: p.Name})
		}

		fuzz, err := s.st.ListFuzzHits(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, f := range fuzz {
			resp.FuzzHits = append(resp.FuzzHits, dashboardFuzzHit{FuzzHitRow: f, ProgramID: p.ID, ProgramName: p.Name})
		}

		params, err := s.st.ListParamHits(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, pr := range params {
			resp.ParamHits = append(resp.ParamHits, dashboardParamHit{ParamHitRow: pr, ProgramID: p.ID, ProgramName: p.Name})
		}

		js, err := s.st.ListJSFindings(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, j := range js {
			resp.JSFindings = append(resp.JSFindings, dashboardJSFinding{JSFindingRow: j, ProgramID: p.ID, ProgramName: p.Name})
		}

		cors, err := s.st.ListCORSFindings(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, c := range cors {
			resp.CORSFindings = append(resp.CORSFindings, dashboardCORSFinding{CORSFindingRow: c, ProgramID: p.ID, ProgramName: p.Name})
		}

		gh, err := s.st.ListGitHubFindings(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, g := range gh {
			resp.GitHubFindings = append(resp.GitHubFindings, dashboardGitHubFinding{GitHubFinding: g, ProgramID: p.ID, ProgramName: p.Name})
		}

		cloud, err := s.st.ListCloudFindings(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, cl := range cloud {
			resp.CloudFindings = append(resp.CloudFindings, dashboardCloudFinding{CloudFinding: cl, ProgramID: p.ID, ProgramName: p.Name})
		}

		takeover, err := s.st.ListTakeoverFindings(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, t := range takeover {
			resp.TakeoverFindings = append(resp.TakeoverFindings, dashboardTakeoverFinding{TakeoverFindingRow: t, ProgramID: p.ID, ProgramName: p.Name})
		}

		tls, err := s.st.ListTLSFindings(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, t := range tls {
			resp.TLSFindings = append(resp.TLSFindings, dashboardTLSFinding{TLSFindingRow: t, ProgramID: p.ID, ProgramName: p.Name})
		}

		dns, err := s.st.ListDNSFindings(p.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, d := range dns {
			resp.DNSFindings = append(resp.DNSFindings, dashboardDNSFinding{DNSFindingRow: d, ProgramID: p.ID, ProgramName: p.Name})
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
