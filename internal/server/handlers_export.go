package server

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// handleExportCSV streams one of a program's tables as a CSV download.
// GET /api/programs/{id}/export?type=<t>. The type selects which existing
// store.List* method to call; each produces a header row plus one row per
// record. Unknown types yield 400.
func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
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

	kind := r.URL.Query().Get("type")
	header, rows, err := s.exportRows(programID, kind)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if header == nil {
		writeError(w, http.StatusBadRequest, "unknown export type: "+kind)
		return
	}

	filename := fmt.Sprintf("%s-%s.csv", sanitizeFilename(program.Name), kind)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write(header)
	for _, row := range rows {
		_ = cw.Write(row)
	}
	cw.Flush()
}

// exportRows returns the header and data rows for a given export type, or a
// nil header for an unknown type.
func (s *Server) exportRows(programID int64, kind string) ([]string, [][]string, error) {
	switch kind {
	case "assets":
		list, err := s.st.ListAssets(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, a := range list {
			var url, title, tech, webserver, ip string
			var status, clen int
			if a.Probe != nil {
				url, title, tech, webserver, ip = a.Probe.URL, a.Probe.Title, a.Probe.Tech, a.Probe.Webserver, a.Probe.IP
				status, clen = a.Probe.StatusCode, a.Probe.ContentLength
			}
			rows = append(rows, []string{
				a.Subdomain, url, itoa(status), title, tech, webserver, ip,
				itoa(clen), boolStr(a.IsNew), a.FirstSeen, a.LastSeen,
			})
		}
		return []string{"subdomain", "url", "status_code", "title", "tech", "webserver", "ip", "content_length", "is_new", "first_seen", "last_seen"}, rows, nil

	case "bounties":
		list, err := s.st.ListBounties(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, b := range list {
			rows = append(rows, []string{
				b.Title, b.Severity, b.Status,
				strconv.FormatFloat(b.RewardAmount, 'f', -1, 64), b.Currency,
				b.SubmittedAt, b.ResolvedAt, b.Notes, b.CreatedAt,
			})
		}
		return []string{"title", "severity", "status", "reward_amount", "currency", "submitted_at", "resolved_at", "notes", "created_at"}, rows, nil

	case "vulnerabilities":
		list, err := s.st.ListVulnerabilities(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, v := range list {
			rows = append(rows, []string{v.Subdomain, v.TemplateID, v.Name, v.Severity, v.MatchedAt, v.FoundAt, v.Status, v.TriageNotes})
		}
		return []string{"subdomain", "template_id", "name", "severity", "matched_at", "found_at", "status", "triage_notes"}, rows, nil

	case "fuzz-hits":
		list, err := s.st.ListFuzzHits(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, h := range list {
			rows = append(rows, []string{h.Subdomain, h.Path, h.URL, itoa(h.StatusCode), itoa(h.ContentLength), h.FoundAt, h.Status, h.TriageNotes})
		}
		return []string{"subdomain", "path", "url", "status_code", "content_length", "found_at", "status", "triage_notes"}, rows, nil

	case "archived-urls":
		list, err := s.st.ListArchivedURLs(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, u := range list {
			rows = append(rows, []string{u.URL, u.Host, u.FirstSeen})
		}
		return []string{"url", "host", "first_seen"}, rows, nil

	case "param-hits":
		list, err := s.st.ListParamHits(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, h := range list {
			rows = append(rows, []string{
				h.Subdomain, h.Param, h.URL,
				itoa(h.BaselineStatus), itoa(h.BaselineLength), itoa(h.HitStatus), itoa(h.HitLength), h.FoundAt,
				h.Status, h.TriageNotes,
			})
		}
		return []string{"subdomain", "param", "url", "baseline_status", "baseline_length", "hit_status", "hit_length", "found_at", "status", "triage_notes"}, rows, nil

	case "js-findings":
		list, err := s.st.ListJSFindings(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			rows = append(rows, []string{f.Subdomain, f.Kind, f.Value, f.SourceURL, f.FoundAt, f.Status, f.TriageNotes})
		}
		return []string{"subdomain", "kind", "value", "source_url", "found_at", "status", "triage_notes"}, rows, nil

	case "cors-findings":
		list, err := s.st.ListCORSFindings(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			rows = append(rows, []string{f.Subdomain, f.Issue, f.URL, f.OriginSent, f.ACAOValue, boolStr(f.ACACAllowed), f.FoundAt, f.Status, f.TriageNotes})
		}
		return []string{"subdomain", "issue", "url", "origin_sent", "acao_value", "acac_allowed", "found_at", "status", "triage_notes"}, rows, nil

	case "github-findings":
		list, err := s.st.ListGitHubFindings(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			rows = append(rows, []string{f.Kind, f.Value, f.Repo, f.Path, f.HTMLURL, f.Dork, f.FoundAt, f.Status, f.TriageNotes})
		}
		return []string{"kind", "value", "repo", "path", "html_url", "dork", "found_at", "status", "triage_notes"}, rows, nil

	case "cloud-findings":
		list, err := s.st.ListCloudFindings(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			rows = append(rows, []string{f.Kind, f.Provider, f.Bucket, f.URL, f.FoundAt, f.Status, f.TriageNotes})
		}
		return []string{"kind", "provider", "bucket", "url", "found_at", "status", "triage_notes"}, rows, nil

	case "takeover-findings":
		list, err := s.st.ListTakeoverFindings(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			rows = append(rows, []string{f.Subdomain, f.Kind, f.Service, f.CNAME, f.Evidence, f.FoundAt, f.Status, f.TriageNotes})
		}
		return []string{"subdomain", "kind", "service", "cname", "evidence", "found_at", "status", "triage_notes"}, rows, nil

	case "tls-findings":
		list, err := s.st.ListTLSFindings(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			rows = append(rows, []string{f.Subdomain, f.Issue, f.Detail, f.FoundAt, f.Status, f.TriageNotes})
		}
		return []string{"subdomain", "issue", "detail", "found_at", "status", "triage_notes"}, rows, nil

	case "dns-findings":
		list, err := s.st.ListDNSFindings(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			rows = append(rows, []string{f.Subdomain, f.Kind, f.Detail, f.Value, f.FoundAt, f.Status, f.TriageNotes})
		}
		return []string{"subdomain", "kind", "detail", "value", "found_at", "status", "triage_notes"}, rows, nil

	case "crawled-urls":
		list, err := s.st.ListCrawledURLs(programID)
		if err != nil {
			return nil, nil, err
		}
		rows := make([][]string, 0, len(list))
		for _, u := range list {
			rows = append(rows, []string{u.Subdomain, u.URL, u.FoundAt})
		}
		return []string{"subdomain", "url", "found_at"}, rows, nil
	}
	return nil, nil, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// sanitizeFilename keeps a program name safe for a Content-Disposition
// filename: alnum, dash, underscore, dot; everything else becomes '_'.
func sanitizeFilename(name string) string {
	if name == "" {
		return "program"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
