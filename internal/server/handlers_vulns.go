package server

import "net/http"

// handleListVulnerabilities returns a program's nuclei findings, most severe
// and most recent first.
func (s *Server) handleListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	vulns, err := s.st.ListVulnerabilities(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, vulns)
}
