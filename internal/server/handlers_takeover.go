package server

import "net/http"

// handleListTakeoverFindings returns a program's subdomain-takeover findings,
// most recently found first.
func (s *Server) handleListTakeoverFindings(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	findings, err := s.st.ListTakeoverFindings(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}
