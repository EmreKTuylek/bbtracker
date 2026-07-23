package server

import "net/http"

// handleListJSFindings returns a program's JS-analysis findings (endpoints
// and secrets), secrets first.
func (s *Server) handleListJSFindings(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	findings, err := s.st.ListJSFindings(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}
