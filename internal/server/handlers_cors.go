package server

import "net/http"

// handleListCORSFindings returns a program's CORS misconfiguration findings,
// most recently found first.
func (s *Server) handleListCORSFindings(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	findings, err := s.st.ListCORSFindings(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}
