package server

import "net/http"

// handleListTLSFindings returns a program's TLS certificate findings, most
// recently found first.
func (s *Server) handleListTLSFindings(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	findings, err := s.st.ListTLSFindings(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}
