package server

import "net/http"

// handleListDNSFindings returns a program's DNS/infrastructure findings,
// most recently found first.
func (s *Server) handleListDNSFindings(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	findings, err := s.st.ListDNSFindings(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}
