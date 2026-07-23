package server

import "net/http"

// handleListGitHubFindings returns a program's GitHub dorking findings, most
// recently found first.
func (s *Server) handleListGitHubFindings(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	findings, err := s.st.ListGitHubFindings(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}
