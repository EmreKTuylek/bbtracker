package server

import "net/http"

// handleListCloudFindings returns a program's cloud storage enumeration
// findings, most recently found first.
func (s *Server) handleListCloudFindings(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	findings, err := s.st.ListCloudFindings(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}
