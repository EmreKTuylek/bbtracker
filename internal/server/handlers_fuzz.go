package server

import "net/http"

// handleListFuzzHits returns a program's directory/file fuzz hits, most
// recent first.
func (s *Server) handleListFuzzHits(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	hits, err := s.st.ListFuzzHits(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, hits)
}
