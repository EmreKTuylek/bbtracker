package server

import "net/http"

// handleListParamHits returns a program's candidate hidden parameters, most
// recently found first.
func (s *Server) handleListParamHits(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	hits, err := s.st.ListParamHits(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, hits)
}
