package server

import "net/http"

// handleListArchivedURLs returns a program's Wayback-discovered URLs, most
// recently seen first.
func (s *Server) handleListArchivedURLs(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	urls, err := s.st.ListArchivedURLs(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, urls)
}
