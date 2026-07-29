package server

import "net/http"

// handleListCrawledURLs returns a program's katana-crawled URLs, most
// recently found first.
func (s *Server) handleListCrawledURLs(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	urls, err := s.st.ListCrawledURLs(programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, urls)
}
