package server

import (
	"errors"
	"net/http"

	"bbtracker/internal/writeups"
)

const writeupListLimit = 500

// handleListWriteups: GET /api/writeups?quality=ok|low|all (default all).
func (s *Server) handleListWriteups(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListWriteups(r.URL.Query().Get("quality"), writeupListLimit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleSyncWriteups: POST /api/writeups/sync - manual Hacktivity sync.
func (s *Server) handleSyncWriteups(w http.ResponseWriter, r *http.Request) {
	n, err := writeups.Sync(r.Context(), s.st)
	switch {
	case errors.Is(err, writeups.ErrNoCredentials):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeError(w, http.StatusBadGateway, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]int{"new": n})
	}
}
