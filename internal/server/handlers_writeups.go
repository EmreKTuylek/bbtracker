package server

import (
	"errors"
	"net/http"
	"strconv"

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

// handleWeeklyWriteups: GET /api/writeups/weekly?days=7 - top bug classes of
// recently disclosed reports plus what the top class has in common.
func (s *Server) handleWeeklyWriteups(w http.ResponseWriter, r *http.Request) {
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 90 {
			writeError(w, http.StatusBadRequest, "days must be 1-90")
			return
		}
		days = n
	}
	sum, err := s.st.WeeklyPatterns(days)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}
