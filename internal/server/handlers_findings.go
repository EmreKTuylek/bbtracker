package server

import (
	"net/http"
	"strings"
)

// triageRequest is the body for PATCH /api/findings/{kind}/{id}.
type triageRequest struct {
	Status string `json:"status"`
	Notes  string `json:"notes"`
}

// handleUpdateFindingTriage sets a finding's review status/notes. kind
// selects which findings table (see store.triageTables) - it comes straight
// from the URL path but is never used to build SQL directly; the store layer
// maps it through a fixed whitelist.
func (s *Server) handleUpdateFindingTriage(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req triageRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := s.st.UpdateFindingTriage(kind, id, req.Status, req.Notes); err != nil {
		if strings.HasPrefix(err.Error(), "unknown") {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
