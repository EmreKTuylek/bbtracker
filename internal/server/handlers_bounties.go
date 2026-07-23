package server

import (
	"net/http"

	"bbtracker/internal/store"
)

func (s *Server) handleListBounties(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	bounties, err := s.st.ListBounties(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, bounties)
}

func (s *Server) handleCreateBounty(w http.ResponseWriter, r *http.Request) {
	programID, ok := pathID(w, r)
	if !ok {
		return
	}
	var b store.Bounty
	if err := readJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if b.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}
	b.ProgramID = programID
	created, err := s.st.CreateBounty(b)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateBounty(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	existing, err := s.st.GetBounty(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "bounty not found")
		return
	}
	var b store.Bounty
	if err := readJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if b.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}
	updated, err := s.st.UpdateBounty(id, b)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteBounty(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteBounty(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleGetEarnings(w http.ResponseWriter, r *http.Request) {
	byProgram, err := s.st.EarningsByProgram()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	overall, err := s.st.OverallEarnings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"by_program": byProgram,
		"overall":    overall,
	})
}
