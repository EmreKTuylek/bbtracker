package server

import (
	"net/http"
	"strconv"

	"bbtracker/internal/store"
)

const (
	bulkAnalyzeDefault = 20
	bulkAnalyzeMax     = 100
)

// requireGemini 400s (and returns false) unless the API key and the needed
// model names are saved - the worker would only fail the job later otherwise.
func (s *Server) requireGemini(w http.ResponseWriter, needTriage bool) bool {
	set, err := s.st.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if set.GeminiAPIKey == "" || set.GeminiAnalysisModel == "" || (needTriage && set.GeminiTriageModel == "") {
		writeError(w, http.StatusBadRequest, "save the Gemini API key and model names in Settings first")
		return false
	}
	return true
}

// handleAnalyzeWriteup: POST /api/writeups/{id}/analyze - queue one deep analysis.
func (s *Server) handleAnalyzeWriteup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	wu, err := s.st.GetWriteupText(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if wu == nil {
		writeError(w, http.StatusNotFound, "write-up not found")
		return
	}
	if !s.requireGemini(w, false) {
		return
	}
	jobID, queued, err := s.st.EnqueueAnalysis(id, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job_id": jobID, "queued": queued, "analyzed": jobID == 0 && !queued})
}

// handleAnalyzeBulk: POST /api/writeups/analyze-bulk?limit=N - queue the newest
// N detailed, not-yet-analyzed write-ups, each gated by the cheap triage model.
func (s *Server) handleAnalyzeBulk(w http.ResponseWriter, r *http.Request) {
	limit := bulkAnalyzeDefault
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > bulkAnalyzeMax {
			writeError(w, http.StatusBadRequest, "limit must be 1-"+strconv.Itoa(bulkAnalyzeMax))
			return
		}
		limit = n
	}
	if !s.requireGemini(w, true) {
		return
	}
	ids, err := s.st.UnanalyzedWriteupIDs(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	queued := 0
	for _, id := range ids {
		if _, ok, err := s.st.EnqueueAnalysis(id, true); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		} else if ok {
			queued++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"queued": queued})
}

// handleGetAnalysis: GET /api/writeups/{id}/analysis - the analysis (if any)
// plus the latest job's state (queued/skipped/failed + error message).
func (s *Server) handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	a, err := s.st.GetAnalysis(id, "tr")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	j, err := s.st.LatestJob(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if a == nil && j == nil {
		writeError(w, http.StatusNotFound, "no analysis for this write-up")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Analysis *store.Analysis    `json:"analysis"`
		Job      *store.AnalysisJob `json:"job"`
	}{a, j})
}
