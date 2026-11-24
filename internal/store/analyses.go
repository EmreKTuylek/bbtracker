package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

const sqlTime = "2006-01-02 15:04:05" // datetime('now') format, UTC

// Analysis is one validated LLM analysis. The JSON columns are returned as
// raw JSON so the API passes the model's (validated) structure straight through.
type Analysis struct {
	ID            int64           `json:"id"`
	WriteupID     int64           `json:"writeup_id"`
	Provider      string          `json:"provider"`
	Model         string          `json:"model"`
	QualityScore  *int            `json:"quality_score"`
	VulnClass     string          `json:"vuln_class"`
	TechTags      json.RawMessage `json:"tech_tags"`
	Summary       string          `json:"summary"`
	RootCause     string          `json:"root_cause"`
	AttackFlow    json.RawMessage `json:"attack_flow"`
	Fix           json.RawMessage `json:"fix"`
	Detection     json.RawMessage `json:"detection"`
	TestChecklist json.RawMessage `json:"test_checklist"`
	Unknowns      json.RawMessage `json:"unknowns"`
	Lang          string          `json:"lang"`
	CreatedAt     string          `json:"created_at"`
}

// AnalysisJob is one queued/finished analysis request.
type AnalysisJob struct {
	ID          int64  `json:"id"`
	WriteupID   int64  `json:"writeup_id"`
	Triage      bool   `json:"triage"`
	TriageScore *int   `json:"triage_score"`
	Stage       string `json:"stage"`
	Attempts    int    `json:"attempts"`
	Error       string `json:"error"`
	RunAfter    string `json:"run_after"`
	CreatedAt   string `json:"created_at"`
}

// GetWriteupText returns a writeup including raw_text (analysis input only;
// never exposed by the API). (nil, nil) when not found.
func (s *Store) GetWriteupText(id int64) (*Writeup, error) {
	var w Writeup
	err := s.db.QueryRow(`SELECT id, source, external_id, url, title, program, weakness, severity, bounty,
			disclosed_at, raw_text, quality_flag FROM writeups WHERE id = ?`, id).
		Scan(&w.ID, &w.Source, &w.ExternalID, &w.URL, &w.Title, &w.Program, &w.Weakness, &w.Severity,
			&w.Bounty, &w.DisclosedAt, &w.RawText, &w.QualityFlag)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &w, err
}

// EnqueueAnalysis queues a job unless the writeup already has an analysis or
// an unfinished job. Returns the job id and whether a new job was created
// (false + id 0 means already analyzed; false + id>0 means already queued).
func (s *Store) EnqueueAnalysis(writeupID int64, triage bool) (int64, bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM analyses WHERE writeup_id = ?`, writeupID).Scan(&n); err != nil {
		return 0, false, err
	}
	if n > 0 {
		return 0, false, nil
	}
	var id int64
	err := s.db.QueryRow(`SELECT id FROM analysis_jobs WHERE writeup_id = ? AND stage IN ('queued','triage','analyzing')
		ORDER BY id DESC LIMIT 1`, writeupID).Scan(&id)
	if err == nil {
		return id, false, nil
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}
	res, err := s.db.Exec(`INSERT INTO analysis_jobs (writeup_id, triage) VALUES (?, ?)`, writeupID, boolToInt(triage))
	if err != nil {
		return 0, false, err
	}
	id, err = res.LastInsertId()
	return id, err == nil, err
}

// UnanalyzedWriteupIDs lists good-quality writeups with no analysis and no
// unfinished job, newest disclosed first, for bulk analysis.
func (s *Store) UnanalyzedWriteupIDs(limit int) ([]int64, error) {
	rows, err := s.db.Query(`SELECT id FROM writeups w WHERE quality_flag = 'ok'
		AND NOT EXISTS (SELECT 1 FROM analyses a WHERE a.writeup_id = w.id)
		AND NOT EXISTS (SELECT 1 FROM analysis_jobs j WHERE j.writeup_id = w.id AND j.stage IN ('queued','triage','analyzing'))
		ORDER BY disclosed_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ClaimDueJob returns the oldest queued job whose run_after has passed and
// marks it 'analyzing'. (nil, nil) when none. Single worker, so no row lock.
func (s *Store) ClaimDueJob() (*AnalysisJob, error) {
	var j AnalysisJob
	var triage int
	err := s.db.QueryRow(`SELECT id, writeup_id, triage, triage_score, attempts, run_after, created_at
		FROM analysis_jobs WHERE stage = 'queued' AND run_after <= datetime('now') ORDER BY id LIMIT 1`).
		Scan(&j.ID, &j.WriteupID, &triage, &j.TriageScore, &j.Attempts, &j.RunAfter, &j.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	j.Triage = triage != 0
	j.Stage = "analyzing"
	_, err = s.db.Exec(`UPDATE analysis_jobs SET stage = 'analyzing' WHERE id = ?`, j.ID)
	return &j, err
}

// SetJobTriageScore caches the triage result so a retried job skips triage.
func (s *Store) SetJobTriageScore(id int64, score int) error {
	_, err := s.db.Exec(`UPDATE analysis_jobs SET triage_score = ? WHERE id = ?`, score, id)
	return err
}

// FinishJob sets a terminal (or requeued) state. For stage 'queued' the delay
// is added to now as run_after (the 429 backoff).
func (s *Store) FinishJob(id int64, stage string, attempts int, errMsg string, delay time.Duration) error {
	_, err := s.db.Exec(`UPDATE analysis_jobs SET stage=?, attempts=?, error=?, run_after=? WHERE id=?`,
		stage, attempts, errMsg, time.Now().UTC().Add(delay).Format(sqlTime), id)
	return err
}

// ResetStaleJobs requeues jobs left mid-flight by a crash/restart.
func (s *Store) ResetStaleJobs() error {
	_, err := s.db.Exec(`UPDATE analysis_jobs SET stage = 'queued' WHERE stage IN ('triage','analyzing')`)
	return err
}

// SaveAnalysis stores (or replaces) the analysis for (writeup, lang).
func (s *Store) SaveAnalysis(a Analysis) error {
	_, err := s.db.Exec(`INSERT INTO analyses (writeup_id, provider, model, quality_score, vuln_class, tech_tags,
			summary, root_cause, attack_flow, fix, detection, test_checklist, unknowns, lang)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(writeup_id, lang) DO UPDATE SET provider=excluded.provider, model=excluded.model,
			quality_score=excluded.quality_score, vuln_class=excluded.vuln_class, tech_tags=excluded.tech_tags,
			summary=excluded.summary, root_cause=excluded.root_cause, attack_flow=excluded.attack_flow,
			fix=excluded.fix, detection=excluded.detection, test_checklist=excluded.test_checklist,
			unknowns=excluded.unknowns`,
		a.WriteupID, a.Provider, a.Model, a.QualityScore, a.VulnClass, string(a.TechTags), a.Summary, a.RootCause,
		string(a.AttackFlow), string(a.Fix), string(a.Detection), string(a.TestChecklist), string(a.Unknowns), a.Lang)
	return err
}

// GetAnalysis returns a writeup's analysis for lang, or (nil, nil).
func (s *Store) GetAnalysis(writeupID int64, lang string) (*Analysis, error) {
	var a Analysis
	var tags, flow, fix, det, checklist, unknowns string
	err := s.db.QueryRow(`SELECT id, writeup_id, provider, model, quality_score, vuln_class, tech_tags, summary,
			root_cause, attack_flow, fix, detection, test_checklist, unknowns, lang, created_at
		FROM analyses WHERE writeup_id = ? AND lang = ?`, writeupID, lang).
		Scan(&a.ID, &a.WriteupID, &a.Provider, &a.Model, &a.QualityScore, &a.VulnClass, &tags, &a.Summary,
			&a.RootCause, &flow, &fix, &det, &checklist, &unknowns, &a.Lang, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.TechTags, a.AttackFlow, a.Fix = json.RawMessage(tags), json.RawMessage(flow), json.RawMessage(fix)
	a.Detection, a.TestChecklist, a.Unknowns = json.RawMessage(det), json.RawMessage(checklist), json.RawMessage(unknowns)
	return &a, nil
}

// LatestJob returns the writeup's most recent job, or (nil, nil).
func (s *Store) LatestJob(writeupID int64) (*AnalysisJob, error) {
	var j AnalysisJob
	var triage int
	err := s.db.QueryRow(`SELECT id, writeup_id, triage, triage_score, stage, attempts, error, run_after, created_at
		FROM analysis_jobs WHERE writeup_id = ? ORDER BY id DESC LIMIT 1`, writeupID).
		Scan(&j.ID, &j.WriteupID, &triage, &j.TriageScore, &j.Stage, &j.Attempts, &j.Error, &j.RunAfter, &j.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	j.Triage = triage != 0
	return &j, err
}
