package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// SaveWriteup upserts a report keyed by (source, external_id). An existing
// row is only rewritten when content_hash changed, so a re-sync of unchanged
// reports is a cheap no-op. Returns whether the row was newly inserted.
func (s *Store) SaveWriteup(w Writeup) (bool, error) {
	var id int64
	var hash string
	err := s.db.QueryRow(`SELECT id, content_hash FROM writeups WHERE source = ? AND external_id = ?`,
		w.Source, w.ExternalID).Scan(&id, &hash)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if err == nil {
		if hash == w.ContentHash {
			return false, nil
		}
		_, err = s.db.Exec(`UPDATE writeups SET url=?, title=?, program=?, weakness=?, severity=?, bounty=?,
				disclosed_at=?, raw_text=?, content_hash=?, quality_flag=? WHERE id=?`,
			w.URL, w.Title, w.Program, w.Weakness, w.Severity, w.Bounty,
			w.DisclosedAt, w.RawText, w.ContentHash, w.QualityFlag, id)
		return false, err
	}
	_, err = s.db.Exec(`INSERT INTO writeups (source, external_id, url, title, program, weakness, severity,
			bounty, disclosed_at, raw_text, content_hash, quality_flag)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w.Source, w.ExternalID, w.URL, w.Title, w.Program, w.Weakness, w.Severity,
		w.Bounty, w.DisclosedAt, w.RawText, w.ContentHash, w.QualityFlag)
	return err == nil, err
}

// ListWriteups returns reports newest-disclosed first, each with its analysis
// state: vuln_class/tech_tags from the analysis if one exists, and
// analysis_status = "done" (analysis exists) or the latest job's stage.
// quality is "ok", "low" or "" / "all". raw_text is intentionally not selected.
func (s *Store) ListWriteups(quality string, limit int) ([]Writeup, error) {
	q := `SELECT w.id, w.source, w.external_id, w.url, w.title, w.program, w.weakness, w.severity, w.bounty,
			w.disclosed_at, w.quality_flag, w.created_at,
			COALESCE(a.vuln_class, ''), COALESCE(a.tech_tags, '[]'),
			CASE WHEN a.id IS NOT NULL THEN 'done'
			     ELSE COALESCE((SELECT stage FROM analysis_jobs j WHERE j.writeup_id = w.id ORDER BY j.id DESC LIMIT 1), '') END,
			COALESCE((SELECT error FROM analysis_jobs j WHERE j.writeup_id = w.id ORDER BY j.id DESC LIMIT 1), '')
		FROM writeups w LEFT JOIN analyses a ON a.writeup_id = w.id AND a.lang = 'tr'`
	args := []any{}
	if quality == "ok" || quality == "low" {
		q += ` WHERE w.quality_flag = ?`
		args = append(args, quality)
	}
	q += ` ORDER BY w.disclosed_at DESC, w.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Writeup{}
	for rows.Next() {
		var w Writeup
		var tags string
		if err := rows.Scan(&w.ID, &w.Source, &w.ExternalID, &w.URL, &w.Title, &w.Program, &w.Weakness,
			&w.Severity, &w.Bounty, &w.DisclosedAt, &w.QualityFlag, &w.CreatedAt,
			&w.VulnClass, &tags, &w.AnalysisStatus, &w.AnalysisError); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(tags), &w.TechTags) != nil || w.TechTags == nil {
			w.TechTags = []string{}
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// MarkWriteupsSynced records now (UTC, RFC3339) as the last successful sync.
func (s *Store) MarkWriteupsSynced() error {
	_, err := s.db.Exec(`UPDATE app_settings SET writeups_last_sync_at = ? WHERE id = 1`,
		time.Now().UTC().Format(time.RFC3339))
	return err
}
