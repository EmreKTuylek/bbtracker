package store

import (
	"database/sql"
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

// ListWriteups returns reports newest-disclosed first. quality is "ok", "low"
// or "" / "all" for both. raw_text is intentionally not selected.
func (s *Store) ListWriteups(quality string, limit int) ([]Writeup, error) {
	q := `SELECT id, source, external_id, url, title, program, weakness, severity, bounty,
			disclosed_at, quality_flag, created_at FROM writeups`
	args := []any{}
	if quality == "ok" || quality == "low" {
		q += ` WHERE quality_flag = ?`
		args = append(args, quality)
	}
	q += ` ORDER BY disclosed_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Writeup{}
	for rows.Next() {
		var w Writeup
		if err := rows.Scan(&w.ID, &w.Source, &w.ExternalID, &w.URL, &w.Title, &w.Program, &w.Weakness,
			&w.Severity, &w.Bounty, &w.DisclosedAt, &w.QualityFlag, &w.CreatedAt); err != nil {
			return nil, err
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
