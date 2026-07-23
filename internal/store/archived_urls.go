package store

import "database/sql"

// SaveArchivedURL upserts a Wayback-discovered URL, keyed by (program_id,
// url): rediscovering the same URL in a later scan just refreshes scan_id,
// never duplicates. Returns whether the row was newly inserted, so callers
// can distinguish "already known" from "found for the first time" (e.g. for
// scan_events).
func (s *Store) SaveArchivedURL(a ArchivedURL) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM archived_urls WHERE program_id = ? AND url = ?`,
		a.ProgramID, a.URL).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO archived_urls (program_id, scan_id, url, host, first_seen)
		VALUES (?, ?, ?, ?, datetime('now'))
		ON CONFLICT(program_id, url) DO UPDATE SET scan_id=excluded.scan_id`,
		a.ProgramID, a.ScanID, a.URL, a.Host)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListArchivedURLs returns a program's archived URLs, most recently seen first.
func (s *Store) ListArchivedURLs(programID int64) ([]ArchivedURL, error) {
	rows, err := s.db.Query(`SELECT id, program_id, scan_id, url, host, first_seen
		FROM archived_urls WHERE program_id = ? ORDER BY id DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ArchivedURL{}
	for rows.Next() {
		var a ArchivedURL
		if err := rows.Scan(&a.ID, &a.ProgramID, &a.ScanID, &a.URL, &a.Host, &a.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
