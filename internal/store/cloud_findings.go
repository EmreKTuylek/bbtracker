package store

import "database/sql"

// SaveCloudFinding upserts a cloud storage enumeration hit, keyed by
// (program_id, provider, bucket, kind): rediscovering it in a later scan
// refreshes found_at/url in place rather than duplicating the row. Returns
// whether the row was newly inserted.
func (s *Store) SaveCloudFinding(f CloudFinding) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM cloud_findings
			WHERE program_id = ? AND provider = ? AND bucket = ? AND kind = ?`,
		f.ProgramID, f.Provider, f.Bucket, f.Kind).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO cloud_findings
		(program_id, scan_id, provider, bucket, url, kind, found_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(program_id, provider, bucket, kind) DO UPDATE SET
			scan_id=excluded.scan_id, url=excluded.url, found_at=excluded.found_at`,
		f.ProgramID, f.ScanID, f.Provider, f.Bucket, f.URL, f.Kind)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListCloudFindings returns a program's cloud storage findings, most
// recently found first.
func (s *Store) ListCloudFindings(programID int64) ([]CloudFinding, error) {
	rows, err := s.db.Query(`SELECT id, program_id, scan_id, provider, bucket, url, kind, found_at,
			status, triage_notes
		FROM cloud_findings WHERE program_id = ? ORDER BY found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CloudFinding{}
	for rows.Next() {
		var f CloudFinding
		if err := rows.Scan(&f.ID, &f.ProgramID, &f.ScanID, &f.Provider,
			&f.Bucket, &f.URL, &f.Kind, &f.FoundAt, &f.Status, &f.TriageNotes); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
