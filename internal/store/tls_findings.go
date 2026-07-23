package store

import "database/sql"

// SaveTLSFinding upserts a TLS certificate finding, keyed by (asset_id,
// issue, detail) - detail is part of the key (unlike other findings tables)
// because 'new_san_subdomain' can legitimately produce several distinct
// entries per asset. Returns whether the row was newly inserted.
func (s *Store) SaveTLSFinding(f TLSFinding) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM tls_findings WHERE asset_id = ? AND issue = ? AND detail = ?`,
		f.AssetID, f.Issue, f.Detail).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO tls_findings (asset_id, scan_id, host, issue, detail, found_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, issue, detail) DO UPDATE SET
			scan_id=excluded.scan_id, host=excluded.host, found_at=excluded.found_at`,
		f.AssetID, f.ScanID, f.Host, f.Issue, f.Detail)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListTLSFindings returns a program's TLS findings joined with the asset's
// subdomain, most recently found first.
func (s *Store) ListTLSFindings(programID int64) ([]TLSFindingRow, error) {
	rows, err := s.db.Query(`SELECT f.id, f.asset_id, f.scan_id, f.host, f.issue, f.detail,
			f.found_at, f.status, f.triage_notes, a.subdomain
		FROM tls_findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE a.program_id = ?
		ORDER BY f.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TLSFindingRow{}
	for rows.Next() {
		var r TLSFindingRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.Host, &r.Issue, &r.Detail,
			&r.FoundAt, &r.Status, &r.TriageNotes, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
