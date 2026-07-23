package store

import "database/sql"

// SaveCORSFinding upserts a CORS misconfiguration finding, keyed by
// (asset_id, issue): rediscovering the same issue in a later scan refreshes
// the evidence in place rather than duplicating the row. Returns whether the
// row was newly inserted.
func (s *Store) SaveCORSFinding(f CORSFinding) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM cors_findings WHERE asset_id = ? AND issue = ?`,
		f.AssetID, f.Issue).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO cors_findings
		(asset_id, scan_id, url, issue, origin_sent, acao_value, acac_allowed, found_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, issue) DO UPDATE SET
			scan_id=excluded.scan_id, url=excluded.url, origin_sent=excluded.origin_sent,
			acao_value=excluded.acao_value, acac_allowed=excluded.acac_allowed, found_at=excluded.found_at`,
		f.AssetID, f.ScanID, f.URL, f.Issue, f.OriginSent, f.ACAOValue, f.ACACAllowed)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListCORSFindings returns a program's CORS findings joined with the asset's
// subdomain, most recently found first.
func (s *Store) ListCORSFindings(programID int64) ([]CORSFindingRow, error) {
	rows, err := s.db.Query(`SELECT f.id, f.asset_id, f.scan_id, f.url, f.issue,
			f.origin_sent, f.acao_value, f.acac_allowed, f.found_at, f.status, f.triage_notes, a.subdomain
		FROM cors_findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE a.program_id = ?
		ORDER BY f.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CORSFindingRow{}
	for rows.Next() {
		var r CORSFindingRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.URL, &r.Issue,
			&r.OriginSent, &r.ACAOValue, &r.ACACAllowed, &r.FoundAt, &r.Status, &r.TriageNotes, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
