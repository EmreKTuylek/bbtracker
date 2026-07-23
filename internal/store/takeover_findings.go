package store

import "database/sql"

// SaveTakeoverFinding upserts a subdomain-takeover finding, keyed by
// (asset_id, service): rediscovering the same signal in a later scan
// refreshes the evidence in place rather than duplicating the row. Returns
// whether the row was newly inserted.
func (s *Store) SaveTakeoverFinding(f TakeoverFinding) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM takeover_findings WHERE asset_id = ? AND service = ?`,
		f.AssetID, f.Service).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO takeover_findings
		(asset_id, scan_id, host, cname, service, kind, evidence, found_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, service) DO UPDATE SET
			scan_id=excluded.scan_id, host=excluded.host, cname=excluded.cname,
			kind=excluded.kind, evidence=excluded.evidence, found_at=excluded.found_at`,
		f.AssetID, f.ScanID, f.Host, f.CNAME, f.Service, f.Kind, f.Evidence)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListTakeoverFindings returns a program's takeover findings joined with the
// asset's subdomain, most recently found first.
func (s *Store) ListTakeoverFindings(programID int64) ([]TakeoverFindingRow, error) {
	rows, err := s.db.Query(`SELECT f.id, f.asset_id, f.scan_id, f.host, f.cname, f.service,
			f.kind, f.evidence, f.found_at, f.status, f.triage_notes, a.subdomain
		FROM takeover_findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE a.program_id = ?
		ORDER BY f.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TakeoverFindingRow{}
	for rows.Next() {
		var r TakeoverFindingRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.Host, &r.CNAME, &r.Service,
			&r.Kind, &r.Evidence, &r.FoundAt, &r.Status, &r.TriageNotes, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
