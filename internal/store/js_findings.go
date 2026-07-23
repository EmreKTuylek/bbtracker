package store

import "database/sql"

// SaveJSFinding upserts a JS-analysis finding, keyed by (asset_id, kind,
// value): rediscovering it in a later scan refreshes scan_id/source_url/
// found_at in place rather than duplicating the row. Returns whether the
// row was newly inserted.
func (s *Store) SaveJSFinding(f JSFinding) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM js_findings WHERE asset_id = ? AND kind = ? AND value = ?`,
		f.AssetID, f.Kind, f.Value).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO js_findings (asset_id, scan_id, kind, source_url, value, found_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, kind, value) DO UPDATE SET
			scan_id=excluded.scan_id, source_url=excluded.source_url, found_at=excluded.found_at`,
		f.AssetID, f.ScanID, f.Kind, f.SourceURL, f.Value)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListJSFindings returns a program's JS-analysis findings joined with the
// asset's subdomain, secrets first (more actionable), then most recent.
func (s *Store) ListJSFindings(programID int64) ([]JSFindingRow, error) {
	rows, err := s.db.Query(`SELECT j.id, j.asset_id, j.scan_id, j.kind, j.source_url, j.value,
			j.found_at, j.status, j.triage_notes, a.subdomain
		FROM js_findings j
		JOIN assets a ON a.id = j.asset_id
		WHERE a.program_id = ?
		ORDER BY CASE j.kind WHEN 'secret' THEN 0 ELSE 1 END, j.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JSFindingRow{}
	for rows.Next() {
		var r JSFindingRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.Kind, &r.SourceURL, &r.Value,
			&r.FoundAt, &r.Status, &r.TriageNotes, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
