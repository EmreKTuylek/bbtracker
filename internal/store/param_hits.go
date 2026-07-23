package store

import "database/sql"

// SaveParamHit upserts a candidate hidden parameter finding, keyed by
// (asset_id, param): rediscovering it in a later scan refreshes the
// baseline/hit values in place rather than duplicating the row. Returns
// whether the row was newly inserted.
func (s *Store) SaveParamHit(p ParamHit) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM param_hits WHERE asset_id = ? AND param = ?`,
		p.AssetID, p.Param).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO param_hits
		(asset_id, scan_id, url, param, baseline_status, baseline_length, hit_status, hit_length, found_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, param) DO UPDATE SET
			scan_id=excluded.scan_id, url=excluded.url,
			baseline_status=excluded.baseline_status, baseline_length=excluded.baseline_length,
			hit_status=excluded.hit_status, hit_length=excluded.hit_length, found_at=excluded.found_at`,
		p.AssetID, p.ScanID, p.URL, p.Param, p.BaselineStatus, p.BaselineLength, p.HitStatus, p.HitLength)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListParamHits returns a program's candidate hidden parameters joined with
// the asset's subdomain, most recently found first.
func (s *Store) ListParamHits(programID int64) ([]ParamHitRow, error) {
	rows, err := s.db.Query(`SELECT p.id, p.asset_id, p.scan_id, p.url, p.param,
			p.baseline_status, p.baseline_length, p.hit_status, p.hit_length, p.found_at,
			p.status, p.triage_notes, a.subdomain
		FROM param_hits p
		JOIN assets a ON a.id = p.asset_id
		WHERE a.program_id = ?
		ORDER BY p.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ParamHitRow{}
	for rows.Next() {
		var r ParamHitRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.URL, &r.Param,
			&r.BaselineStatus, &r.BaselineLength, &r.HitStatus, &r.HitLength, &r.FoundAt,
			&r.Status, &r.TriageNotes, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
