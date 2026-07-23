package store

import "database/sql"

// SaveFuzzHit upserts a directory/file fuzz hit, keyed by (asset_id, path):
// a path that responds again in a later scan updates status_code/
// content_length/scan_id/found_at in place rather than duplicating the row.
// Returns whether the row was newly inserted, so callers can distinguish
// "still there" from "found for the first time" (e.g. for scan_events).
func (s *Store) SaveFuzzHit(h FuzzHit) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM fuzz_hits WHERE asset_id = ? AND path = ?`,
		h.AssetID, h.Path).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO fuzz_hits (asset_id, scan_id, path, url, status_code, content_length, found_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, path) DO UPDATE SET
			scan_id=excluded.scan_id, url=excluded.url, status_code=excluded.status_code,
			content_length=excluded.content_length, found_at=excluded.found_at`,
		h.AssetID, h.ScanID, h.Path, h.URL, h.StatusCode, h.ContentLength)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListFuzzHits returns a program's fuzz hits joined with the asset's
// subdomain, most recent first.
func (s *Store) ListFuzzHits(programID int64) ([]FuzzHitRow, error) {
	rows, err := s.db.Query(`SELECT f.id, f.asset_id, f.scan_id, f.path, f.url, f.status_code,
			f.content_length, f.found_at, f.status, f.triage_notes, a.subdomain
		FROM fuzz_hits f
		JOIN assets a ON a.id = f.asset_id
		WHERE a.program_id = ?
		ORDER BY f.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FuzzHitRow{}
	for rows.Next() {
		var r FuzzHitRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.Path, &r.URL, &r.StatusCode,
			&r.ContentLength, &r.FoundAt, &r.Status, &r.TriageNotes, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
