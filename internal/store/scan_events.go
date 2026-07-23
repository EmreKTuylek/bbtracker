package store

// SaveScanEvent records one notable thing a scan produced (a new asset, a
// changed asset, or a new vulnerability) - see schema.sql's scan_events
// table. Plain insert, no upsert: every scan gets its own independent rows,
// unlike probes/vulnerabilities which keep a single current row per key.
func (s *Store) SaveScanEvent(scanID, assetID int64, kind, oldValue, newValue string) error {
	_, err := s.db.Exec(`INSERT INTO scan_events (scan_id, asset_id, kind, old_value, new_value)
		VALUES (?, ?, ?, ?, ?)`, scanID, assetID, kind, oldValue, newValue)
	return err
}

// ListScanEvents returns everything scanID produced, joined with each
// asset's subdomain, grouped by kind then insertion order - for the UI's
// scan-diff view.
func (s *Store) ListScanEvents(scanID int64) ([]ScanEventRow, error) {
	rows, err := s.db.Query(`SELECT e.id, e.scan_id, e.asset_id, e.kind, e.old_value, e.new_value,
			e.created_at, a.subdomain
		FROM scan_events e
		JOIN assets a ON a.id = e.asset_id
		WHERE e.scan_id = ?
		ORDER BY CASE e.kind
				WHEN 'new_asset' THEN 1 WHEN 'changed_asset' THEN 2 WHEN 'new_vuln' THEN 3 ELSE 4 END,
			e.id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanEventRow{}
	for rows.Next() {
		var r ScanEventRow
		if err := rows.Scan(&r.ID, &r.ScanID, &r.AssetID, &r.Kind, &r.OldValue, &r.NewValue,
			&r.CreatedAt, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
