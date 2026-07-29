package store

import "database/sql"

// SaveDNSFinding upserts a DNS/infrastructure finding, keyed by (asset_id,
// kind, detail, value) - detail is part of the key (like tls_findings) since
// a host can legitimately have several distinct record values of the same
// kind (e.g. multiple NS/TXT entries). Returns whether the row was newly
// inserted.
func (s *Store) SaveDNSFinding(f DNSFinding) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM dns_findings WHERE asset_id = ? AND kind = ? AND detail = ? AND value = ?`,
		f.AssetID, f.Kind, f.Detail, f.Value).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO dns_findings (asset_id, scan_id, host, kind, detail, value, found_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, kind, detail, value) DO UPDATE SET
			scan_id=excluded.scan_id, host=excluded.host, found_at=excluded.found_at`,
		f.AssetID, f.ScanID, f.Host, f.Kind, f.Detail, f.Value)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListDNSFindings returns a program's DNS findings joined with the asset's
// subdomain, most recently found first.
func (s *Store) ListDNSFindings(programID int64) ([]DNSFindingRow, error) {
	rows, err := s.db.Query(`SELECT f.id, f.asset_id, f.scan_id, f.host, f.kind, f.detail, f.value,
			f.found_at, f.status, f.triage_notes, a.subdomain
		FROM dns_findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE a.program_id = ?
		ORDER BY f.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSFindingRow{}
	for rows.Next() {
		var r DNSFindingRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.Host, &r.Kind, &r.Detail, &r.Value,
			&r.FoundAt, &r.Status, &r.TriageNotes, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
