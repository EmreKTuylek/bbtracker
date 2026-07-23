package store

import "database/sql"

// SaveVulnerability upserts a nuclei finding, keyed by (asset_id, template_id):
// a finding that matches again in a later scan updates found_at/matched_at/
// severity/name/scan_id in place rather than duplicating the row. Returns
// whether the row was newly inserted (not seen for this asset+template
// before), so callers can notify only on genuinely new findings.
func (s *Store) SaveVulnerability(v Vulnerability) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM vulnerabilities WHERE asset_id = ? AND template_id = ?`,
		v.AssetID, v.TemplateID).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO vulnerabilities (asset_id, scan_id, template_id, name, severity, matched_at, found_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, template_id) DO UPDATE SET
			scan_id=excluded.scan_id, name=excluded.name, severity=excluded.severity,
			matched_at=excluded.matched_at, found_at=excluded.found_at`,
		v.AssetID, v.ScanID, v.TemplateID, v.Name, v.Severity, v.MatchedAt)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListVulnerabilities returns a program's findings joined with the asset's
// subdomain, most severe and most recent first.
func (s *Store) ListVulnerabilities(programID int64) ([]VulnerabilityRow, error) {
	rows, err := s.db.Query(`SELECT v.id, v.asset_id, v.scan_id, v.template_id, v.name, v.severity,
			v.matched_at, v.found_at, v.status, v.triage_notes, a.subdomain
		FROM vulnerabilities v
		JOIN assets a ON a.id = v.asset_id
		WHERE a.program_id = ?
		ORDER BY CASE v.severity
				WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
				WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC,
			v.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnerabilityRow{}
	for rows.Next() {
		var r VulnerabilityRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.TemplateID, &r.Name, &r.Severity,
			&r.MatchedAt, &r.FoundAt, &r.Status, &r.TriageNotes, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
