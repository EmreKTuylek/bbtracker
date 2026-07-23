package store

import "database/sql"

// SaveGitHubFinding upserts a leaked-secret/sensitive-file finding, keyed by
// (program_id, repo, path, kind, value): rediscovering it in a later scan
// refreshes found_at/dork in place rather than duplicating the row. Returns
// whether the row was newly inserted.
func (s *Store) SaveGitHubFinding(f GitHubFinding) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM github_findings
			WHERE program_id = ? AND repo = ? AND path = ? AND kind = ? AND value = ?`,
		f.ProgramID, f.Repo, f.Path, f.Kind, f.Value).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO github_findings
		(program_id, scan_id, repo, path, html_url, dork, kind, value, found_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(program_id, repo, path, kind, value) DO UPDATE SET
			scan_id=excluded.scan_id, html_url=excluded.html_url, dork=excluded.dork, found_at=excluded.found_at`,
		f.ProgramID, f.ScanID, f.Repo, f.Path, f.HTMLURL, f.Dork, f.Kind, f.Value)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListGitHubFindings returns a program's GitHub dorking findings, most
// recently found first. Unlike asset-scoped findings there's no subdomain to
// join - a GitHub finding belongs to a repo, not a probed asset.
func (s *Store) ListGitHubFindings(programID int64) ([]GitHubFinding, error) {
	rows, err := s.db.Query(`SELECT id, program_id, scan_id, repo, path, html_url, dork, kind, value,
			found_at, status, triage_notes
		FROM github_findings WHERE program_id = ? ORDER BY found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GitHubFinding{}
	for rows.Next() {
		var f GitHubFinding
		if err := rows.Scan(&f.ID, &f.ProgramID, &f.ScanID, &f.Repo, &f.Path,
			&f.HTMLURL, &f.Dork, &f.Kind, &f.Value, &f.FoundAt, &f.Status, &f.TriageNotes); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
