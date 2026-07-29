package store

import "database/sql"

// SaveCrawledURL upserts a crawled URL, keyed by (asset_id, url) - a URL
// rediscovered on a later scan refreshes scan_id/found_at in place rather
// than duplicating the row. Returns whether the row was newly inserted, so
// the caller can log a "new_crawled_url" scan_events entry the same way
// every other findings table does.
func (s *Store) SaveCrawledURL(u CrawledURL) (bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM crawled_urls WHERE asset_id = ? AND url = ?`,
		u.AssetID, u.URL).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	isNew := err == sql.ErrNoRows

	_, err = s.db.Exec(`INSERT INTO crawled_urls (asset_id, scan_id, url, found_at)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(asset_id, url) DO UPDATE SET
			scan_id=excluded.scan_id, found_at=excluded.found_at`,
		u.AssetID, u.ScanID, u.URL)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// ListCrawledURLs returns a program's crawled URLs joined with the asset's
// subdomain, most recently found first.
func (s *Store) ListCrawledURLs(programID int64) ([]CrawledURLRow, error) {
	rows, err := s.db.Query(`SELECT u.id, u.asset_id, u.scan_id, u.url, u.found_at, a.subdomain
		FROM crawled_urls u
		JOIN assets a ON a.id = u.asset_id
		WHERE a.program_id = ?
		ORDER BY u.found_at DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CrawledURLRow{}
	for rows.Next() {
		var r CrawledURLRow
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ScanID, &r.URL, &r.FoundAt, &r.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
