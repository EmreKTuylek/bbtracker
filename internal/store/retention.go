package store

// PruneOldScans deletes old scan rows for a program, keeping at least the
// most recent `keep` scans, and reports how many were deleted.
//
// This deliberately does NOT simply "delete scans past the Nth" - store.Open
// runs PRAGMA foreign_keys = ON, and every findings table (vulnerabilities,
// fuzz_hits, cors_findings, js_findings, param_hits, archived_urls,
// github_findings, cloud_findings, takeover_findings, tls_findings)
// references scan_id with ON DELETE CASCADE. A finding's scan_id is simply
// "the last scan that (re)confirmed it" - findings are never deleted on
// their own even when a later scan stops reproducing them (see schema.sql).
// Naively deleting an old scans row would cascade-delete any
// still-current finding whose scan_id happens to point at that scan,
// silently destroying data that has nothing to do with "old scan history".
//
// So a scan is only eligible for deletion when it is NOT the most recent
// `keep` scans for the program AND it is not referenced as scan_id by any
// row in any findings table. This safely shrinks scan_events (a pure
// diff-log with no "current state" semantics - always fine to lose, and
// cascades automatically) while never touching a finding that still
// represents the latest known state of anything.
func (s *Store) PruneOldScans(programID int64, keep int) (int64, error) {
	if keep <= 0 {
		return 0, nil
	}
	res, err := s.db.Exec(`
		DELETE FROM scans
		WHERE program_id = ?
		  AND id NOT IN (SELECT id FROM scans WHERE program_id = ? ORDER BY started_at DESC LIMIT ?)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM vulnerabilities)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM fuzz_hits)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM cors_findings)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM js_findings)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM param_hits)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM archived_urls)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM github_findings)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM cloud_findings)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM takeover_findings)
		  AND id NOT IN (SELECT DISTINCT scan_id FROM tls_findings)`,
		programID, programID, keep)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
