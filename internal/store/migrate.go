package store

import "strings"

// addColumnIfMissing runs ALTER TABLE <table> ADD COLUMN <ddl>, tolerating
// SQLite's "duplicate column name" error. schema.sql's CREATE TABLE IF NOT
// EXISTS is a no-op for columns added to an already-existing table, so this
// is the only path that brings an existing bbtracker.db up to date.
func (s *Store) addColumnIfMissing(table, ddl string) error {
	_, err := s.db.Exec("ALTER TABLE " + table + " ADD COLUMN " + ddl)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	return nil
}

// migrate applies incremental, idempotent schema changes not expressible via
// CREATE TABLE IF NOT EXISTS. Runs after schema.sql, before failStaleScans.
func (s *Store) migrate() error {
	migrations := []struct{ table, ddl string }{
		{"scans", "run_subfinder INTEGER NOT NULL DEFAULT 1"},
		{"scans", "run_httpx INTEGER NOT NULL DEFAULT 1"},
		{"scans", "screenshot INTEGER NOT NULL DEFAULT 0"},
		{"probes", "screenshot BLOB"},
		{"programs", "schedule_enabled INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_interval_days INTEGER NOT NULL DEFAULT 7"},
		{"programs", "schedule_run_subfinder INTEGER NOT NULL DEFAULT 1"},
		{"programs", "schedule_run_httpx INTEGER NOT NULL DEFAULT 1"},
		{"programs", "schedule_screenshot INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_next_run_at TEXT"},
		{"programs", "schedule_last_run_at TEXT"},
		{"programs", "schedule_time_of_day TEXT NOT NULL DEFAULT '03:00'"},
		{"scans", "triggered_by TEXT NOT NULL DEFAULT 'manual'"},
		{"probes", "ip TEXT NOT NULL DEFAULT ''"},
		{"scans", "run_nuclei INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_nuclei INTEGER NOT NULL DEFAULT 0"},
		{"app_settings", "telegram_notify_new_assets INTEGER NOT NULL DEFAULT 1"},
		{"app_settings", "telegram_notify_changes INTEGER NOT NULL DEFAULT 0"},
		{"app_settings", "telegram_notify_vulnerabilities INTEGER NOT NULL DEFAULT 1"},
		{"scans", "run_fuzz INTEGER NOT NULL DEFAULT 0"},
		{"scans", "fuzz_wordlist_path TEXT NOT NULL DEFAULT ''"},
		{"programs", "schedule_run_fuzz INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_fuzz_wordlist_path TEXT NOT NULL DEFAULT ''"},
		{"scans", "run_wayback INTEGER NOT NULL DEFAULT 0"},
		{"scans", "run_params INTEGER NOT NULL DEFAULT 0"},
		{"scans", "params_wordlist_path TEXT NOT NULL DEFAULT ''"},
		{"scans", "run_jsanalysis INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_wayback INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_params INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_params_wordlist_path TEXT NOT NULL DEFAULT ''"},
		{"programs", "schedule_run_jsanalysis INTEGER NOT NULL DEFAULT 0"},
		{"scans", "run_cors INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_cors INTEGER NOT NULL DEFAULT 0"},
		{"scans", "run_github_dork INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_github_dork INTEGER NOT NULL DEFAULT 0"},
		{"app_settings", "github_token TEXT NOT NULL DEFAULT ''"},
		{"scans", "run_cloud_enum INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_cloud_enum INTEGER NOT NULL DEFAULT 0"},
		{"scans", "run_takeover INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_takeover INTEGER NOT NULL DEFAULT 0"},
		{"scans", "run_tls INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_tls INTEGER NOT NULL DEFAULT 0"},
		{"app_settings", "scan_retention_count INTEGER NOT NULL DEFAULT 0"},
		{"vulnerabilities", "status TEXT NOT NULL DEFAULT 'open'"},
		{"vulnerabilities", "triage_notes TEXT NOT NULL DEFAULT ''"},
		{"fuzz_hits", "status TEXT NOT NULL DEFAULT 'open'"},
		{"fuzz_hits", "triage_notes TEXT NOT NULL DEFAULT ''"},
		{"param_hits", "status TEXT NOT NULL DEFAULT 'open'"},
		{"param_hits", "triage_notes TEXT NOT NULL DEFAULT ''"},
		{"js_findings", "status TEXT NOT NULL DEFAULT 'open'"},
		{"js_findings", "triage_notes TEXT NOT NULL DEFAULT ''"},
		{"cors_findings", "status TEXT NOT NULL DEFAULT 'open'"},
		{"cors_findings", "triage_notes TEXT NOT NULL DEFAULT ''"},
		{"github_findings", "status TEXT NOT NULL DEFAULT 'open'"},
		{"github_findings", "triage_notes TEXT NOT NULL DEFAULT ''"},
		{"cloud_findings", "status TEXT NOT NULL DEFAULT 'open'"},
		{"cloud_findings", "triage_notes TEXT NOT NULL DEFAULT ''"},
		{"assets", "notes TEXT NOT NULL DEFAULT ''"},
		{"app_settings", "hackerone_username TEXT NOT NULL DEFAULT ''"},
		{"app_settings", "hackerone_api_token TEXT NOT NULL DEFAULT ''"},
		{"scans", "cors_wordlist_path TEXT NOT NULL DEFAULT ''"},
		{"programs", "schedule_cors_wordlist_path TEXT NOT NULL DEFAULT ''"},
		{"scans", "run_dns INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_dns INTEGER NOT NULL DEFAULT 0"},
		{"scans", "run_uncover INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_uncover INTEGER NOT NULL DEFAULT 0"},
		{"app_settings", "uncover_api_keys TEXT NOT NULL DEFAULT ''"},
		{"scans", "asset_id INTEGER NOT NULL DEFAULT 0"},
		{"scans", "run_crawl INTEGER NOT NULL DEFAULT 0"},
		{"programs", "schedule_run_crawl INTEGER NOT NULL DEFAULT 0"},
	}
	for _, m := range migrations {
		if err := s.addColumnIfMissing(m.table, m.ddl); err != nil {
			return err
		}
	}
	return nil
}
