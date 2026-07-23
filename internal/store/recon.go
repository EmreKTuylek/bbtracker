package store

import "database/sql"

// CreateScan inserts a running scan with the given tool options and returns
// its id. triggeredBy records whether a human clicked "scan" ("manual") or
// internal/scheduler fired it ("scheduled").
func (s *Store) CreateScan(programID int64, opts ScanOptions, triggeredBy string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO scans (program_id, status, run_subfinder, run_httpx, screenshot, run_nuclei,
			run_fuzz, fuzz_wordlist_path, run_wayback, run_params, params_wordlist_path, run_jsanalysis, run_cors,
			cors_wordlist_path, run_github_dork, run_cloud_enum, run_takeover, run_tls, triggered_by)
		VALUES (?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		programID, boolToInt(opts.RunSubfinder), boolToInt(opts.RunHTTPX), boolToInt(opts.Screenshot),
		boolToInt(opts.RunNuclei), boolToInt(opts.RunFuzz), opts.FuzzWordlistPath,
		boolToInt(opts.RunWayback), boolToInt(opts.RunParams), opts.ParamsWordlistPath,
		boolToInt(opts.RunJSAnalysis), boolToInt(opts.RunCORS), opts.CORSWordlistPath, boolToInt(opts.RunGithubDork),
		boolToInt(opts.RunCloudEnum), boolToInt(opts.RunTakeover), boolToInt(opts.RunTLS), triggeredBy)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetScan returns a scan by id.
func (s *Store) GetScan(id int64) (*Scan, error) {
	var sc Scan
	var finished sql.NullString
	var runSubfinder, runHTTPX, screenshot, runNuclei, runFuzz int
	var runWayback, runParams, runJSAnalysis, runCORS, runGithubDork, runCloudEnum int
	var runTakeover, runTLS int
	err := s.db.QueryRow(`SELECT id, program_id, status, started_at, finished_at,
		new_assets_count, error, run_subfinder, run_httpx, screenshot, run_nuclei, run_fuzz, fuzz_wordlist_path,
		run_wayback, run_params, params_wordlist_path, run_jsanalysis, run_cors, cors_wordlist_path,
		run_github_dork, run_cloud_enum,
		run_takeover, run_tls, triggered_by FROM scans WHERE id = ?`, id).
		Scan(&sc.ID, &sc.ProgramID, &sc.Status, &sc.StartedAt, &finished, &sc.NewAssetsCount, &sc.Error,
			&runSubfinder, &runHTTPX, &screenshot, &runNuclei, &runFuzz, &sc.FuzzWordlistPath,
			&runWayback, &runParams, &sc.ParamsWordlistPath, &runJSAnalysis, &runCORS, &sc.CORSWordlistPath,
			&runGithubDork,
			&runCloudEnum, &runTakeover, &runTLS, &sc.TriggeredBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sc.FinishedAt = finished.String
	sc.RunSubfinder = runSubfinder != 0
	sc.RunHTTPX = runHTTPX != 0
	sc.Screenshot = screenshot != 0
	sc.RunNuclei = runNuclei != 0
	sc.RunFuzz = runFuzz != 0
	sc.RunWayback = runWayback != 0
	sc.RunParams = runParams != 0
	sc.RunJSAnalysis = runJSAnalysis != 0
	sc.RunCORS = runCORS != 0
	sc.RunGithubDork = runGithubDork != 0
	sc.RunCloudEnum = runCloudEnum != 0
	sc.RunTakeover = runTakeover != 0
	sc.RunTLS = runTLS != 0
	return &sc, nil
}

// FinishScan marks a scan done/error with the new-asset count.
func (s *Store) FinishScan(id int64, status string, newAssets int, errMsg string) error {
	_, err := s.db.Exec(`UPDATE scans SET status=?, finished_at=datetime('now'),
		new_assets_count=?, error=? WHERE id=?`, status, newAssets, errMsg, id)
	return err
}

// RunningScanForProgram returns the id of a running scan for the program, or 0 if none.
func (s *Store) RunningScanForProgram(programID int64) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM scans
		WHERE program_id = ? AND status = 'running' ORDER BY id DESC LIMIT 1`, programID).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

// UpsertAsset inserts a subdomain or refreshes last_seen. Returns (assetID, isNew).
//
// isNew is determined via an explicit existence check rather than
// res.RowsAffected(), since that count is driver-specific for
// INSERT ... ON CONFLICT DO UPDATE and unreliable across sqlite drivers.
func (s *Store) UpsertAsset(programID int64, subdomain, source string) (int64, bool, error) {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM assets WHERE program_id = ? AND subdomain = ?`,
		programID, subdomain).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return 0, false, err
	}
	isNew := err == sql.ErrNoRows

	res, err := s.db.Exec(`INSERT INTO assets (program_id, subdomain, source)
		VALUES (?, ?, ?)
		ON CONFLICT(program_id, subdomain)
		DO UPDATE SET last_seen = datetime('now')`, programID, subdomain, source)
	if err != nil {
		return 0, false, err
	}

	if isNew {
		id, err := res.LastInsertId()
		if err != nil {
			return 0, false, err
		}
		return id, true, nil
	}
	return existingID, false, nil
}

// SaveProbe stores/replaces the latest httpx result for an asset. A nil
// p.Screenshot (a scan that ran without the screenshot option) keeps
// whatever screenshot was captured by a previous scan rather than clearing
// it - screenshots are expensive to (re)capture, so a routine httpx-only
// scan shouldn't blow away one taken earlier. Passing an actual new
// screenshot always replaces the old one.
func (s *Store) SaveProbe(assetID int64, p Probe) error {
	_, err := s.db.Exec(`INSERT INTO probes
		(asset_id, url, status_code, title, tech, content_length, webserver, scanned_at, screenshot, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)
		ON CONFLICT(asset_id) DO UPDATE SET
			url=excluded.url, status_code=excluded.status_code, title=excluded.title,
			tech=excluded.tech, content_length=excluded.content_length,
			webserver=excluded.webserver, scanned_at=excluded.scanned_at,
			screenshot=COALESCE(excluded.screenshot, screenshot),
			ip=excluded.ip`,
		assetID, p.URL, p.StatusCode, p.Title, p.Tech, p.ContentLength, p.Webserver, p.Screenshot, p.IP)
	return err
}

// GetProbe returns an asset's current probe row, or nil if it's never been
// probed. Used by Engine.Run to compare a fresh httpx result against the
// prior one before overwriting it, to detect status/title changes.
func (s *Store) GetProbe(assetID int64) (*Probe, error) {
	var p Probe
	var url, title, tech, webserver, scannedAt, ip sql.NullString
	var status, clen sql.NullInt64
	err := s.db.QueryRow(`SELECT url, status_code, title, tech, content_length, webserver, scanned_at, ip
		FROM probes WHERE asset_id = ?`, assetID).
		Scan(&url, &status, &title, &tech, &clen, &webserver, &scannedAt, &ip)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.URL = url.String
	p.StatusCode = int(status.Int64)
	p.Title = title.String
	p.Tech = tech.String
	p.ContentLength = int(clen.Int64)
	p.Webserver = webserver.String
	p.ScannedAt = scannedAt.String
	p.IP = ip.String
	return &p, nil
}

// AssetHosts returns a program's known asset ids keyed by hostname, so a
// scan that skips subfinder can probe existing assets directly instead of
// rediscovering them.
func (s *Store) AssetHosts(programID int64) (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT id, subdomain FROM assets WHERE program_id = ?`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id int64
		var host string
		if err := rows.Scan(&id, &host); err != nil {
			return nil, err
		}
		out[host] = id
	}
	return out, rows.Err()
}

// GetScreenshot returns an asset's stored screenshot PNG bytes, or nil if
// none was captured (no probe row, or the probe has no screenshot).
func (s *Store) GetScreenshot(assetID int64) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT screenshot FROM probes WHERE asset_id = ?`, assetID).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return b, err
}

// UpdateAssetNotes sets an asset's free-text notes.
func (s *Store) UpdateAssetNotes(assetID int64, notes string) error {
	_, err := s.db.Exec(`UPDATE assets SET notes = ? WHERE id = ?`, notes, assetID)
	return err
}

// CountAssets returns how many assets a program has, without loading the
// full asset+probe rows ListAssets does - used by the cross-program
// dashboard (handleDashboard), which needs a count per program, not the
// asset table itself.
func (s *Store) CountAssets(programID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE program_id = ?`, programID).Scan(&n)
	return n, err
}

// ListAssets returns a program's assets joined with their latest probe.
// IsNew marks assets first seen at or after the program's most recently
// completed scan started, so the UI can highlight what a scan just found.
func (s *Store) ListAssets(programID int64) ([]AssetRow, error) {
	rows, err := s.db.Query(`SELECT a.id, a.program_id, a.subdomain, a.source, a.notes,
			a.first_seen, a.last_seen,
			p.url, p.status_code, p.title, p.tech, p.content_length, p.webserver, p.scanned_at, p.ip,
			(a.first_seen >= COALESCE(
				(SELECT started_at FROM scans WHERE program_id = a.program_id AND status = 'done' ORDER BY id DESC LIMIT 1),
				a.first_seen)) AS is_new,
			(p.screenshot IS NOT NULL AND length(p.screenshot) > 0) AS has_screenshot
		FROM assets a
		LEFT JOIN probes p ON p.asset_id = a.id
		WHERE a.program_id = ?
		ORDER BY a.subdomain`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetRow{}
	for rows.Next() {
		var r AssetRow
		var url, title, tech, webserver, scannedAt, ip sql.NullString
		var status, clen sql.NullInt64
		var isNew, hasScreenshot int
		if err := rows.Scan(&r.ID, &r.ProgramID, &r.Subdomain, &r.Source, &r.Notes,
			&r.FirstSeen, &r.LastSeen,
			&url, &status, &title, &tech, &clen, &webserver, &scannedAt, &ip, &isNew, &hasScreenshot); err != nil {
			return nil, err
		}
		if url.Valid || status.Valid {
			r.Probe = &Probe{
				URL:           url.String,
				StatusCode:    int(status.Int64),
				Title:         title.String,
				Tech:          tech.String,
				ContentLength: int(clen.Int64),
				Webserver:     webserver.String,
				ScannedAt:     scannedAt.String,
				IP:            ip.String,
				HasScreenshot: hasScreenshot != 0,
			}
		}
		r.IsNew = isNew != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListScans returns a program's scans, most recent first.
func (s *Store) ListScans(programID int64) ([]Scan, error) {
	rows, err := s.db.Query(`SELECT id, program_id, status, started_at, finished_at,
			new_assets_count, error, run_subfinder, run_httpx, screenshot, run_nuclei, run_fuzz, fuzz_wordlist_path,
			run_wayback, run_params, params_wordlist_path, run_jsanalysis, run_cors, cors_wordlist_path,
			run_github_dork, run_cloud_enum,
			run_takeover, run_tls, triggered_by
		FROM scans WHERE program_id = ? ORDER BY id DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		var sc Scan
		var finished sql.NullString
		var runSubfinder, runHTTPX, screenshot, runNuclei, runFuzz int
		var runWayback, runParams, runJSAnalysis, runCORS, runGithubDork, runCloudEnum int
		var runTakeover, runTLS int
		if err := rows.Scan(&sc.ID, &sc.ProgramID, &sc.Status, &sc.StartedAt, &finished,
			&sc.NewAssetsCount, &sc.Error, &runSubfinder, &runHTTPX, &screenshot, &runNuclei,
			&runFuzz, &sc.FuzzWordlistPath, &runWayback, &runParams, &sc.ParamsWordlistPath,
			&runJSAnalysis, &runCORS, &sc.CORSWordlistPath, &runGithubDork, &runCloudEnum, &runTakeover, &runTLS, &sc.TriggeredBy); err != nil {
			return nil, err
		}
		sc.FinishedAt = finished.String
		sc.RunSubfinder = runSubfinder != 0
		sc.RunHTTPX = runHTTPX != 0
		sc.Screenshot = screenshot != 0
		sc.RunNuclei = runNuclei != 0
		sc.RunFuzz = runFuzz != 0
		sc.RunWayback = runWayback != 0
		sc.RunParams = runParams != 0
		sc.RunJSAnalysis = runJSAnalysis != 0
		sc.RunCORS = runCORS != 0
		sc.RunGithubDork = runGithubDork != 0
		sc.RunCloudEnum = runCloudEnum != 0
		sc.RunTakeover = runTakeover != 0
		sc.RunTLS = runTLS != 0
		out = append(out, sc)
	}
	return out, rows.Err()
}
