package store

import (
	"database/sql"
	"strings"
)

const programColumns = `id, name, platform, url, notes, created_at,
	schedule_enabled, schedule_interval_days, schedule_time_of_day, schedule_run_subfinder,
	schedule_run_httpx, schedule_screenshot, schedule_run_nuclei, schedule_run_fuzz,
	schedule_fuzz_wordlist_path, schedule_run_wayback, schedule_run_params,
	schedule_params_wordlist_path, schedule_run_jsanalysis, schedule_run_cors,
	schedule_cors_wordlist_path,
	schedule_run_github_dork, schedule_run_cloud_enum, schedule_run_takeover, schedule_run_tls,
	schedule_next_run_at, schedule_last_run_at`

// scanProgram scans one programColumns row into a Program.
func scanProgram(row interface{ Scan(...any) error }) (*Program, error) {
	var p Program
	var enabled, runSubfinder, runHTTPX, screenshot, runNuclei, runFuzz int
	var runWayback, runParams, runJSAnalysis, runCORS, runGithubDork, runCloudEnum int
	var runTakeover, runTLS int
	var nextRun, lastRun sql.NullString
	err := row.Scan(&p.ID, &p.Name, &p.Platform, &p.URL, &p.Notes, &p.CreatedAt,
		&enabled, &p.ScheduleIntervalDays, &p.ScheduleTimeOfDay, &runSubfinder, &runHTTPX, &screenshot, &runNuclei,
		&runFuzz, &p.ScheduleFuzzWordlistPath, &runWayback, &runParams, &p.ScheduleParamsWordlistPath,
		&runJSAnalysis, &runCORS, &p.ScheduleCORSWordlistPath,
		&runGithubDork, &runCloudEnum, &runTakeover, &runTLS, &nextRun, &lastRun)
	if err != nil {
		return nil, err
	}
	p.ScheduleEnabled = enabled != 0
	p.ScheduleRunSubfinder = runSubfinder != 0
	p.ScheduleRunHTTPX = runHTTPX != 0
	p.ScheduleScreenshot = screenshot != 0
	p.ScheduleRunNuclei = runNuclei != 0
	p.ScheduleRunFuzz = runFuzz != 0
	p.ScheduleRunWayback = runWayback != 0
	p.ScheduleRunParams = runParams != 0
	p.ScheduleRunJSAnalysis = runJSAnalysis != 0
	p.ScheduleRunCORS = runCORS != 0
	p.ScheduleRunGithubDork = runGithubDork != 0
	p.ScheduleRunCloudEnum = runCloudEnum != 0
	p.ScheduleRunTakeover = runTakeover != 0
	p.ScheduleRunTLS = runTLS != 0
	p.ScheduleNextRunAt = nextRun.String
	p.ScheduleLastRunAt = lastRun.String
	return &p, nil
}

// ListPrograms returns all programs, newest first.
func (s *Store) ListPrograms() ([]Program, error) {
	rows, err := s.db.Query(`SELECT ` + programColumns + ` FROM programs ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Program{}
	for rows.Next() {
		p, err := scanProgram(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetProgram returns a single program by id.
func (s *Store) GetProgram(id int64) (*Program, error) {
	row := s.db.QueryRow(`SELECT `+programColumns+` FROM programs WHERE id = ?`, id)
	p, err := scanProgram(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// CreateProgram inserts a program and returns it with its new id.
func (s *Store) CreateProgram(p Program) (*Program, error) {
	res, err := s.db.Exec(`INSERT INTO programs (name, platform, url, notes)
		VALUES (?, ?, ?, ?)`, p.Name, p.Platform, p.URL, p.Notes)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetProgram(id)
}

// UpdateProgram updates editable fields of a program.
func (s *Store) UpdateProgram(id int64, p Program) (*Program, error) {
	_, err := s.db.Exec(`UPDATE programs SET name=?, platform=?, url=?, notes=? WHERE id=?`,
		p.Name, p.Platform, p.URL, p.Notes, id)
	if err != nil {
		return nil, err
	}
	return s.GetProgram(id)
}

// DeleteProgram removes a program (cascades to scopes, scans, assets, probes).
func (s *Store) DeleteProgram(id int64) error {
	_, err := s.db.Exec(`DELETE FROM programs WHERE id = ?`, id)
	return err
}

// ListScopes returns the scopes of a program.
func (s *Store) ListScopes(programID int64) ([]Scope, error) {
	rows, err := s.db.Query(`SELECT id, program_id, domain, type, created_at
		FROM scopes WHERE program_id = ? ORDER BY id`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scope{}
	for rows.Next() {
		var sc Scope
		if err := rows.Scan(&sc.ID, &sc.ProgramID, &sc.Domain, &sc.Type, &sc.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// InScopeDomains returns just the in-scope domain strings for recon.
func (s *Store) InScopeDomains(programID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT domain FROM scopes
		WHERE program_id = ? AND type = 'in' ORDER BY domain`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// OutScopeDomains returns just the out-of-scope domain strings for recon.
func (s *Store) OutScopeDomains(programID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT domain FROM scopes
		WHERE program_id = ? AND type = 'out' ORDER BY domain`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CreateScope adds a scope entry.
func (s *Store) CreateScope(sc Scope) (*Scope, error) {
	if sc.Type != "out" {
		sc.Type = "in"
	}
	res, err := s.db.Exec(`INSERT INTO scopes (program_id, domain, type) VALUES (?, ?, ?)`,
		sc.ProgramID, sc.Domain, sc.Type)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	sc.ID = id
	return &sc, nil
}

// ImportScopes bulk-inserts scope entries (each entry's Domain+Type), skipping
// any (type, domain) pair already present for the program - either already in
// the DB or repeated within entries itself - so re-running an import (e.g. a
// HackerOne program whose scope grew) never creates duplicate rows. Returns
// how many were actually added vs. skipped.
func (s *Store) ImportScopes(programID int64, entries []Scope) (imported, skipped int, err error) {
	existing, err := s.ListScopes(programID)
	if err != nil {
		return 0, 0, err
	}
	seen := make(map[string]bool, len(existing))
	for _, sc := range existing {
		seen[sc.Type+"|"+sc.Domain] = true
	}
	for _, e := range entries {
		domain := strings.TrimSpace(e.Domain)
		scType := "in"
		if e.Type == "out" {
			scType = "out"
		}
		key := scType + "|" + domain
		if domain == "" || seen[key] {
			skipped++
			continue
		}
		seen[key] = true
		if _, err := s.CreateScope(Scope{ProgramID: programID, Domain: domain, Type: scType}); err != nil {
			return imported, skipped, err
		}
		imported++
	}
	return imported, skipped, nil
}

// DeleteScope removes a scope entry.
func (s *Store) DeleteScope(id int64) error {
	_, err := s.db.Exec(`DELETE FROM scopes WHERE id = ?`, id)
	return err
}
