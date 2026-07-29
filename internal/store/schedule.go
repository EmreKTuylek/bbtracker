package store

import (
	"database/sql"
	"fmt"
	"time"
)

// scheduleTimeLayout matches the format SQLite's datetime('now') produces
// elsewhere in this schema, so schedule_next_run_at/schedule_last_run_at
// read consistently alongside other timestamp columns in the UI.
const scheduleTimeLayout = "2006-01-02 15:04:05"

// nextOccurrence returns the next moment timeOfDay ("HH:MM", 24-hour) occurs
// at or after from - today if it hasn't passed yet, otherwise tomorrow.
func nextOccurrence(timeOfDay string, from time.Time) (time.Time, error) {
	t, err := time.Parse("15:04", timeOfDay)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time %q, expected HH:MM: %w", timeOfDay, err)
	}
	next := time.Date(from.Year(), from.Month(), from.Day(), t.Hour(), t.Minute(), 0, 0, from.Location())
	if !next.After(from) {
		next = next.AddDate(0, 0, 1)
	}
	return next, nil
}

// UpdateSchedule sets a program's recurring-scan configuration.
//
// schedule_next_run_at/schedule_last_run_at are computed here in Go using
// the local machine's clock (time.Now(), NOT SQLite's datetime('now'),
// which is UTC) - a schedule's time-of-day is meant to match the user's own
// wall clock on the machine running bbtracker, so all scheduling math stays
// in local time end to end. Every other timestamp column in this schema
// (scans.started_at, programs.created_at, etc.) is still UTC via SQL
// datetime('now') and is unaffected by this.
//
// next_run_at is only recomputed when the schedule transitions from
// disabled to enabled, or when the interval or time-of-day actually
// changes - otherwise an already-ticking clock isn't reset just because the
// user re-saved the same values (e.g. toggling a tool checkbox).
func (s *Store) UpdateSchedule(programID int64, enabled bool, intervalDays int, timeOfDay string,
	runSubfinder, runHTTPX, screenshot, runNuclei, runFuzz bool, fuzzWordlistPath string,
	runWayback, runParams bool, paramsWordlistPath string, runJSAnalysis bool, runCORS bool, corsWordlistPath string,
	runGithubDork bool, runCloudEnum, runTakeover, runTLS, runDNS, runUncover, runCrawl bool) (*Program, error) {
	existing, err := s.GetProgram(programID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, sql.ErrNoRows
	}

	nextRunAt := existing.ScheduleNextRunAt
	shouldRecompute := enabled && (!existing.ScheduleEnabled ||
		existing.ScheduleIntervalDays != intervalDays ||
		existing.ScheduleTimeOfDay != timeOfDay)
	if shouldRecompute {
		next, err := nextOccurrence(timeOfDay, time.Now())
		if err != nil {
			return nil, err
		}
		nextRunAt = next.Format(scheduleTimeLayout)
	}

	_, err = s.db.Exec(`UPDATE programs SET schedule_enabled=?, schedule_interval_days=?,
		schedule_time_of_day=?, schedule_run_subfinder=?, schedule_run_httpx=?, schedule_screenshot=?,
		schedule_run_nuclei=?, schedule_run_fuzz=?, schedule_fuzz_wordlist_path=?,
		schedule_run_wayback=?, schedule_run_params=?, schedule_params_wordlist_path=?,
		schedule_run_jsanalysis=?, schedule_run_cors=?, schedule_cors_wordlist_path=?,
		schedule_run_github_dork=?, schedule_run_cloud_enum=?,
		schedule_run_takeover=?, schedule_run_tls=?, schedule_run_dns=?, schedule_run_uncover=?, schedule_run_crawl=?,
		schedule_next_run_at=? WHERE id=?`,
		boolToInt(enabled), intervalDays, timeOfDay, boolToInt(runSubfinder), boolToInt(runHTTPX),
		boolToInt(screenshot), boolToInt(runNuclei), boolToInt(runFuzz), fuzzWordlistPath,
		boolToInt(runWayback), boolToInt(runParams), paramsWordlistPath, boolToInt(runJSAnalysis),
		boolToInt(runCORS), corsWordlistPath, boolToInt(runGithubDork), boolToInt(runCloudEnum),
		boolToInt(runTakeover), boolToInt(runTLS), boolToInt(runDNS), boolToInt(runUncover), boolToInt(runCrawl), nextRunAt, programID)
	if err != nil {
		return nil, err
	}
	return s.GetProgram(programID)
}

// DuePrograms returns programs with an enabled schedule whose next run has
// arrived (or was never set despite being enabled, as a defensive backfill).
func (s *Store) DuePrograms() ([]Program, error) {
	now := time.Now().Format(scheduleTimeLayout)
	rows, err := s.db.Query(`SELECT `+programColumns+` FROM programs
		WHERE schedule_enabled = 1
		AND (schedule_next_run_at IS NULL OR schedule_next_run_at = '' OR schedule_next_run_at <= ?)`, now)
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

// MarkScheduleRun advances a program's schedule right after a scheduled scan
// was triggered. next_run_at advances from the PREVIOUS next_run_at (not
// from "now"), so the time-of-day never drifts even if the app was closed
// and the run happened late - "every 7 days at 03:00" always lands on
// 03:00, not on whatever moment the scheduler happened to notice it was due.
func (s *Store) MarkScheduleRun(programID int64) error {
	p, err := s.GetProgram(programID)
	if err != nil {
		return err
	}
	if p == nil {
		return sql.ErrNoRows
	}
	base := time.Now()
	if t, err := time.ParseInLocation(scheduleTimeLayout, p.ScheduleNextRunAt, time.Local); err == nil {
		base = t
	}
	next := base.AddDate(0, 0, p.ScheduleIntervalDays)
	_, err = s.db.Exec(`UPDATE programs SET schedule_last_run_at=?, schedule_next_run_at=? WHERE id=?`,
		time.Now().Format(scheduleTimeLayout), next.Format(scheduleTimeLayout), programID)
	return err
}
