// Package store is the SQLite data layer for bbtracker.
package store

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo
)

//go:embed schema.sql
var schema string

// Store wraps the database connection.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite works best single-connection for writes; keep it simple.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return nil, fmt.Errorf("enable fk: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	st := &Store{db: db}
	if err := st.migrate(); err != nil {
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	if err := st.failStaleScans(); err != nil {
		return nil, fmt.Errorf("clean up stale scans: %w", err)
	}
	return st, nil
}

// failStaleScans marks any scan left in "running" state as errored. A
// "running" row can only be legitimate while the process that started it is
// still alive to finish it; on a fresh Open, any such row is a leftover from
// a previous run that was killed or crashed mid-scan, and would otherwise
// block that program from ever scanning again (see RunningScanForProgram).
func (s *Store) failStaleScans() error {
	_, err := s.db.Exec(`UPDATE scans SET status='error', finished_at=datetime('now'),
		error='interrupted: app restarted while scan was running'
		WHERE status='running'`)
	return err
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }
