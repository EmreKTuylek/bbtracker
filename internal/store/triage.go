package store

import "fmt"

// triageTables whitelists the findings tables an UpdateFindingTriage call may
// target, keyed by the short "kind" name the API uses. The table name is
// always taken from this fixed map, never from caller input, so there is no
// SQL-injection surface even though the table name has to be interpolated
// into the query (database/sql cannot parameterize identifiers).
var triageTables = map[string]string{
	"vulnerabilities": "vulnerabilities",
	"cors":            "cors_findings",
	"fuzz":            "fuzz_hits",
	"github":          "github_findings",
	"cloud":           "cloud_findings",
	"js":              "js_findings",
	"params":          "param_hits",
	"takeover":        "takeover_findings",
	"tls":             "tls_findings",
}

// validTriageStatuses whitelists the values UpdateFindingTriage accepts for
// status, so a typo doesn't silently create a new, unrecognized status value.
var validTriageStatuses = map[string]bool{
	"open": true, "accepted_risk": true, "false_positive": true, "fixed": true,
}

// UpdateFindingTriage sets a finding's triage status/notes. kind selects
// which findings table (see triageTables); an unknown kind or status is
// rejected with an error rather than silently doing nothing.
func (s *Store) UpdateFindingTriage(kind string, id int64, status, notes string) error {
	table, ok := triageTables[kind]
	if !ok {
		return fmt.Errorf("unknown finding kind %q", kind)
	}
	if !validTriageStatuses[status] {
		return fmt.Errorf("unknown status %q", status)
	}
	_, err := s.db.Exec("UPDATE "+table+" SET status = ?, triage_notes = ? WHERE id = ?", status, notes, id)
	return err
}
