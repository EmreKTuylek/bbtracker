package store

import (
	"encoding/json"
	"sort"
	"time"
)

// ClassCount is how many write-ups in the window fall in one bug class.
type ClassCount struct {
	Class    string `json:"class"`
	Count    int    `json:"count"`
	Analyzed int    `json:"analyzed"`
}

// WeeklyExample is one analyzed write-up of the top class, with its root cause.
type WeeklyExample struct {
	WriteupID int64  `json:"writeup_id"`
	Title     string `json:"title"`
	RootCause string `json:"root_cause"`
}

// WeeklySummary answers "what was disclosed most this week, and what do those
// reports have in common". Everything is derived from stored rows (no LLM call).
type WeeklySummary struct {
	Since    string          `json:"since"`
	Total    int             `json:"total"`
	Classes  []ClassCount    `json:"classes"`
	TopClass string          `json:"top_class"`
	TopTech  []string        `json:"top_tech"`
	Examples []WeeklyExample `json:"examples"`
}

const (
	weeklyMaxClasses  = 10
	weeklyMaxTech     = 5
	weeklyMaxExamples = 5
)

// WeeklyPatterns summarizes write-ups disclosed in the last `days` days.
// A write-up's class is its analysis' vuln_class if analyzed, else the
// platform's own weakness name, else "unknown", grouped case-insensitively.
//
// ponytail: the model's vuln_class ("IDOR") and HackerOne's weakness names
// ("Insecure Direct Object Reference (IDOR)") are different vocabularies, so
// the same bug class can split across two rows until it's analyzed. "Common
// thread" is the top class' most frequent tech tags plus its analyzed root
// causes, not an LLM synthesis; add one call over those root causes if needed.
func (s *Store) WeeklyPatterns(days int) (*WeeklySummary, error) {
	since := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	sum := &WeeklySummary{Since: since, Classes: []ClassCount{}, TopTech: []string{}, Examples: []WeeklyExample{}}

	if err := s.db.QueryRow(`SELECT COUNT(*) FROM writeups WHERE disclosed_at >= ?`, since).Scan(&sum.Total); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT MIN(cls), COUNT(*), SUM(analyzed) FROM (
			SELECT COALESCE(NULLIF(a.vuln_class, ''), NULLIF(w.weakness, ''), 'unknown') AS cls,
			       (a.id IS NOT NULL) AS analyzed
			FROM writeups w LEFT JOIN analyses a ON a.writeup_id = w.id AND a.lang = 'tr'
			WHERE w.disclosed_at >= ?)
		GROUP BY LOWER(cls) ORDER BY COUNT(*) DESC, LOWER(cls) LIMIT ?`, since, weeklyMaxClasses)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c ClassCount
		if err := rows.Scan(&c.Class, &c.Count, &c.Analyzed); err != nil {
			rows.Close()
			return nil, err
		}
		sum.Classes = append(sum.Classes, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, c := range sum.Classes {
		if c.Class != "unknown" {
			sum.TopClass = c.Class
			break
		}
	}
	if sum.TopClass == "" {
		return sum, nil
	}

	ex, err := s.db.Query(`SELECT w.id, w.title, a.root_cause, a.tech_tags
		FROM analyses a JOIN writeups w ON w.id = a.writeup_id
		WHERE a.lang = 'tr' AND w.disclosed_at >= ? AND LOWER(a.vuln_class) = LOWER(?)
		ORDER BY w.disclosed_at DESC`, since, sum.TopClass)
	if err != nil {
		return nil, err
	}
	defer ex.Close()
	techCount := map[string]int{}
	for ex.Next() {
		var e WeeklyExample
		var tags string
		if err := ex.Scan(&e.WriteupID, &e.Title, &e.RootCause, &tags); err != nil {
			return nil, err
		}
		if len(sum.Examples) < weeklyMaxExamples {
			sum.Examples = append(sum.Examples, e)
		}
		var list []string
		if json.Unmarshal([]byte(tags), &list) == nil {
			for _, t := range list {
				techCount[t]++
			}
		}
	}
	if err := ex.Err(); err != nil {
		return nil, err
	}
	tech := make([]string, 0, len(techCount))
	for t := range techCount {
		tech = append(tech, t)
	}
	sort.Slice(tech, func(i, j int) bool {
		if techCount[tech[i]] != techCount[tech[j]] {
			return techCount[tech[i]] > techCount[tech[j]]
		}
		return tech[i] < tech[j]
	})
	if len(tech) > weeklyMaxTech {
		tech = tech[:weeklyMaxTech]
	}
	sum.TopTech = tech
	return sum, nil
}
