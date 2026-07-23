package store

import "database/sql"

// ListBounties returns a program's bounties, newest first.
func (s *Store) ListBounties(programID int64) ([]Bounty, error) {
	rows, err := s.db.Query(`SELECT id, program_id, title, severity, status, reward_amount,
		currency, submitted_at, resolved_at, notes, created_at
		FROM bounties WHERE program_id = ? ORDER BY id DESC`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bounty{}
	for rows.Next() {
		var b Bounty
		var submitted, resolved sql.NullString
		if err := rows.Scan(&b.ID, &b.ProgramID, &b.Title, &b.Severity, &b.Status,
			&b.RewardAmount, &b.Currency, &submitted, &resolved, &b.Notes, &b.CreatedAt); err != nil {
			return nil, err
		}
		b.SubmittedAt = submitted.String
		b.ResolvedAt = resolved.String
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetBounty returns a single bounty by id.
func (s *Store) GetBounty(id int64) (*Bounty, error) {
	var b Bounty
	var submitted, resolved sql.NullString
	err := s.db.QueryRow(`SELECT id, program_id, title, severity, status, reward_amount,
		currency, submitted_at, resolved_at, notes, created_at FROM bounties WHERE id = ?`, id).
		Scan(&b.ID, &b.ProgramID, &b.Title, &b.Severity, &b.Status, &b.RewardAmount,
			&b.Currency, &submitted, &resolved, &b.Notes, &b.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.SubmittedAt = submitted.String
	b.ResolvedAt = resolved.String
	return &b, nil
}

// CreateBounty inserts a bounty and returns it with its new id.
func (s *Store) CreateBounty(b Bounty) (*Bounty, error) {
	if b.Status == "" {
		b.Status = "draft"
	}
	if b.Currency == "" {
		b.Currency = "USD"
	}
	res, err := s.db.Exec(`INSERT INTO bounties
		(program_id, title, severity, status, reward_amount, currency, submitted_at, resolved_at, notes)
		VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?)`,
		b.ProgramID, b.Title, b.Severity, b.Status, b.RewardAmount, b.Currency,
		b.SubmittedAt, b.ResolvedAt, b.Notes)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetBounty(id)
}

// UpdateBounty updates editable fields of a bounty.
func (s *Store) UpdateBounty(id int64, b Bounty) (*Bounty, error) {
	_, err := s.db.Exec(`UPDATE bounties SET title=?, severity=?, status=?, reward_amount=?,
		currency=?, submitted_at=NULLIF(?, ''), resolved_at=NULLIF(?, ''), notes=? WHERE id=?`,
		b.Title, b.Severity, b.Status, b.RewardAmount, b.Currency, b.SubmittedAt, b.ResolvedAt, b.Notes, id)
	if err != nil {
		return nil, err
	}
	return s.GetBounty(id)
}

// DeleteBounty removes a bounty.
func (s *Store) DeleteBounty(id int64) error {
	_, err := s.db.Exec(`DELETE FROM bounties WHERE id = ?`, id)
	return err
}

// EarningsByProgram sums RESOLVED bounties per program, grouped by currency
// (amounts in different currencies are never summed together - that would
// silently misreport totals since this app does no currency conversion).
func (s *Store) EarningsByProgram() ([]BountyEarningsRow, error) {
	rows, err := s.db.Query(`SELECT b.program_id, p.name, b.currency, SUM(b.reward_amount), COUNT(*)
		FROM bounties b JOIN programs p ON p.id = b.program_id
		WHERE b.status = 'resolved'
		GROUP BY b.program_id, b.currency
		ORDER BY p.name, b.currency`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BountyEarningsRow{}
	for rows.Next() {
		var r BountyEarningsRow
		if err := rows.Scan(&r.ProgramID, &r.ProgramName, &r.Currency, &r.Total, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OverallEarnings sums RESOLVED bounties across all programs, grouped by currency.
func (s *Store) OverallEarnings() ([]CurrencyTotal, error) {
	rows, err := s.db.Query(`SELECT currency, SUM(reward_amount)
		FROM bounties WHERE status = 'resolved' GROUP BY currency ORDER BY currency`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CurrencyTotal{}
	for rows.Next() {
		var c CurrencyTotal
		if err := rows.Scan(&c.Currency, &c.Total); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
