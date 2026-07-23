package store

// GetSettings returns the single app-wide settings row, creating it with
// defaults (Telegram disabled, no token/chat id) on first use.
func (s *Store) GetSettings() (*Settings, error) {
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO app_settings (id) VALUES (1)`); err != nil {
		return nil, err
	}
	var set Settings
	var enabled, notifyNew, notifyChanges, notifyVulns int
	err := s.db.QueryRow(`SELECT telegram_bot_token, telegram_chat_id, telegram_enabled,
			telegram_notify_new_assets, telegram_notify_changes, telegram_notify_vulnerabilities, github_token,
			scan_retention_count, hackerone_username, hackerone_api_token
		FROM app_settings WHERE id = 1`).Scan(&set.TelegramBotToken, &set.TelegramChatID, &enabled,
		&notifyNew, &notifyChanges, &notifyVulns, &set.GithubToken, &set.ScanRetentionCount,
		&set.HackerOneUsername, &set.HackerOneAPIToken)
	if err != nil {
		return nil, err
	}
	set.TelegramEnabled = enabled != 0
	set.TelegramNotifyNewAssets = notifyNew != 0
	set.TelegramNotifyChanges = notifyChanges != 0
	set.TelegramNotifyVulnerabilities = notifyVulns != 0
	return &set, nil
}

// UpdateSettings replaces the Telegram notification configuration, the
// GitHub dorking token, the scan-history retention count, and the
// HackerOne API credentials (used only for scope import, see
// internal/hackerone).
func (s *Store) UpdateSettings(botToken, chatID string, enabled, notifyNewAssets, notifyChanges, notifyVulnerabilities bool,
	githubToken string, scanRetentionCount int, h1Username, h1APIToken string) (*Settings, error) {
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO app_settings (id) VALUES (1)`); err != nil {
		return nil, err
	}
	_, err := s.db.Exec(`UPDATE app_settings SET telegram_bot_token=?, telegram_chat_id=?, telegram_enabled=?,
			telegram_notify_new_assets=?, telegram_notify_changes=?, telegram_notify_vulnerabilities=?, github_token=?,
			scan_retention_count=?, hackerone_username=?, hackerone_api_token=?
		WHERE id=1`,
		botToken, chatID, boolToInt(enabled),
		boolToInt(notifyNewAssets), boolToInt(notifyChanges), boolToInt(notifyVulnerabilities), githubToken,
		scanRetentionCount, h1Username, h1APIToken)
	if err != nil {
		return nil, err
	}
	return s.GetSettings()
}
