package server

import (
	"net/http"

	"bbtracker/internal/store"
	"bbtracker/internal/telegram"
)

// settingsRequest is the body for PUT /api/settings.
type settingsRequest struct {
	TelegramBotToken              string `json:"telegram_bot_token"`
	TelegramChatID                string `json:"telegram_chat_id"`
	TelegramEnabled               bool   `json:"telegram_enabled"`
	TelegramNotifyNewAssets       bool   `json:"telegram_notify_new_assets"`
	TelegramNotifyChanges         bool   `json:"telegram_notify_changes"`
	TelegramNotifyVulnerabilities bool   `json:"telegram_notify_vulnerabilities"`
	GithubToken                   string `json:"github_token"`
	ScanRetentionCount            int    `json:"scan_retention_count"`
	HackerOneUsername             string `json:"hackerone_username"`
	HackerOneAPIToken             string `json:"hackerone_api_token"`
	UncoverAPIKeys                string `json:"uncover_api_keys"`
}

// settingsView is what GET /api/settings returns: everything except the
// three API tokens (telegram bot token, github token, hackerone api token),
// which are secrets an unauthenticated local caller shouldn't be able to
// read back - only whether one is saved. Telegram chat id and the hackerone
// username are identifiers, not credentials, so they're still returned
// as-is. PUT /api/settings is unaffected: it still takes real token values,
// and (see handleUpdateSettings) an empty token field on write means "leave
// the saved token unchanged" rather than "clear it", so the frontend never
// needs to know a real token to preserve it across an edit.
type settingsView struct {
	TelegramBotTokenSet           bool   `json:"telegram_bot_token_set"`
	TelegramChatID                string `json:"telegram_chat_id"`
	TelegramEnabled               bool   `json:"telegram_enabled"`
	TelegramNotifyNewAssets       bool   `json:"telegram_notify_new_assets"`
	TelegramNotifyChanges         bool   `json:"telegram_notify_changes"`
	TelegramNotifyVulnerabilities bool   `json:"telegram_notify_vulnerabilities"`
	GithubTokenSet                bool   `json:"github_token_set"`
	ScanRetentionCount            int    `json:"scan_retention_count"`
	HackerOneUsername             string `json:"hackerone_username"`
	HackerOneAPITokenSet          bool   `json:"hackerone_api_token_set"`
	UncoverAPIKeysSet             bool   `json:"uncover_api_keys_set"`
}

func toSettingsView(s *store.Settings) settingsView {
	return settingsView{
		TelegramBotTokenSet:           s.TelegramBotToken != "",
		TelegramChatID:                s.TelegramChatID,
		TelegramEnabled:               s.TelegramEnabled,
		TelegramNotifyNewAssets:       s.TelegramNotifyNewAssets,
		TelegramNotifyChanges:         s.TelegramNotifyChanges,
		TelegramNotifyVulnerabilities: s.TelegramNotifyVulnerabilities,
		GithubTokenSet:                s.GithubToken != "",
		ScanRetentionCount:            s.ScanRetentionCount,
		HackerOneUsername:             s.HackerOneUsername,
		HackerOneAPITokenSet:          s.HackerOneAPIToken != "",
		UncoverAPIKeysSet:             s.UncoverAPIKeys != "",
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.st.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toSettingsView(settings))
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.ScanRetentionCount < 0 {
		writeError(w, http.StatusBadRequest, "scan retention count cannot be negative")
		return
	}

	// An empty token field means "keep the currently saved token" - the
	// frontend never has the real value to round-trip (see settingsView),
	// so a blank submit must not silently wipe it out.
	current, err := s.st.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	botToken := req.TelegramBotToken
	if botToken == "" {
		botToken = current.TelegramBotToken
	}
	githubToken := req.GithubToken
	if githubToken == "" {
		githubToken = current.GithubToken
	}
	h1Token := req.HackerOneAPIToken
	if h1Token == "" {
		h1Token = current.HackerOneAPIToken
	}
	uncoverKeys := req.UncoverAPIKeys
	if uncoverKeys == "" {
		uncoverKeys = current.UncoverAPIKeys
	}

	if req.TelegramEnabled && (botToken == "" || req.TelegramChatID == "") {
		writeError(w, http.StatusBadRequest, "bot token and chat id are required to enable notifications")
		return
	}

	updated, err := s.st.UpdateSettings(botToken, req.TelegramChatID, req.TelegramEnabled,
		req.TelegramNotifyNewAssets, req.TelegramNotifyChanges, req.TelegramNotifyVulnerabilities, githubToken,
		req.ScanRetentionCount, req.HackerOneUsername, h1Token, uncoverKeys)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toSettingsView(updated))
}

// handleTestTelegram sends a one-off test message using the *currently
// saved* settings, so the user can confirm the bot token/chat id work before
// (or after) relying on them for real scan notifications.
func (s *Server) handleTestTelegram(w http.ResponseWriter, r *http.Request) {
	settings, err := s.st.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if settings.TelegramBotToken == "" || settings.TelegramChatID == "" {
		writeError(w, http.StatusBadRequest, "save a bot token and chat id first")
		return
	}
	if err := telegram.SendMessage(settings.TelegramBotToken, settings.TelegramChatID, "bbtracker: test message"); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
