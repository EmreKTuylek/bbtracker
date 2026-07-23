// Package telegram sends bbtracker's new-asset notifications through the
// Telegram Bot HTTP API (https://core.telegram.org/bots/api#sendmessage).
// No SDK - a single POST via net/http, so no new go.mod entry.
package telegram

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"bbtracker/internal/store"
)

const (
	apiBase     = "https://api.telegram.org"
	sendTimeout = 10 * time.Second
	// maxListed caps how many new hosts are named in one message so a scan
	// that finds hundreds of new assets doesn't blow past Telegram's ~4096
	// character message limit.
	maxListed = 25
)

// Asset is one newly discovered host, with its resolved IP if httpx probed
// it in the same scan (empty if the scan ran subfinder-only, or httpx
// couldn't resolve/connect to that particular host).
type Asset struct {
	Host string
	IP   string
}

// AssetChange is a known asset whose httpx result changed between scans.
type AssetChange struct {
	Host      string
	OldStatus int
	NewStatus int
	OldTitle  string
	NewTitle  string
}

// Vuln is one nuclei template match, for the new-vulnerability notification.
type Vuln struct {
	Host       string
	TemplateID string
	Name       string
	Severity   string
	MatchedAt  string
}

// NotifyNewAssets sends a Telegram message listing newly discovered assets
// for a program, if notifications (and this category) are enabled and
// configured. It is a no-op (nil error) when disabled, unconfigured, or
// there's nothing new to report - callers don't need to check settings
// themselves before calling.
func NotifyNewAssets(st *store.Store, programName string, assets []Asset) error {
	if len(assets) == 0 {
		return nil
	}
	settings, err := loadEnabledSettings(st, func(s *store.Settings) bool { return s.TelegramNotifyNewAssets })
	if err != nil || settings == nil {
		return err
	}
	lines := make([]string, len(assets))
	for i, a := range assets {
		if a.IP != "" {
			lines[i] = fmt.Sprintf("%s -> %s", a.Host, a.IP)
		} else {
			lines[i] = a.Host
		}
	}
	header := fmt.Sprintf("bbtracker: %s - %d new asset(s) found", programName, len(assets))
	return SendMessage(settings.TelegramBotToken, settings.TelegramChatID, buildListMessage(header, lines))
}

// NotifyChangedAssets sends a Telegram message listing known assets whose
// httpx result (status code and/or title) changed since the last scan.
func NotifyChangedAssets(st *store.Store, programName string, changes []AssetChange) error {
	if len(changes) == 0 {
		return nil
	}
	settings, err := loadEnabledSettings(st, func(s *store.Settings) bool { return s.TelegramNotifyChanges })
	if err != nil || settings == nil {
		return err
	}
	lines := make([]string, len(changes))
	for i, c := range changes {
		lines[i] = fmt.Sprintf("%s: [%d] %s -> [%d] %s", c.Host, c.OldStatus, c.OldTitle, c.NewStatus, c.NewTitle)
	}
	header := fmt.Sprintf("bbtracker: %s - %d asset(s) changed", programName, len(changes))
	return SendMessage(settings.TelegramBotToken, settings.TelegramChatID, buildListMessage(header, lines))
}

// NotifyNewVulnerabilities sends a Telegram message listing newly found
// nuclei findings (ones not previously recorded for their asset+template).
func NotifyNewVulnerabilities(st *store.Store, programName string, vulns []Vuln) error {
	if len(vulns) == 0 {
		return nil
	}
	settings, err := loadEnabledSettings(st, func(s *store.Settings) bool { return s.TelegramNotifyVulnerabilities })
	if err != nil || settings == nil {
		return err
	}
	lines := make([]string, len(vulns))
	for i, v := range vulns {
		lines[i] = fmt.Sprintf("[%s] %s - %s (%s)", strings.ToUpper(v.Severity), v.Name, v.Host, v.TemplateID)
	}
	header := fmt.Sprintf("bbtracker: %s - %d new vulnerability(ies) found", programName, len(vulns))
	return SendMessage(settings.TelegramBotToken, settings.TelegramChatID, buildListMessage(header, lines))
}

// loadEnabledSettings loads settings and returns nil (no error) if the
// master switch, the bot token/chat id, or the given per-category flag
// isn't set - the shared no-op gate for all three Notify* functions above.
func loadEnabledSettings(st *store.Store, categoryEnabled func(*store.Settings) bool) (*store.Settings, error) {
	settings, err := st.GetSettings()
	if err != nil {
		return nil, fmt.Errorf("load settings: %w", err)
	}
	if !settings.TelegramEnabled || settings.TelegramBotToken == "" || settings.TelegramChatID == "" || !categoryEnabled(settings) {
		return nil, nil
	}
	return settings, nil
}

// buildListMessage renders a header line followed by up to maxListed
// entries, so a scan that finds hundreds of items doesn't blow past
// Telegram's ~4096 character message limit.
func buildListMessage(header string, lines []string) string {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")
	shown := lines
	truncated := 0
	if len(shown) > maxListed {
		truncated = len(shown) - maxListed
		shown = shown[:maxListed]
	}
	for _, l := range shown {
		b.WriteString(l)
		b.WriteString("\n")
	}
	if truncated > 0 {
		fmt.Fprintf(&b, "...and %d more\n", truncated)
	}
	return strings.TrimRight(b.String(), "\n")
}

// SendMessage posts text to chatID through botToken's Telegram bot. Exported
// so the settings UI can send a one-off test message.
func SendMessage(botToken, chatID, text string) error {
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

	form := url.Values{
		"chat_id": {chatID},
		"text":    {text},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		apiBase+"/bot"+botToken+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned %s", resp.Status)
	}
	return nil
}
