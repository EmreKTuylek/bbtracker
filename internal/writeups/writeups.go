// Package writeups syncs disclosed HackerOne reports (Hacktivity) into the
// writeups table, for the Learn view and, later, LLM root-cause analysis.
package writeups

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"bbtracker/internal/hackerone"
	"bbtracker/internal/store"
)

const (
	source        = "hackerone"
	maxPages      = 5 // 500 newest disclosed reports per sync
	syncEvery     = 24 * time.Hour
	checkInterval = time.Hour
	minTextLen    = 300
)

// ErrNoCredentials means HackerOne username/token aren't saved in Settings.
var ErrNoCredentials = errors.New("save a HackerOne username and API token in Settings first")

var mu sync.Mutex // one sync at a time (ticker vs. manual button)

// qualityMarkers: any one of these suggests the text carries technical detail.
var qualityMarkers = []string{"http://", "https://", "payload", "curl", "<script", "step", "post ", "get ", "1."}

// QualityFlag is a naive heuristic: short text or text with no sign of
// requests/payloads/steps is "low".
// ponytail: substring checks tuned by guess, and applied to HackerOne's short
// generated summary, not a full body; revisit against real data.
func QualityFlag(text string) string {
	if len(text) < minTextLen {
		return "low"
	}
	l := strings.ToLower(text)
	for _, m := range qualityMarkers {
		if strings.Contains(l, m) {
			return "ok"
		}
	}
	return "low"
}

// Sync fetches Hacktivity and upserts it. Returns the number of new reports.
func Sync(ctx context.Context, st *store.Store) (int, error) {
	if !mu.TryLock() {
		return 0, errors.New("a write-up sync is already running")
	}
	defer mu.Unlock()

	set, err := st.GetSettings()
	if err != nil {
		return 0, err
	}
	if set.HackerOneUsername == "" || set.HackerOneAPIToken == "" {
		return 0, ErrNoCredentials
	}
	items, err := hackerone.FetchHacktivity(ctx, set.HackerOneUsername, set.HackerOneAPIToken, maxPages)
	if err != nil {
		return 0, err
	}
	added := 0
	for _, it := range items {
		sum := sha256.Sum256([]byte(it.Title + "\n" + it.Summary))
		isNew, err := st.SaveWriteup(store.Writeup{
			Source: source, ExternalID: it.ID, URL: it.URL, Title: it.Title, Program: it.Program,
			Weakness: it.Weakness, Severity: it.Severity, Bounty: it.Bounty, DisclosedAt: it.DisclosedAt,
			RawText: it.Summary, ContentHash: hex.EncodeToString(sum[:]), QualityFlag: QualityFlag(it.Summary),
		})
		if err != nil {
			return added, err
		}
		if isNew {
			added++
		}
	}
	return added, st.MarkWriteupsSynced()
}

// Run syncs at startup and then whenever the last sync is over 24h old,
// checked hourly (a desktop app may not stay up a full 24h, so a plain 24h
// ticker would never fire). Silent when credentials are missing.
func Run(ctx context.Context, st *store.Store) {
	tick := func() {
		set, err := st.GetSettings()
		if err != nil {
			log.Printf("writeups: settings: %v", err)
			return
		}
		if last, err := time.Parse(time.RFC3339, set.WriteupsLastSyncAt); err == nil && time.Since(last) < syncEvery {
			return
		}
		n, err := Sync(ctx, st)
		switch {
		case errors.Is(err, ErrNoCredentials):
		case err != nil:
			log.Printf("writeups: sync: %v", err)
		default:
			log.Printf("writeups: synced, %d new", n)
		}
	}
	tick()
	t := time.NewTicker(checkInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
