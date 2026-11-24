# bbtracker

Local-web-UI bug bounty recon & tracking tool: manage programs/scope, run subdomain
discovery + HTTP probing, browse results in a vanilla-JS single page app.

## Run / build / check

```
go run ./cmd/bbtracker          # starts on http://127.0.0.1:8787, opens browser
go build -o bbtracker.exe ./cmd/bbtracker
go vet ./...
go test ./...                   # no tests yet
```

Flags: `-addr host:port`, `-db path/to/file.db`, `-no-browser`.

## File map

| Path | Responsibility |
|---|---|
| `cmd/bbtracker/main.go` | Entry point: flags, opens store, builds server, opens browser, listens. |
| `internal/store/schema.sql` | SQLite DDL (programs, scopes, scans, assets, probes, bounties, vulnerabilities, scan_events, fuzz_hits, archived_urls, param_hits, js_findings, cors_findings, github_findings, cloud_findings, takeover_findings, tls_findings, dns_findings, crawled_urls). |
| `internal/store/models.go` | Row structs shared by store + JSON API. |
| `internal/store/store.go` | `Open`/`Close`, embeds schema, pure-Go driver (`modernc.org/sqlite`). |
| `internal/store/migrate.go` | `ALTER TABLE ... ADD COLUMN` migrations for existing DBs (see below). |
| `internal/store/programs.go` | CRUD for programs + scopes. |
| `internal/store/schedule.go` | Recurring-schedule logic (`UpdateSchedule`, `DuePrograms`, `MarkScheduleRun`, `nextOccurrence`) — split out of `programs.go`. |
| `internal/store/recon.go` | Scan lifecycle, asset upsert, probe save, asset listing, `GetProbe` (for change detection). |
| `internal/store/vulns.go` | `SaveVulnerability` (upsert by asset+template), `ListVulnerabilities`. |
| `internal/store/scan_events.go` | `SaveScanEvent`/`ListScanEvents` — the scan-diff event log (see below). |
| `internal/store/fuzz.go` | `SaveFuzzHit` (upsert by asset+path), `ListFuzzHits`. |
| `internal/store/archived_urls.go` | `SaveArchivedURL` (upsert by program+url), `ListArchivedURLs`. |
| `internal/store/param_hits.go` | `SaveParamHit` (upsert by asset+param), `ListParamHits`. |
| `internal/store/js_findings.go` | `SaveJSFinding` (upsert by asset+kind+value), `ListJSFindings`. |
| `internal/store/cors_findings.go` | `SaveCORSFinding` (upsert by asset+issue), `ListCORSFindings`. |
| `internal/store/github_findings.go` | `SaveGitHubFinding` (upsert by program+repo+path+kind+value), `ListGitHubFindings`. |
| `internal/store/cloud_findings.go` | `SaveCloudFinding` (upsert by program+provider+bucket+kind), `ListCloudFindings`. |
| `internal/store/takeover_findings.go` | `SaveTakeoverFinding` (upsert by asset+service), `ListTakeoverFindings`. |
| `internal/store/tls_findings.go` | `SaveTLSFinding` (upsert by asset+issue+detail), `ListTLSFindings`. |
| `internal/store/dns_findings.go` | `SaveDNSFinding` (upsert by asset+kind+detail+value), `ListDNSFindings`. |
| `internal/store/crawled_urls.go` | `SaveCrawledURL` (upsert by asset+url), `ListCrawledURLs`. |
| `internal/store/triage.go` | `UpdateFindingTriage` — generic status/notes update across all 10 findings tables via a fixed kind→table whitelist. |
| `internal/store/retention.go` | `PruneOldScans` — safely deletes old `scans` rows that no finding table still references. |
| `internal/store/settings.go` | Single-row `app_settings` (Telegram bot token/chat id/enabled + per-category notify flags, GitHub token, scan retention count). |
| `internal/store/writeups.go` | `SaveWriteup` (upsert by source+external_id, rewrites only when `content_hash` changed), `ListWriteups`, `MarkWriteupsSynced`, plus `UpdateGeminiSettings` in `settings.go`. |
| `internal/hackerone/hacktivity.go` | `FetchHacktivity`: pages `GET /v1/hackers/hacktivity` (disclosed reports) for the write-up module. |
| `internal/writeups/writeups.go` | `Sync`/`Run`/`QualityFlag`: Hacktivity → `writeups` table, startup + hourly check for a >24h-old sync. |
| `internal/server/handlers_writeups.go` | `GET /api/writeups`, `POST /api/writeups/sync`. |
| `internal/store/analyses.go` | `analyses` + `analysis_jobs` store: `EnqueueAnalysis` (dedupes), `ClaimDueJob`, `FinishJob` (carries the backoff `run_after`), `SaveAnalysis`, `GetAnalysis`, `GetWriteupText` (the only reader of `raw_text`). |
| `internal/llm/gemini.go` | `GenerateJSON`: native Gemini `generateContent` client, key in the `x-goog-api-key` header, `*RetryError` for 429/5xx. |
| `internal/analysis/analysis.go` | Prompts, Go output validation, and the sequential `Worker` (triage gate, deep analysis, backoff). |
| `internal/server/handlers_analysis.go` | `POST /api/writeups/{id}/analyze`, `POST /api/writeups/analyze-bulk`, `GET /api/writeups/{id}/analysis`. |
| `internal/recon/recon.go` | `Engine`/`Subfinder`/`HTTPProbe`/`VulnScanner` interfaces + orchestration (`Run`). |
| `internal/recon/subfinder.go` | `LibSubfinder`: subfinder-as-library implementation of `Subfinder`. |
| `internal/recon/httpx.go` | `LibHTTPProbe`: httpx-as-library implementation of `HTTPProbe`. |
| `internal/recon/nuclei.go` | `LibNuclei`: nuclei-as-library implementation of `VulnScanner`. |
| `internal/recon/fuzz.go` | `SimpleFuzzer`: hand-rolled concurrent `net/http` implementation of `Fuzzer` (directory/file discovery). |
| `internal/recon/wordlists/common.txt` | Embedded (`go:embed`) default fuzz wordlist, ~300 curated entries. |
| `internal/recon/wayback.go` | `LibWayback`: hand-rolled Wayback Machine CDX API client, implements `URLArchive`. |
| `internal/recon/paramfuzz.go` | `SimpleParamFuzzer`: hand-rolled hidden-parameter discovery (baseline diffing), implements `ParamFuzzer`. |
| `internal/recon/wordlists/params.txt` | Embedded default parameter-name wordlist, ~150 curated entries. |
| `internal/recon/jsanalysis.go` | `SimpleJSAnalyzer`: regex-based endpoint/secret extraction from page + linked `.js` bodies, implements `JSAnalyzer`. |
| `internal/recon/cors.go` | `SimpleCORSScanner`: hand-rolled CORS misconfiguration prober (fixed Origin-header probe set, no wordlist), implements `CORSScanner`. |
| `internal/recon/githubdork.go` | `LibGitHubDorker`: GitHub Code Search dorking (google/go-github, already vendored via nuclei), implements `GitHubDorker`. |
| `internal/recon/cloudenum.go` | `SimpleCloudEnumerator`: hand-rolled, read-only S3/GCS/Azure Blob bucket enumeration, implements `CloudEnumerator`. |
| `internal/recon/wordlists/cloud_suffixes.txt` | Embedded default cloud-bucket-name suffix/prefix wordlist, ~49 curated entries. |
| `internal/recon/takeover.go` | `SimpleTakeoverScanner`: hand-rolled subdomain-takeover checker (CNAME lookup + fixed hosting-provider fingerprint list), implements `TakeoverScanner`. |
| `internal/recon/tlsinfo.go` | `SimpleTLSScanner`: stdlib `crypto/tls` certificate inspector (expiry, self-signed, hostname mismatch, weak protocol, SAN entries), implements `TLSScanner`. |
| `internal/recon/dnsinfra.go` | `SimpleDNSInfraScanner`: DNS record enumeration + AXFR zone-transfer probe (`dnsx`) + WAF/CDN/cloud attribution (`cdncheck`) + ASN attribution (`asnmap`), implements `DNSScanner`. |
| `internal/recon/uncover.go` | `LibUncover`: passive host discovery via Shodan/Censys/FOFA/... (`projectdiscovery/uncover`), implements `PassiveDiscoverer`. |
| `internal/recon/crawl.go` | `LibKatana`: standard-mode (non-headless) web crawler (`projectdiscovery/katana`), implements `Crawler`. |
| `internal/scheduler/scheduler.go` | Background goroutine that triggers recurring auto-scans for programs with a schedule enabled. |
| `internal/telegram/telegram.go` | Telegram Bot API client (`SendMessage`) + `NotifyNewAssets`/`NotifyChangedAssets`/`NotifyNewVulnerabilities`, called from `Engine.Run`. |
| `internal/server/server.go` | `Server`, routes, `writeJSON`/`readJSON` helpers, static file serving. |
| `internal/server/web.go` | `//go:embed all:static` for the frontend. |
| `internal/server/handlers_programs.go` | Programs/scopes/assets REST handlers. |
| `internal/server/handlers_recon.go` | Start-scan / get-scan / list-scans / list-scan-events handlers. |
| `internal/server/handlers_settings.go` | Get/update Telegram settings + send-test-message handlers. |
| `internal/server/handlers_vulns.go` | List-vulnerabilities handler. |
| `internal/server/handlers_fuzz.go` | List-fuzz-hits handler. |
| `internal/server/handlers_wayback.go` | List-archived-URLs handler. |
| `internal/server/handlers_params.go` | List-param-hits handler. |
| `internal/server/handlers_jsfindings.go` | List-JS-findings handler. |
| `internal/server/handlers_cors.go` | List-CORS-findings handler. |
| `internal/server/handlers_github.go` | List-GitHub-dorking-findings handler. |
| `internal/server/handlers_cloud.go` | List-cloud-storage-findings handler. |
| `internal/server/handlers_takeover.go` | List-subdomain-takeover-findings handler. |
| `internal/server/handlers_tls.go` | List-TLS-findings handler. |
| `internal/server/handlers_dns.go` | List-DNS-findings handler. |
| `internal/server/handlers_crawled.go` | List-crawled-URLs handler. |
| `internal/server/handlers_findings.go` | Generic findings-triage handler (`PATCH /api/findings/{kind}/{id}`). |
| `internal/server/handlers_export.go` | CSV export handler (`GET /api/programs/{id}/export?type=<t>`). |
| `internal/server/static/*` | Vanilla JS/CSS/HTML frontend, no build step. |

## Conventions

- **No cgo, ever.** Only `modernc.org/sqlite`. Do not add `mattn/go-sqlite3`.
- Router is stdlib `net/http` `ServeMux` with Go 1.22+ method+path patterns
  (`"GET /api/programs/{id}"`, `r.PathValue("id")`). No third-party router.
- Frontend is hand-written vanilla JS/CSS/HTML under `internal/server/static/`,
  embedded via `go:embed`. No npm, no bundler, no framework.
- Recon tools sit behind the `recon.Subfinder`/`recon.HTTPProbe` interfaces so the
  backend can be swapped. Current backend: **Go libraries**
  (`projectdiscovery/subfinder/v2` and `projectdiscovery/httpx`), not external
  binaries — `subfinder.exe`/`httpx.exe` are not required at runtime.
- Store methods return `(nil, nil)` for "not found" (see `GetProgram`, `GetScan`) —
  handlers must check for a nil pointer and return 404, not rely on an error.
- Out-of-scope filtering: `Engine.Run` loads both `InScopeDomains` and
  `OutScopeDomains`; any discovered host under an out-of-scope domain (exact match
  or subdomain, see `hostInScopeSuffix`) is dropped before upsert/probe — it's
  never persisted, so it can't reappear in the UI.
- Subfinder now resolves candidates instead of just aggregating passive-source
  text: `LibSubfinder` sets `RemoveWildcard: true` and collects hits via
  `runner.Options.ResultCallback` (not the `EnumerateSingleDomainWithCtx`
  sourceMap return, which is unpopulated per-domain in this mode). Only hosts
  that actually resolve (via subfinder's own resolver pool, seeded with
  `resolve.DefaultResolvers` / public DNS — bypasses the OS resolver) and aren't
  flagged as wildcard DNS are stored as assets. In network environments where
  outbound DNS is blocked, this means zero assets are found — that's expected,
  not a bug.
- `AssetRow.IsNew` (`is_new` in JSON) is true when the asset's `first_seen` is at
  or after the `started_at` of the program's most recent completed (`status =
  'done'`) scan; computed in `ListAssets`' SQL, not in Go.
- **Asset notes**: `assets.notes` is a free-text field for the user's own
  observations, unrelated to findings triage (`triage_notes`, which lives on
  the 10 findings tables, not `assets`). `PATCH /api/assets/{id}/notes` →
  `store.UpdateAssetNotes`; no upsert/scan interaction — recon never touches
  this column, only the user does via the Assets table's Notes input.
- **Schema migrations**: `CREATE TABLE IF NOT EXISTS` in `schema.sql` never adds
  columns to a table that already exists, so a real, already-populated
  `bbtracker.db` from a previous version won't pick up new columns from
  `schema.sql` alone. `store.Open()` runs `st.migrate()` (in `migrate.go`) right
  after applying `schema.sql` and before `failStaleScans()`; it issues
  `ALTER TABLE ... ADD COLUMN` for each new column, tolerating SQLite's
  "duplicate column name" error so it's idempotent across restarts. There's no
  migration framework/version table — this ad hoc approach is deliberately kept
  minimal for a single-user desktop app. When adding a column: add it to both
  `schema.sql` (for fresh installs) and `migrate.go` (for upgrades of existing DBs).
- **Scan tool selection**: `POST /api/programs/{id}/scans` accepts an optional
  JSON body `{run_subfinder, run_httpx, screenshot}` (all default `true`/`true`/
  `false` when omitted or the body is empty) — see `store.ScanOptions`. At least
  one of `run_subfinder`/`run_httpx` must be true; `screenshot` requires
  `run_httpx`. `Engine.Run` skips subfinder by reusing `store.AssetHosts` (probing
  known assets directly) or skips httpx entirely, per the flags.
- **Screenshot capture**: `LibHTTPProbe.Probe` sets `runner.Options.Screenshot`,
  which drives httpx's existing go-rod-based headless-Chrome capture (go-rod is
  already a transitive dependency — zero new `go.mod` entries). `UseInstalledChrome`
  defaults to `true` so it uses the user's installed Chrome instead of go-rod's
  ~100MB+ auto-downloaded Chromium. Screenshot mode forces httpx's `StoreResponse`
  side effect on; probe redirects that to a scratch temp dir that's removed after
  the call, since only `Result.ScreenshotBytes` (kept in memory, saved as a BLOB
  in `probes.screenshot`) is wanted. `store.SaveProbe`'s upsert uses
  `COALESCE(excluded.screenshot, screenshot)`, so a later scan that runs
  without the screenshot option (the common case) preserves a previously
  captured screenshot instead of nulling it out — only a scan that itself
  captures a new screenshot replaces the old one. `GET /api/assets/{id}/screenshot` serves the
  raw PNG.
- **Vendored dependencies + the Leakless(false) patch (Windows AV false
  positive)**: this project vendors its dependencies (`vendor/` dir, via
  `go mod vendor`) specifically to carry ONE patch:
  `vendor/github.com/projectdiscovery/httpx/runner/headless.go` changes
  `launcher.New().Leakless(true)` (upstream) to `Leakless(false)`. Reason:
  go-rod's "leakless" mechanism (`github.com/ysmood/leakless`) extracts a
  small guard binary to a fixed temp path
  (`%TEMP%/leakless-<arch>-<pkg-version-hash>/leakless.exe` — stable across
  runs, not randomized, since `leakless.GetLeaklessBin()` reuses the file if
  it already exists) and execs it to supervise/force-kill Chrome if the
  parent process dies. That extract-then-exec-from-temp pattern is a common
  Windows Defender/AV heuristic false-positive trigger, surfacing to the user
  as a scan-ending `fork/exec ...\leakless.exe: ...` error. `Leakless(false)`
  makes go-rod's launcher skip that code path entirely and exec Chrome
  directly (`lib/launcher/launcher.go`'s `Launch()`: the `leakless.Support()`
  branch is simply never taken) — the tradeoff is losing leakless's
  automatic orphaned-Chrome cleanup if bbtracker itself crashes mid-screenshot
  (rare; the user can end it manually via Task Manager). **Maintenance
  warning**: `go build`/`go vet`/`go run` all auto-use `vendor/` (Go 1.14+,
  since `vendor/modules.txt` is present and consistent with `go.mod` — no
  `-mod=vendor` flag needed), so this patch is silently load-bearing. If
  `go.mod` ever changes (dependency bump, new import) and someone reruns
  `go mod vendor`, it regenerates `vendor/` from scratch and **overwrites this
  patch** — reapply the one-line `Leakless(true)` → `Leakless(false)` edit to
  `vendor/github.com/projectdiscovery/httpx/runner/headless.go` immediately
  after any `go mod vendor` run, or the AV false positive comes back.
- **Cancelling a scan**: `Engine` keeps a `scanID -> context.CancelFunc` registry;
  `POST /api/scans/{id}/stop` calls `Engine.Cancel(scanID)`. The scan's own
  goroutine notices via `ctx.Err()` and marks the row `"cancelled"` (distinct from
  `"error"`) through `finishFailed`, which checks `errors.Is(err, context.Canceled)`.
- **Recurring auto-scan**: `cmd/bbtracker/main.go` constructs a single
  `*recon.Engine` and passes it to both `server.NewServer(st, engine)` and
  `scheduler.New(st, engine)` — they MUST share the same engine instance, or
  the "Stop scan" cancel registry would be split in two and stop-scan would
  silently no-op for whichever trigger source (manual vs. scheduled) doesn't
  own the engine that started it. `Scheduler.Run` ticks every minute (plus an
  immediate catch-up tick on startup), calling `store.DuePrograms()` and, for
  each due program without an already-running scan, `CreateScan` +
  `MarkScheduleRun` + `engine.Run` in a goroutine — the exact same call
  `handleStartScan` makes. Schedule config lives on `programs`
  (`schedule_enabled`, `schedule_interval_days`, `schedule_time_of_day`,
  `schedule_run_subfinder`, `schedule_run_httpx`, `schedule_screenshot`,
  `schedule_next_run_at`, `schedule_last_run_at`) set via
  `PUT /api/programs/{id}/schedule` (`handleUpdateSchedule` →
  `store.UpdateSchedule`, in `internal/store/schedule.go`); new programs
  default to `schedule_enabled=0` so pre-existing/newly-created programs never
  auto-scan unless explicitly opted in. No cron-expression parser — day-count
  interval only, matching this project's minimal-dependencies convention.
- **Schedule time-of-day is local time, not UTC**: `schedule_time_of_day`
  (`"HH:MM"`, default `"03:00"`) is the wall-clock time on the machine
  running bbtracker. Every other timestamp column in this schema
  (`scans.started_at`, `programs.created_at`, ...) is SQL-computed UTC via
  `datetime('now')`, but `schedule_next_run_at`/`schedule_last_run_at` are
  deliberately computed in Go with `time.Now()` (local) instead — see
  `nextOccurrence` and the comments in `internal/store/schedule.go` — because
  "run at 3 AM" has to mean 3 AM on the user's own clock, and `datetime('now')`
  is UTC. `MarkScheduleRun` advances `next_run_at` from the *previous*
  `next_run_at` (not from "now"), so the time-of-day never drifts across
  cycles even if the app was closed and a run happened late.
- **`scans.triggered_by`** (`'manual'` | `'scheduled'`, default `'manual'`)
  records whether a scan came from `handleStartScan` (API/UI button) or
  `scheduler.tick()`. Both call the same `store.CreateScan(programID, opts,
  triggeredBy)`; shown as a "Trigger" column in the scan history table.
- **Telegram notifications (three independent categories)**: app-wide (not
  per-program) config in the single-row `app_settings` table
  (`store.GetSettings`/`UpdateSettings`), edited via the sidebar's "Telegram
  notifications" panel → `PUT /api/settings`. `telegram_enabled` is the
  master switch (nothing sends if false, and `NotifyNewAssets`/
  `NotifyChangedAssets`/`NotifyNewVulnerabilities` all short-circuit to a
  silent no-op without it or without a saved bot token/chat id); three
  further per-category flags (`telegram_notify_new_assets` default on,
  `telegram_notify_changes` default **off** since routine status/title
  churn is noisy, `telegram_notify_vulnerabilities` default on) let the user
  mute a category independently. All three `Notify*` funcs share
  `loadEnabledSettings`/`buildListMessage` in `internal/telegram/telegram.go`.
  `telegram.SendMessage` is a plain `net/http` POST to the Bot API (no SDK,
  zero new `go.mod` entries), 10s timeout, message capped at `maxListed` (25)
  entries to stay under Telegram's ~4096-char limit. A Telegram send failure
  is logged (`log.Printf("telegram notify: ...")`) and **never** fails the
  scan — notification delivery is best-effort, not part of the scan's
  success criteria. The bot token lives in plaintext in `app_settings` (same
  trust model as the rest of `bbtracker.db` — no auth on the local HTTP API
  either) — don't log it, don't put a real token in this file, and tell the
  user not to share their `bbtracker.db` or screen while the token/chat id
  fields are visible. Note for whoever wires up a bot: Telegram bots can't
  message a user who hasn't started a conversation with the bot first, so
  the user must open a chat with their bot (send it anything) before a chat
  id becomes usable — `getUpdates` on the bot token after that reveals the
  numeric chat id.
  - *New assets*: `Engine.Run` collects hosts upserted as new (`isNew` from
    `UpsertAsset`) during the subfinder phase, then looks up each one's
    resolved IP from the httpx phase (`HTTPResult.IP`, from httpx's
    `Result.HostIP` — **not** `Result.Host`, which is just the hostname
    string again). A subfinder-only scan (RunHTTPX=false) still notifies,
    just without IPs.
  - *Changed assets*: before `SaveProbe` overwrites a known asset's probe row,
    `Engine.Run` calls `store.GetProbe(id)` for the prior value and compares
    `StatusCode`/`Title` only (tech/webserver/content_length are too noisy)
    — a difference queues a `telegram.AssetChange`.
  - *New vulnerabilities*: `store.SaveVulnerability`'s return value indicates
    whether the (asset_id, template_id) pair was seen before; only genuinely
    new findings are notified, not ones that matched again on a later scan.
- **Nuclei vulnerability scanning**: `internal/recon/nuclei.go`'s `LibNuclei`
  wraps `github.com/projectdiscovery/nuclei/v3/lib`'s `NucleiEngine`
  (`NewNucleiEngine` → `LoadTargets(urls, false)` →
  `ExecuteWithCallback(func(*output.ResultEvent))`), the same callback shape
  as `LibHTTPProbe.Probe`'s `OnResult`. Runs over the *live URLs* httpx just
  probed (`Engine.Run` builds `assetIDByURL` keyed by `HTTPResult.URL` during
  the httpx-saving loop for this), not over bare hostnames — nuclei matches
  are looked back up by `event.Host`, which nuclei sets to the exact input
  URL for http-protocol templates. Safety defaults: `ExcludeTags: []string{
  "dos", "intrusive"}` and `ProtocolTypes: "http"` on every scan, since a
  schedule-triggered scan runs unattended with no per-run review; restricting
  to http-protocol templates also cuts the template count drastically (an
  unrestricted default run against a single host took 20+ minutes and hit
  `nucleiPhaseTimeout`, vs. ~2 minutes with `ProtocolTypes: "http"`).
  **`ProtocolTypes: "http"` does NOT guarantee nuclei only touches the input
  host:port** — a small number of official nuclei-templates hardcode an
  alternate port for a specific known service (e.g. `{{BaseURL}}:4040/...`
  to check for an exposed Mesos/Marathon API); these are still "http"
  protocol templates by nuclei's own classification, just targeting a
  different port than the one httpx probed. This is a
  [known, documented nuclei-templates limitation](https://github.com/projectdiscovery/nuclei-templates/issues/5648),
  not something the SDK's `TemplateFilters` can fully suppress. Observed
  in practice as quick connection-refused attempts (not full connections)
  to a couple of alternate ports even with the http restriction on —
  low-impact, but worth knowing before pointing nuclei at a program whose
  scope explicitly excludes non-web/network-level testing. **First-ever
  nuclei-enabled scan on a machine downloads and caches the nuclei-templates
  repo from GitHub** (a one-time cost handled by nuclei itself, not
  bbtracker) — this is why `nucleiPhaseTimeout` (30 minutes, in `recon.go`)
  is far larger than the httpx/subfinder phase timeouts; expect the first
  such scan to be slow regardless of the protocol restriction.
  `scans.run_nuclei`/`programs.schedule_run_nuclei` default to **0** (unlike
  `run_subfinder`/`run_httpx`, which default to 1) since this is a newer,
  more invasive opt-in tool, and requires `run_httpx`/`schedule_run_httpx`
  (same validation shape as `screenshot`). Findings upsert into
  `vulnerabilities` keyed by `(asset_id, template_id)` — a finding that
  stops matching in a later scan is **not** deleted, matching `assets`'
  "never disappears on its own" philosophy; the UI's "Vulnerabilities" panel
  always shows the latest known state per finding, not scan-by-scan history.
- **Scan diff (`scan_events`)**: `probes`/`vulnerabilities` only ever keep a
  single *current* row (no history), so retroactively diffing two arbitrary
  past scans isn't possible from them alone. Instead, `Engine.Run` already
  computes exactly what changed at scan time for Telegram (`newHosts`,
  `changedAssets`, `newVulns`) — `scan_events` persists that same
  information as an append-only log (`kind` one of `new_asset`/
  `changed_asset`/`new_vuln`, `old_value`/`new_value` human-readable
  strings), written via `store.SaveScanEvent` right alongside each of those
  three slices being built (best-effort, like the `telegram.Notify*` calls —
  a write failure never fails the scan). `GET /api/scans/{id}/events` →
  `store.ListScanEvents` lets the UI show "what this scan found" for any
  historical scan; clicking a `#scan-table` row opens `#scan-diff-modal`
  with the three categories grouped. Since it's a new table, no
  `migrate.go` entry was needed (`CREATE TABLE IF NOT EXISTS` handles
  existing DBs the same as fresh ones).
- **Fuzzing (directory/file discovery)**: `internal/recon/fuzz.go`'s
  `SimpleFuzzer` is a **hand-rolled** `Fuzzer` (plain concurrent `net/http`
  GET requests, one per (live URL, wordlist entry) pair, capped at
  `fuzzWorkers` = 20 in flight across the whole phase, not per host) —
  deliberately **not** built on `ffuf`, despite ffuf being the obvious
  off-the-shelf Go tool. `ffuf`'s `pkg/ffuf` is the CLI's own internal
  package split (`Config`/`Job`/`MatcherManager`, plus separate
  `pkg/input`/`pkg/output`/`pkg/runner`/`pkg/filter`/`pkg/scraper`
  packages), not a documented SDK; wiring it up would have been
  substantially more code and version-fragility than this project's actual
  v1 need ("try each wordlist entry, report non-404 responses") warrants.
  Plain `http.StatusNotFound` (404) responses are skipped, plus soft-404
  suppression: `fetchBaselines` requests one random-looking nonexistent path
  per host up front, and any wordlist hit whose status+content-length
  exactly matches that host's baseline is treated as a miss too. The match
  is exact, not a size-delta threshold or word-count heuristic like
  ffuf/wfuzz — a soft-404 page with byte-varying content (e.g. a timestamp)
  still evades it (`ponytail:` comment in `fuzz.go`). `run_fuzz`/
  `schedule_run_fuzz` default to **0** like nuclei (opt-in, and requires
  `run_httpx`/`schedule_run_httpx` — same validation shape as
  screenshot/nuclei), since it is by far the most request-heavy tool this
  project runs (host count × wordlist size requests, versus one request per
  host for httpx or one scan per URL for nuclei). The wordlist defaults to
  `internal/recon/wordlists/common.txt` (embedded via `go:embed`, ~300
  hand-curated entries — not a substitute for a full wordlist like
  SecLists); both a manual scan (`scans.fuzz_wordlist_path`, sent per-request
  via `POST /api/programs/{id}/scans`) and the schedule
  (`programs.schedule_fuzz_wordlist_path`, edited in the same "Auto-scan
  schedule" form as the other schedule options) can instead point at a
  wordlist file path on disk — an empty path means "use the embedded
  default." Findings upsert into `fuzz_hits` keyed by `(asset_id, path)`,
  same "never disappears, upsert refreshes it" philosophy as
  `vulnerabilities`. New hits also write a `scan_events` row
  (`kind = "new_fuzz_hit"`), so they show up in the scan-diff modal
  alongside new assets/changed assets/new vulnerabilities. No Telegram
  category was added for fuzz hits (v1 scope decision — results can be
  numerous/noisy; revisit if that turns out to be wanted).
- **Wayback URL discovery, hidden-parameter discovery, JS/secret analysis**:
  three more opt-in tools (`run_wayback`/`run_params`/`run_jsanalysis`, all
  default 0, all with `schedule_*` counterparts), added for the same reason
  as fuzzing — the obvious CLI tools (waybackurls/gau, Arjun, LinkFinder/
  SecretFinder/Mantra) are Python or CLI-only, not Go SDKs, so each is a
  small hand-rolled implementation rather than a shelled-out binary. Note:
  **Wappalyzer-equivalent tech detection needed no new work** — `httpx.go`
  already sets `TechDetect: true`, which drives httpx's own (already-
  vendored, transitive) `projectdiscovery/wappalyzergo` dependency; results
  land in `probes.tech`, shown in the Assets table's Tech column. wafw00f
  (WAF fingerprinting) was explicitly left out of scope by the user.
  - *Wayback* (`internal/recon/wayback.go`): one HTTP GET + JSON parse per
    in-scope domain against the public CDX API
    (`web.archive.org/cdx/search/cdx?...&output=json`), no library needed.
    Unlike every other opt-in tool, it never sends a request to the target
    itself (archive.org only) — still defaults off, for consistency with
    the "new tool starts opt-in" pattern rather than because it's risky.
    Results go in `archived_urls`, keyed by `(program_id, url)` — NOT
    `asset_id`, since an archived URL's host may not be a known asset yet.
    A `scan_events` row (`kind = "new_archived_url"`) is only written when
    the URL's host happens to match an asset already discovered this scan
    (via the subfinder phase's `assetIDByHost`) — `scan_events.asset_id` is
    `NOT NULL`, and retrofitting it nullable would mean rebuilding the
    table rather than a simple `ALTER TABLE ADD COLUMN`, so URLs for
    unknown hosts are still saved and visible in the Archived URLs tab,
    just without a scan-diff entry.
  - *Hidden parameters* (`internal/recon/paramfuzz.go`, wordlist
    `internal/recon/wordlists/params.txt`): a v1-simplified Arjun — one
    baseline request (no extra param) per URL, then one request per
    wordlist entry with `?name=bbtracker_probe` appended; a status-code
    change OR a content-length delta past a threshold
    (`max(10% of baseline, 20 bytes)`) counts as a hit. No Arjun-style
    batching/binary-search — slower, much simpler. Results in `param_hits`,
    keyed by `(asset_id, param)`.
  - *JS analysis* (`internal/recon/jsanalysis.go`): `httpx.go`'s
    `ProbeOptions.CaptureBody` (only set when `run_jsanalysis` is on) turns
    on httpx's `ResponseInStdout` + an explicit `MaxResponseBodySizeToSave`
    (2 MiB — **must** be set explicitly since it defaults to the zero value
    when `runner.Options` is built directly rather than via
    `ParseOptions`, which would silently truncate every captured body to
    empty), populating the new `HTTPResult.Body` field. `SimpleJSAnalyzer`
    then regex-scans each page body plus any linked `.js` files it
    discovers (`<script src="...">`) and fetches itself, for LinkFinder-
    style endpoint-like strings and a small curated set of secret patterns
    (AWS key, Google API key, Slack token, JWT, generic `api_key=`/
    `secret=`/`token=` assignments). Results in `js_findings`
    (`kind = "endpoint" | "secret"`), keyed by `(asset_id, kind, value)`;
    scan_events uses two distinct kinds (`new_endpoint`/`new_secret`) so
    secrets stand out separately in the scan-diff modal.
    **`MaxResponseBodySizeToSave` alone was not enough — found and fixed
    as a real bug**: httpx has a *second*, separate knob,
    `MaxResponseBodySizeToRead` (`runner.Options`), governing how many
    bytes get read off the wire *at all*
    (`vendor/.../httpx/common/httpx/httpx.go`'s
    `io.ReadAll(io.LimitReader(httpresp.Body, h.Options.MaxResponseBodySizeToRead))`).
    `httpx.go` never set it, so it defaulted to `0` — and worse,
    `runner.go`'s own constructor clamps `MaxResponseBodySizeToSave` down
    to `MaxResponseBodySizeToRead` when the latter is smaller, so the
    unset Read limit silently zeroed the Save limit too. Net effect: httpx
    read **zero bytes** of every response body regardless of
    `CaptureBody`/`ResponseInStdout`, so `js_findings` was **always empty
    on every scan**, with no error anywhere — the phase "ran," found
    nothing, and looked like a normal negative result. `maxProbeBodyBytes`
    (`httpx.go`) now sets both `MaxResponseBodySizeToSave` *and*
    `MaxResponseBodySizeToRead` to the same 2 MiB value. Found via a live
    reproduction (a local test target with a guaranteed secret + endpoint
    in its JS, scanned through the real pipeline, not seeded DB rows) after
    a user report — CORS scanning was independently verified working
    correctly on the same reproduction (it doesn't depend on body capture
    at all), so an empty `cors_findings` table is not this bug; it means
    the scanned target genuinely has none of the four misconfigurations
    `cors.go` checks for.
- **CORS misconfiguration scanning**: `internal/recon/cors.go`'s
  `SimpleCORSScanner` sends a small, **fixed** set of GET requests per live
  probed URL (no wordlist, unlike fuzz/param-fuzz) with crafted `Origin`
  headers, and inspects the `Access-Control-Allow-Origin`/
  `Access-Control-Allow-Credentials` response headers for four
  misconfiguration classes: `reflects_arbitrary_origin` (ACAO echoes back an
  arbitrary attacker-controlled origin), `wildcard_with_credentials` (ACAO is
  `*` while ACAC is `true` — a spec-violating combination some servers still
  send), `null_origin_allowed` (ACAO echoes `null`, exploitable via sandboxed
  iframes/`file://` origins), and `subdomain_bypass` (ACAO reflects a naive
  prefix/suffix variant of the target's own host, e.g. `evil<host>` or
  `<host>.evil.test`, indicating a substring/suffix check without proper
  anchoring). `run_cors`/`schedule_run_cors` default to **0** like the other
  newer opt-in tools, require `run_httpx`/`schedule_run_httpx` (same
  validation shape as nuclei/fuzz), and need no wordlist path option since
  the probe set is fixed. Findings upsert into `cors_findings` keyed by
  `(asset_id, issue)` — same never-deleted/upsert-refreshes-it philosophy as
  `vulnerabilities`/`fuzz_hits`. `scan_events` kind: `new_cors_finding`.
  **HTTP Request Smuggling detection (a `smuggler`-equivalent) was proposed
  alongside CORS scanning in the same request and explicitly deferred by the
  user** after being asked: it requires sending deliberately ambiguous/
  malformed requests (conflicting `Content-Length`/`Transfer-Encoding`
  headers to force a CL.TE/TE.CL desync), a materially more intrusive
  technique than anything else this project runs — every other tool here
  sends normal, well-formed, idempotent requests (nuclei additionally
  excludes `dos`/`intrusive` tags for the same reason class). A successful
  desync probe against a target behind shared front-end infrastructure
  (CDN, load balancer) risks corrupting connection state for other tenants,
  not just the target being tested. Don't silently add smuggling detection
  in a future session without re-raising that trade-off with the user.
  **Fixed a real bug: CORS (and every other follow-up request tool)
  silently skipped any HTTPS host with a certificate problem.**
  `internal/recon/httpx.go`'s httpx-backed probe sets
  `InsecureSkipVerify: true` internally (several places in
  `vendor/.../httpx/common/httpx/httpx.go`) — a self-signed/mismatched/
  untrusted-CA host (common on staging/internal/newly-discovered
  subdomains, exactly what subfinder tends to surface) still gets probed
  successfully and registered as a live asset. But `cors.go`'s
  `http.Client{}` had no custom `Transport`, so it used Go's *default
  strict* certificate verification — every probe against such a host
  failed at the TLS handshake, `doGetWithOrigin` swallowed the error into
  `ok=false`, and the phase reported zero findings with no error anywhere,
  indistinguishable from "this host has no CORS issues." Confirmed via live
  reproduction: an `httptest`-style self-signed HTTPS target with a
  genuine `reflects_arbitrary_origin` misconfiguration was correctly
  probed as a live `200` asset by httpx, and `cors_findings` still came
  back empty until this was fixed. The same gap existed in `fuzz.go`,
  `paramfuzz.go`, `takeover.go`, and `jsanalysis.go`'s linked-`.js`-file
  fetcher — every recon tool that makes its own follow-up request to a
  host httpx already discovered. Fixed once via a shared
  `skipVerifyTransport` (`fuzz.go`, next to `maxFuzzBodyBytes`) that all
  five now set as their client's `Transport`. **Deliberately not applied
  to `cloudenum.go`**: its requests target fixed, well-known cloud
  provider domains (`s3.amazonaws.com`, `storage.googleapis.com`,
  `*.blob.core.windows.net`), not program-scope hosts httpx discovered, so
  there's no "httpx already tolerated this cert" precedent to stay
  consistent with there. Not a new security concern — these are outbound
  requests to the user's own authorized bug-bounty target, the same
  posture nuclei/httpx/Burp already take, and the same precedent
  `tlsinfo.go`'s `SimpleTLSScanner` already established in this codebase.
- **CORS extra-paths wordlist**: `cors.go`'s probe set originally only ever
  hit the single root URL httpx probed. Live-testing against a real
  PortSwigger Web Security Academy CORS lab surfaced a real, separate
  limitation (not a bug in the fix above): that lab's misconfiguration
  lives on `/accountDetails`, an API endpoint the homepage's own JS calls
  via `fetch(..., {credentials:'include'})` — a single-URL, no-crawling
  scanner structurally cannot reach it. `SimpleCORSScanner.Scan` (and the
  `CORSScanner` interface) now takes a second parameter, `pathsWordlistPath`
  (empty ⇒ embedded default, same "empty means embedded default" convention
  as `Fuzzer.Fuzz`'s `wordlistPath` — reuses the exact same
  `loadWordlistFile` helper from `fuzz.go`, no new loader written) and
  additionally probes `rootURL + "/" + path` for a small, curated list of
  common account/API path names (`wordlists/cors_paths.txt`, ~24 entries:
  `accountDetails`, `api/me`, `profile`, `graphql`, etc. — CORS bugs are
  disproportionately found on this exact class of endpoint). Configurable
  per scan (`cors_wordlist_path`) and per schedule
  (`schedule_cors_wordlist_path`), same override-file pattern as
  `fuzz_wordlist_path`/`params_wordlist_path`, validated with the same
  `validateWordlistPath`.
  **Still does not crawl or authenticate** — this closes the "wrong path"
  gap, not the "needs a logged-in session" gap; confirmed live against the
  same PortSwigger lab that the extra path (`api/accountDetails`, tried
  unauthenticated) still correctly gets a 401 with no CORS headers, so the
  lab's own bug remains out of reach on purpose, not by oversight. Adding
  crawling and/or login/session support was explicitly discussed and
  deferred as a materially bigger feature (credential storage for a
  *target* application, not just an API token — a different risk class)
  — don't add it silently in a future session without re-raising that
  trade-off, same as the smuggling-detection and cloud-write-test
  deferrals above.
  `CORSFinding.Host` changed meaning slightly to stay correct under this:
  it's always the original httpx-probed asset URL (used for the
  `assetIDByURL` lookup in `Engine.Run`), while `CORSFinding.URL` is the
  exact URL actually probed (root, or root plus an extra path) — before
  this change the two were always identical, so nothing else in the
  codebase depended on them being interchangeable, but a future reader
  should not assume `Host` is a real, dereferenceable URL for every kind of
  display purpose (it can be a "virtual" root the extra-path findings are
  filed under). `corsPerHostBudget`/`corsMaxTimeout` (`recon.go`) were
  bumped (5s→30s per host, 10m→20m cap) to cover the larger probe volume;
  same flat-budget-not-wordlist-size-scaled approach `fuzzPerHostBudget`
  already uses, not dynamically computed from the wordlist length.
- **GitHub source-code dorking**: `internal/recon/githubdork.go`'s
  `LibGitHubDorker` searches **public** GitHub repositories for leaked
  secrets/sensitive files associated with a program's in-scope domains
  (the GitDorker/TruffleHog/Gitleaks idea), using
  `github.com/google/go-github/v30` against GitHub's Code Search API with
  `SearchOptions.TextMatch: true` — this returns the matched text fragment
  inline with the search result, so **no second request is needed** to fetch
  file contents. **Zero new `go.mod` footprint**: `go-github/v30` and
  `golang.org/x/oauth2` were already vendored transitively (nuclei's own
  `pkg/external/customtemplates` and `pkg/reporting/trackers/github` import
  `go-github`), confirmed by reading the vendored source before adding a
  direct import — `go build` picked it up with no `go mod tidy`/`go mod
  vendor` needed. **`LibGitHubDorker.BaseURL`** (empty = real
  `api.github.com`) is a small testability field mirroring
  `LibHTTPProbe.UseInstalledChrome`, letting tests point the client at an
  `httptest.Server`. The dork list (`githubDorkQueries` in `githubdork.go`)
  is a small hardcoded Go slice (`filename:.env`, `filename:id_rsa`,
  `extension:pem`, etc. — ~10 entries), not an embedded wordlist file, kept
  deliberately short to bound request volume: GitHub's code-search endpoint
  has a much stricter secondary rate limit (~10 req/min) than the general
  Search API (30/min) even when authenticated, so queries are paced with a
  flat 6s delay (`githubQueryDelay`) rather than parsing rate-limit headers
  precisely; hitting a `*github.RateLimitError`/`*github.AbuseRateLimitError`
  stops the scan early with whatever was already found (nil error — an
  external rate limit is an expected outcome, not a scan failure, same
  philosophy as other tools' per-request error handling).
  Each `CodeResult`'s text-match fragments are scanned with `jsanalysis.go`'s
  existing `secretPatterns` (reused directly, same package, no duplication);
  a match is stored as `kind="secret"`, and a dork hit with no regex match is
  still stored as `kind="dork_match"` (a `.env`/`id_rsa` filename hit is
  signal on its own even without an extractable secret string) — mirrors
  `js_findings`' `endpoint`/`secret` split. **Requires a GitHub token**
  (`app_settings.github_token`, same plaintext-storage model as
  `telegram_bot_token` — see that section's trust-model warning) since
  GitHub's code search is unusable unauthenticated; **the token needs no
  special scopes**, because code search only ever indexes public
  repositories — this feature structurally cannot see a user's private
  repos no matter what the token can otherwise access. Unlike other opt-in
  tools, the "requires X" precondition checked at the handler layer
  (`handleStartScan`/`handleUpdateSchedule`, returning 400 "GitHub dorking
  requires a GitHub token in Settings") is a **missing setting**, not a
  missing sibling tool flag. `run_github_dork`/`schedule_run_github_dork`
  default to 0 and are independent of `run_httpx` (like `run_wayback` — it
  only needs `InScopeDomains`, never touches the target's own
  infrastructure). Findings upsert into `github_findings`, keyed by
  `(program_id, repo, path, kind, value)` — **no `scan_events` integration
  at all** (unlike `archived_urls`, which sometimes gets an event when its
  host matches a known asset): a GitHub finding has no asset relationship
  whatsoever, and `scan_events.asset_id` is `NOT NULL`, so there's no
  fallback path here — findings are only visible in their own "GitHub
  Findings" tab, never in the scan-diff modal.
- **Cloud storage (S3/GCS/Azure Blob) enumeration**: `internal/recon/cloudenum.go`'s
  `SimpleCloudEnumerator` implements the cloud_enum/S3Scanner idea by hand
  (both are Python/Go-binary CLIs, not Go SDKs) - candidate bucket/container
  names are derived from in-scope domains (`deriveCloudKeywords`: the full
  domain, since a literal full-domain bucket name is a common static-website-
  hosting convention, plus the domain's leftmost label as a "company name"
  stand-in, since bbtracker's scope model has no separate company-name
  field) combined with a small embedded suffix/prefix wordlist
  (`wordlists/cloud_suffixes.txt`, ~49 entries: `backup`, `dev`, `staging`,
  `assets`, etc., tried as both `<keyword>-<suffix>` and `<suffix>-<keyword>`).
  Each candidate is checked with a single **read-only GET** against all three
  providers' public HTTP endpoints (S3: path-style
  `s3.amazonaws.com/<bucket>/` for names containing dots to avoid a real TLS
  SNI/certificate mismatch that breaks virtual-hosted-style `<bucket>.s3.
  amazonaws.com` URLs for dotted names, virtual-hosted style otherwise; GCS:
  `storage.googleapis.com/<bucket>/`; Azure: `<account>.blob.core.windows.
  net/?comp=list`, pre-filtered by `azureAccountNameRe` to skip candidates
  that can never be valid Azure account names rather than wasting a doomed
  request). Response status classifies the finding: `200` → `open_listable`
  (the actionable finding - publicly listable), `403` → `exists_private`
  (bucket/account confirmed to exist, useful recon signal even though not
  directly accessible), anything else (404, network error) is discarded as
  noise. **Deliberately read-only, by explicit user decision**: a
  write-permission check (uploading a test object to confirm open write
  access, what `cloud_enum`/`S3Scanner` sometimes also probe for) was
  proposed and the user chose to exclude it - actually writing to a third
  party's cloud storage is a real state-changing action against their
  infrastructure, a materially different risk class than every read-only
  probe this project runs (same category of concern as the HTTP request
  smuggling deferral above; don't add a write-permission test in a future
  session without re-raising that trade-off). `run_cloud_enum`/
  `schedule_run_cloud_enum` default to 0, independent of `run_httpx` (like
  `run_wayback`/`run_github_dork` - only needs `InScopeDomains`, never
  touches the target's own infrastructure), no wordlist-path override
  exposed in the UI (unlike fuzz/params) since the suffix list is small and
  fixed. Findings upsert into `cloud_findings`, keyed by `(program_id,
  provider, bucket, kind)` - like `github_findings`, **no `scan_events`
  integration** (no asset relationship, `scan_events.asset_id` is `NOT
  NULL`) - visible only in the "Cloud Storage" tab.

- **Scan phase orchestration (`Engine.Run` runs domain-only phases in
  parallel)**: `Engine.Run` splits work into two concurrent tracks. The
  **asset chain** (`runAssetChain`: httpx → nuclei/cors/fuzz/params/jsanalysis,
  each depending on the URLs httpx probed) runs sequentially on the main
  goroutine. The **domain-only phases** (`runWaybackPhase`/`runGithubPhase`/
  `runCloudPhase` — each needs only `InScopeDomains`, nothing from the asset
  chain or each other) run as concurrent goroutines launched right after the
  subfinder phase, so their network-bound work overlaps the asset chain
  instead of running end to end. Safe because every store write serializes
  through the single DB connection (`store.Open` sets `MaxOpenConns(1)`), so
  concurrent `Save*` calls can't hit SQLite lock errors — they just queue. The
  first fatal error from any phase is recorded under a mutex (`recordErr`) and
  calls `cancel()` to stop the rest; after `wg.Wait()`, Run reports that one
  error via `finishFailed` (or `FinishScan("done")` + Telegram if none). This
  preserves the old "any phase failure fails the whole scan" semantics while
  overlapping the phases. When adding a new phase: if it depends on
  `assetIDByURL`/`pages`, put it in `runAssetChain` (return
  `..., "<name>", err` on failure); if it only needs domains, make it a
  `run*Phase` method and launch it in the goroutine block.
- **Domain-only standalone scans**: a scan may enable *only* domain-only tools
  (wayback/github/cloud) with no subfinder/httpx. `ScanOptions.AnyToolEnabled()`
  gates this — both `handleStartScan` and `Engine.Run` reject a scan only when
  **no** tool at all is selected, not when subfinder/httpx specifically are
  off. In `Engine.Run` the "load known assets" branch is `else if opts.RunHTTPX`
  (not a bare `else`), so a domain-only scan never tries to load/require assets.
  The httpx-requiring validations (screenshot/nuclei/fuzz/params/jsanalysis/cors
  still need `RunHTTPX`) are unchanged.
- **CSV export (`internal/server/handlers_export.go`)**: one generic handler,
  `GET /api/programs/{id}/export?type=<t>`, streams a program's table as a CSV
  download (`encoding/csv`, `Content-Disposition: attachment`). `type` selects
  which existing `store.List*` method to call (`assets`, `bounties`,
  `vulnerabilities`, `fuzz-hits`, `archived-urls`, `param-hits`, `js-findings`,
  `cors-findings`, `github-findings`, `cloud-findings`, `takeover-findings`,
  `tls-findings`, `dns-findings`, `crawled-urls`); unknown type → 400.
  The frontend's `setupExportLinks` injects an "Export CSV" `<a>` (not a fetch)
  into each exportable tab's `.panel-header`, so the browser downloads directly.
  When adding a new findings table, add a `case` here and an `EXPORT_TYPES`
  entry in `app.js`.
- **Frontend asset-table pagination**: `renderAssets` filters+sorts the full
  `state.assets` but only renders the active page (`ASSET_PAGE_SIZE = 100`) into
  the DOM — a program with tens of thousands of assets (subfinder can find many)
  would otherwise build that many `<tr>` and freeze the tab. `state.assetPage`
  is reset to 0 on load / search / filter / sort; search is `debounce`d (200ms)
  so huge lists aren't re-filtered on every keystroke. `#asset-pagination`
  Prev/Next controls call `renderAssets` again (no refetch).
- **Unified findings panel (Overview)**: `renderUnifiedFindings` (frontend only,
  no API) merges `state.vulns / githubFindings / cloudFindings / corsFindings /
  jsFindings / fuzzHits / paramHits / takeoverFindings / tlsFindings` into one
  severity-sorted list via `FINDING_SOURCES` (each entry maps a state array +
  its tab + severity/title/detail derivations), rendered in `#all-findings-table`
  on the Overview, capped at `UNIFIED_FINDINGS_LIMIT` (100) with a "+N more"
  note. Each row's type badge links to that finding's own tab.
  `renderOverviewStats` also shows per-tool count cards (cloud/GitHub/CORS/JS/
  fuzz/takeover/TLS). By default rows with `status` `false_positive`/`fixed`
  are hidden (`RESOLVED_STATUSES`) — a "Show resolved" checkbox un-hides them.
  When adding a new findings type, add a `FINDING_SOURCES` entry so it appears
  here automatically.
- **Subdomain takeover detection**: `internal/recon/takeover.go`'s
  `SimpleTakeoverScanner` checks each known host's `net.LookupCNAME`, then: if
  the apex doesn't resolve at all (`net.LookupHost` returns an `IsNotFound`
  DNS error) → `kind="nxdomain"` (the strongest signal — a dangling CNAME to
  nothing); else if the CNAME's suffix matches a small hardcoded fingerprint
  table (`takeoverFingerprints`, ~20 entries: GitHub Pages, Heroku, S3, Azure,
  Shopify, Fastly, Surge.sh, etc. — same "small curated Go slice" pattern as
  `githubDorkQueries`) → fetch the host once and check the body for that
  provider's own "nothing claimed here" signature (`kind="fingerprint_match"`,
  confirmed) or fall back to `kind="cname_match"` (matched but unconfirmed —
  needs manual review) if the body doesn't contain it. **This tool needs only
  hostnames, not httpx's probed URLs** (it does its own DNS lookup + GET), so
  it runs in the *same concurrent goroutine group* as
  wayback/github/cloud (`runTakeoverPhase`, launched right after the
  subfinder/asset-loading step in `Engine.Run` — see "Scan phase
  orchestration" above) rather than inside `runAssetChain`. Because of that,
  `Engine.Run`'s "load known assets without subfinder" branch is
  `else if opts.RunHTTPX || opts.RunTakeover || opts.RunTLS`, not just
  `opts.RunHTTPX` — a takeover- or TLS-only scan still needs `assetIDByHost`
  even though neither needs httpx itself. `run_takeover`/
  `schedule_run_takeover` default to 0, independent of `run_httpx`. Findings
  upsert into `takeover_findings` keyed by `(asset_id, service)`, same
  never-deleted/upsert-refreshes-it pattern as `cors_findings`. `scan_events`
  kind: `new_takeover_finding`.
- **TLS/certificate analysis**: `internal/recon/tlsinfo.go`'s
  `SimpleTLSScanner` dials each host on port 443 with stdlib `crypto/tls`
  (`InsecureSkipVerify: true` — deliberately, so an invalid cert doesn't just
  fail the handshake; the whole point is inspecting *why* it's invalid) and
  reports: `expired`/`expiring_soon` (<30 days, `tlsExpiringSoonWindow`),
  `self_signed` (`Issuer == Subject`), `hostname_mismatch`
  (`cert.VerifyHostname` fails), `weak_protocol` (< TLS 1.2), and
  `new_san_subdomain` — an informational finding for each SAN entry other
  than the probed host itself. **`new_san_subdomain` is NOT cross-checked
  against known assets/scope and never auto-registers a new asset** — the
  `TLSScanner` interface deliberately takes only a host list (mirroring
  `TakeoverScanner`), so this cross-referencing would require broadening the
  interface; the finding is surfaced for the user to manually decide if it's
  worth adding to scope, not auto-expanding scope silently. Same host-only
  concurrent-phase placement as takeover (`runTLSPhase`, no `run_httpx`
  requirement). Schema: `tls_findings` is keyed by `(asset_id, issue, detail)`
  — **`detail` is part of the uniqueness key**, unlike every other findings
  table, specifically because `new_san_subdomain` can legitimately produce
  several distinct rows per asset; a plain `(asset_id, issue)` key would
  collapse them into one. `run_tls`/`schedule_run_tls` default to 0. `scan_events`
  kind: `new_tls_finding`.
- **Findings triage (status/notes)**: all 10 non-asset findings tables
  (`vulnerabilities`, `cors_findings`, `fuzz_hits`, `github_findings`,
  `cloud_findings`, `js_findings`, `param_hits`, `takeover_findings`,
  `tls_findings`, `dns_findings` — NOT `archived_urls`/`crawled_urls`, which have no triage) carry
  `status` (`open`|`accepted_risk`|`false_positive`|`fixed`, default `'open'`)
  and `triage_notes` columns. **One generic endpoint**,
  `PATCH /api/findings/{kind}/{id}` (`handlers_findings.go`), handles all
  ten — `kind` (e.g. `"cors"`, `"takeover"`) is looked up in
  `store.triageTables`, a **fixed Go map** from kind → real table name; the
  table name is never built from request input directly, so there is no SQL-
  injection surface even though `database/sql` can't parameterize identifiers.
  `status` is validated against `validTriageStatuses` the same way. Existing
  `Save*` upsert methods were deliberately **left untouched** — their
  `ON CONFLICT DO UPDATE SET` clauses never mention `status`/`triage_notes`,
  so re-discovering a finding on a later scan refreshes its evidence without
  ever resetting a status the user already set. Frontend: one shared
  `appendTriageCells(tr, kind, row)` helper (in `app.js`) renders the
  `<select>` + notes `<input>` pair and wires the PATCH call, reused by all
  ten tables' render functions instead of duplicating the widget ten times.
- **Scan phase progress (in-memory, not a DB column)**: `Engine` tracks which
  named phases are currently running per scan in an in-memory
  `map[int64]map[string]bool` (`activePhases`, guarded by `phaseMu`), via
  `startPhase`/`endPhase` calls bracketing each phase (both the sequential
  sub-phases inside `runAssetChain` — httpx, nuclei, cors, fuzz, params,
  jsanalysis — and each concurrent `run*Phase` goroutine). **Deliberately not
  a single `scans.current_phase` column**: since domain/host-only phases run
  concurrently with the httpx chain (see "Scan phase orchestration" above),
  several phases can be genuinely active at the same time, and a single
  string column can't represent that. `Engine.ActivePhases(scanID) []string`
  exposes the current set; `handleGetScan` wraps the DB row in a
  `scanWithProgress{*store.Scan, ActivePhases}` and includes `active_phases`
  in the JSON response **only** while `status == "running"`. The frontend's
  `pollScan` shows it inline in `#scan-status` (e.g. "Scan running...
  (httpx, wayback, takeover)").
- **Scan history retention**: `internal/store/retention.go`'s
  `PruneOldScans(programID, keep)` is intentionally **not** a naive "delete
  scans past the Nth" — `store.Open` runs `PRAGMA foreign_keys = ON` and
  every findings table's `scan_id` is `ON DELETE CASCADE`, so deleting an old
  `scans` row would cascade-delete any **still-current** finding whose
  `scan_id` happens to point at that scan (a finding's `scan_id` is just "the
  last scan that reconfirmed it," not history — see each findings table's
  "never disappears on its own" comment in `schema.sql`). Instead, a scan is
  only eligible for deletion when it's outside the most recent `keep` scans
  **AND** not referenced as `scan_id` by any row in any of the 10 findings
  tables. This safely shrinks `scan_events` (a pure diff-log, always fine to
  lose — cascades automatically) while never touching a finding that still
  represents the latest known state of anything. Configured via a new
  app-wide `app_settings.scan_retention_count` (default 0 = unlimited/off,
  same singleton-row pattern as the Telegram/GitHub settings), called
  best-effort from `Engine.Run` right after `FinishScan("done", ...)` —
  a prune failure is logged, never fails the scan.
- **Scope import**: two independent ways to add many scope entries at once
  instead of one-by-one, both landing on the same `store.ImportScopes`
  dedup/insert path (skips any (type, domain) pair already present for the
  program, so re-running an import is idempotent).
  - *Bulk paste* (`POST /api/programs/{id}/scopes/import`, body
    `{text, type}`): works for **any** platform, including ones with no
    public scope API (Bugcrowd, Intigriti, private programs) — it's just
    line-by-line parsing of whatever the user copy-pastes off the program's
    scope page. Blank lines and `#`-prefixed comments are skipped; each
    remaining line goes through the same `normalizeDomain` used by the
    single-entry "Add" form.
  - *HackerOne* (`POST /api/programs/{id}/scopes/import-hackerone`, body
    `{handle}`): calls HackerOne's structured-scope API
    (`internal/hackerone`), which requires the account's own
    username + API token (`app_settings.hackerone_username`/
    `hackerone_api_token`, same plaintext-storage/trust model as
    `github_token` — see that section's warning) since HackerOne's API has
    no unauthenticated access, even for public programs. Only
    `asset_type == "URL"` entries are imported as domains (CIDR ranges,
    mobile app store IDs, source code, hardware, etc. are silently
    skipped); `eligible_for_submission` maps to scope `type` (`true` → `in`,
    `false` → `out`). **Unverified against a live HackerOne account** — the
    JSON field names (`asset_type`/`asset_identifier`/
    `eligible_for_submission`, cursor pagination via `links.next`) are from
    HackerOne's public API docs, not confirmed against a real response;
    test with a real username/token/handle before relying on it, and check
    `internal/hackerone/hackerone.go` first if it returns unexpected results.
  - `normalizeDomain` (in `handlers_programs.go`, shared by the single-entry
    scope form, both import paths, and the manual scope endpoint) strips a
    leading `*.` rather than rejecting it — a bare apex domain already
    covers all its subdomains in this codebase's scope-matching model (see
    `hostInScopeSuffix` in `internal/recon/recon.go`), so `*.example.com`
    and `example.com` normalize to the same stored value.
- **API hardening (local-tool trust model, not full auth)**: this app still
  has no login/session — see the plaintext-token trust model documented
  throughout this file — but three gaps that went beyond "trusts the local
  user" were closed:
  - *Tokens never round-trip through the API*: `GET /api/settings` used to
    return `telegram_bot_token`/`github_token`/`hackerone_api_token` in
    cleartext. It now returns `settingsView` (`handlers_settings.go`) —
    `*_set bool` flags instead of the values (`telegram_chat_id` and
    `hackerone_username` aren't secrets and are still returned as-is). The
    tokens are still plaintext **in the DB file** (unchanged trust model,
    see the Telegram/GitHub/HackerOne sections above) — this only stops an
    HTTP client from reading them back. Because the frontend can no longer
    pre-fill token `<input>`s with the real value, `PUT /api/settings`
    changed contract: an **empty token field means "keep the currently
    saved token"**, not "clear it" — `handleUpdateSettings` fetches the
    current settings and falls back to the existing value for any of the
    three token fields left blank in the request body. The settings form
    (`app.js`) shows a "•••••••• (saved — leave blank to keep)" placeholder
    via `tokenPlaceholder()` instead of pre-filling the input.
  - *Wordlist paths are validated, not just opened*: `fuzz_wordlist_path`/
    `params_wordlist_path` (scan-start and schedule-save) used to flow
    straight into `os.Open` inside `loadWordlistFile` (`fuzz.go`) with zero
    validation — any request could make the server open an arbitrary
    filesystem path, and since fuzz hits store the matched wordlist *line*
    verbatim in `fuzz_hits.path`, a crafted path plus a non-404 response
    could leak file content back through the API. `validateWordlistPath`
    (`handlers_recon.go`) now requires the path (when non-empty — empty
    still means "use the embedded default") to exist, be a regular file, and
    be under `maxWordlistBytes` (20 MiB), checked at `handleStartScan` and
    `handleUpdateSchedule` time so a bad path is an immediate 400, not a
    mid-scan failure. **Deliberately not confined to a fixed directory** —
    pointing the field at an external wordlist (e.g. a local SecLists
    checkout) is a documented, intended use of this field; a hard base-dir
    would have broken it. The size cap is the proportionate fix given that.
  - *DNS-rebinding / cross-origin defense*: `internal/server/middleware.go`'s
    `hostOriginCheck` wraps `Server.Handler()` (so it covers the static
    frontend too, not just `/api/*`). It 403s any request whose `Host` isn't
    a recognized loopback address (`127.0.0.1`/`::1`/`localhost`, any port)
    — the listener being loopback-only (`-addr` default) doesn't by itself
    stop a browser tab on an attacker domain that resolves to 127.0.0.1 via
    DNS rebinding, since the browser still sends that domain as the `Host`
    header regardless of what IP it resolved to. For state-changing methods
    (`POST`/`PUT`/`PATCH`/`DELETE`) it additionally 403s if an `Origin` or
    `Referer` header is present and isn't loopback (absent is allowed
    through — covers curl/scripts, the same trade-off every Origin-check
    CSRF defense makes for non-browser clients). No auth token was added;
    this is the alternative that doesn't require the user to manage one for
    a single-operator local tool.
- **Cross-program dashboard**: before this, every view (Overview, findings
  tabs, the unified findings panel) was scoped to whichever single program
  was selected — the only genuinely cross-program thing in the whole app was
  `GET /api/earnings` in the sidebar. `GET /api/dashboard`
  (`handlers_dashboard.go`) closes that gap: it loops every program and,
  reusing the exact same `store.List*`/`CountAssets`/`ListScans` methods each
  program's own tabs already call, returns one merged payload — per-program
  summaries (`dashboardProgramSummary`: asset count, most recent scan) plus
  all 10 findings types, each row tagged with `program_id`/`program_name` via
  a small per-type wrapper struct (`dashboardVuln`, `dashboardFuzzHit`, …).
  **A generic `dashboardFinding[T any]` wrapper was tried first and doesn't
  compile** — Go disallows embedding a bare type parameter — so it's 10
  concrete wrapper types instead, one per finding type; this is more
  boilerplate than generics would have been, but it's the same "repeat the
  shape once per finding type" convention every other findings feature in
  this codebase already uses (10 tables, 10 `List*`, 10 handlers, 10 render
  functions), so it stays consistent rather than being the codebase's first
  (and only) generics usage. One round trip, not N-programs × 10-endpoints,
  is the reason this is a backend endpoint at all rather than a client-side
  fan-out loop.
  Frontend: `showDashboard()` (`app.js`) is now the **default view** — shown
  on initial load (once programs exist), via a "Dashboard" button in the
  sidebar (`#dashboard-nav-btn`), and after deleting a program — replacing
  the old plain "select a program" placeholder (`#empty-state` is now only
  the fallback for when the initial `GET /api/programs` call itself fails).
  Both `showDashboard()` and `selectProgram()` must each hide the other's
  root view (`#dashboard-view` / `#program-view`) as well as `#empty-state` —
  an early version of `selectProgram()` only toggled `#empty-state`/
  `#program-view` and forgot `#dashboard-view`, so visiting the dashboard and
  then picking a program left both views visible, stacked. Fixed by adding
  `el("#dashboard-view").classList.add("hidden")` to `selectProgram()`; if a
  future view is added to this same three-way toggle, all three (now four)
  spots need the new view added symmetrically. Program cards
  (`renderDashboardPrograms`) link to `selectProgram(id)`. The
  cross-program findings inbox (`renderDashboardFindings`) **reuses
  `buildUnifiedFindings` and `FINDING_SOURCES` unchanged** — the function
  gained one optional parameter (a `{[type]: rows[]}` map; omitted, it falls
  back to reading `state.*` exactly as before for the per-program Overview
  panel) rather than duplicating each finding type's severity/title/detail
  derivation in a second place. `DASHBOARD_FINDING_MAP` bridges
  `FINDING_SOURCES`' short type keys (`"vuln"`, `"cors"`, …) to
  `/api/dashboard`'s JSON field names (`vulnerabilities`, `cors_findings`,
  …). The dashboard's search/severity-filter/show-resolved controls
  re-render from a cached `lastDashboardData` instead of re-fetching on every
  keystroke — only `showDashboard()`/`loadDashboard()` itself hits the
  network.
- **Findings-table search/filter**: before this, only the Assets tab had a
  search box (`renderAssets`) — the 10 findings tables (vulnerabilities, fuzz,
  params, JS, CORS, GitHub, cloud, takeover, TLS, DNS) and the per-program
  Overview's unified "All findings" panel had none. `filterBySearch(rows,
  inputSel, fields)` (`app.js`, next to `debounce`/`td`) is the shared
  primitive: reads `inputSel`'s current value, and if non-empty keeps only
  rows where `fields(row)` (an array of strings) joins to a case-insensitive
  substring match — same semantics as `renderAssets`' own inline filter,
  factored out so the other 10 tables don't each reimplement it. Each
  `renderX(rows)` findings function calls it once, right after `tbody.innerHTML
  = ""`, with a small array of the fields relevant to that type (e.g. CORS:
  `[issue, subdomain, origin_sent]`). A single wiring block right before the
  "Overview" section debounces each table's search `<input>` and re-invokes
  `renderX(state.X)` — the render function re-reads its own search box, so
  the filter state doesn't need to be threaded through the call. The Overview
  panel's unified findings table additionally got a severity `<select>`
  (`#all-findings-severity`) alongside its search box, filtering
  `buildUnifiedFindings()`'s output by `f.severity` — the same filter the
  cross-program dashboard's own findings inbox already had from C1.
- **Quick-Wins triage**: severity alone doesn't tell a hunter where to spend
  limited manual-testing time — a `critical` nuclei CVE match often still
  needs real exploitation before it's reportable, while a confirmed
  subdomain takeover or an open S3 bucket is frequently a complete,
  submittable bug already. `isQuickWin(type, row)` (`app.js`, next to
  `buildUnifiedFindings`) classifies four narrow categories as "quick wins":
  `takeover` with `kind=fingerprint_match`, `cloud` with
  `kind=open_listable`, `github`/`js` with `kind=secret`, and `cors` with
  `acac_allowed=true`. Computed once per row inside `buildUnifiedFindings`
  (so it's available everywhere that function's output is used) and stored
  as `quickWin` on the unified row. A "⚡ Quick wins only" chip
  (`#all-findings-quick-wins` on the per-program Overview,
  `#dashboard-findings-quick-wins` on the cross-program Dashboard) filters
  to just these; quick-win rows also get a ⚡ badge in the Finding cell
  (`quickWinTitleTd`) even when the filter is off, so they stand out in the
  normal severity-sorted view too. Pure frontend classification of fields
  already on the row — no new scanning, no schema/backend change.
- **Report draft**: a "Draft report" button (`appendReportCell`) on every
  findings-table row (all 10 tables, plus both unified views) opens a modal
  (`#report-modal`, styled like the existing `#scan-diff-modal`) with a
  copy-pasteable markdown skeleton generated entirely client-side by
  `buildReportMarkdown` — title, affected asset, program, a per-finding-type
  description pulled from fields already on the row (`REPORT_TEMPLATES`, one
  function per kind, keyed by the same `kind` strings as the triage PATCH
  endpoint — see `store/triage.go`'s `triageTables`), and blank Steps-to-
  Reproduce/Impact sections for the hunter to fill in. Deliberately
  **client-side, no new endpoint**: every field the templates use is already
  loaded into `state.*`/the dashboard payload, and speed-to-submission
  (first valid report wins on most platforms) is the entire point, so a
  server round trip adds latency for no benefit. `UNIFIED_TYPE_TO_KIND`
  bridges `FINDING_SOURCES`' short `type` keys (`"vuln"`, `"param"`) to the
  triage endpoint's longer `kind` strings (`"vulnerabilities"`, `"params"`)
  so the two unified views (which only carry `type`) can still resolve the
  right template — the two vocabularies exist because `FINDING_SOURCES`
  predates the triage endpoint's naming; bridging was chosen over renaming
  one to match the other, which would have touched all 10 findings tables.
  `buildUnifiedFindings` carries the original `row` through unchanged
  (needed by the templates) alongside its derived `severity`/`title`/etc.
  fields. Copy-to-clipboard uses `navigator.clipboard`, falling back to
  select-all-and-prompt-Ctrl+C if the Clipboard API is unavailable (e.g. a
  non-secure context).
- **DNS/infrastructure analysis**: `internal/recon/dnsinfra.go`'s
  `SimpleDNSInfraScanner` uses three already-vendored ProjectDiscovery
  libraries that needed **zero new `go.mod` entries** (`cdncheck`, `dnsx`,
  `asnmap` were already `## explicit` in `vendor/modules.txt`, pulled in
  transitively by nuclei/subfinder — same precedent as `go-github`, see the
  GitHub dorking section below) — for each known host: `dnsx.QueryMultiple`
  for A/AAAA/CNAME/MX/TXT/NS records (`kind="record"`, `detail=<type>`), a
  `dnsx.AXFR` zone-transfer attempt (`kind="zone_transfer"` on any
  success — a critical, independently reportable finding on its own: the
  authoritative server discloses its whole zone to anyone who asks), and,
  from the host's first resolved A record, `cdncheck.CheckWAF/CheckCDN/
  CheckCloud` (`kind="waf"|"cdn"|"cloud"`) plus `asnmap.GetData`
  (`kind="asn"`). **This reverses the "no WAF fingerprinting" non-goal in
  PRD.md** — that decision predated discovering `cdncheck` was already a
  zero-cost dependency; PRD.md has been updated to match. Host-only phase
  (`runDNSPhase`, `run_dns`/`schedule_run_dns`), same concurrent-group
  placement as takeover/TLS. `dns_findings` is keyed by
  `(asset_id, kind, detail, value)` — `detail` and `value` are both part of
  the key (unlike `tls_findings`' `(asset_id, issue, detail)`) because a host
  can have several distinct records of the same kind (multiple NS/TXT
  entries). ponytail: none of dnsx/cdncheck/asnmap's calls take a `context`,
  so a slow resolver can't be interrupted mid-call — only bounded by a
  per-query timeout (`dnsQueryTimeout`) and the phase-level
  `dnsWithDeadline` race; upgrade path is a context-aware DNS client if this
  proves too slow in practice.
- **Passive host discovery (Shodan/Censys/FOFA/...)**: `internal/recon/
  uncover.go`'s `LibUncover` wraps `github.com/projectdiscovery/uncover`
  (also already vendored transitively, zero new `go.mod` entries) to find
  hosts subfinder's passive-source enumeration misses entirely — unlike
  every other domain-only tool (wayback/GitHub dork/cloud enum), this one
  **discovers assets**, so it runs in `Engine.Run`'s sequential discovery
  prelude alongside subfinder (not the wayback/github/cloud concurrent
  group), sharing the same `upsertDiscovered` out-of-scope-filter/upsert
  helper subfinder uses. `assets.source` (already existed) gets the engine
  name (`"shodan"`, `"censys"`, ...) — no schema change for assets
  themselves. API keys live in one `app_settings.uncover_api_keys` column
  (`provider:value` per line, e.g. `censys:id:secret` — multi-part
  credentials pass through as a single colon-joined value since
  `sources.Provider.GetKeys()` does that splitting itself), parsed by
  `parseUncoverKeys`; masked the same way as `github_token`/`telegram_bot_
  token` in `GET /api/settings` (`uncover_api_keys_set` bool, blank-on-save
  keeps the existing value). No keys configured → `Discover` returns
  `(nil, nil)`, a silent no-op, **not** a 400 like GitHub dorking's hard
  token requirement — running with zero configured search engines is a
  normal, expected state here. `RunUncover`/`ScheduleRunUncover` are
  independent of `RunHTTPX` (only need `InScopeDomains`, like
  `RunGithubDork`/`RunCloudEnum`). ponytail: one generic `hostname:<domain>`
  query per domain (Shodan's own syntax), not tuned per provider's actual
  query dialect (FOFA/Censys/etc. each have distinct syntax) — acceptable
  baseline, but expect variable result relevance across non-Shodan engines;
  upgrade path is per-agent query templates. Port info in uncover's
  `host:port` results is discarded in v1 (only the hostname becomes an
  asset) — a deliberate scope-reduction near the port-scanning non-goal, not
  an oversight.
- **Web crawling (katana)**: `internal/recon/crawl.go`'s `LibKatana` wraps
  `github.com/projectdiscovery/katana` in its **standard (non-headless)**
  mode — headless mode uses go-rod, which would reintroduce the Leakless/
  Windows Defender false-positive problem documented earlier in this file
  (see the Leakless(false) patch section); standard mode has no such
  dependency. **This is the one genuinely new `go.mod`
  dependency added across this whole round of features** (`go get
  github.com/projectdiscovery/katana@latest` + `go mod tidy` + `go mod
  vendor`), unlike DNS/uncover/GitHub-dorking which were all already
  vendored transitively. Runs inside `runAssetChain` (the sequential
  httpx-dependent chain), right after httpx and before nuclei — crawled
  URLs merge into `assetIDByURL` (keyed the same way httpx's own probed
  URLs are), so **nuclei/CORS/hidden-params see the wider URL set with zero
  changes to those three phases** — they already iterate `assetIDByURL` for
  their input list. **Fuzz is the one exception**: brute-forcing every
  wordlist entry against every crawled URL as well would multiply request
  volume (URL × wordlist), so `runAssetChain` captures `rootURLs` (httpx's
  own probed URLs only) *before* the crawl phase expands `assetIDByURL`, and
  fuzz uses `rootURLs` instead. **JS analysis is deliberately NOT expanded**
  with crawled URLs in v1 — `jsAnalysisWithDeadline` needs page *bodies*
  (`pages map[string]string`), only available from httpx's own
  `CaptureBody`; katana isn't configured to fetch/store response bodies
  here, and doing so would need its own size cap and complexity — a
  documented simplification, not an oversight. A single `standard.Crawler`
  instance is shared across a small worker pool (`crawlWorkers`) crawling
  different root URLs concurrently — confirmed safe by reading katana's own
  CLI (`internal/runner/executer.go` in the katana source), which does
  exactly this (one shared crawler, a `sizedwaitgroup`, `Crawl()` called
  concurrently from multiple goroutines), not an assumption. `maxCrawledURLs`
  (500/scan) bounds total results across every asset — unbounded crawling
  feeding nuclei/CORS/params could otherwise turn a routine scan into an
  hours-long one. Persisted in `crawled_urls`, keyed by `(asset_id, url)`
  (asset-scoped, unlike `archived_urls` which is program-scoped since an
  archived URL's host may not be a known asset); `scan_events` kind:
  `new_crawled_url`. `run_crawl`/`schedule_run_crawl` require
  `run_httpx`/`schedule_run_httpx` (same validation shape as nuclei/fuzz/
  params/CORS/JS-analysis), and are exposed on both the whole-program scan
  form and the single-asset "Rescan" button (see below) via the same shared
  `buildAssetScanBody()` on the frontend.
  **The Leakless patch must be reapplied after `go mod vendor`**: adding
  katana required regenerating `vendor/` from scratch, which — exactly as
  warned elsewhere in this file — silently overwrote
  `vendor/github.com/projectdiscovery/httpx/runner/headless.go`'s
  `Leakless(false)` back to upstream's `Leakless(true)`. Reapplied
  immediately as part of this same change; **any future `go mod vendor` run
  will do this again** — always `grep -n "Leakless"
  vendor/github.com/projectdiscovery/httpx/runner/headless.go` right after,
  and reapply `Leakless(true)` → `Leakless(false)` if it reverted.
- **Single-asset rescan**: `POST /api/assets/{id}/scan` (`handleStartAssetScan`,
  a narrower `assetScanRequest` — no subfinder/uncover/wayback/GitHub-dork/
  cloud-enum, which are domain-scoped and meaningless for one asset) reuses
  `Engine.Run`/`store.CreateScan` unchanged via a new `store.ScanOptions.
  AssetID` field (0 = whole-program scan, the existing default; nonzero
  scopes `Run` to loading just that one asset via the new `store.GetAsset`
  instead of the domain-discovery/`AssetHosts` branches). `scans.asset_id`
  (`INTEGER NOT NULL DEFAULT 0`) records which scan targeted which asset —
  **deliberately not a `REFERENCES assets(id)` foreign key**: with
  `PRAGMA foreign_keys = ON`, the `0` sentinel would itself violate an FK
  constraint (no asset has id `0`, `AUTOINCREMENT` starts at 1), so it stays
  a plain column. Same one-scan-per-program-at-a-time semantics as a
  whole-program scan (`RunningScanForProgram` has no asset-level
  granularity) — a subscan and a whole-program scan can't run concurrently
  either. Frontend: a "Rescan" button per Assets-tab row
  (`rescanAsset(assetID)`) reuses `buildAssetScanBody()` (the same
  toolbar checkboxes the whole-program "Scan" button reads, minus the
  domain-scoped ones) and the existing `pollScan` status line/refresh logic
  — no new progress UI, since only one scan runs per program at a time
  regardless of scope.
- **Screenshot gallery**: `renderGallery()` (`app.js`) is a pure-frontend
  grid view over `state.assets` — every asset with `probe.has_screenshot`
  gets a tile (`GET /api/assets/{id}/screenshot`, already existed), no new
  endpoint or schema change. Reuses the existing `#screenshot-modal`
  lightbox on click, same as the Assets table's inline thumbnail.
- **Print / PDF export**: alongside each tab's existing "Export CSV" link,
  a "Print / PDF" button (`setupExportLinks`) calls `window.print()`; a
  `@media print` block in `style.css` hides the sidebar/tab-bar/scan
  controls/pagination and forces tables to full width with
  `overflow: visible` (a scrollable `.table-wrap` would otherwise clip
  content when printed). No new dependency — the browser's own
  print-to-PDF, same as any other webpage.

- **Write-up module (Learn tab, week 1 of `WRITEUP_MODULE.md`)**: pulls
  *disclosed* HackerOne reports into `writeups` and lists them in the sidebar's
  "Learn" view. The spec assumed Next.js + Supabase (multi-user, RLS); this is
  the single-user Go/SQLite adaptation — no `user_id`, no RLS. Weeks 1-2 are
  built: fetch, dedupe, heuristic quality flag, daily sync, LLM settings, the
  Gemini adapter, job queue/backoff and triage + deep analysis (below). The
  UI for it (analyze buttons, `/learn/[id]` detail page, bulk button) is
  **not built** (week 3); today the analysis API is only reachable via HTTP.
  - **The Hacker API does not return other people's report bodies.**
    `GET /v1/hackers/hacktivity` items carry metadata plus HackerOne's generated
    `hacktivity_summary`; `vulnerability_information` (the full body) is only
    returned for reports the caller owns. So `writeups.raw_text` holds that short
    summary, and `QualityFlag` (`ok`/`low`, naive length + marker check) is judged
    on it. Getting real bodies is the open question in the spec's §11.2.
  - **Undocumented bits, unverified live**: the exact `disclosed:true`
    `queryString` value, `links.next` on hacktivity (pagination is therefore
    `page[number]` until an empty page, capped at `maxPages` = 5 x 100), and rate
    limits. `FetchHacktivity` also re-checks `attributes.disclosed` client-side.
    Test with real credentials before relying on it. Reuses the HackerOne
    username/token from Settings (same ones scope import uses).
  - `raw_text` and `content_hash` are `json:"-"` and `ListWriteups` doesn't even
    select `raw_text` — analysis input only, never served (spec §9).
  - **Gemini key** (`app_settings.gemini_api_key` + two model-name columns, no
    model names hardcoded) follows the existing token model: plaintext in the DB,
    never returned (`gemini_api_key_set` only), blank on save = keep. Deleting it
    needs the explicit `clear_gemini_api_key: true` (the "Remove key" button
    re-submits the whole form with it). It is stored via
    `Store.UpdateGeminiSettings`, deliberately separate from the already-long
    `UpdateSettings` signature. A **new** key is verified with one tiny
    `generateContent` call *before anything is saved* (`geminiCheck` in
    `handlers_settings.go`, a var so tests stub it); a rejected key is a 400 and
    isn't stored. A blank key (keep) is not re-checked.
  - **Analysis pipeline (week 2)**: `analysis.Worker` (started in `main.go`)
    drains `analysis_jobs` strictly one at a time, `Pace` (6s) between LLM
    calls, polling every 5s. Single analyze = deep model only; bulk
    (`analyze-bulk?limit=N`, newest detailed un-analyzed, default 20, max 100)
    = triage model first, and a score below 5 ends the job as `skipped` with the
    reason. The triage score is cached on the job (`triage_score`) so a 429 retry
    doesn't re-pay for it. Errors are classified: `*llm.RetryError` (429/5xx)
    requeues with exponential backoff from 15s (never shorter than the server's
    `retryDelay` hint, capped at 15m, `maxAttempts` = 5 then `failed`); invalid
    model output is retried once *inside the same attempt* (`callValidated`)
    then fails; anything else (bad key, 400) fails immediately. Jobs stranded by
    a crash are requeued at startup (`ResetStaleJobs`).
  - **Structured output is prompt-described and Go-validated, not native
    `responseSchema`.** Google's docs conflict on `responseSchema` vs
    `responseJsonSchema`, so `llm.GenerateJSON` only sets
    `responseMimeType: application/json`; the schema lives in the system prompt
    and `parseDeep`/`parseTriage` are the zod equivalent. `deepOut` also asks
    for `vuln_class` (the spec's output schema lacked it, but `analyses.vuln_class`
    is NOT NULL and single mode has no triage to supply it). The API key goes in
    the `x-goog-api-key` header, not `?key=` (the docs show both): net/http errors
    embed the URL, so a header keeps the key out of error text; it is also
    scrubbed from messages. **Unverified live** — no real key was used; the 429
    `retryDelay` shape, header auth on this endpoint, and the prompts' quality
    (does `root_cause` really avoid just naming the vuln? does it invent?) need
    the 20-30 real reports the spec calls for. Model IDs are never hardcoded:
    Google's own page says `gemini-2.5-flash/pro` start auto-routing to other
    models on 2026-12-01, so users pick names in Settings.
  - **Untrusted input in, untrusted output out**: report text is third-party
    content fed to an LLM (prompts tell it to treat it as data, wrapped in
    `<rapor_metni>`), and the analysis fields are model output — the week-3 UI
    must render them with `textContent`, never `innerHTML`.
  - `writeups.Run` is started in `main.go` next to the scheduler: syncs at
    startup, then hourly checks `writeups_last_sync_at` and syncs if >24h old
    (a desktop app may not stay up 24h, so a plain 24h ticker would never fire).
    A mutex makes the ticker and the manual "Sync now" button mutually exclusive.
    Missing credentials is a silent no-op for the ticker and a 400 for the button.
  - The Learn view is a fourth entry in the dashboard/program/empty-state view
    toggle: `showLearn`, `showDashboard` and `selectProgram` all hide the others.

## When editing X, look at Y

- Changing the DB schema → update `schema.sql`, then `models.go`, then the
  affected methods in `programs.go`/`recon.go`, then any handler/JS that reads
  those fields.
- Adding an API endpoint → register it in `server.go`'s `routes()`, implement in
  `handlers_programs.go` or `handlers_recon.go`, then wire it up in `app.js`.
  Current endpoints include `GET /api/programs/{id}/scans` (scan history,
  `handleListScans` → `store.ListScans`), `POST /api/scans/{id}/stop`
  (`handleStopScan` → `Engine.Cancel`), and `GET /api/assets/{id}/screenshot`
  (`handleGetAssetScreenshot` → `store.GetScreenshot`).
- Changing recon behavior → `internal/recon/recon.go`'s `Engine.Run` is the only
  orchestration point; `subfinder.go`/`httpx.go` must keep satisfying the
  `Subfinder`/`HTTPProbe` interfaces exactly.
- Bounty tracking → `bounties` table, `internal/store/bounties.go`,
  `internal/server/handlers_bounties.go`, and the "Bounties" panel in
  `app.js`/`index.html` are all implemented; see `PRD.md` for remaining
  roadmap items (CSV export).
- Adding a new app-wide (not per-program) setting → follow the
  `app_settings`/`internal/store/settings.go`/`handlers_settings.go` pattern:
  one `CREATE TABLE IF NOT EXISTS ... CHECK (id = 1)` singleton row, not a
  new column on `programs`.
