# bbtracker — Product Requirements

## Problem

Bug bounty hunters juggle multiple programs, each with its own scope, and need to
repeatedly re-run subdomain discovery + HTTP probing to find new attack surface as
programs evolve. Existing tooling is either CLI-only (no persistent view of "what's
new since last time") or a hosted SaaS. bbtracker is a small, local, single-binary
tool: no server to run, no accounts, your data stays in a SQLite file next to the
binary.

## Goals (v1)

- Track multiple bug bounty programs with metadata (platform, URL, notes).
- Track in-scope / out-of-scope domains per program.
- One-click recon: subdomain enumeration (subfinder) + HTTP probing (httpx) over
  in-scope domains, with results persisted and diffed against prior runs (new vs.
  already-known assets).
- Browse discovered assets (subdomain, resolved URL, status code, title, tech
  stack, webserver, first/last seen) in a simple web UI.
- Zero external runtime dependencies: recon tools are linked in as Go libraries,
  not shelled out to.
- Bounty/earnings tracking: per-program CRUD over findings (title, severity,
  status, reward amount/currency, submitted/resolved dates, notes), plus a
  resolved-bounties earnings summary grouped by currency, both per-program and
  overall (shown as a running total in the sidebar).
- Optional nuclei vulnerability scan over live probed URLs (opt-in per scan
  and per recurring schedule), with a conservative default template set
  (dos/intrusive tags excluded) since it can run unattended.
- Telegram notifications (app-wide, opt-in per category) for new assets,
  changed assets (status code/title), and new vulnerability findings.
- Optional directory/file discovery fuzzing over live probed URLs (opt-in
  per scan and per recurring schedule), using a small embedded default
  wordlist or a user-supplied wordlist file.
- Scan-diff view: every scan's new assets, changed assets, new
  vulnerabilities, new fuzz hits, new archived URLs, new hidden parameters,
  and new JS endpoints/secrets are persisted and browsable per scan, not
  just sent as a point-in-time Telegram notification.
- Optional archived-URL discovery (Wayback Machine CDX API), hidden-
  parameter discovery (baseline-diffing fuzz), and JS analysis
  (endpoint/secret extraction from page + linked .js bodies) — all opt-in
  per scan and per recurring schedule, same pattern as nuclei/fuzz.
- Optional CORS misconfiguration scanning (fixed Origin-header probe set
  against live probed URLs, plus a small curated wordlist of common
  account/API paths per host — CORS bugs are disproportionately found on
  endpoints like `/accountDetails` rather than the homepage — arbitrary-
  origin reflection, wildcard + credentials, null-origin allowance, naive
  subdomain-bypass matching), opt-in per scan and per recurring schedule.
  Doesn't crawl pages or authenticate, so a misconfiguration only reachable
  via a logged-in session stays out of reach — see CLAUDE.md.
- Optional GitHub source-code dorking (public repos only) for in-scope
  domains — leaked secrets and sensitive files (`.env`, `id_rsa`, etc.) via
  GitHub's Code Search API, opt-in per scan and per recurring schedule,
  requires a GitHub token (app-wide setting, no special scopes needed).
- Optional cloud storage enumeration (AWS S3, Google Cloud Storage, Azure
  Blob) for in-scope domains — read-only existence/public-listing checks
  against candidate bucket/container names, opt-in per scan and per
  recurring schedule. No write-permission testing (see Non-goals).
- CSV export of any program table (assets, bounties, and every findings type)
  for offline reporting.
- Fast scans: independent domain-only phases (wayback, GitHub dorking, cloud
  enum) run concurrently with the httpx-dependent asset chain; a scan may run
  domain-only tools standalone (no subfinder/httpx required).
- Unified findings overview: all findings across tools shown in one
  severity-sorted list on the dashboard, plus per-tool count cards; findings
  marked resolved (false positive / fixed) are hidden by default.
- Optional subdomain takeover detection (dangling-CNAME + hosting-provider
  fingerprint checks against known hosts), opt-in per scan and per recurring
  schedule, needs no HTTP probing of its own dependency.
- Optional TLS/certificate analysis (expiry, self-signed, hostname mismatch,
  weak protocol version, informational SAN entries) against known hosts,
  opt-in per scan and per recurring schedule.
- Findings triage: every findings type (vulnerabilities, fuzz hits, hidden
  params, JS findings, CORS/GitHub/cloud/takeover/TLS findings) can be marked
  open / accepted risk / false positive / fixed, with a free-text note.
- Scan history retention: an optional "keep last N scans per program" setting
  prunes old scan rows (and their diff-log entries) without ever deleting a
  finding that's still the latest known state of anything.
- Asset notes: a free-text field per asset for the user's own manual
  observations, separate from findings triage notes.
- Scope import: bulk-paste a domain list (works for any platform) or pull a
  program's structured scope directly from HackerOne's API (requires an
  API token in Settings), instead of adding scope entries one at a time.
- Cross-program dashboard: a default landing view aggregating every
  program's asset count/last-scan status and a merged, severity-sorted
  findings inbox across all programs, so nothing requires selecting a
  program first.
- Search/filter on every findings table (and the unified findings panels),
  matching the Assets tab's existing search box.
- Quick-Wins triage: a filter/badge highlighting findings that are typically
  submittable with little further manual work (confirmed subdomain
  takeovers, open cloud storage, leaked secrets, CORS misconfigs with
  credentials allowed) — narrower than "high severity," meant to answer
  "where do I start today."
- Report draft: a one-click, client-side-generated markdown report skeleton
  per finding (title, affected asset, per-type description, Steps to
  Reproduce/Impact placeholders), copy-pasteable into a platform's
  submission form.
- Optional DNS/infrastructure analysis (DNS record enumeration, an AXFR
  zone-transfer probe, and WAF/CDN/cloud-provider + ASN attribution derived
  from each host's resolved IP) against known hosts, opt-in per scan and per
  recurring schedule.
- Optional passive host discovery via internet-wide search engines (Shodan,
  Censys, FOFA, and others), finding assets subfinder's own passive-source
  enumeration misses entirely — opt-in per scan and per recurring schedule,
  requires at least one search-engine API key (app-wide setting); running
  with none configured is a normal, expected no-op, not an error.
- Optional web crawling (linked pages, forms, JS-referenced endpoints) over
  live probed URLs, widening the URL set that nuclei/CORS/hidden-parameter
  discovery scan over — opt-in per scan and per recurring schedule, requires
  the HTTP probe tool.
- Single-asset rescan: a "Rescan" action on any known asset re-runs the
  selected host-oriented tools (HTTP probe, nuclei, fuzz, CORS, hidden
  params, JS analysis, crawl, takeover, TLS, DNS/infra) against just that
  asset, without re-running domain-wide discovery.
- Screenshot gallery: a grid view of every asset with a captured screenshot,
  for quickly scanning a program's visual footprint.
- Print/PDF export: a print-optimized view of any findings table or the
  unified findings panel, for offline reporting via the browser's own
  print-to-PDF.

- Write-up library (Learn tab): disclosed HackerOne reports synced daily from
  the Hacktivity feed into a searchable list with a heuristic detail flag,
  linking to the original report. Metadata plus HackerOne's generated summary
  only (the API withholds other people's full report bodies). Optional LLM
  root-cause analysis with the user's own Gemini key (BYOK): a sequential job
  queue with rate-limit backoff, a cheap triage gate for bulk runs, and a
  validated Turkish purple-team analysis (root cause, attack flow, fix,
  detection, test checklist, and a separate "unknowns" list), browsable in the
  Learn tab with bug-class / technology / analyzed filters, per-report Analyze
  and a bulk "Analyze top 20". A showcase page and weekly pattern summary are
  planned, see `WRITEUP_MODULE.md`.

## Non-goals (v1)

- No multi-user/auth — this is a single-operator local tool.
- No cloud sync/backup.
- No currency conversion — earnings are summed per-currency, never combined.
- No port scanning.
- ~~No WAF fingerprinting~~ — reversed: DNS/infrastructure analysis now
  includes WAF attribution via `cdncheck`, which turned out to already be a
  zero-cost transitive dependency (see CLAUDE.md's DNS/infrastructure
  analysis section). The original deferral assumed a new dependency would be
  needed; it wasn't.
- No HTTP request smuggling detection (smuggler-equivalent) — explicitly
  deferred, too intrusive (requires deliberately malformed/ambiguous
  requests) for an opt-in recon tool that may run unattended; see CLAUDE.md.
- No cloud storage write-permission testing — enumeration is read-only
  (existence/public-listing checks only); actually uploading a test object
  to a third party's bucket was explicitly declined as too intrusive for
  an opt-in recon tool; see CLAUDE.md.

## Data model (see `internal/store/schema.sql`)

- `programs` — id, name, platform, url, notes, created_at.
- `scopes` — program_id, domain, type (`in`/`out`).
- `scans` — program_id, status (`running`/`done`/`error`), timestamps,
  new_assets_count, error, asset_id (0 = whole-program scan; nonzero scopes
  the scan to a single asset, see "Single-asset rescan").
- `assets` — program_id, subdomain (unique per program), source, notes,
  first/last seen.
- `probes` — one-per-asset latest httpx result (url, status_code, title, tech,
  content_length, webserver, scanned_at).
- `bounties` — program_id, title, severity (`info`/`low`/`medium`/`high`/`critical`),
  status (`draft`/`submitted`/`triaged`/`resolved`/`duplicate`/`na`),
  reward_amount, currency, submitted_at, resolved_at, notes, created_at.
- `vulnerabilities` — asset_id, scan_id, template_id, name, severity, matched_at,
  found_at; one current row per (asset_id, template_id).
- `scan_events` — scan_id, asset_id, kind (`new_asset`/`changed_asset`/`new_vuln`/
  `new_fuzz_hit`), old_value, new_value; append-only log of what each scan found
  (the scan-diff view).
- `fuzz_hits` — asset_id, scan_id, path, url, status_code, content_length, found_at;
  one current row per (asset_id, path).
- `archived_urls` — program_id, scan_id, url, host, first_seen; one row per
  (program_id, url) ever seen in the Wayback Machine's CDX API.
- `param_hits` — asset_id, scan_id, url, param, baseline_status, baseline_length,
  hit_status, hit_length, found_at; one current row per (asset_id, param).
- `js_findings` — asset_id, scan_id, kind (`endpoint`/`secret`), source_url, value,
  found_at; one current row per (asset_id, kind, value).
- `cors_findings` — asset_id, scan_id, url, issue (`reflects_arbitrary_origin`/
  `wildcard_with_credentials`/`null_origin_allowed`/`subdomain_bypass`),
  origin_sent, acao_value, acac_allowed, found_at; one current row per
  (asset_id, issue).
- `github_findings` — program_id, scan_id, repo, path, html_url, dork, kind
  (`secret`/`dork_match`), value, found_at; one current row per (program_id,
  repo, path, kind, value). No asset_id — not tied to a probed asset.
- `cloud_findings` — program_id, scan_id, provider (`s3`/`gcs`/`azure`),
  bucket, url, kind (`open_listable`/`exists_private`), found_at; one
  current row per (program_id, provider, bucket, kind). No asset_id.
- `takeover_findings` — asset_id, scan_id, host, cname, service, kind
  (`nxdomain`/`fingerprint_match`/`cname_match`), evidence, found_at; one
  current row per (asset_id, service).
- `tls_findings` — asset_id, scan_id, host, issue (`expired`/`expiring_soon`/
  `self_signed`/`hostname_mismatch`/`weak_protocol`/`new_san_subdomain`),
  detail, found_at; one current row per (asset_id, issue, detail).
- `dns_findings` — asset_id, scan_id, host, kind (`record`/`zone_transfer`/
  `waf`/`cdn`/`cloud`/`asn`), detail, value, found_at; one current row per
  (asset_id, kind, detail, value).
- `crawled_urls` — asset_id, scan_id, url, found_at; one row per (asset_id,
  url) katana has ever discovered while crawling that asset. No status/
  triage_notes (same as `archived_urls`) — a wider URL surface for other
  tools, not a finding of its own.
- Every findings table above (except `archived_urls`/`crawled_urls`) also
  has `status` (`open`/`accepted_risk`/`false_positive`/`fixed`, default
  `open`) and `triage_notes`, settable via one generic endpoint (see API
  surface).
- `app_settings` — single row: Telegram bot token/chat id/enabled + per-category
  notify flags (new assets, changed assets, vulnerabilities), GitHub token,
  scan retention count (0 = unlimited), HackerOne username/API token (scope
  import), Uncover API keys (one `agent:value` pair per line, for the
  passive-discovery search engines).

## API surface

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/dashboard` | Cross-program overview: per-program summaries + every finding across every program |
| GET | `/api/programs` | List programs |
| POST | `/api/programs` | Create program |
| GET | `/api/programs/{id}` | Get program |
| PUT | `/api/programs/{id}` | Update program |
| DELETE | `/api/programs/{id}` | Delete program (cascades) |
| GET | `/api/programs/{id}/scopes` | List scopes |
| POST | `/api/programs/{id}/scopes` | Add scope entry |
| DELETE | `/api/scopes/{id}` | Remove scope entry |
| POST | `/api/programs/{id}/scopes/import` | Bulk-import scope entries from pasted text (one domain per line) |
| POST | `/api/programs/{id}/scopes/import-hackerone` | Import a HackerOne program's structured scope (requires a saved API token) |
| GET | `/api/programs/{id}/assets` | List assets + latest probe |
| GET | `/api/assets/{id}/screenshot` | Get an asset's latest probe screenshot (PNG) |
| PATCH | `/api/assets/{id}/notes` | Set an asset's free-text notes |
| POST | `/api/programs/{id}/scans` | Start a scan (409 if one is already running) |
| POST | `/api/assets/{id}/scan` | Start a scan scoped to a single known asset (same 409 semantics) |
| GET | `/api/programs/{id}/scans` | List past scans for a program |
| GET | `/api/scans/{id}` | Poll scan status |
| POST | `/api/scans/{id}/stop` | Stop a running scan |
| GET | `/api/programs/{id}/bounties` | List bounties for a program |
| POST | `/api/programs/{id}/bounties` | Create a bounty |
| PUT | `/api/bounties/{id}` | Update a bounty |
| DELETE | `/api/bounties/{id}` | Delete a bounty |
| GET | `/api/earnings` | Resolved-bounty earnings, per-program and overall, by currency |
| GET | `/api/programs/{id}/vulnerabilities` | List nuclei findings for a program |
| GET | `/api/scans/{id}/events` | List what a scan found (new/changed assets, new vulns, new fuzz hits) — the scan-diff view |
| GET | `/api/programs/{id}/fuzz-hits` | List directory/file fuzz hits for a program |
| GET | `/api/programs/{id}/archived-urls` | List Wayback-discovered URLs for a program |
| GET | `/api/programs/{id}/param-hits` | List candidate hidden parameters for a program |
| GET | `/api/programs/{id}/js-findings` | List JS-analysis endpoints/secrets for a program |
| GET | `/api/programs/{id}/cors-findings` | List CORS misconfiguration findings for a program |
| GET | `/api/programs/{id}/github-findings` | List GitHub dorking findings for a program |
| GET | `/api/programs/{id}/cloud-findings` | List cloud storage enumeration findings for a program |
| GET | `/api/programs/{id}/takeover-findings` | List subdomain-takeover findings for a program |
| GET | `/api/programs/{id}/tls-findings` | List TLS certificate findings for a program |
| GET | `/api/programs/{id}/dns-findings` | List DNS/infrastructure findings for a program |
| GET | `/api/programs/{id}/crawled-urls` | List katana-crawled URLs for a program |
| GET | `/api/writeups` | List synced disclosed reports (`?quality=ok\|low\|all`; never includes the report text) |
| POST | `/api/writeups/sync` | Sync disclosed reports from HackerOne Hacktivity now |
| POST | `/api/writeups/{id}/analyze` | Queue one deep Gemini analysis (needs key + model names in Settings) |
| POST | `/api/writeups/analyze-bulk?limit=N` | Queue triage-gated analysis of the newest N detailed, un-analyzed reports |
| GET | `/api/writeups/{id}/analysis` | The analysis (if any) plus the latest job state |
| PATCH | `/api/findings/{kind}/{id}` | Set a finding's triage status/notes (kind: vulnerabilities, cors, fuzz, github, cloud, js, params, takeover, tls, dns) |
| GET | `/api/programs/{id}/export?type=<t>` | Download a program's table as CSV (assets, bounties, or any findings type) |
| GET | `/api/settings` | Get Telegram notification settings, GitHub token, scan retention count, HackerOne credentials, Uncover API keys |
| PUT | `/api/settings` | Update Telegram notification settings, GitHub token, scan retention count, HackerOne credentials, Uncover API keys |
| POST | `/api/settings/test` | Send a one-off Telegram test message |

Frontend polls `GET /api/scans/{id}` every 2s while `status == "running"`, then
refreshes the asset table and shows `new_assets_count`.

## v1.1+ roadmap

- ~~Fuzzing auto-calibration / wildcard-response suppression~~ — done: exact
  status+length match against a per-host random-path baseline (see
  `fetchBaselines` in `internal/recon/fuzz.go`); still not a size-delta
  threshold, so a soft-404 page with byte-varying content can still evade it.
- ~~Scope import from platform APIs~~ — done for HackerOne (`internal/hackerone`,
  **unverified against a live account**, see CLAUDE.md); Bugcrowd has no
  stable public scope API for third-party tools, covered instead by the
  platform-agnostic bulk-paste importer.
