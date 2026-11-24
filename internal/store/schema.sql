-- bbtracker schema. Applied idempotently on startup.

CREATE TABLE IF NOT EXISTS programs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    platform   TEXT NOT NULL DEFAULT '',   -- hackerone | bugcrowd | intigriti | private | ...
    url        TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),

    schedule_enabled        INTEGER NOT NULL DEFAULT 0,
    schedule_interval_days  INTEGER NOT NULL DEFAULT 7,
    schedule_time_of_day    TEXT NOT NULL DEFAULT '03:00',
    schedule_run_subfinder  INTEGER NOT NULL DEFAULT 1,
    schedule_run_httpx      INTEGER NOT NULL DEFAULT 1,
    schedule_screenshot     INTEGER NOT NULL DEFAULT 0,
    schedule_run_nuclei     INTEGER NOT NULL DEFAULT 0,
    schedule_run_fuzz          INTEGER NOT NULL DEFAULT 0,
    schedule_fuzz_wordlist_path TEXT NOT NULL DEFAULT '',
    schedule_run_wayback         INTEGER NOT NULL DEFAULT 0,
    schedule_run_params          INTEGER NOT NULL DEFAULT 0,
    schedule_params_wordlist_path TEXT NOT NULL DEFAULT '',
    schedule_run_jsanalysis      INTEGER NOT NULL DEFAULT 0,
    schedule_run_cors           INTEGER NOT NULL DEFAULT 0,
    schedule_cors_wordlist_path TEXT NOT NULL DEFAULT '',
    schedule_run_github_dork    INTEGER NOT NULL DEFAULT 0,
    schedule_run_cloud_enum     INTEGER NOT NULL DEFAULT 0,
    schedule_run_takeover       INTEGER NOT NULL DEFAULT 0,
    schedule_run_tls            INTEGER NOT NULL DEFAULT 0,
    schedule_run_dns            INTEGER NOT NULL DEFAULT 0,
    schedule_run_uncover        INTEGER NOT NULL DEFAULT 0,
    schedule_run_crawl          INTEGER NOT NULL DEFAULT 0,
    schedule_next_run_at    TEXT,
    schedule_last_run_at    TEXT
);

CREATE TABLE IF NOT EXISTS scopes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    type       TEXT NOT NULL DEFAULT 'in', -- 'in' | 'out'
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(program_id);

CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id       INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    status           TEXT NOT NULL DEFAULT 'running', -- running | done | error
    started_at       TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at      TEXT,
    new_assets_count INTEGER NOT NULL DEFAULT 0,
    error            TEXT NOT NULL DEFAULT '',
    run_subfinder    INTEGER NOT NULL DEFAULT 1,
    run_httpx        INTEGER NOT NULL DEFAULT 1,
    screenshot       INTEGER NOT NULL DEFAULT 0,
    run_nuclei       INTEGER NOT NULL DEFAULT 0,
    run_fuzz            INTEGER NOT NULL DEFAULT 0,
    fuzz_wordlist_path  TEXT NOT NULL DEFAULT '',
    run_wayback         INTEGER NOT NULL DEFAULT 0,
    run_params          INTEGER NOT NULL DEFAULT 0,
    params_wordlist_path TEXT NOT NULL DEFAULT '',
    run_jsanalysis      INTEGER NOT NULL DEFAULT 0,
    run_cors            INTEGER NOT NULL DEFAULT 0,
    cors_wordlist_path  TEXT NOT NULL DEFAULT '',
    run_github_dork     INTEGER NOT NULL DEFAULT 0,
    run_cloud_enum      INTEGER NOT NULL DEFAULT 0,
    run_takeover        INTEGER NOT NULL DEFAULT 0,
    run_tls             INTEGER NOT NULL DEFAULT 0,
    run_dns             INTEGER NOT NULL DEFAULT 0,
    run_uncover         INTEGER NOT NULL DEFAULT 0,
    run_crawl           INTEGER NOT NULL DEFAULT 0,
    -- 0 = whole-program scan (the default); a nonzero value scopes the scan
    -- to a single asset (see the "Rescan" button on the Assets tab). Deliberately
    -- NOT a REFERENCES assets(id) foreign key: with foreign_keys=ON, 0 would
    -- violate that constraint since no asset has id 0 (AUTOINCREMENT starts at 1) -
    -- this is a sentinel value, not a real reference, so it stays a plain INTEGER.
    asset_id            INTEGER NOT NULL DEFAULT 0,
    triggered_by     TEXT NOT NULL DEFAULT 'manual' -- 'manual' | 'scheduled'
);
CREATE INDEX IF NOT EXISTS idx_scans_program ON scans(program_id);

CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    subdomain  TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(program_id, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program_id);

CREATE TABLE IF NOT EXISTS probes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id       INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    url            TEXT NOT NULL DEFAULT '',
    status_code    INTEGER NOT NULL DEFAULT 0,
    title          TEXT NOT NULL DEFAULT '',
    tech           TEXT NOT NULL DEFAULT '',
    content_length INTEGER NOT NULL DEFAULT 0,
    webserver      TEXT NOT NULL DEFAULT '',
    scanned_at     TEXT NOT NULL DEFAULT (datetime('now')),
    screenshot     BLOB,
    ip             TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id)
);

CREATE TABLE IF NOT EXISTS bounties (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id    INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT '',   -- info|low|medium|high|critical
    status        TEXT NOT NULL DEFAULT 'draft', -- draft|submitted|triaged|resolved|duplicate|na
    reward_amount REAL NOT NULL DEFAULT 0,
    currency      TEXT NOT NULL DEFAULT 'USD',
    submitted_at  TEXT,
    resolved_at   TEXT,
    notes         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_bounties_program ON bounties(program_id);

-- One row per (asset, template) that has ever matched - mirrors probes'
-- "single current row per asset" pattern but keyed by asset+template so an
-- asset can have several distinct findings. A finding that matches again in
-- a later scan updates found_at/matched_at/severity in place rather than
-- inserting a duplicate; a finding that stops matching is NOT deleted (same
-- "never disappears on its own" philosophy as assets).
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    template_id TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '', -- info|low|medium|high|critical
    matched_at  TEXT NOT NULL DEFAULT '', -- the exact URL nuclei matched against
    found_at    TEXT NOT NULL DEFAULT (datetime('now')),
    status        TEXT NOT NULL DEFAULT 'open', -- open|accepted_risk|false_positive|fixed
    triage_notes  TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, template_id)
);
CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vulnerabilities(asset_id);

-- One row per (asset, path) that a fuzz scan found (any non-404 response) -
-- same "single current row per key, upsert refreshes it, never deleted"
-- pattern as vulnerabilities.
CREATE TABLE IF NOT EXISTS fuzz_hits (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id       INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path           TEXT NOT NULL,
    url            TEXT NOT NULL DEFAULT '',
    status_code    INTEGER NOT NULL DEFAULT 0,
    content_length INTEGER NOT NULL DEFAULT 0,
    found_at       TEXT NOT NULL DEFAULT (datetime('now')),
    status         TEXT NOT NULL DEFAULT 'open',
    triage_notes   TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, path)
);
CREATE INDEX IF NOT EXISTS idx_fuzz_hits_asset ON fuzz_hits(asset_id);

-- One row per notable event a scan produced (new asset / changed asset /
-- new vulnerability) - the same three categories Engine.Run already computes
-- for Telegram notifications (internal/telegram), now also persisted so the
-- UI can show "what changed" for any past scan. Deliberately an append-only
-- event log rather than point-in-time snapshots of assets/probes/
-- vulnerabilities, which would require a much larger schema change - this
-- captures exactly the diff Engine.Run already derives at scan time, no more.
CREATE TABLE IF NOT EXISTS scan_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL, -- 'new_asset' | 'changed_asset' | 'new_vuln'
    old_value  TEXT NOT NULL DEFAULT '',
    new_value  TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id);

-- One row per URL the Wayback Machine's CDX API has ever archived for an
-- in-scope domain. Keyed by (program_id, url) rather than asset_id, since
-- an archived URL's host may not (yet) be a known asset - "never disappears
-- on its own" philosophy, same as assets/vulnerabilities.
CREATE TABLE IF NOT EXISTS archived_urls (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    host       TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(program_id, url)
);
CREATE INDEX IF NOT EXISTS idx_archived_urls_program ON archived_urls(program_id);

-- One row per (asset, param) candidate hidden parameter a param-fuzz scan
-- found, by comparing a baseline (no extra param) request against one with
-- a wordlist entry appended as a query param. Same upsert/never-deleted
-- pattern as fuzz_hits.
CREATE TABLE IF NOT EXISTS param_hits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url             TEXT NOT NULL DEFAULT '',
    param           TEXT NOT NULL,
    baseline_status INTEGER NOT NULL DEFAULT 0,
    baseline_length INTEGER NOT NULL DEFAULT 0,
    hit_status      INTEGER NOT NULL DEFAULT 0,
    hit_length      INTEGER NOT NULL DEFAULT 0,
    found_at        TEXT NOT NULL DEFAULT (datetime('now')),
    status          TEXT NOT NULL DEFAULT 'open',
    triage_notes    TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, param)
);
CREATE INDEX IF NOT EXISTS idx_param_hits_asset ON param_hits(asset_id);

-- One row per (asset, kind, value) JS-analysis finding - an extracted
-- endpoint-like string or a matched secret pattern, found either in a
-- probed page's own body or a linked .js file. Same upsert/never-deleted
-- pattern as vulnerabilities/fuzz_hits.
CREATE TABLE IF NOT EXISTS js_findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL, -- 'endpoint' | 'secret'
    source_url TEXT NOT NULL DEFAULT '', -- the page or .js file the match came from
    value      TEXT NOT NULL,
    found_at   TEXT NOT NULL DEFAULT (datetime('now')),
    status         TEXT NOT NULL DEFAULT 'open',
    triage_notes   TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_js_findings_asset ON js_findings(asset_id);

-- One row per (asset, issue) CORS misconfiguration a CORS scan found - a fixed
-- probe set (arbitrary-origin reflection, wildcard+credentials, null origin,
-- subdomain-bypass) run per live probed URL, not a wordlist. Same
-- upsert/never-deleted pattern as vulnerabilities/fuzz_hits.
CREATE TABLE IF NOT EXISTS cors_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url          TEXT NOT NULL DEFAULT '',
    issue        TEXT NOT NULL, -- reflects_arbitrary_origin | wildcard_with_credentials | null_origin_allowed | subdomain_bypass
    origin_sent  TEXT NOT NULL DEFAULT '',
    acao_value   TEXT NOT NULL DEFAULT '',
    acac_allowed INTEGER NOT NULL DEFAULT 0,
    found_at     TEXT NOT NULL DEFAULT (datetime('now')),
    status         TEXT NOT NULL DEFAULT 'open',
    triage_notes   TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, issue)
);
CREATE INDEX IF NOT EXISTS idx_cors_findings_asset ON cors_findings(asset_id);

-- One row per (repo, path, kind, value) leaked-secret/sensitive-file hit a
-- GitHub code-search dork found. Keyed by program_id (not asset_id) since a
-- GitHub finding has no natural asset relationship - never eligible for
-- scan_events (asset_id there is NOT NULL). Same upsert/never-deleted
-- pattern as vulnerabilities/fuzz_hits.
CREATE TABLE IF NOT EXISTS github_findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repo       TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL DEFAULT '',
    html_url   TEXT NOT NULL DEFAULT '',
    dork       TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '', -- 'secret' | 'dork_match'
    value      TEXT NOT NULL,
    found_at   TEXT NOT NULL DEFAULT (datetime('now')),
    status         TEXT NOT NULL DEFAULT 'open',
    triage_notes   TEXT NOT NULL DEFAULT '',
    UNIQUE(program_id, repo, path, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_github_findings_program ON github_findings(program_id);

-- One row per (provider, bucket, kind) cloud storage enumeration hit -
-- candidate bucket/container names (derived from in-scope domains, combined
-- with a small curated suffix/prefix list) checked read-only against AWS
-- S3, Google Cloud Storage, and Azure Blob's public HTTP endpoints. Keyed by
-- program_id (not asset_id) - a cloud bucket has no asset relationship,
-- never eligible for scan_events (asset_id there is NOT NULL). Same
-- upsert/never-deleted pattern as vulnerabilities/fuzz_hits.
CREATE TABLE IF NOT EXISTS cloud_findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL DEFAULT '', -- 's3' | 'gcs' | 'azure'
    bucket     TEXT NOT NULL DEFAULT '',
    url        TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '', -- 'open_listable' | 'exists_private'
    found_at   TEXT NOT NULL DEFAULT (datetime('now')),
    status         TEXT NOT NULL DEFAULT 'open',
    triage_notes   TEXT NOT NULL DEFAULT '',
    UNIQUE(program_id, provider, bucket, kind)
);
CREATE INDEX IF NOT EXISTS idx_cloud_findings_program ON cloud_findings(program_id);

-- One row per (asset, service) subdomain-takeover signal - a dangling CNAME
-- that either doesn't resolve at all ('nxdomain'), matches a known hosting
-- provider confirmed by that provider's own "unclaimed" page body
-- ('fingerprint_match'), or matches without body confirmation
-- ('cname_match'). Same upsert/never-deleted pattern as vulnerabilities.
CREATE TABLE IF NOT EXISTS takeover_findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host       TEXT NOT NULL DEFAULT '',
    cname      TEXT NOT NULL DEFAULT '',
    service    TEXT NOT NULL DEFAULT '', -- empty for 'nxdomain'
    kind       TEXT NOT NULL DEFAULT '', -- 'nxdomain' | 'fingerprint_match' | 'cname_match'
    evidence   TEXT NOT NULL DEFAULT '',
    found_at   TEXT NOT NULL DEFAULT (datetime('now')),
    status         TEXT NOT NULL DEFAULT 'open',
    triage_notes   TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, service)
);
CREATE INDEX IF NOT EXISTS idx_takeover_findings_asset ON takeover_findings(asset_id);

-- One row per (asset, issue, detail) TLS certificate finding - expiry,
-- self-signed, hostname mismatch, weak protocol version, or an informational
-- SAN entry ('new_san_subdomain', which can legitimately repeat per host with
-- a different detail, hence detail being part of the key unlike other
-- findings tables). Same upsert/never-deleted pattern as vulnerabilities.
CREATE TABLE IF NOT EXISTS tls_findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host       TEXT NOT NULL DEFAULT '',
    issue      TEXT NOT NULL DEFAULT '', -- expired|expiring_soon|self_signed|hostname_mismatch|weak_protocol|new_san_subdomain
    detail     TEXT NOT NULL DEFAULT '',
    found_at   TEXT NOT NULL DEFAULT (datetime('now')),
    status         TEXT NOT NULL DEFAULT 'open',
    triage_notes   TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, issue, detail)
);
CREATE INDEX IF NOT EXISTS idx_tls_findings_asset ON tls_findings(asset_id);

-- One row per (asset, kind, detail, value) DNS/infrastructure signal - a raw
-- record (kind='record', detail is the record type: A|AAAA|CNAME|MX|TXT|NS),
-- a successful zone transfer (kind='zone_transfer', a critical finding on its
-- own), or WAF/CDN/cloud-provider/ASN attribution derived from the host's
-- resolved IP (kind='waf'|'cdn'|'cloud'|'asn'). detail is part of the
-- uniqueness key (like tls_findings) since a host can legitimately have
-- several distinct record values of the same kind (e.g. multiple NS/TXT
-- entries). Same upsert/never-deleted pattern as vulnerabilities.
CREATE TABLE IF NOT EXISTS dns_findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host       TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '', -- 'record' | 'zone_transfer' | 'waf' | 'cdn' | 'cloud' | 'asn'
    detail     TEXT NOT NULL DEFAULT '', -- record type, for kind='record' only
    value      TEXT NOT NULL DEFAULT '',
    found_at   TEXT NOT NULL DEFAULT (datetime('now')),
    status         TEXT NOT NULL DEFAULT 'open',
    triage_notes   TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, kind, detail, value)
);
CREATE INDEX IF NOT EXISTS idx_dns_findings_asset ON dns_findings(asset_id);

-- One row per (asset, url) katana discovered while crawling a probed asset's
-- root URL - linked pages, forms, JS-referenced endpoints. Unlike
-- archived_urls (keyed by program_id, no asset relationship guaranteed),
-- every crawled URL originates from a specific known asset, so this is
-- keyed by asset_id. Same upsert/never-deleted pattern as archived_urls; no
-- status/triage_notes - a crawled URL is a wider recon surface for other
-- tools to consume, not a finding of its own.
CREATE TABLE IF NOT EXISTS crawled_urls (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    found_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_id, url)
);
CREATE INDEX IF NOT EXISTS idx_crawled_urls_asset ON crawled_urls(asset_id);

-- Single-row app-wide configuration (id is always 1). Currently just the
-- Telegram notification settings; see internal/telegram.
CREATE TABLE IF NOT EXISTS app_settings (
    id                               INTEGER PRIMARY KEY CHECK (id = 1),
    telegram_bot_token               TEXT NOT NULL DEFAULT '',
    telegram_chat_id                 TEXT NOT NULL DEFAULT '',
    telegram_enabled                 INTEGER NOT NULL DEFAULT 0,
    telegram_notify_new_assets       INTEGER NOT NULL DEFAULT 1,
    telegram_notify_changes          INTEGER NOT NULL DEFAULT 0,
    telegram_notify_vulnerabilities  INTEGER NOT NULL DEFAULT 1,
    github_token                     TEXT NOT NULL DEFAULT '',
    scan_retention_count             INTEGER NOT NULL DEFAULT 0, -- 0 = unlimited; see Store.PruneOldScans
    hackerone_username               TEXT NOT NULL DEFAULT '',
    hackerone_api_token              TEXT NOT NULL DEFAULT '',
    uncover_api_keys                 TEXT NOT NULL DEFAULT '', -- one "agent:value" pair per line; see recon.parseUncoverKeys
    gemini_api_key                   TEXT NOT NULL DEFAULT '', -- write-up analysis (BYOK); never returned by the API
    gemini_triage_model              TEXT NOT NULL DEFAULT '',
    gemini_analysis_model            TEXT NOT NULL DEFAULT '',
    writeups_last_sync_at            TEXT NOT NULL DEFAULT '' -- UTC, set by Store.MarkWriteupsSynced
);

-- Disclosed bug bounty reports pulled from HackerOne Hacktivity (see
-- internal/writeups). raw_text is analysis input only: never served by the
-- API/UI (Writeup.RawText is json:"-").
CREATE TABLE IF NOT EXISTS writeups (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT NOT NULL,
    external_id  TEXT NOT NULL,
    url          TEXT NOT NULL,
    title        TEXT NOT NULL,
    program      TEXT NOT NULL DEFAULT '',
    weakness     TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT '',
    bounty       REAL NOT NULL DEFAULT 0,
    disclosed_at TEXT NOT NULL DEFAULT '',
    raw_text     TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL,
    quality_flag TEXT NOT NULL DEFAULT 'ok' CHECK (quality_flag IN ('ok', 'low')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(source, external_id)
);
CREATE INDEX IF NOT EXISTS idx_writeups_disclosed ON writeups(disclosed_at DESC);
