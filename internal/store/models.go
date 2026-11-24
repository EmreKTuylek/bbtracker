package store

// Program is a bug bounty program the user tracks.
type Program struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	URL       string `json:"url"`
	Notes     string `json:"notes"`
	CreatedAt string `json:"created_at"`

	// Schedule* fields configure an optional recurring auto-scan for this
	// program, run by internal/scheduler while the app is open. See
	// Store.UpdateSchedule/DuePrograms/MarkScheduleRun.
	ScheduleEnabled            bool   `json:"schedule_enabled"`
	ScheduleIntervalDays       int    `json:"schedule_interval_days"`
	ScheduleTimeOfDay          string `json:"schedule_time_of_day"`
	ScheduleRunSubfinder       bool   `json:"schedule_run_subfinder"`
	ScheduleRunHTTPX           bool   `json:"schedule_run_httpx"`
	ScheduleScreenshot         bool   `json:"schedule_screenshot"`
	ScheduleRunNuclei          bool   `json:"schedule_run_nuclei"`
	ScheduleRunFuzz            bool   `json:"schedule_run_fuzz"`
	ScheduleFuzzWordlistPath   string `json:"schedule_fuzz_wordlist_path"`
	ScheduleRunWayback         bool   `json:"schedule_run_wayback"`
	ScheduleRunParams          bool   `json:"schedule_run_params"`
	ScheduleParamsWordlistPath string `json:"schedule_params_wordlist_path"`
	ScheduleRunJSAnalysis      bool   `json:"schedule_run_jsanalysis"`
	ScheduleRunCORS            bool   `json:"schedule_run_cors"`
	ScheduleCORSWordlistPath   string `json:"schedule_cors_wordlist_path"`
	ScheduleRunGithubDork      bool   `json:"schedule_run_github_dork"`
	ScheduleRunCloudEnum       bool   `json:"schedule_run_cloud_enum"`
	ScheduleRunTakeover        bool   `json:"schedule_run_takeover"`
	ScheduleRunTLS             bool   `json:"schedule_run_tls"`
	ScheduleRunDNS             bool   `json:"schedule_run_dns"`
	ScheduleRunUncover         bool   `json:"schedule_run_uncover"`
	ScheduleRunCrawl           bool   `json:"schedule_run_crawl"`
	ScheduleNextRunAt          string `json:"schedule_next_run_at"`
	ScheduleLastRunAt          string `json:"schedule_last_run_at"`
}

// Scope is an in/out-of-scope domain for a program.
type Scope struct {
	ID        int64  `json:"id"`
	ProgramID int64  `json:"program_id"`
	Domain    string `json:"domain"`
	Type      string `json:"type"` // "in" | "out"
	CreatedAt string `json:"created_at"`
}

// Scan is one recon run over a program's in-scope domains.
type Scan struct {
	ID                 int64  `json:"id"`
	ProgramID          int64  `json:"program_id"`
	Status             string `json:"status"` // running | done | error | cancelled
	StartedAt          string `json:"started_at"`
	FinishedAt         string `json:"finished_at"`
	NewAssetsCount     int    `json:"new_assets_count"`
	Error              string `json:"error"`
	RunSubfinder       bool   `json:"run_subfinder"`
	RunHTTPX           bool   `json:"run_httpx"`
	Screenshot         bool   `json:"screenshot"`
	RunNuclei          bool   `json:"run_nuclei"`
	RunFuzz            bool   `json:"run_fuzz"`
	FuzzWordlistPath   string `json:"fuzz_wordlist_path"`
	RunWayback         bool   `json:"run_wayback"`
	RunParams          bool   `json:"run_params"`
	ParamsWordlistPath string `json:"params_wordlist_path"`
	RunJSAnalysis      bool   `json:"run_jsanalysis"`
	RunCORS            bool   `json:"run_cors"`
	CORSWordlistPath   string `json:"cors_wordlist_path"`
	RunGithubDork      bool   `json:"run_github_dork"`
	RunCloudEnum       bool   `json:"run_cloud_enum"`
	RunTakeover        bool   `json:"run_takeover"`
	RunTLS             bool   `json:"run_tls"`
	RunDNS             bool   `json:"run_dns"`
	RunUncover         bool   `json:"run_uncover"`
	RunCrawl           bool   `json:"run_crawl"`
	AssetID            int64  `json:"asset_id"` // 0 = whole-program scan; see schema.sql's scans.asset_id
	TriggeredBy        string `json:"triggered_by"` // "manual" | "scheduled"
}

// ScanOptions selects which recon tools run for one scan.
type ScanOptions struct {
	RunSubfinder       bool
	RunHTTPX           bool
	Screenshot         bool
	RunNuclei          bool
	RunFuzz            bool
	FuzzWordlistPath   string // empty => use the embedded default wordlist
	RunWayback         bool
	RunParams          bool
	ParamsWordlistPath string // empty => use the embedded default wordlist
	RunJSAnalysis      bool
	RunCORS            bool
	CORSWordlistPath   string // empty => use the embedded default extra-paths wordlist
	RunGithubDork      bool
	RunCloudEnum       bool
	RunTakeover        bool
	RunTLS             bool
	RunDNS             bool
	RunUncover         bool
	RunCrawl           bool
	AssetID            int64 // 0 = whole-program scan; nonzero scopes the scan to a single asset (see Engine.Run)
}

// AnyToolEnabled reports whether at least one recon tool is selected. Used to
// reject an empty scan request; unlike the old subfinder/httpx-only check,
// this also accepts a scan that runs only domain-only tools (wayback, GitHub
// dorking, cloud enumeration) with no subfinder/httpx.
func (o ScanOptions) AnyToolEnabled() bool {
	return o.RunSubfinder || o.RunHTTPX || o.RunNuclei || o.RunFuzz ||
		o.RunWayback || o.RunParams || o.RunJSAnalysis || o.RunCORS ||
		o.RunGithubDork || o.RunCloudEnum || o.RunTakeover || o.RunTLS || o.RunDNS || o.RunUncover || o.RunCrawl
}

// Asset is a discovered subdomain for a program.
type Asset struct {
	ID        int64  `json:"id"`
	ProgramID int64  `json:"program_id"`
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
	Notes     string `json:"notes"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// Probe is the latest httpx result for an asset.
type Probe struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	Title         string `json:"title"`
	Tech          string `json:"tech"`
	ContentLength int    `json:"content_length"`
	Webserver     string `json:"webserver"`
	ScannedAt     string `json:"scanned_at"`
	IP            string `json:"ip"`
	Screenshot    []byte `json:"-"`              // write-side; never inline in JSON
	HasScreenshot bool   `json:"has_screenshot"` // read-side; computed by ListAssets
}

// AssetRow is an asset joined with its latest probe, for the UI table.
type AssetRow struct {
	Asset
	Probe *Probe `json:"probe"`
	IsNew bool   `json:"is_new"`
}

// Bounty is one submitted (or drafted) finding for a program, with its
// severity, status, and reward.
type Bounty struct {
	ID           int64   `json:"id"`
	ProgramID    int64   `json:"program_id"`
	Title        string  `json:"title"`
	Severity     string  `json:"severity"`
	Status       string  `json:"status"`
	RewardAmount float64 `json:"reward_amount"`
	Currency     string  `json:"currency"`
	SubmittedAt  string  `json:"submitted_at"`
	ResolvedAt   string  `json:"resolved_at"`
	Notes        string  `json:"notes"`
	CreatedAt    string  `json:"created_at"`
}

// BountyEarningsRow is one program's total resolved-bounty earnings in one currency.
type BountyEarningsRow struct {
	ProgramID   int64   `json:"program_id"`
	ProgramName string  `json:"program_name"`
	Currency    string  `json:"currency"`
	Total       float64 `json:"total"`
	Count       int     `json:"count"`
}

// CurrencyTotal is a grand total across all programs in one currency.
type CurrencyTotal struct {
	Currency string  `json:"currency"`
	Total    float64 `json:"total"`
}

// Settings is the single-row app-wide configuration (currently just Telegram
// notifications). See Store.GetSettings/UpdateSettings. TelegramEnabled is
// the master switch - when false, nothing is sent regardless of the three
// per-category flags below.
type Settings struct {
	TelegramBotToken              string `json:"telegram_bot_token"`
	TelegramChatID                string `json:"telegram_chat_id"`
	TelegramEnabled               bool   `json:"telegram_enabled"`
	TelegramNotifyNewAssets       bool   `json:"telegram_notify_new_assets"`
	TelegramNotifyChanges         bool   `json:"telegram_notify_changes"`
	TelegramNotifyVulnerabilities bool   `json:"telegram_notify_vulnerabilities"`
	GithubToken                   string `json:"github_token"`
	ScanRetentionCount            int    `json:"scan_retention_count"` // 0 = unlimited; see Store.PruneOldScans
	HackerOneUsername             string `json:"hackerone_username"`
	HackerOneAPIToken             string `json:"hackerone_api_token"`
	UncoverAPIKeys                string `json:"uncover_api_keys"` // one "agent:value" pair per line; see recon.parseUncoverKeys
	GeminiAPIKey                  string `json:"gemini_api_key"`
	GeminiTriageModel             string `json:"gemini_triage_model"`
	GeminiAnalysisModel           string `json:"gemini_analysis_model"`
	WriteupsLastSyncAt            string `json:"writeups_last_sync_at"`
}

// Writeup is one disclosed bug bounty report. RawText is analysis input only
// and is deliberately excluded from JSON so it can never reach the UI.
type Writeup struct {
	ID          int64   `json:"id"`
	Source      string  `json:"source"`
	ExternalID  string  `json:"external_id"`
	URL         string  `json:"url"`
	Title       string  `json:"title"`
	Program     string  `json:"program"`
	Weakness    string  `json:"weakness"`
	Severity    string  `json:"severity"`
	Bounty      float64 `json:"bounty"`
	DisclosedAt string  `json:"disclosed_at"`
	RawText     string  `json:"-"`
	ContentHash string  `json:"-"`
	QualityFlag string  `json:"quality_flag"`
	CreatedAt   string  `json:"created_at"`
}

// Vulnerability is one nuclei template match for an asset, kept as a single
// current row per (asset, template) - see schema.sql's vulnerabilities table.
type Vulnerability struct {
	ID         int64  `json:"id"`
	AssetID    int64  `json:"asset_id"`
	ScanID     int64  `json:"scan_id"`
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	MatchedAt  string `json:"matched_at"`
	FoundAt    string `json:"found_at"`
	Status       string `json:"status"`
	TriageNotes  string `json:"triage_notes"`
}

// VulnerabilityRow is a Vulnerability joined with its asset's subdomain, for
// the UI's Vulnerabilities table.
type VulnerabilityRow struct {
	Vulnerability
	Subdomain string `json:"subdomain"`
}

// ScanEvent is one notable thing a scan produced - a new asset, a changed
// asset (status_code/title), or a new vulnerability - see schema.sql's
// scan_events table.
type ScanEvent struct {
	ID        int64  `json:"id"`
	ScanID    int64  `json:"scan_id"`
	AssetID   int64  `json:"asset_id"`
	Kind      string `json:"kind"` // "new_asset" | "changed_asset" | "new_vuln"
	OldValue  string `json:"old_value"`
	NewValue  string `json:"new_value"`
	CreatedAt string `json:"created_at"`
}

// ScanEventRow is a ScanEvent joined with its asset's subdomain, for the
// UI's scan-diff view.
type ScanEventRow struct {
	ScanEvent
	Subdomain string `json:"subdomain"`
}

// FuzzHit is one non-404 response a directory/file fuzz scan found for an
// asset, kept as a single current row per (asset, path) - see schema.sql's
// fuzz_hits table.
type FuzzHit struct {
	ID            int64  `json:"id"`
	AssetID       int64  `json:"asset_id"`
	ScanID        int64  `json:"scan_id"`
	Path          string `json:"path"`
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	FoundAt       string `json:"found_at"`
	Status        string `json:"status"`
	TriageNotes   string `json:"triage_notes"`
}

// FuzzHitRow is a FuzzHit joined with its asset's subdomain, for the UI's
// Fuzzing table.
type FuzzHitRow struct {
	FuzzHit
	Subdomain string `json:"subdomain"`
}

// ArchivedURL is one URL the Wayback Machine's CDX API has archived for an
// in-scope domain - see schema.sql's archived_urls table.
type ArchivedURL struct {
	ID        int64  `json:"id"`
	ProgramID int64  `json:"program_id"`
	ScanID    int64  `json:"scan_id"`
	URL       string `json:"url"`
	Host      string `json:"host"`
	FirstSeen string `json:"first_seen"`
}

// CrawledURL is one URL katana discovered while crawling a probed asset -
// see schema.sql's crawled_urls table. Kept as a single current row per
// (asset_id, url), same upsert/never-deleted pattern as archived_urls.
type CrawledURL struct {
	ID      int64  `json:"id"`
	AssetID int64  `json:"asset_id"`
	ScanID  int64  `json:"scan_id"`
	URL     string `json:"url"`
	FoundAt string `json:"found_at"`
}

// CrawledURLRow is a CrawledURL joined with its asset's subdomain, for the
// UI's Crawled URLs table.
type CrawledURLRow struct {
	CrawledURL
	Subdomain string `json:"subdomain"`
}

// ParamHit is one candidate hidden query parameter a param-fuzz scan found
// for an asset's probed URL - see schema.sql's param_hits table.
type ParamHit struct {
	ID             int64  `json:"id"`
	AssetID        int64  `json:"asset_id"`
	ScanID         int64  `json:"scan_id"`
	URL            string `json:"url"`
	Param          string `json:"param"`
	BaselineStatus int    `json:"baseline_status"`
	BaselineLength int    `json:"baseline_length"`
	HitStatus      int    `json:"hit_status"`
	HitLength      int    `json:"hit_length"`
	FoundAt        string `json:"found_at"`
	Status         string `json:"status"`
	TriageNotes    string `json:"triage_notes"`
}

// ParamHitRow is a ParamHit joined with its asset's subdomain, for the UI's
// Hidden Params table.
type ParamHitRow struct {
	ParamHit
	Subdomain string `json:"subdomain"`
}

// JSFinding is one endpoint-like string or matched secret pattern a JS
// analysis scan found for an asset - see schema.sql's js_findings table.
type JSFinding struct {
	ID        int64  `json:"id"`
	AssetID   int64  `json:"asset_id"`
	ScanID    int64  `json:"scan_id"`
	Kind      string `json:"kind"` // "endpoint" | "secret"
	SourceURL string `json:"source_url"`
	Value     string `json:"value"`
	FoundAt   string `json:"found_at"`
	Status      string `json:"status"`
	TriageNotes string `json:"triage_notes"`
}

// JSFindingRow is a JSFinding joined with its asset's subdomain, for the
// UI's JS Findings table.
type JSFindingRow struct {
	JSFinding
	Subdomain string `json:"subdomain"`
}

// CORSFinding is one CORS misconfiguration a CORS scan found for an asset's
// probed URL - a fixed probe set (arbitrary-origin reflection, wildcard +
// credentials, null origin, subdomain bypass), not a wordlist - see
// schema.sql's cors_findings table.
type CORSFinding struct {
	ID          int64  `json:"id"`
	AssetID     int64  `json:"asset_id"`
	ScanID      int64  `json:"scan_id"`
	URL         string `json:"url"`
	Issue       string `json:"issue"` // reflects_arbitrary_origin | wildcard_with_credentials | null_origin_allowed | subdomain_bypass
	OriginSent  string `json:"origin_sent"`
	ACAOValue   string `json:"acao_value"`
	ACACAllowed bool   `json:"acac_allowed"`
	FoundAt     string `json:"found_at"`
	Status      string `json:"status"`
	TriageNotes string `json:"triage_notes"`
}

// CORSFindingRow is a CORSFinding joined with its asset's subdomain, for the
// UI's CORS Findings table.
type CORSFindingRow struct {
	CORSFinding
	Subdomain string `json:"subdomain"`
}

// GitHubFinding is one leaked-secret/sensitive-file hit a GitHub code-search
// dork found for a program's in-scope domains - see schema.sql's
// github_findings table. Unlike asset-scoped findings, this has no asset_id
// (a GitHub repo isn't a probed asset), so it's never eligible for
// scan_events.
type GitHubFinding struct {
	ID        int64  `json:"id"`
	ProgramID int64  `json:"program_id"`
	ScanID    int64  `json:"scan_id"`
	Repo      string `json:"repo"`
	Path      string `json:"path"`
	HTMLURL   string `json:"html_url"`
	Dork      string `json:"dork"`
	Kind      string `json:"kind"` // "secret" | "dork_match"
	Value     string `json:"value"`
	FoundAt   string `json:"found_at"`
	Status      string `json:"status"`
	TriageNotes string `json:"triage_notes"`
}

// CloudFinding is one cloud storage bucket/container enumeration hit for a
// program's in-scope domains - see schema.sql's cloud_findings table. Like
// GitHubFinding, it has no asset_id and is never eligible for scan_events.
type CloudFinding struct {
	ID        int64  `json:"id"`
	ProgramID int64  `json:"program_id"`
	ScanID    int64  `json:"scan_id"`
	Provider  string `json:"provider"` // "s3" | "gcs" | "azure"
	Bucket    string `json:"bucket"`
	URL       string `json:"url"`
	Kind      string `json:"kind"` // "open_listable" | "exists_private"
	FoundAt   string `json:"found_at"`
	Status      string `json:"status"`
	TriageNotes string `json:"triage_notes"`
}

// TakeoverFinding is one subdomain-takeover signal found for an asset - see
// schema.sql's takeover_findings table.
type TakeoverFinding struct {
	ID       int64  `json:"id"`
	AssetID  int64  `json:"asset_id"`
	ScanID   int64  `json:"scan_id"`
	Host     string `json:"host"`
	CNAME    string `json:"cname"`
	Service  string `json:"service"`
	Kind     string `json:"kind"` // "nxdomain" | "fingerprint_match" | "cname_match"
	Evidence string `json:"evidence"`
	FoundAt  string `json:"found_at"`
	Status      string `json:"status"`
	TriageNotes string `json:"triage_notes"`
}

// TakeoverFindingRow is a TakeoverFinding joined with its asset's subdomain,
// for the UI's Takeover Findings table.
type TakeoverFindingRow struct {
	TakeoverFinding
	Subdomain string `json:"subdomain"`
}

// TLSFinding is one certificate issue (or informational SAN entry) found for
// an asset - see schema.sql's tls_findings table.
type TLSFinding struct {
	ID      int64  `json:"id"`
	AssetID int64  `json:"asset_id"`
	ScanID  int64  `json:"scan_id"`
	Host    string `json:"host"`
	Issue   string `json:"issue"` // expired|expiring_soon|self_signed|hostname_mismatch|weak_protocol|new_san_subdomain
	Detail  string `json:"detail"`
	FoundAt string `json:"found_at"`
	Status      string `json:"status"`
	TriageNotes string `json:"triage_notes"`
}

// TLSFindingRow is a TLSFinding joined with its asset's subdomain, for the
// UI's TLS Findings table.
type TLSFindingRow struct {
	TLSFinding
	Subdomain string `json:"subdomain"`
}

// DNSFinding is one DNS/infrastructure signal found for an asset - a raw
// record, a zone-transfer disclosure, or WAF/CDN/cloud/ASN attribution - see
// schema.sql's dns_findings table.
type DNSFinding struct {
	ID      int64  `json:"id"`
	AssetID int64  `json:"asset_id"`
	ScanID  int64  `json:"scan_id"`
	Host    string `json:"host"`
	Kind    string `json:"kind"` // "record" | "zone_transfer" | "waf" | "cdn" | "cloud" | "asn"
	Detail  string `json:"detail"`
	Value   string `json:"value"`
	FoundAt string `json:"found_at"`
	Status      string `json:"status"`
	TriageNotes string `json:"triage_notes"`
}

// DNSFindingRow is a DNSFinding joined with its asset's subdomain, for the
// UI's DNS Findings table.
type DNSFindingRow struct {
	DNSFinding
	Subdomain string `json:"subdomain"`
}
