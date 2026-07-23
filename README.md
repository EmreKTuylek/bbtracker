# bbtracker

A local, single-binary bug bounty recon & tracking tool with a small web UI:
manage programs and scope, run subdomain discovery + HTTP probing, and browse
results — all backed by a local SQLite file.

## Prerequisites

- Go 1.26+ (developed against 1.26.2).
- No external binaries required: subfinder and httpx are linked in as Go
  libraries (`projectdiscovery/subfinder/v2`, `projectdiscovery/httpx`), so
  there's nothing else to install or put on `PATH`.

## Quick start

```
go run ./cmd/bbtracker
```

This opens `http://127.0.0.1:8787/` in your default browser and creates
`bbtracker.db` in the current directory.

To build a standalone binary:

```
go build -o bbtracker.exe ./cmd/bbtracker
./bbtracker.exe
```

Flags: `-addr host:port` (default `127.0.0.1:8787`), `-db path` (default
`bbtracker.db`), `-no-browser` (skip auto-opening a browser tab).

## Usage

1. Add a program (name, platform, URL, notes) in the left sidebar.
2. Select it, add its in-scope (and optionally out-of-scope) domains.
3. Click **Scan** to run subdomain enumeration + HTTP probing over the
   in-scope domains. The page polls scan status and refreshes the asset table
   when it finishes, showing how many new assets were found.
4. Browse discovered subdomains with their resolved URL, status code, title,
   detected tech, webserver, and first-seen date.

## Screenshots

_(placeholder — add screenshots of the program list and asset table here)_

## Roadmap

Bounty/earnings tracking (severity, reward, status per finding) is planned as
a near-term follow-up — the database schema for it (`bounties` table) already
exists; see `PRD.md` for details.
