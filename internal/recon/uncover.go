package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
)

// uncoverResultLimit caps how many results uncover returns per domain query -
// this is a discovery source, not expected to return thousands of hits per
// domain the way a dedicated Shodan/Censys hunt might.
const uncoverResultLimit = 200

// uncoverRequestTimeout/uncoverMaxRetry bound each individual HTTP request
// uncover's agents make - without an explicit timeout, Options.Timeout
// defaults to 0, which sources.NewSession turns into an *unbounded*
// http.Client.Timeout (a hung upstream API would block forever).
const (
	uncoverRequestTimeout = 15 // seconds - sources.NewSession takes an int
	uncoverMaxRetry       = 2
)

// LibUncover implements PassiveDiscoverer using ProjectDiscovery's uncover
// library (github.com/projectdiscovery/uncover, already vendored transitively
// via other recon tools' dependency graphs - zero new go.mod entries, same
// precedent as go-github; see CLAUDE.md) to search Shodan/Censys/FOFA/... for
// hosts associated with in-scope domains - finding assets subfinder's passive
// source enumeration misses entirely.
type LibUncover struct{}

// NewLibUncover returns a LibUncover.
func NewLibUncover() *LibUncover {
	return &LibUncover{}
}

// parseUncoverKeys reads apiKeys (one "agent:value" pair per line, blank
// lines and "#" comments skipped) into a sources.Provider plus the list of
// agent names that ended up with a key configured. Multi-part credentials
// (censys "id:secret", fofa "email:key", google "key:cx") are passed through
// as a single colon-joined value - sources.Provider.GetKeys() does that
// splitting itself (see vendor/github.com/projectdiscovery/uncover/sources/provider.go).
func parseUncoverKeys(apiKeys string) (*sources.Provider, []string) {
	provider := &sources.Provider{}
	var agents []string
	seen := map[string]bool{}

	for _, line := range strings.Split(apiKeys, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		agent := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		switch agent {
		case "shodan":
			provider.Shodan = append(provider.Shodan, value)
		case "censys":
			provider.Censys = append(provider.Censys, value)
		case "fofa":
			provider.Fofa = append(provider.Fofa, value)
		case "quake":
			provider.Quake = append(provider.Quake, value)
		case "hunter":
			provider.Hunter = append(provider.Hunter, value)
		case "zoomeye":
			provider.ZoomEye = append(provider.ZoomEye, value)
		case "netlas":
			provider.Netlas = append(provider.Netlas, value)
		case "criminalip":
			provider.CriminalIP = append(provider.CriminalIP, value)
		case "publicwww":
			provider.Publicwww = append(provider.Publicwww, value)
		case "hunterhow":
			provider.HunterHow = append(provider.HunterHow, value)
		case "google":
			provider.Google = append(provider.Google, value)
		case "odin":
			provider.Odin = append(provider.Odin, value)
		case "binaryedge":
			provider.BinaryEdge = append(provider.BinaryEdge, value)
		case "onyphe":
			provider.Onyphe = append(provider.Onyphe, value)
		case "driftnet":
			provider.Driftnet = append(provider.Driftnet, value)
		case "greynoise":
			provider.GreyNoise = append(provider.GreyNoise, value)
		case "daydaymap":
			provider.Daydaymap = append(provider.Daydaymap, value)
		case "nerdydata":
			provider.NerdyData = append(provider.NerdyData, value)
		default:
			continue // unknown provider name - skip rather than error, forgiving of typos
		}
		if !seen[agent] {
			seen[agent] = true
			agents = append(agents, agent)
		}
	}
	return provider, agents
}

// Discover implements PassiveDiscoverer. Returns (nil, nil) - a silent no-op,
// not an error - when apiKeys has no valid "agent:value" lines, since running
// with zero configured search engines is a normal, expected state (unlike
// GitHub dorking, which hard-requires its one token).
func (u *LibUncover) Discover(ctx context.Context, apiKeys string, domains []string) ([]SubResult, error) {
	provider, agents := parseUncoverKeys(apiKeys)
	if len(agents) == 0 {
		return nil, nil
	}

	queries := make([]string, 0, len(domains))
	for _, d := range domains {
		// ponytail: one generic "hostname:" query per domain, not tuned per
		// provider's own query dialect (FOFA/Censys/etc. each have distinct
		// syntax) - Shodan supports this directly, and it's a reasonable
		// baseline for the others too. Upgrade path: per-agent query
		// templates if result relevance across non-Shodan engines proves poor.
		queries = append(queries, fmt.Sprintf("hostname:%s", d))
	}

	svc, err := uncover.New(&uncover.Options{
		Agents:   agents,
		Queries:  queries,
		Limit:    uncoverResultLimit,
		MaxRetry: uncoverMaxRetry,
		Timeout:  uncoverRequestTimeout,
	})
	if err != nil {
		return nil, err
	}
	// New() already populated svc.Provider/svc.Keys from the default
	// config-file/env-var location (sources.NewProvider) - override with the
	// keys the user actually saved in bbtracker's own Settings. svc.Keys is
	// reassigned (not just svc.Provider) because the uncover.Service.Session
	// was already built against &svc.Keys's address; reassigning that same
	// struct field is what makes the already-constructed Session observe the
	// new values (see uncover.go's New()/ExecuteWithCallback in the vendored
	// library).
	svc.Provider = provider
	svc.Keys = svc.Provider.GetKeys()

	var out []SubResult
	err = svc.ExecuteWithCallback(ctx, func(r sources.Result) {
		host := strings.ToLower(strings.TrimSpace(r.Host))
		if host == "" {
			return
		}
		out = append(out, SubResult{Host: host, Source: r.Source})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
