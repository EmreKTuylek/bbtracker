package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	miekgdns "github.com/miekg/dns"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// dnsWorkers caps concurrent DNS/infra checks across the whole phase - same
// modest pool size as takeoverWorkers/tlsWorkers.
const dnsWorkers = 10

// dnsQueryTimeout bounds each individual DNS round trip (dnsx.Options.Timeout),
// separate from the phase-level deadline dnsWithDeadline races against.
const dnsQueryTimeout = 3 * time.Second

// dnsQuestionTypes is the fixed record-type set queried per host: the
// standard "what does this host's DNS look like" inventory, not user
// configurable (same "small fixed probe set" pattern as cors.go's Origin
// headers or takeover.go's fingerprint list).
var dnsQuestionTypes = []uint16{
	miekgdns.TypeA, miekgdns.TypeAAAA, miekgdns.TypeCNAME,
	miekgdns.TypeMX, miekgdns.TypeTXT, miekgdns.TypeNS,
}

// SimpleDNSInfraScanner implements DNSScanner using three already-vendored
// ProjectDiscovery libraries that needed zero new go.mod entries (see
// CLAUDE.md's go-github precedent) - dnsx for record enumeration and AXFR
// zone-transfer probing, cdncheck for WAF/CDN/cloud-provider attribution, and
// asnmap for ASN/org attribution - all derived from one DNS lookup per host
// plus one IP-based lookup, the same "small hand-rolled implementation over
// a library" shape as every other recon.go tool.
type SimpleDNSInfraScanner struct{}

// NewSimpleDNSInfraScanner returns a SimpleDNSInfraScanner.
func NewSimpleDNSInfraScanner() *SimpleDNSInfraScanner {
	return &SimpleDNSInfraScanner{}
}

func (d *SimpleDNSInfraScanner) Scan(ctx context.Context, hosts []string) ([]DNSFinding, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	resolver, err := dnsx.New(dnsx.Options{
		BaseResolvers: dnsx.DefaultResolvers,
		MaxRetries:    2,
		QuestionTypes: dnsQuestionTypes,
		Timeout:       dnsQueryTimeout,
	})
	if err != nil {
		return nil, err
	}
	cdn := cdncheck.New()

	jobs := make(chan string)
	resultsCh := make(chan DNSFinding)

	var wg sync.WaitGroup
	for i := 0; i < dnsWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				for _, f := range inspectDNS(resolver, cdn, h) {
					select {
					case resultsCh <- f:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, h := range hosts {
			select {
			case jobs <- h:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var out []DNSFinding
	for f := range resultsCh {
		out = append(out, f)
	}
	return out, nil
}

// inspectDNS queries host's DNS records, attempts a zone transfer, and - if
// the host has a resolved A record - checks that IP against cdncheck's
// WAF/CDN/cloud denylists and asnmap's ASN database.
//
// ponytail: none of dnsx/cdncheck/asnmap's calls here take a context, so a
// single slow/hanging resolver can't be interrupted mid-call - only bounded
// by dnsQueryTimeout per DNS round trip and the phase-level dnsWithDeadline
// racing the whole per-host call. Same limitation the other host-only
// scanners' library calls have (see takeover.go/tlsinfo.go); upgrade path is
// a context-aware DNS client if this proves too slow in practice.
func inspectDNS(resolver *dnsx.DNSX, cdn *cdncheck.Client, host string) []DNSFinding {
	var findings []DNSFinding

	data, err := resolver.QueryMultiple(host)
	if err == nil && data != nil {
		addRecords := func(kind string, values []string) {
			for _, v := range values {
				v = strings.TrimSuffix(strings.TrimSpace(v), ".")
				if v == "" {
					continue
				}
				findings = append(findings, DNSFinding{Host: host, Kind: "record", Detail: kind, Value: v})
			}
		}
		addRecords("A", data.A)
		addRecords("AAAA", data.AAAA)
		addRecords("CNAME", data.CNAME)
		addRecords("MX", data.MX)
		addRecords("TXT", data.TXT)
		addRecords("NS", data.NS)

		if len(data.A) > 0 {
			if ip := net.ParseIP(data.A[0]); ip != nil {
				if matched, value, err := cdn.CheckWAF(ip); err == nil && matched {
					findings = append(findings, DNSFinding{Host: host, Kind: "waf", Value: value})
				}
				if matched, value, err := cdn.CheckCDN(ip); err == nil && matched {
					findings = append(findings, DNSFinding{Host: host, Kind: "cdn", Value: value})
				}
				if matched, value, err := cdn.CheckCloud(ip); err == nil && matched {
					findings = append(findings, DNSFinding{Host: host, Kind: "cloud", Value: value})
				}
			}
			if resp, err := asnmap.GetData(data.A[0]); err == nil && len(resp) > 0 {
				r := resp[0]
				if r.ASN != 0 {
					findings = append(findings, DNSFinding{Host: host, Kind: "asn",
						Value: fmt.Sprintf("AS%d · %s · %s-%s", r.ASN, r.Org, r.FirstIp, r.LastIp)})
				}
			}
		}
	}

	// A successful zone transfer (any records returned) is a critical,
	// independently reportable finding on its own: the authoritative DNS
	// server discloses its entire zone to anyone who asks.
	if axfr, err := resolver.AXFR(host); err == nil && axfr != nil && len(axfr.DNSData) > 0 {
		findings = append(findings, DNSFinding{Host: host, Kind: "zone_transfer",
			Value: fmt.Sprintf("%d records disclosed via AXFR", len(axfr.DNSData))})
	}

	return findings
}
