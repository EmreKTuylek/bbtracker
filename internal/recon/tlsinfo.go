package recon

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// tlsWorkers caps concurrent TLS handshakes across the whole phase - one dial
// per host, so a modest pool is plenty (same shape as corsWorkers/takeoverWorkers).
const tlsWorkers = 10

// tlsExpiringSoonWindow flags a certificate as "expiring_soon" (distinct from
// already "expired") inside this window.
const tlsExpiringSoonWindow = 30 * 24 * time.Hour

// SimpleTLSScanner implements TLSScanner: for each host it dials port 443
// with certificate verification deliberately disabled (InsecureSkipVerify) so
// an invalid certificate doesn't just fail the handshake outright - the point
// is to inspect *why* it's invalid (expired, self-signed, hostname mismatch)
// rather than only detect that it is. Read-only, one connection per host.
type SimpleTLSScanner struct{}

// NewSimpleTLSScanner returns a SimpleTLSScanner.
func NewSimpleTLSScanner() *SimpleTLSScanner {
	return &SimpleTLSScanner{}
}

func (t *SimpleTLSScanner) Scan(ctx context.Context, hosts []string) ([]TLSFinding, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	jobs := make(chan string)
	resultsCh := make(chan TLSFinding)

	var wg sync.WaitGroup
	for i := 0; i < tlsWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				for _, f := range inspectTLS(ctx, h) {
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

	var out []TLSFinding
	for f := range resultsCh {
		out = append(out, f)
	}
	return out, nil
}

// inspectTLS dials host:443 and reports certificate issues. Hosts with no TLS
// listener on 443 are silently skipped (not every asset serves HTTPS).
func inspectTLS(ctx context.Context, host string) []TLSFinding {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: host}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	cert := state.PeerCertificates[0]

	var findings []TLSFinding
	now := time.Now()
	switch {
	case now.After(cert.NotAfter):
		findings = append(findings, TLSFinding{Host: host, Issue: "expired",
			Detail: fmt.Sprintf("expired %s", cert.NotAfter.Format("2006-01-02"))})
	case cert.NotAfter.Sub(now) < tlsExpiringSoonWindow:
		findings = append(findings, TLSFinding{Host: host, Issue: "expiring_soon",
			Detail: fmt.Sprintf("expires %s", cert.NotAfter.Format("2006-01-02"))})
	}

	if cert.Issuer.String() == cert.Subject.String() {
		findings = append(findings, TLSFinding{Host: host, Issue: "self_signed", Detail: cert.Subject.String()})
	}

	if err := cert.VerifyHostname(host); err != nil {
		findings = append(findings, TLSFinding{Host: host, Issue: "hostname_mismatch", Detail: err.Error()})
	}

	if state.Version < tls.VersionTLS12 {
		findings = append(findings, TLSFinding{Host: host, Issue: "weak_protocol", Detail: tlsVersionName(state.Version)})
	}

	// SAN entries other than the probed host itself are surfaced for manual
	// review as candidate additional subdomains - not automatically cross-
	// checked against known assets/scope, since Scan only takes a host list
	// (keeping the TLSScanner interface minimal); the finding is informational.
	for _, san := range cert.DNSNames {
		if san == "" || strings.Contains(san, "*") || strings.EqualFold(san, host) {
			continue
		}
		findings = append(findings, TLSFinding{Host: host, Issue: "new_san_subdomain", Detail: san})
	}

	return findings
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
