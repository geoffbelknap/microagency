// Package safedial provides an HTTP client whose dialer refuses to connect to
// internal/metadata addresses — the SSRF defense for microagency's own outbound
// calls to UNTRUSTED targets (a user-supplied upstream MCP URL). It is
// deliberately NOT used for the sandbox's egress (allowlisted separately) or for
// trusted operator-configured infra (Nango / Vault / the OIDC issuer), which may
// legitimately live on a private network.
package safedial

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// isInternal reports whether ip is in a range an untrusted outbound request must
// never reach: loopback, link-local (incl. the 169.254.169.254 cloud-metadata
// address), RFC1918 / ULA private, CGNAT, unspecified, and multicast. A nil
// (unparseable) IP is treated as internal — fail closed.
func isInternal(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// CGNAT 100.64.0.0/10 (not covered by IsPrivate).
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true
	}
	return false
}

// guardControl is a net.Dialer Control hook. It runs after DNS resolution, on the
// concrete IP about to be dialed, so it also defeats DNS-rebinding: a hostname
// can resolve to a public IP when the URL is validated and to an internal one at
// connect time — this checks connect time.
func guardControl(_ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("safedial: bad address %q: %w", address, err)
	}
	if isInternal(net.ParseIP(host)) {
		return fmt.Errorf("safedial: refusing connection to internal address %s (SSRF guard)", host)
	}
	return nil
}

// GuardedClient returns an *http.Client whose dialer refuses internal/metadata
// addresses (SSRF guard). The two timeouts are deliberately separate:
//
//   - dialTimeout bounds connection setup (dial + TLS handshake). Keep it short —
//     that's SSRF/connect hygiene, not a limit on how long real work may take.
//   - requestTimeout bounds the whole request, including a server that is slow to
//     send the first response byte (e.g. a security query that computes before
//     responding). Set it generously.
//
// Conflating the two — reusing a short dial timeout as the response-header/overall
// bound — kills legitimate slow upstream calls (an upstream tool that takes >10s
// to first byte trips ResponseHeaderTimeout). Non-positive values fall back to
// sensible defaults: dial 10s, request 5m.
func GuardedClient(dialTimeout, requestTimeout time.Duration) *http.Client {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	if requestTimeout <= 0 {
		requestTimeout = 5 * time.Minute
	}
	dialer := &net.Dialer{Timeout: dialTimeout, Control: guardControl}
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   dialTimeout,
			ResponseHeaderTimeout: requestTimeout,
			ForceAttemptHTTP2:     true,
		},
	}
}
