package jitcore

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Canonicalization (PROTOCOL §4). These two functions decide what a MAC is
// computed over and what a grant is keyed by, so they MUST produce output
// identical to the Python and Lua references — a one-byte divergence between
// engines silently breaks cross-engine portability (SECURITY-REVIEW H1/C10).

// CanonServerName lowercases the host and strips a trailing dot, an optional
// :port, and IPv6 brackets. Mirrors canon_server_name in core/py/jitcrypto.py.
func CanonServerName(host string) string {
	h := strings.TrimSpace(host)
	// bracketed IPv6 literal [::1]:443 (defensive; server_name is normally a name)
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end != -1 {
			return strings.ToLower(strings.TrimSpace(h[1:end]))
		}
	}
	// strip a trailing :port — only when what follows the last colon is all digits
	if i := strings.LastIndex(h, ":"); i != -1 && isASCIIDigits(h[i+1:]) {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".") // a single trailing dot (root label)
	return strings.ToLower(h)
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// CanonIP parses and normalizes a client address, masking it to the configured
// prefix. IPv4-mapped IPv6 (::ffff:1.2.3.4) collapses to plain IPv4 first, so a
// dual-stack listener cannot produce two different grant keys for one client.
//
// Rejects (rather than silently accepting) anything ambiguous: leading zeros in
// an octet — which some resolvers read as octal — and zoned addresses. Callers
// treat an error as deny; an IP we cannot canonicalize must never key a grant.
func CanonIP(addr string, v6Prefix, v4Prefix int) (string, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return "", fmt.Errorf("canon_ip %q: %w", addr, err)
	}
	if a.Zone() != "" {
		return "", fmt.Errorf("canon_ip %q: zoned address", addr)
	}
	a = a.Unmap()

	prefix := v6Prefix
	full := 128
	if a.Is4() {
		prefix, full = v4Prefix, 32
	}
	if prefix >= full {
		return a.String(), nil
	}
	if prefix < 0 {
		return "", errors.New("canon_ip: negative prefix")
	}
	p, err := a.Prefix(prefix)
	if err != nil {
		return "", fmt.Errorf("canon_ip %q/%d: %w", addr, prefix, err)
	}
	return p.Addr().String(), nil
}
