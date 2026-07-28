// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

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

// asciiSpace is Lua's "%s" character class. Go's strings.TrimSpace and
// strings.ToLower are Unicode-aware and Lua's are not, so a Host carrying U+00A0
// or a non-ASCII letter canonicalized one way on the Go engines and another on
// the Lua ones — different MAC input and different grant key for one client.
// Hostnames are ASCII by IDNA (non-ASCII travels as punycode), so restricting
// both operations to ASCII costs nothing real and makes all four references
// byte-identical.
const asciiSpace = " \t\n\v\f\r"

// asciiLower is byte-wise by design: an ASCII byte never appears inside a
// multi-byte UTF-8 sequence, so this cannot corrupt non-ASCII input — it
// leaves it alone, which is the point.
func asciiLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// Trim whitespace and trailing dots to a fixpoint BEFORE the port strip as
// well as after. Doing it only after meant removing a trailing dot could
// expose a port that then survived to the next pass: "[:0." became "[:0"
// became "[", and "example.com:443." became "example.com:443" became
// "example.com". Two layers canonicalizing the same Host a different number
// of times would hold two different names for one service.
func trimDotsAndSpace(s string) string {
	for {
		t := strings.TrimSuffix(strings.Trim(s, asciiSpace), ".")
		if t == s {
			return s
		}
		s = t
	}
}

// CanonServerName lowercases the host and strips a trailing dot, an optional
// :port, and IPv6 brackets. Mirrors canon_server_name in core/py/jitcrypto.py.
func CanonServerName(host string) string {
	h := trimDotsAndSpace(host)

	// A bracketed literal delimits its own host. The port strip below is guarded
	// by colon count alone rather than by "was it bracketed": no valid IPv6
	// address has exactly one colon, so the guard only ever protected malformed
	// input like "[a:80]" - which then canonicalized to "a:80" and, on a second
	// pass, to "a".
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end != -1 {
			h = trimDotsAndSpace(h[1:end])
		}
	}

	// Strip a trailing :port - but ONLY when the host has exactly one colon.
	//
	// An unbracketed host with several colons is an IPv6 literal: RFC 3986
	// requires brackets to carry a port, so there is no port to strip. Stripping
	// anyway truncated "2001:db8::1" to "2001:db8:" - and "2001:db8::2" to the
	// SAME value, which is a cross-service collision in both the grant key and
	// the MAC input, the exact class PAE framing exists to prevent. It also made
	// the bracketed and unbracketed spellings of one host canonicalize
	// differently, so a grant made via one would not match a request via the
	// other.
	if strings.Count(h, ":") == 1 {
		if i := strings.LastIndex(h, ":"); i != -1 && isASCIIDigits(h[i+1:]) {
			h = h[:i]
		}
	}
	return asciiLower(trimDotsAndSpace(h))
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

	// Bounds are checked BEFORE the >= full shortcut. With the check after it, a
	// config typo of 1280 silently behaved as /128 here while the Lua core
	// rejected it outright — the same registry admitting a client on one engine
	// and denying it on another. Fail closed on nonsense config.
	if v6Prefix < 0 || v6Prefix > 128 || v4Prefix < 0 || v4Prefix > 32 {
		return "", errors.New("canon_ip: prefix out of range")
	}
	prefix := v6Prefix
	full := 128
	if a.Is4() {
		prefix, full = v4Prefix, 32
	}
	if prefix >= full {
		return a.String(), nil
	}
	p, err := a.Prefix(prefix)
	if err != nil {
		return "", fmt.Errorf("canon_ip %q/%d: %w", addr, prefix, err)
	}
	return p.Addr().String(), nil
}
