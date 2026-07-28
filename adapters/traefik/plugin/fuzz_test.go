// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	jitcore "github.com/Slopapalooza/jit-network-access/adapters/traefik/plugin/internal/jitcore"
)

// Mirror of the Caddy fuzzer: same trust boundary, separate implementation.
//
// The client IP is the grant key, so whoever controls it controls who a grant
// belongs to. A client can put anything it likes in X-Forwarded-For, but our own
// proxies APPEND the peer they actually saw — so everything the client wrote sits
// to the LEFT of the truth, and the answer must depend only on the right-hand
// part our infrastructure added.
func FuzzClientIPIgnoresPrependedXFF(f *testing.F) {
	for _, s := range []string{
		"", "203.0.113.9", "198.51.100.7, 203.0.113.200",
		"10.0.0.1, 10.0.0.2", "::1", "[::1]:80", ",,,", "   ",
		"not-an-ip", "999.999.999.999", "fe80::1%eth0",
		"1.2.3.4, 10.0.0.1, 1.2.3.4", "\t10.0.0.1\n",
	} {
		f.Add(s, byte(198), byte(51), byte(100), byte(7))
	}

	j := newFuzzPlugin(f, func(c *Config) {
		c.TrustForwarded = true
		c.TrustedProxies = []string{"10.0.0.0/8"}
	})

	f.Fuzz(func(t *testing.T, prepended string, a, b, c, d byte) {
		// 10/8 is our own proxy range: an address in it is a hop, not a client.
		if a == 10 {
			return
		}
		client := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
		want, err := jitcore.CanonIP(client, j.cfg.IPv6Prefix, 32)
		if err != nil {
			return
		}

		r := mkreq(http.MethodGet, "/", "10.0.0.1:5000", nil)
		// What the client sent, then the address our edge proxy appended for it.
		r.Header.Set("X-Forwarded-For", prepended+", "+client)
		// An inner hop then appended the edge. Separate header line on purpose:
		// the walk has to flatten repeated lines to find the true right-most entry.
		r.Header.Add("X-Forwarded-For", "10.0.0.1")

		got, err := j.clientIP(r)
		if err != nil {
			t.Fatalf("clientIP failed on chain %q: %v", r.Header.Values("X-Forwarded-For"), err)
		}
		if got != want {
			t.Fatalf("prepended %q changed the grant key: got %q want %q", prepended, got, want)
		}
	})
}

// Without trustForwarded the peer is the only input, and NOTHING in a header may
// move it. This is the configuration every deployment starts in.
func FuzzClientIPUntrustedIgnoresHeadersEntirely(f *testing.F) {
	for _, s := range []string{
		"", "203.0.113.9", "10.0.0.1", "1.2.3.4, 5.6.7.8", "::1", "junk",
	} {
		f.Add(s, s)
	}

	j := newFuzzPlugin(f, nil)

	f.Fuzz(func(t *testing.T, xff, realIP string) {
		want, err := jitcore.CanonIP("203.0.113.9", j.cfg.IPv6Prefix, 32)
		if err != nil {
			t.Fatal(err)
		}
		r := mkreq(http.MethodGet, "/", peer, nil)
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Real-IP", realIP)
		r.Header.Set("X-Forwarded-Host", xff)

		got, err := j.clientIP(r)
		if err != nil {
			t.Fatalf("clientIP failed: %v", err)
		}
		if got != want {
			t.Fatalf("headers moved the grant key without trustForwarded: "+
				"xff=%q real-ip=%q -> %q want %q", xff, realIP, got, want)
		}
	})
}

// build() takes a *testing.T, which a fuzz seed phase does not have.
func newFuzzPlugin(f *testing.F, mutate func(*Config)) *JITAccess {
	f.Helper()
	if err := shared(); err != nil {
		f.Fatalf("shared: %v", err)
	}
	cfg := CreateConfig()
	cfg.Tokens = []Token{{Kid: testKid, Secret: testSecret, Label: "test"}}
	cfg.Allow = []string{testKid}
	if mutate != nil {
		mutate(cfg)
	}
	h, err := New(context.Background(), upstream(), cfg, "jit")
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	j, ok := h.(*JITAccess)
	if !ok {
		f.Fatalf("New returned %T, not *JITAccess", h)
	}
	return j
}
