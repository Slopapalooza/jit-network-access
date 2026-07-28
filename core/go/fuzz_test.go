// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitcore

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// Fuzzing the pure functions that decide MAC inputs and grant keys.
//
// vectors.json pins agreed answers for inputs somebody thought of. These assert
// the PROPERTIES instead, on inputs nobody thought of — which is where the
// cross-engine divergences kept coming from.

// PAE exists to make the field list injective: distinct field lists must never
// serialize alike, or a proof minted for one (service, kid, nonce) could be
// reinterpreted as another (SECURITY-REVIEW H1). This is the single most
// load-bearing property in the protocol.
func FuzzPAEInjective(f *testing.F) {
	f.Add([]byte("aa"), []byte("bb"))
	f.Add([]byte("aab"), []byte("b"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("grafana.example.com"), []byte("kid_x"))

	f.Fuzz(func(t *testing.T, a, b []byte) {
		// The classic collision: naive concatenation makes ("aa","bb") and
		// ("aab","b") identical. PAE must keep them apart.
		if bytes.Equal(PAE(a, b), PAE(append(append([]byte{}, a...), b...))) {
			t.Fatalf("COLLISION: PAE(%q,%q) == PAE(%q)", a, b, append(append([]byte{}, a...), b...))
		}
		// Order matters.
		if !bytes.Equal(a, b) && bytes.Equal(PAE(a, b), PAE(b, a)) {
			t.Fatalf("COLLISION: PAE(%q,%q) == PAE(%q,%q)", a, b, b, a)
		}
		// Arity matters: one field is never two.
		if bytes.Equal(PAE(a), PAE(a, b)) {
			t.Fatalf("COLLISION: PAE(%q) == PAE(%q,%q)", a, a, b)
		}
		// Splitting a field differently is a different list.
		for i := 0; i <= len(a); i++ {
			if bytes.Equal(PAE(a), PAE(a[:i], a[i:])) {
				t.Fatalf("COLLISION: PAE(%q) == PAE(%q,%q)", a, a[:i], a[i:])
			}
		}
	})
}

// A proof is bound to (service, kid, nonce). Changing any of them must change
// the tag — that binding is what stops a proof for one service opening another.
func FuzzProofBinding(f *testing.F) {
	f.Add("grafana.example.com", "kid_a", "wiki.internal", "kid_b")
	f.Add("a", "b", "b", "a")
	secret := bytes.Repeat([]byte{7}, 32)
	nonce := bytes.Repeat([]byte{9}, NonceLen)

	f.Fuzz(func(t *testing.T, s1, k1, s2, k2 string) {
		p1 := BuildProof(secret, s1, k1, nonce)
		p2 := BuildProof(secret, s2, k2, nonce)
		sameInput := CanonServerName(s1) == CanonServerName(s2) && k1 == k2
		if bytes.Equal(p1, p2) != sameInput {
			t.Fatalf("proof binding broken: (%q,%q) vs (%q,%q) — canon %q/%q, equal=%v",
				s1, k1, s2, k2, CanonServerName(s1), CanonServerName(s2), bytes.Equal(p1, p2))
		}
		// A proof must verify only against its own inputs.
		if !VerifyProof(secret, s1, k1, nonce, p1) {
			t.Fatalf("proof did not verify against its own inputs: %q %q", s1, k1)
		}
	})
}

func FuzzCanonServerName(f *testing.F) {
	for _, s := range []string{
		"grafana.example.com", "GRAFANA.example.com.:443", "[2001:db8::1]:8443",
		"[ ::1 ]", "  spaced.example.com  ", "xn--caf-dma.example.com",
		"host:notaport", "host:", ":443", "..", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got := CanonServerName(in)

		// Idempotent: a canonical form must already be canonical. Anything else
		// means two components that normalize a different number of times
		// disagree about the grant key. This caught three separate bugs — an
		// unbracketed IPv6 losing its last group to the :port strip, ".."
		// collapsing one dot per pass, and a trailing dot whose removal exposed
		// a port that the next pass then ate.
		if again := CanonServerName(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, got, again)
		}
		// Case-folded and untrimmed input never survives. ASCII-only on purpose:
		// Lua's :lower() and %s are ASCII, so matching Go's Unicode-aware
		// versions here would assert a property the Lua engines do not hold.
		if got != asciiLower(got) {
			t.Fatalf("not lowercased: %q -> %q", in, got)
		}
		if got != strings.Trim(got, asciiSpace) {
			t.Fatalf("whitespace survived: %q -> %q", in, got)
		}
		if strings.HasSuffix(got, ".") {
			t.Fatalf("trailing dot survived: %q -> %q", in, got)
		}
		// A valid IPv6 literal must come out as the same address. The :port strip
		// used to eat the last group, so "2001:db8::1" and "2001:db8::2" both
		// became "2001:db8:" — one grant key and one MAC input for two different
		// services. Zoned addresses are exempt: a zone is not part of the host.
		if addr, err := netip.ParseAddr(in); err == nil && addr.Is6() && addr.Zone() == "" {
			back, err := netip.ParseAddr(got)
			if err != nil || back != addr {
				t.Fatalf("IPv6 literal mangled: %q -> %q", in, got)
			}
		}
	})
}

func FuzzCanonIP(f *testing.F) {
	for _, s := range []string{
		"1.2.3.4", "192.168.001.005", "2001:db8::1", "::ffff:1.2.3.4",
		"fe80::1%eth0", "1::2::3", ":::", "2001:db8::1:", "", "1.2.3.256",
	} {
		f.Add(s, 128, 32)
	}
	f.Fuzz(func(t *testing.T, in string, p6, p4 int) {
		got, err := CanonIP(in, p6, p4)
		if err != nil {
			if got != "" {
				t.Fatalf("error path returned a value: %q -> %q", in, got)
			}
			return
		}
		// Out-of-range prefixes must never reach a successful result: that was a
		// cross-engine split (Go said /128, Lua rejected).
		if p6 < 0 || p6 > 128 || p4 < 0 || p4 > 32 {
			t.Fatalf("accepted out-of-range prefix: %q v6=%d v4=%d -> %q", in, p6, p4, got)
		}
		// Idempotent at the same prefix — the output IS an address, and
		// re-canonicalizing it must not move it, or a stored grant key would stop
		// matching the request that created it.
		again, err2 := CanonIP(got, p6, p4)
		if err2 != nil || again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q (err %v)", in, got, again, err2)
		}
		// A canonical address never carries a zone or brackets.
		if strings.ContainsAny(got, "%[]") {
			t.Fatalf("uncanonical output: %q -> %q", in, got)
		}
	})
}

// The nonce is what binds a challenge to one service and one client. A nonce
// must never verify for a different (service, ip) pair.
func FuzzNonceBinding(f *testing.F) {
	f.Add("app.example.com", "1.2.3.4", "other.example.com", "5.6.7.8")
	f.Add("a", "1.2.3.4", "a", "1.2.3.5")
	key := bytes.Repeat([]byte{3}, 32)
	rnd := bytes.Repeat([]byte{4}, 16)

	f.Fuzz(func(t *testing.T, s1, i1, s2, i2 string) {
		n, err := IssueNonce(key, 1000, rnd, s1, i1, 128)
		if err != nil {
			return // unusable ip; nothing was minted
		}
		ok, _ := VerifyNonce(key, n, s2, i2, 1000, 60, 128)
		if !ok {
			return
		}
		// It verified — so the canonical targets MUST be the same pair.
		c1, e1 := CanonIP(i1, 128, 32)
		c2, e2 := CanonIP(i2, 128, 32)
		if e1 != nil || e2 != nil || CanonServerName(s1) != CanonServerName(s2) || c1 != c2 {
			t.Fatalf("NONCE MISBINDING: minted for (%q,%q) verified for (%q,%q)", s1, i1, s2, i2)
		}
	})
}
