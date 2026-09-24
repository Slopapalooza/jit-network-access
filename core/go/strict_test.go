// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitcore

import (
	"math"
	"testing"
)

// The four references used to disagree on malformed base64url: Go skipped
// embedded newlines, Lua stopped at the first "=" and accepted the standard
// alphabet, Python dropped anything outside the alphabet. Only well-formed
// spellings, padded or not, may decode anywhere.
func TestB64uDecodeIsStrict(t *testing.T) {
	for _, ok := range []string{"", "AQ", "AQID", "AQID==", "AQID=", "-_-_"} {
		if _, err := B64uDecode(ok); err != nil {
			t.Errorf("%q must decode: %v", ok, err)
		}
	}
	for _, bad := range []string{"AQ\nID", "AQID=xyz", "AQ+D", "AQ/D", "AQ ID", "AQID=A", "A=QID", "\tAQID"} {
		if _, err := B64uDecode(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// ts is an unsigned 64-bit field; a value above MaxInt64 went negative on
// conversion and the subtraction wrapped, so such a nonce passed the freshness
// window at any `now`. Python and Lua reject the same bytes.
func TestVerifyNonceRejectsTimestampBeyondInt64(t *testing.T) {
	key := make([]byte, 32)
	rnd := make([]byte, 16)
	const now = int64(1_700_000_000)
	for _, ts := range []uint64{1 << 63, math.MaxUint64, math.MaxInt64 + 1} {
		n, err := IssueNonce(key, ts, rnd, "svc.example.com", "1.2.3.4", 128)
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := VerifyNonce(key, n, "svc.example.com", "1.2.3.4", now, 60, 128); ok {
			t.Errorf("ts=%d verified as fresh at now=%d", ts, now)
		}
	}
	// and the window itself is unchanged
	n, _ := IssueNonce(key, uint64(now), rnd, "svc.example.com", "1.2.3.4", 128)
	if ok, _ := VerifyNonce(key, n, "svc.example.com", "1.2.3.4", now+59, 60, 128); !ok {
		t.Error("a nonce inside its window must verify")
	}
	if ok, _ := VerifyNonce(key, n, "svc.example.com", "1.2.3.4", now+60, 60, 128); ok {
		t.Error("a nonce at the end of its window must not verify")
	}
}

// The per-kid algorithm pin (SPEC §3) was written by every loader and read by
// nobody. A token carrying anything but the pinned algorithm must fail both at
// the knock and on the grant re-check, never default to HMAC-SHA256.
func TestAlgorithmPinIsEnforced(t *testing.T) {
	reg := NewRegistry(
		map[string]*Token{
			"kid_sha1":  {Secret: []byte("0123456789abcdef"), Alg: "HMAC-SHA1"},
			"kid_blank": {Secret: []byte("0123456789abcdef")},
		},
		map[string]map[string]bool{"app.example.com": {"*": true}},
	)
	for _, kid := range []string{"kid_sha1", "kid_blank"} {
		if _, err := reg.Authorize(kid, "app.example.com", now); err != ErrBadAlg {
			t.Errorf("%s: Authorize returned %v, want ErrBadAlg", kid, err)
		}
		s := NewGrantStore()
		g := liveGrant(kid)
		g.SecretFP = reg.Lookup(kid).Fingerprint()
		s.Put(g)
		if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") != nil {
			t.Errorf("%s: a grant under an unpinned algorithm was honored", kid)
		}
	}
}
