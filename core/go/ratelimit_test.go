// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitcore

import (
	"strconv"
	"testing"
)

// One site's flood must not darken every other site for everyone behind the
// same egress address: buckets are per scope.
func TestRateLimiterIsScopedPerService(t *testing.T) {
	l := NewRateLimiter(0)
	for i := 0; i < 3; i++ {
		l.Allow(RateKey("app.example.com", "203.0.113.9"), 3, now)
	}
	if l.Allow(RateKey("app.example.com", "203.0.113.9"), 3, now) {
		t.Fatal("precondition: the app bucket should be exhausted")
	}
	if !l.Allow(RateKey("other.example.com", "203.0.113.9"), 3, now) {
		t.Error("a flood on one service throttled the same address on another")
	}
	if !l.Allow(RateKey("app.example.com", "203.0.113.9"), 3, now+60) {
		t.Error("the window did not reset after a minute")
	}
}

// A routed /64 is one source. Bucketing per /128 let a single host mint a fresh
// bucket per request and never be throttled at all.
func TestRateKeyCollapsesIPv6ToSlash64(t *testing.T) {
	a := RateKey("svc", "2001:db8:1:2::1")
	b := RateKey("svc", "2001:db8:1:2:ffff:ffff:ffff:9")
	c := RateKey("svc", "2001:db8:1:3::1")
	if a != b {
		t.Errorf("two hosts on one /64 got different buckets: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("hosts on different /64s share a bucket: %q", a)
	}
	if got := RateKey("svc", "203.0.113.9"); got != "svc|203.0.113.9" {
		t.Errorf("IPv4 key changed: %q", got)
	}
	// An address that does not parse is still a usable, distinct key rather
	// than a crash or a shared catch-all.
	if RateKey("svc", "not-an-ip") == RateKey("svc", "also-not") {
		t.Error("unparseable sources collapsed into one bucket")
	}
}

// The table is bounded. When it is full, finished windows are reclaimed; if it
// is still full the attempt is refused rather than the table growing without
// limit, which is what an IPv6 source sweep used to do to the pod's memory.
func TestRateLimiterIsBounded(t *testing.T) {
	l := NewRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !l.Allow(RateKey("svc", "203.0.113."+strconv.Itoa(i)), 10, now) {
			t.Fatalf("entry %d refused while the table had room", i)
		}
	}
	if l.Allow(RateKey("svc", "203.0.113.99"), 10, now) {
		t.Error("a full table admitted a new source instead of refusing it")
	}
	if got := l.Len(); got != 3 {
		t.Errorf("table grew past its cap: %d entries", got)
	}
	// existing windows keep counting while full
	if !l.Allow(RateKey("svc", "203.0.113.0"), 10, now+1) {
		t.Error("a known source was refused because the table was full")
	}
	// once the windows finish, a new source is admitted again
	if !l.Allow(RateKey("svc", "203.0.113.99"), 10, now+60) {
		t.Error("finished windows were not reclaimed to make room")
	}
	if n := l.Sweep(now + 120); n == 0 {
		t.Error("sweep reclaimed nothing a minute after the last window")
	}
}
