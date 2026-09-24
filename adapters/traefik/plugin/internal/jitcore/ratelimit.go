// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitcore

import "sync"

// RateLimiter is the knock throttle shared by the Go engines: a fixed
// one-minute window per key (PROTOCOL §2.1). Knock failures never feed a WAF's
// abuse counters (SECURITY-REVIEW R4), so this is the only throttle and it has
// to survive hostile input on its own. It replaced three identical copies, one
// per engine, none of which bounded its table.
type RateLimiter struct {
	mu     sync.Mutex
	window map[string]*rlEntry
	max    int
}

type rlEntry struct {
	start int64
	n     int
}

// DefaultRateLimitEntries bounds the table. An entry costs on the order of a
// hundred bytes, so this is about 10 MiB at worst, against the 128 MiB the
// Kubernetes manifest gives the Authorizer. Before the cap a single IPv6 /64
// sending a few thousand distinct sources per second grew the table without
// limit for a minute at a time and could take the pod down with it.
const DefaultRateLimitEntries = 100_000

func NewRateLimiter(maxEntries int) *RateLimiter {
	if maxEntries <= 0 {
		maxEntries = DefaultRateLimitEntries
	}
	return &RateLimiter{window: map[string]*rlEntry{}, max: maxEntries}
}

// RateKey names the bucket a request counts against.
//
// The scope (the canonical service name for a knock, a fixed word for
// enrollment) keeps one site's flood from locking a shared egress address out
// of every other site on the instance: ten bad requests from an office NAT
// used to darken every gated site for everyone behind it for a minute. The
// source is the canonical client address with IPv6 collapsed to its /64, so a
// single host on a routed /64 cannot mint a fresh bucket per request and
// escape the throttle entirely.
func RateKey(scope, ipCanon string) string {
	if c, err := CanonIP(ipCanon, 64, 32); err == nil {
		ipCanon = c
	}
	return scope + "|" + ipCanon
}

// Allow counts one attempt against key and reports whether it is within perMin
// for the current window. perMin <= 0 disables the limiter. When the table is
// full, finished windows are reclaimed first; if it is still full, the attempt
// is refused. Fail closed, never grow without bound.
func (l *RateLimiter) Allow(key string, perMin int, now int64) bool {
	if perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.window[key]
	if ok && now-e.start < 60 {
		e.n++
		return e.n <= perMin
	}
	if !ok && len(l.window) >= l.max {
		l.sweepLocked(now)
		if len(l.window) >= l.max {
			return false
		}
	}
	l.window[key] = &rlEntry{start: now, n: 1}
	return true
}

// Sweep drops finished windows and returns how many it removed. Lazy expiry
// already makes them harmless; this reclaims their memory on a timer.
func (l *RateLimiter) Sweep(now int64) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sweepLocked(now)
}

func (l *RateLimiter) sweepLocked(now int64) int {
	n := 0
	for k, e := range l.window {
		if now-e.start >= 60 {
			delete(l.window, k)
			n++
		}
	}
	return n
}

// Len is the number of windows currently held (tests and metrics).
func (l *RateLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.window)
}
