// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

// Not under the race detector. It instruments every memory access, which inflates
// and distorts exactly the intervals being compared here — a timing measurement
// taken through it says nothing about the timing of the real binary. CI runs the
// suite with -race, so this is excluded there and runs on a plain `go test`:
//
//	go test -run TestKnockRejectionTiming -v ./authorizer
//
//go:build !race

package main

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"runtime"
	"sort"
	"testing"
	"time"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

// PROTOCOL §6 requires every rejection at the knock endpoints to be the same
// generic response. "Same" was only ever checked as the same STATUS CODE —
// security_suite.py compares unknown-kid against bad-proof and stops there. This
// checks the other half: whether they take the same amount of TIME.
//
// It matters because the cheap way to implement "unknown kid" is to return
// before doing any crypto, which lets a probe enumerate valid key ids for a
// service without ever holding a secret. handleRespond avoids that on purpose,
// running a full VerifyProof against a fixed all-zero dummy secret when the kid
// resolves to nothing. This measures whether that holds, instead of trusting the
// comment that says it does.
//
// METHOD, arrived at by measurement. Three plausible designs were tried and
// discarded first, each for a reason worth keeping:
//
//   - Timing single calls. time.Now() granularity on some platforms (Windows
//     here) is coarser than the ~20us this handler takes, so every sample read
//     zero. Hence batching.
//   - Independent medians against a measured "noise floor". The floor is itself
//     a noisy estimate, so the budget jittered; it caught a real oracle in two
//     runs out of four.
//   - A per-round sign test. One round's noise dwarfs the effect, so a decisive
//     oracle still agreed in only ~59% of rounds against ~51% for correct code.
//     Gating on it caught nothing at all.
//
// What works: the median of PAIRED differences, branch order shuffled each
// round, repeated over several independent passes and the passes themselves
// reduced by median. Pairing cancels drift, shuffling removes the cache
// advantage the first-called branch gets, the inner median cancels symmetric
// per-round noise, and the outer median discards a whole pass that caught a load
// spike — without which this reported a 6.5% false positive on a busy laptop
// roughly one run in four.
//
// Calibration against this handler: ~0.2% for correct code, ~12% with the
// equalization removed. The 3% threshold sits between them with a wide margin
// on each side, so it is not tuned to one machine.

const (
	timingPasses  = 5   // independent estimates; reduced by median
	timingRounds  = 80  // paired rounds per pass
	timingBatch   = 200 // calls per timed sample, to clear the clock granularity
	timingWarmups = 3

	timingOracleBudgetPct = 3.0

	// If the independent passes disagree by more than this, the machine is too
	// busy for the measurement to mean anything and the test SKIPS rather than
	// guesses. Measured on a saturated laptop: passes swung from -10% to +10%
	// within one run on correct code, which a median of three would happily
	// report as a finding. A skip is visible and honest; a coin-flip verdict on
	// a security property is not.
	timingNoiseSkipPct = 6.0
)

func medianDur(d []time.Duration) time.Duration {
	c := append([]time.Duration(nil), d...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

func medianFloat(f []float64) float64 {
	c := append([]float64(nil), f...)
	sort.Float64s(c)
	return c[len(c)/2]
}

// timeRespondBatch posts the same /respond body n times and returns how long the
// whole batch took. Request construction is inside the timed section on purpose:
// it is identical work for every branch, and hoisting it out would mean timing
// something the server does not actually do on its own.
func timeRespondBatch(s *Server, host, body string, n int) time.Duration {
	prefix := s.config().URIPrefix + "/respond"
	hdrs := map[string]string{"Content-Type": "application/json"}
	raw := []byte(body)
	start := time.Now()
	for i := 0; i < n; i++ {
		do(s, req(http.MethodPost, host, prefix, proxyIP, hdrs, raw))
	}
	return time.Since(start)
}

func TestKnockRejectionTimingRevealsNoKidOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement: skipped under -short")
	}

	s := testServer(t, func(c *Config) {
		// The limiter would start denying long before enough samples are
		// collected, and a rate-limited path is a different path.
		c.RateLimit = 1 << 30
		// A kid that EXISTS but is not on svcA's allow list, so the third
		// rejection branch (ErrNotAllowed) is exercised too.
		// SAME LENGTH as testKid ("kid_test"). The kid is part of the PAE that gets
		// HMAC'd, so a longer one is genuinely more work — an 18-character
		// "kid_does_not_exist" against an 8-character real kid was measuring string
		// length as much as control flow.
		c.Tokens = append(c.Tokens, TokenConfig{Kid: "kid_othr", Secret: testSecret, Label: "other"})
	})

	// One nonce serves every sample: verify-then-burn means a REJECTED proof
	// never consumes it, which is exactly the property being relied on here.
	ch := do(s, req(http.MethodGet, svcA, s.config().URIPrefix+"/challenge", proxyIP, nil, nil))
	if ch.Code != http.StatusNoContent {
		t.Fatalf("challenge: got %d", ch.Code)
	}
	nonce := ch.Header().Get("X-JIT-Nonce")
	nonceRaw, err := jitcore.B64uDecode(nonce)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong but well-formed: same length and encoding as a real proof, so only
	// the comparison outcome differs, never the parsing work.
	wrong := jitcore.B64u(jitcore.BuildProof(make([]byte, 32), svcA, testKid, nonceRaw))

	mk := func(kid string) string {
		b, _ := json.Marshal(respondBody{V: 1, Kid: kid, Nonce: nonce, Proof: wrong})
		return string(b)
	}
	branches := []struct{ name, body string }{
		{"unknown kid", mk("kid_none")}, // 8 chars, as are the other two
		{"known kid, wrong proof", mk(testKid)},
		{"known kid, not allowed here", mk("kid_othr")},
	}

	// Every branch must actually be rejected, or the timing means nothing.
	for _, b := range branches {
		r := req(http.MethodPost, svcA, s.config().URIPrefix+"/respond", proxyIP,
			map[string]string{"Content-Type": "application/json"}, []byte(b.body))
		if w := do(s, r); w.Code == http.StatusNoContent {
			t.Fatalf("%s: got 204 — this branch is not a rejection", b.name)
		}
	}
	for i := 0; i < timingWarmups; i++ {
		for _, b := range branches {
			timeRespondBatch(s, svcA, b.body, timingBatch)
		}
	}

	rng := rand.New(rand.NewSource(1)) // fixed seed: a failure has to be reproducible
	order := make([]int, len(branches))
	for i := range order {
		order[i] = i
	}

	// estimates[branch] = one relative difference (%) per pass
	estimates := make([][]float64, len(branches))
	var lastMedians []time.Duration

	for pass := 0; pass < timingPasses; pass++ {
		// Start each pass from a collected heap. Timing 200 handler calls means
		// timing 200 request allocations, so a GC cycle landing inside one batch
		// and not the next is a large part of the per-round noise. This does not
		// remove it — GC still runs mid-pass — but it stops a pass inheriting
		// whatever the previous one left behind.
		runtime.GC()

		samples := make([][]time.Duration, len(branches))
		for i := range samples {
			samples[i] = make([]time.Duration, 0, timingRounds)
		}
		for n := 0; n < timingRounds; n++ {
			// Shuffle which branch runs first. With a fixed order the first one
			// gets a systematic cache and branch-predictor advantage, which showed
			// up as a 5-8% paired difference whose sign flipped between runs.
			rng.Shuffle(len(order), func(a, b int) { order[a], order[b] = order[b], order[a] })
			for _, i := range order {
				samples[i] = append(samples[i], timeRespondBatch(s, svcA, branches[i].body, timingBatch))
			}
		}

		base := medianDur(samples[0])
		lastMedians = make([]time.Duration, len(branches))
		for i := range branches {
			lastMedians[i] = medianDur(samples[i])
		}
		for i := 1; i < len(branches); i++ {
			diffs := make([]time.Duration, timingRounds)
			for n := 0; n < timingRounds; n++ {
				diffs[n] = samples[i][n] - samples[0][n]
			}
			estimates[i] = append(estimates[i], float64(medianDur(diffs))/float64(base)*100)
		}
	}

	t.Logf("median batch of %d rejections, last pass:", timingBatch)
	for i, b := range branches {
		t.Logf("    %-28s %v", b.name, lastMedians[i])
	}
	// Is this machine quiet enough to have measured anything? Independent passes
	// of the same comparison should land close together; when they do not, the
	// spread is the load, not the code.
	worst := 0.0
	for i := 1; i < len(branches); i++ {
		lo, hi := estimates[i][0], estimates[i][0]
		for _, e := range estimates[i] {
			if e < lo {
				lo = e
			}
			if e > hi {
				hi = e
			}
		}
		if hi-lo > worst {
			worst = hi - lo
		}
	}
	if worst > timingNoiseSkipPct {
		for i := 1; i < len(branches); i++ {
			t.Logf("    %-28s passes: %v", branches[i].name, estimates[i])
		}
		t.Skipf("machine too noisy to measure: passes disagree by %.1f%% (limit %.1f%%). "+
			"Re-run on an idle machine; this is a measurement, not a verdict.",
			worst, timingNoiseSkipPct)
	}

	for i := 1; i < len(branches); i++ {
		pct := medianFloat(estimates[i])
		t.Logf("    %-28s %+.2f%% vs %q  (passes: %v)",
			branches[i].name, pct, branches[0].name, estimates[i])

		if pct < 0 {
			pct = -pct
		}
		if pct > timingOracleBudgetPct {
			t.Errorf("TIMING ORACLE: %q differs from %q by %.2f%% of the operation "+
				"(budget %.0f%%) - a probe can tell these rejections apart by clock alone",
				branches[i].name, branches[0].name, pct, timingOracleBudgetPct)
		}
	}
}
