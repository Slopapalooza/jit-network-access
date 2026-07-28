// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/url"
	"path"
	"strings"
	"testing"
)

// Fuzzing the one function whose failure mode is an unauthenticated bypass.
//
// cleanURIPath decides whether a request is a protocol endpoint, which is the
// only path answered without consulting a grant. Reading it is not enough: the
// original bug here shipped, and both defects this fuzzer found (double-encoded
// input, and non-idempotency) survived three rounds of review.
//
// Run longer with:  go test -run XXX -fuzz FuzzCleanURIPath -fuzztime 5m
//
// The property that matters: whatever cleanURIPath returns must be the path the
// PROXY will route on. If an input exists where the verifier's view and nginx's
// normalization disagree, the protocol-prefix carve-out is a bypass.
func FuzzCleanURIPath(f *testing.F) {
	seeds := []string{
		"/.well-known/jit-access/challenge",
		"/.well-known/jit-access/../../x",
		"/.well-known/jit-access/..%2f..%2fx",
		"//.well-known//jit-access//",
		"/.well-known/jit-access/./.././x",
		"/.well-known/jit-access%2f..%2f..",
		"/.well-known/jit-access/;/../x",
		"/%2e%2e/.well-known/jit-access",
		"/.well-known/jit-access/#/../x",
		"/.well-known/jit-access/%2e%2e%2f",
		"/.well-known/jit-access/..;/x",
		"/.well-known/jit-access/%252e%252e/x",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	const prefix = "/.well-known/jit-access"

	f.Fuzz(func(t *testing.T, in string) {
		got := cleanURIPath(in)

		if !strings.HasPrefix(got, "/") {
			t.Fatalf("not absolute: %q -> %q", in, got)
		}
		for _, seg := range strings.Split(got, "/") {
			if seg == ".." || seg == "." {
				t.Fatalf("dot segment survived: %q -> %q", in, got)
			}
		}
		// Idempotent. Not cosmetic: a normalizer that changes its answer when
		// applied twice is the same confusion that makes double-encoding
		// exploitable against any upstream that decodes more than once.
		if again := cleanURIPath(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, got, again)
		}

		// THE security property. If the result lands inside the carve-out, then
		// decoding and cleaning the input the way a proxy does must land inside
		// it too. A mismatch is the bypass class that shipped once already.
		if got == prefix || strings.HasPrefix(got, prefix+"/") {
			raw := in
			if i := strings.IndexAny(raw, "?#"); i != -1 {
				raw = raw[:i]
			}
			dec, err := url.PathUnescape(raw)
			if err != nil {
				return // proxy answers 400; verifier returned "/" which cannot match
			}
			if !strings.HasPrefix(dec, "/") {
				dec = "/" + dec
			}
			proxyView := path.Clean(dec)
			if proxyView != prefix && !strings.HasPrefix(proxyView, prefix+"/") {
				t.Fatalf("VERIFIER/PROXY DISAGREE: %q -> verifier %q (carved out) but proxy routes %q",
					in, got, proxyView)
			}
		}
	})
}
