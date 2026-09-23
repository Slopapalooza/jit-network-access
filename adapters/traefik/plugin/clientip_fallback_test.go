// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"context"
	"net/http"
	"testing"
)

// A trusted peer that forwards no usable client address identifies nobody. This
// used to key the grant on the peer's own address, so every client behind a
// proxy that omitted the header, or a chain made only of trusted hops, shared
// ONE grant. With Traefik that is one config slip away: an edge proxy missing
// from the entryPoint's forwardedHeaders.trustedIPs has its X-Forwarded-For
// dropped before the plugin runs. Now it is denied: a lockout an operator
// notices.
func TestTrustedPeerWithoutClientAddressIsDenied(t *testing.T) {
	const proxy = "10.0.0.1:5000"
	reset(t)
	cfg := CreateConfig()
	cfg.Tokens = []Token{{Kid: testKid, Secret: testSecret, Label: "test"}}
	cfg.Allow = []string{testKid}
	cfg.TrustForwarded = true
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	h, err := New(context.Background(), upstream(), cfg, "jit")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	j, ok := h.(*JITAccess)
	if !ok {
		t.Fatalf("New returned %T, not *JITAccess", h)
	}

	for name, xff := range map[string]string{
		"no header":        "",
		"all trusted hops": "10.0.0.7, 10.0.0.1",
		"unparseable only": "not-an-ip, ,",
	} {
		r := mkreq(http.MethodGet, "/dashboard", proxy, nil)
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if got, err := j.clientIP(r); err == nil {
			t.Errorf("%s: resolved to %q; must be denied", name, got)
		}
		if w := serve(j, r); w.Body.String() == "UPSTREAM" {
			t.Errorf("%s: SECURITY: a request with no client identity reached the upstream", name)
		}
	}

	// Without trustForwarded the peer IS the client, exactly as before.
	plain := build(t, nil)
	if w := serve(plain, mkreq(http.MethodGet, defaultPrefix+"/challenge", proxy, nil)); w.Code != http.StatusNoContent {
		t.Errorf("direct peer must still resolve: challenge got %d", w.Code)
	}
}
