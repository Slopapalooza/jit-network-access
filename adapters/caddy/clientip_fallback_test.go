// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"net/http"
	"testing"
)

// A trusted peer that forwards no usable client address identifies nobody. This
// used to key the grant on the peer's own address, so every client behind a
// proxy that omitted the header, or a chain made only of trusted hops, shared
// ONE grant. Now it is denied: a lockout an operator notices.
func TestTrustedPeerWithoutClientAddressIsDenied(t *testing.T) {
	const proxy = "10.0.0.1:5000"
	j := newHandler(t, func(j *JITAccess) {
		j.TrustForwarded = true
		j.TrustedProxies = []string{"10.0.0.0/8"}
	})
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
		if w := serve(t, j, r); w.Body.String() == "UPSTREAM" {
			t.Errorf("%s: SECURITY: a request with no client identity reached the upstream", name)
		}
	}

	// Without trust_forwarded the peer IS the client, exactly as before.
	plain := newHandler(t, nil)
	if _, err := plain.clientIP(mkreq(http.MethodGet, "/", proxy, nil)); err != nil {
		t.Errorf("direct peer must still resolve: %v", err)
	}
}
