// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

// Grants survive a config reload by design. So when an operator discovers a
// shared egress and switches the site to ip+cookie, the ip-only grants minted
// before the switch were still honored until their TTL: exactly the exposure
// the switch was meant to close. The re-check on every request only compared
// the grant to the registry, never to the site's current binding.
func TestReloadToCookieBindingEvictsIPGrants(t *testing.T) {
	j := newHandler(t, nil) // binding ip
	if w := knock(t, j, peer, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", w.Code)
	}
	if w := serve(t, j, mkreq(http.MethodGet, "/", peer, nil)); w.Body.String() != "UPSTREAM" {
		t.Fatalf("precondition: ip-bound grant should admit, got %d", w.Code)
	}

	// The operator switches the site to ip+cookie and reloads. A reload
	// provisions a new handler over the SAME process-wide stores.
	j2 := &JITAccess{
		Tokens:  []Token{{Kid: testKid, Secret: testSecret, Label: "test"}},
		Allow:   []string{testKid},
		Binding: jitcore.BindingIPCookie,
	}
	if err := j2.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := j2.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if w := serve(t, j2, mkreq(http.MethodGet, "/", peer, nil)); w.Body.String() == "UPSTREAM" {
		t.Error("SECURITY: an ip-only grant was honored after the site required ip+cookie")
	}

	// A fresh knock under the new binding works, with its cookie.
	r := knock(t, j2, peer, testKid, secretBytes(t))
	if r.Code != http.StatusNoContent {
		t.Fatalf("re-knock: %d", r.Code)
	}
	var ck *http.Cookie
	for _, c := range r.Result().Cookies() {
		if c.Name == grantCookieName {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("re-knock under ip+cookie set no grant cookie")
	}
	rq := mkreq(http.MethodGet, "/", peer, nil)
	rq.AddCookie(ck)
	if w := serve(t, j2, rq); w.Body.String() != "UPSTREAM" {
		t.Errorf("cookie-bound grant should admit, got %d", w.Code)
	}
}
