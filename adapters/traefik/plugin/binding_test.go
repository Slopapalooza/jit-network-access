// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"context"
	"net/http"
	"testing"

	jitcore "github.com/Slopapalooza/jit-network-access/adapters/traefik/plugin/internal/jitcore"
)

// Grants survive a dynamic-config reload by design. So when an operator
// discovers a shared egress and switches the router to ip+cookie, the ip-only
// grants minted before the switch were still honored until their TTL: exactly
// the exposure the switch was meant to close. The re-check on every request
// only compared the grant to the registry, never to the router's current
// binding.
func TestReloadToCookieBindingEvictsIPGrants(t *testing.T) {
	const remote = "203.0.113.90:1000"
	h := build(t, nil) // binding ip
	if r := knock(t, h, remote, testKid, secretBytes(t)); r.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", r.Code)
	}
	if w := serve(h, mkreq(http.MethodGet, "/", remote, nil)); w.Body.String() != "UPSTREAM" {
		t.Fatalf("precondition: ip-bound grant should admit, got %d", w.Code)
	}

	// The operator switches the router to ip+cookie. Traefik calls New again
	// over the SAME package-level stores; no reset here, on purpose.
	cfg := CreateConfig()
	cfg.Tokens = []Token{{Kid: testKid, Secret: testSecret, Label: "test"}}
	cfg.Allow = []string{testKid}
	cfg.Binding = jitcore.BindingIPCookie
	h2, err := New(context.Background(), upstream(), cfg, "jit")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if w := serve(h2, mkreq(http.MethodGet, "/", remote, nil)); w.Body.String() == "UPSTREAM" {
		t.Error("SECURITY: an ip-only grant was honored after the router required ip+cookie")
	}

	// A fresh knock under the new binding works, with its cookie.
	r := knock(t, h2, remote, testKid, secretBytes(t))
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
	rq := mkreq(http.MethodGet, "/", remote, nil)
	rq.AddCookie(ck)
	if w := serve(h2, rq); w.Body.String() != "UPSTREAM" {
		t.Errorf("cookie-bound grant should admit, got %d", w.Code)
	}
}
