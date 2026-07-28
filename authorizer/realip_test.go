// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"testing"
)

// The protocol-prefix carve-out in handleAuthz is the one place the gate answers
// "allow" without consulting a grant, so the path it matches on MUST be the same
// path the proxy will route and proxy on. nginx forwards the RAW $request_uri
// (and ingress-nginx the raw $scheme://$http_host$request_uri) but matches
// locations on the NORMALIZED path — so an un-normalized comparison here let
// "/.well-known/jit-access/../../index.html" through the carve-out and the
// upstream then served "/index.html" to an unauthenticated client.

func TestCleanURIPath(t *testing.T) {
	cases := []struct{ in, want string }{
		// ordinary paths are untouched
		{"/.well-known/jit-access/challenge", "/.well-known/jit-access/challenge"},
		{"/.well-known/jit-access", "/.well-known/jit-access"},
		{"/index.html", "/index.html"},
		// query and fragment are not part of the path
		{"/.well-known/jit-access/respond?x=1", "/.well-known/jit-access/respond"},
		{"/index.html?next=/.well-known/jit-access/", "/index.html"},
		// dot segments resolve exactly as nginx resolves them
		{"/.well-known/jit-access/../../index.html", "/index.html"},
		{"/.well-known/jit-access/../admin", "/.well-known/admin"},
		{"/.well-known/jit-access/./../secret", "/.well-known/secret"},
		{"/a/../.well-known/jit-access/challenge", "/.well-known/jit-access/challenge"},
		// percent-encoded traversal, including an encoded separator
		{"/.well-known/jit-access/%2e%2e/%2e%2e/index.html", "/index.html"},
		{"/.well-known/jit-access/..%2f..%2fadmin", "/admin"},
		// escaping above the root collapses to the root, never below it
		{"/.well-known/jit-access/../../../../etc/passwd", "/etc/passwd"},
		{"/../..", "/"},
		// malformed escapes fail closed to a path that cannot match the prefix
		{"/.well-known/jit-access/%zz/../secret", "/"},
		// relative input is anchored
		{"", "/"},
		{"index.html", "/index.html"},
	}
	for _, tc := range cases {
		if got := cleanURIPath(tc.in); got != tc.want {
			t.Errorf("cleanURIPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// End-to-end: the traversal must not be authorized by /authz, through either
// forwarding convention, while genuine protocol endpoints still are.
func TestAuthzPrefixCarveOutRejectsTraversal(t *testing.T) {
	s := testServer(t, nil)

	bypass := []string{
		"/.well-known/jit-access/../../index.html",
		"/.well-known/jit-access/../admin",
		"/.well-known/jit-access/..%2f..%2fadmin",
		"/.well-known/jit-access/%2e%2e/%2e%2e/index.html",
		"/.well-known/jit-access/./../secret",
		"/.well-known/jit-access/../../../../etc/passwd",
		// The BARE prefix is not an endpoint. nginx routes only
		// "<prefix>/" to the Authorizer, so 204 here was an ungated
		// pass-through to the backend on this exact path.
		"/.well-known/jit-access",
		"/.well-known/jit-access/",
	}
	for _, uri := range bypass {
		// nginx auth_request convention
		r := req(http.MethodGet, svcA, "/authz", proxyIP, map[string]string{
			"X-Forwarded-Host": svcA,
			"X-Forwarded-Uri":  uri,
		}, nil)
		if w := do(s, r); w.Code == http.StatusNoContent {
			t.Errorf("X-Forwarded-Uri %q: authorized with no grant (204)", uri)
		}
		// ingress-nginx convention
		r2 := req(http.MethodGet, "jit-authorizer.jit-system.svc", "/authz", proxyIP, map[string]string{
			"X-Original-URL": "https://" + svcA + uri,
		}, nil)
		if w := do(s, r2); w.Code == http.StatusNoContent {
			t.Errorf("X-Original-URL %q: authorized with no grant (204)", uri)
		}
	}

	// The carve-out must still work for the real endpoints, or nobody can knock.
	for _, uri := range []string{
		"/.well-known/jit-access/challenge",
		"/.well-known/jit-access/respond",
		"/.well-known/jit-access/challenge?cachebust=1",
		"/a/../.well-known/jit-access/challenge",
	} {
		r := req(http.MethodGet, svcA, "/authz", proxyIP, map[string]string{
			"X-Forwarded-Host": svcA,
			"X-Forwarded-Uri":  uri,
		}, nil)
		if w := do(s, r); w.Code != http.StatusNoContent {
			t.Errorf("X-Forwarded-Uri %q: got %d, want 204 (knock endpoint must stay reachable)", uri, w.Code)
		}
	}
}

// A client-supplied X-Forwarded-Host must not be able to select which service's
// grant is evaluated. ingress-nginx sets X-Original-URL and forwards the
// client's own headers, so X-Original-URL has to win.
func TestServiceNameIgnoresForgedForwardedHost(t *testing.T) {
	s := testServer(t, func(c *Config) {
		c.Services[svcB] = ServiceConfig{Tokens: []string{testKid}}
	})

	// Earn a real grant on svcB the honest way.
	if w := knock(t, s, svcB, proxyIP, nil, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("knock on %s: got %d", svcB, w.Code)
	}
	r := req(http.MethodGet, "jit-authorizer.jit-system.svc", "/authz", proxyIP, map[string]string{
		"X-Original-URL": "https://" + svcB + "/",
	}, nil)
	if w := do(s, r); w.Code != http.StatusNoContent {
		t.Fatalf("precondition: grant on %s should admit, got %d", svcB, w.Code)
	}

	// Now ask for svcA (no grant) while claiming to be svcB via the forgeable
	// header. The real origin is in X-Original-URL, which must decide.
	spoof := req(http.MethodGet, "jit-authorizer.jit-system.svc", "/authz", proxyIP, map[string]string{
		"X-Original-URL":   "https://" + svcA + "/",
		"X-Forwarded-Host": svcB,
		"X-Original-Host":  svcB,
	}, nil)
	if w := do(s, spoof); w.Code == http.StatusNoContent {
		t.Errorf("forged X-Forwarded-Host inherited %s's grant on %s (204)", svcB, svcA)
	}
}

// ---- forwarding-convention conflicts ---------------------------------------
//
// Which header is authoritative depends on the proxy, so the Authorizer refuses
// to guess: if two conventions are both present and disagree, the request is
// denied. These pin both directions, because a fixed precedence was tried twice
// and each ordering was safe on one deployment and exploitable on the other.

// ingress-nginx sets X-Original-URL and forwards the client's own headers. A
// forged X-Forwarded-Uri must not open the protocol-prefix carve-out — that is
// the one path answered without consulting a grant at all.
func TestForgedForwardedUriCannotOpenCarveOut(t *testing.T) {
	s := testServer(t, nil)
	r := req(http.MethodGet, "jit-authorizer.jit-system.svc", "/authz", proxyIP, map[string]string{
		"X-Original-URL":  "https://" + svcA + "/admin/secrets",
		"X-Forwarded-Uri": "/.well-known/jit-access/challenge",
	}, nil)
	if w := do(s, r); w.Code == http.StatusNoContent {
		t.Error("SECURITY: forged X-Forwarded-Uri opened the carve-out for /admin/secrets")
	}
}

// Plain nginx sets X-Forwarded-Host authoritatively. A forged X-Original-URL
// must not select which service's grant is evaluated.
func TestForgedOriginalURLCannotSelectService(t *testing.T) {
	s := testServer(t, func(c *Config) {
		c.Services[svcB] = ServiceConfig{Tokens: []string{testKid}}
	})
	// earn a real grant on svcB
	if w := knock(t, s, svcB, proxyIP, map[string]string{"X-Forwarded-Host": svcB}, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("knock on %s: %d", svcB, w.Code)
	}
	if w := do(s, req(http.MethodGet, "x", "/authz", proxyIP, map[string]string{
		"X-Forwarded-Host": svcB, "X-Forwarded-Uri": "/",
	}, nil)); w.Code != http.StatusNoContent {
		t.Fatalf("precondition: %s grant should admit, got %d", svcB, w.Code)
	}
	// ask for svcA while forging the other convention
	spoof := req(http.MethodGet, "x", "/authz", proxyIP, map[string]string{
		"X-Forwarded-Host": svcA,
		"X-Forwarded-Uri":  "/",
		"X-Original-URL":   "https://" + svcB + "/",
	}, nil)
	if w := do(s, spoof); w.Code == http.StatusNoContent {
		t.Errorf("SECURITY: forged X-Original-URL inherited %s's grant on %s", svcB, svcA)
	}
}

// A conflict denies rather than silently picking one side, and denies for the
// protocol endpoints too — not only for /authz.
func TestConflictingConventionsDeny(t *testing.T) {
	s := testServer(t, nil)
	cases := []struct {
		name string
		hdrs map[string]string
	}{
		{"host conflict", map[string]string{
			"X-Forwarded-Host": svcA, "X-Original-URL": "https://" + svcB + "/"}},
		{"uri conflict", map[string]string{
			"X-Forwarded-Host": svcA, "X-Forwarded-Uri": "/a",
			"X-Original-URL": "https://" + svcA + "/b"}},
		{"original-host conflict", map[string]string{
			"X-Forwarded-Host": svcA, "X-Original-Host": svcB, "X-Forwarded-Uri": "/"}},
	}
	for _, tc := range cases {
		if w := do(s, req(http.MethodGet, "x", "/authz", proxyIP, tc.hdrs, nil)); w.Code == http.StatusNoContent {
			t.Errorf("%s: allowed (204) instead of denying", tc.name)
		}
		h := map[string]string{}
		for k, v := range tc.hdrs {
			h[k] = v
		}
		ch := do(s, req(http.MethodGet, "x", s.config().URIPrefix+"/challenge", proxyIP, h, nil))
		if ch.Code == http.StatusNoContent {
			t.Errorf("%s: /challenge minted a nonce despite an ambiguous target", tc.name)
		}
	}
}

// Agreement between conventions is normal and must still work — a proxy may set
// both, and a request that names the same target twice is not an attack.
func TestAgreeingConventionsAreAccepted(t *testing.T) {
	s := testServer(t, nil)
	hdrs := map[string]string{
		"X-Forwarded-Host": svcA,
		"X-Forwarded-Uri":  "/dashboard",
		"X-Original-URL":   "https://" + svcA + "/dashboard",
	}
	if w := knock(t, s, svcA, proxyIP, map[string]string{"X-Forwarded-Host": svcA}, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", w.Code)
	}
	if w := do(s, req(http.MethodGet, "x", "/authz", proxyIP, hdrs, nil)); w.Code != http.StatusNoContent {
		t.Errorf("agreeing conventions should be admitted, got %d", w.Code)
	}
	// ...and the trailing-slash / query forms still agree after normalization
	hdrs["X-Original-URL"] = "https://" + svcA + "/dashboard?x=1"
	if w := do(s, req(http.MethodGet, "x", "/authz", proxyIP, hdrs, nil)); w.Code != http.StatusNoContent {
		t.Errorf("query string must not create a false conflict, got %d", w.Code)
	}
}

// An untrusted peer's forwarded headers are not evidence at all, so they cannot
// manufacture a conflict against a request described only by its own line.
func TestDirectClientForwardedHeadersIgnored(t *testing.T) {
	s := testServer(t, nil)
	w := do(s, req(http.MethodGet, svcA, "/authz", directIP, map[string]string{
		"X-Forwarded-Host": svcB, "X-Original-URL": "https://" + svcB + "/",
	}, nil))
	// direct peers are refused by the /authz trusted-peer gate regardless
	if w.Code == http.StatusNoContent {
		t.Error("SECURITY: untrusted peer was authorized")
	}
}
