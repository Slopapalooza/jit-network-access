// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jitcore "github.com/Slopapalooza/jit-network-access/adapters/traefik/plugin/internal/jitcore"
)

// A grant is keyed on the client IP, so whoever controls that value controls who
// the grant belongs to. These pin the trustForwarded switch: it must refuse to
// start without a trusted-proxy list, and with one it must walk X-Forwarded-For
// from the right so a client-appended entry can never win.

func TestTrustForwardedRequiresTrustedProxies(t *testing.T) {
	reset(t)
	cfg := CreateConfig()
	cfg.Tokens = []Token{{Kid: testKid, Secret: testSecret}}
	cfg.Allow = []string{testKid}
	cfg.TrustForwarded = true // no TrustedProxies

	if _, err := New(context.Background(), upstream(), cfg, "jit"); err == nil {
		t.Fatal("trustForwarded without trustedProxies must be refused, not silently trusted")
	}
}

func TestBadTrustedProxiesRefused(t *testing.T) {
	reset(t)
	cfg := CreateConfig()
	cfg.Tokens = []Token{{Kid: testKid, Secret: testSecret}}
	cfg.Allow = []string{testKid}
	cfg.TrustedProxies = []string{"not-an-address"}

	if _, err := New(context.Background(), upstream(), cfg, "jit"); err == nil {
		t.Fatal("unparseable trustedProxies must be refused")
	}
}

// The core regression: a client that appends its own X-Forwarded-For entry must
// not be able to nominate the grant key, and must not be able to ride a grant
// earned by the address it names.
func TestForgedXFFCannotChooseGrantKey(t *testing.T) {
	const proxy = "10.0.0.1:5000" // inside trusted_proxies
	h := build(t, func(c *Config) {
		c.TrustForwarded = true
		c.TrustedProxies = []string{"10.0.0.0/8"}
	})
	serve2 := func(r *http.Request) *httptest.ResponseRecorder { return serve(h, r) }
	// Models what a proxy really does: it APPENDS the peer it saw. So the victim's
	// chain ends with the victim's address, and the attacker's chain ends with the
	// attacker's — no matter what the attacker prepends.
	//
	// The earlier version of this test issued only a /challenge (which creates no
	// grant, so "the spoofer was denied" was vacuously true) and then replayed an
	// identical chain from a second trusted peer — which legitimately resolves to
	// the same client, so it was asserting the wrong thing as well as asserting it
	// against nothing.
	victimXFF := "198.51.100.7"                // proxy appended the victim
	attackXFF := "198.51.100.7, 203.0.113.200" // attacker prepends the victim; proxy appends the attacker

	// Victim completes a real knock.
	ch := mkreq(http.MethodGet, defaultPrefix+"/challenge", proxy, nil)
	ch.Header.Set("X-Forwarded-For", victimXFF)
	chw := serve2(ch)
	if chw.Code != http.StatusNoContent {
		t.Fatalf("victim challenge: got %d", chw.Code)
	}
	nonceB64 := chw.Header().Get("X-JIT-Nonce")
	nonceRaw, err := jitcore.B64uDecode(nonceB64)
	if err != nil {
		t.Fatal(err)
	}
	tag := jitcore.BuildProof(secretBytes(t), site, testKid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: testKid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})
	rs := mkreq(http.MethodPost, defaultPrefix+"/respond", proxy, body)
	rs.Header.Set("X-Forwarded-For", victimXFF)
	if w := serve2(rs); w.Code != http.StatusNoContent {
		t.Fatalf("victim knock: got %d — without a real grant this test proves nothing", w.Code)
	}

	// Precondition: the victim is admitted.
	ok := mkreq(http.MethodGet, "/dashboard", proxy, nil)
	ok.Header.Set("X-Forwarded-For", victimXFF)
	if w := serve2(ok); w.Body.String() != "UPSTREAM" {
		t.Fatalf("precondition: victim should be admitted, got %d", w.Code)
	}

	// The attacker names the victim on the left. The proxy still appended the
	// attacker on the right, so the rightmost-untrusted walk sees the attacker.
	spoof := mkreq(http.MethodGet, "/dashboard", proxy, nil)
	spoof.Header.Set("X-Forwarded-For", attackXFF)
	if w := serve2(spoof); w.Body.String() == "UPSTREAM" {
		t.Error("SECURITY: prepending the victim's address inherited the victim's grant")
	}
}

// With a trusted-proxy list the legitimate case still works: the address the
// proxy appended is the client, and it is what the grant is keyed on.
func TestRightmostUntrustedIsTheClient(t *testing.T) {
	const proxy = "10.0.0.1:5000"
	h := build(t, func(c *Config) {
		c.TrustForwarded = true
		c.TrustedProxies = []string{"10.0.0.0/8", "192.168.0.0/16"}
	})

	// client 198.51.100.7 -> edge 192.168.1.1 -> traefik peer 10.0.0.1
	xff := "198.51.100.7, 192.168.1.1"

	ch := mkreq(http.MethodGet, defaultPrefix+"/challenge", proxy, nil)
	ch.Header.Set("X-Forwarded-For", xff)
	chw := serve(h, ch)
	if chw.Code != http.StatusNoContent {
		t.Fatalf("challenge: got %d", chw.Code)
	}
	nonceB64 := chw.Header().Get("X-JIT-Nonce")
	nonceRaw, err := jitcore.B64uDecode(nonceB64)
	if err != nil {
		t.Fatal(err)
	}
	tag := jitcore.BuildProof(secretBytes(t), site, testKid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: testKid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})

	rs := mkreq(http.MethodPost, defaultPrefix+"/respond", proxy, body)
	rs.Header.Set("X-Forwarded-For", xff)
	if w := serve(h, rs); w.Code != http.StatusNoContent {
		t.Fatalf("respond: got %d want 204", w.Code)
	}

	// Same client, same chain -> admitted.
	ok := mkreq(http.MethodGet, "/dashboard", proxy, nil)
	ok.Header.Set("X-Forwarded-For", xff)
	if w := serve(h, ok); w.Body.String() != "UPSTREAM" {
		t.Errorf("the client that knocked should be admitted, got %d", w.Code)
	}

	// A different client behind the same proxies -> still dark.
	no := mkreq(http.MethodGet, "/dashboard", proxy, nil)
	no.Header.Set("X-Forwarded-For", "198.51.100.8, 192.168.1.1")
	if w := serve(h, no); w.Body.String() == "UPSTREAM" {
		t.Error("SECURITY: a different client inherited the grant")
	}
}

// Without trustForwarded, X-Forwarded-For is not evidence at all.
func TestDefaultIgnoresForwardedEntirely(t *testing.T) {
	h := build(t, nil) // trustForwarded off

	if r := knock(t, h, peer, testKid, secretBytes(t)); r.Code != http.StatusNoContent {
		t.Fatalf("knock: got %d", r.Code)
	}
	// The granted peer stays granted no matter what header it sends...
	lit := mkreq(http.MethodGet, "/dashboard", peer, nil)
	lit.Header.Set("X-Forwarded-For", "203.0.113.99")
	if w := serve(h, lit); w.Body.String() != "UPSTREAM" {
		t.Errorf("granted peer should be admitted regardless of XFF, got %d", w.Code)
	}
	// ...and a different peer cannot claim it.
	sp := mkreq(http.MethodGet, "/dashboard", "198.51.100.50:1234", nil)
	sp.Header.Set("X-Forwarded-For", "203.0.113.9")
	if w := serve(h, sp); w.Body.String() == "UPSTREAM" {
		t.Error("SECURITY: XFF was honored with trustForwarded off")
	}
}

// ---- the case that distinguishes the two algorithms ------------------------
//
// The tests above were written with a single untrusted entry in the chain, where
// left-most and right-most-untrusted coincide — so they passed against the
// vulnerable left-most implementation and proved nothing. The chain below has
// TWO untrusted entries: the client's forged one on the left, the real one the
// proxy appended on the right. Only the correct walk picks the right one.

func TestXFFWalkPicksRightmostUntrusted(t *testing.T) {
	const proxy = "10.0.0.1:5000"
	h := build(t, func(c *Config) {
		c.TrustForwarded = true
		c.TrustedProxies = []string{"10.0.0.0/8"}
	})
	// forged (left)          real client (right, appended by our proxy)
	xff := "203.0.113.200, 198.51.100.7"

	ch := mkreq(http.MethodGet, defaultPrefix+"/challenge", proxy, nil)
	ch.Header.Set("X-Forwarded-For", xff)
	chw := serve(h, ch)
	if chw.Code != http.StatusNoContent {
		t.Fatalf("challenge: %d", chw.Code)
	}
	nonceB64 := chw.Header().Get("X-JIT-Nonce")
	nonceRaw, err := jitcore.B64uDecode(nonceB64)
	if err != nil {
		t.Fatal(err)
	}
	tag := jitcore.BuildProof(secretBytes(t), site, testKid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: testKid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})
	rs := mkreq(http.MethodPost, defaultPrefix+"/respond", proxy, body)
	rs.Header.Set("X-Forwarded-For", xff)
	if w := serve(h, rs); w.Code != http.StatusNoContent {
		t.Fatalf("respond: %d", w.Code)
	}

	// The grant must belong to 198.51.100.7 (rightmost untrusted), NOT to the
	// forged 203.0.113.200. Prove it by presenting each address alone.
	real := mkreq(http.MethodGet, "/dashboard", proxy, nil)
	real.Header.Set("X-Forwarded-For", "198.51.100.7")
	if w := serve(h, real); w.Body.String() != "UPSTREAM" {
		t.Errorf("grant was not keyed on the rightmost-untrusted address (got %d)", w.Code)
	}
	forged := mkreq(http.MethodGet, "/dashboard", proxy, nil)
	forged.Header.Set("X-Forwarded-For", "203.0.113.200")
	if w := serve(h, forged); w.Body.String() == "UPSTREAM" {
		t.Error("SECURITY: grant was keyed on the client-supplied left-most entry")
	}
}

// Repeated header lines: the right-most entry OVERALL is the most recently
// appended, so a per-line walk would pick the wrong one.
func TestXFFWalkAcrossRepeatedHeaderLines(t *testing.T) {
	const proxy = "10.0.0.1:5000"
	h := build(t, func(c *Config) {
		c.TrustForwarded = true
		c.TrustedProxies = []string{"10.0.0.0/8"}
	})
	r := mkreq(http.MethodGet, defaultPrefix+"/challenge", proxy, nil)
	r.Header.Add("X-Forwarded-For", "203.0.113.200") // forged, first line
	r.Header.Add("X-Forwarded-For", "198.51.100.7")  // real, appended after
	if w := serve(h, r); w.Code != http.StatusNoContent {
		t.Fatalf("challenge: %d", w.Code)
	}
	ip, err := h.(*JITAccess).clientIP(r)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "198.51.100.7" {
		t.Errorf("across repeated header lines got %q, want 198.51.100.7", ip)
	}
}

// Mirror of the Caddy test: the register page is the only thing a browser
// without the extension ever sees at a registration link.
func TestRegisterLandingPage(t *testing.T) {
	h := build(t, nil)

	w := serve(h, mkreq(http.MethodGet, defaultPrefix+"/register?code=abc123", peer, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("register page while dark: got %d want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, jitcore.ExtensionReleasesURL) {
		t.Error("register page must link to the releases page")
	}
	if strings.Contains(body, "abc123") {
		t.Error("SECURITY: the single-use enrollment code was echoed into the page")
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("the URL carries a single-use code; referrer must be suppressed")
	}
	for _, q := range []string{"", "?code=", "?code=nope"} {
		w2 := serve(h, mkreq(http.MethodGet, defaultPrefix+"/register"+q, peer, nil))
		if w2.Code != http.StatusOK || w2.Body.String() != body {
			t.Errorf("register page differs for %q — that is an enrollment-code oracle", q)
		}
	}
	if w3 := serve(h, mkreq(http.MethodGet, defaultPrefix+"/registerx", peer, nil)); w3.Code == http.StatusOK {
		t.Error("only the exact /register path may be served")
	}
	if w4 := serve(h, mkreq(http.MethodPost, defaultPrefix+"/register", peer, nil)); w4.Code == http.StatusOK {
		t.Error("register is GET-only")
	}
}
