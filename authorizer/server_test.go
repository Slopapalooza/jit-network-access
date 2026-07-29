// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

// Black-box tests over the real HTTP surface. These mirror the probes in
// test/conformance/security_suite.py, which is engine-agnostic and will be run
// against this binary too — an adapter is only "supported" once it passes them
// (DESIGN §9 M2.5 / SECURITY-REVIEW H15).

const (
	testKid    = "kid_test"
	testSecret = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" // b64u(0x01 * 32)
	svcA       = "app.example.com"
	svcB       = "other.example.com"
	proxyIP    = "127.0.0.1:5555"    // inside trusted_proxies
	directIP   = "203.0.113.5:41000" // outside
)

func testServer(t *testing.T, mutate func(*Config)) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.AdminToken = "admin-secret"
	cfg.Tokens = []TokenConfig{{Kid: testKid, Secret: testSecret, Label: "test"}}
	cfg.Services = map[string]ServiceConfig{
		svcA: {Tokens: []string{testKid}},
		svcB: {Tokens: []string{}},
	}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.finalize(); err != nil {
		t.Fatalf("config: %v", err)
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	return s
}

func secretBytes(t *testing.T) []byte {
	t.Helper()
	b, err := jitcore.B64uDecode(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// req builds a forward-auth style request as a proxy would send it.
func req(method, host, path, remoteAddr string, hdrs map[string]string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, "https://"+host+path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, "https://"+host+path, nil)
	}
	r.RemoteAddr = remoteAddr
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	return r
}

func do(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// knock runs the full challenge->respond handshake and returns the respond
// response, so tests can assert on both the status and any Set-Cookie.
func knock(t *testing.T, s *Server, host, remoteAddr string, hdrs map[string]string, kid string, secret []byte) *httptest.ResponseRecorder {
	t.Helper()
	prefix := s.config().URIPrefix
	ch := do(s, req(http.MethodGet, host, prefix+"/challenge", remoteAddr, hdrs, nil))
	if ch.Code != http.StatusNoContent {
		t.Fatalf("challenge: got %d want 204 (body %s)", ch.Code, ch.Body.String())
	}
	nonceB64 := ch.Header().Get("X-JIT-Nonce")
	if nonceB64 == "" {
		t.Fatal("challenge returned no nonce")
	}
	nonceRaw, err := jitcore.B64uDecode(nonceB64)
	if err != nil {
		t.Fatalf("nonce decode: %v", err)
	}
	tag := jitcore.BuildProof(secret, host, kid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: kid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})
	return do(s, req(http.MethodPost, host, prefix+"/respond", remoteAddr, hdrs, body))
}

func authz(s *Server, host, remoteAddr, uri string, hdrs map[string]string) *httptest.ResponseRecorder {
	h := map[string]string{"X-Forwarded-Host": host, "X-Forwarded-Uri": uri}
	for k, v := range hdrs {
		h[k] = v
	}
	return do(s, req(http.MethodGet, "authorizer.internal", "/authz", remoteAddr, h, nil))
}

// ---- happy path ------------------------------------------------------------

func TestKnockGrantsAccess(t *testing.T) {
	s := testServer(t, nil)

	if w := authz(s, svcA, proxyIP, "/dashboard", nil); w.Code != http.StatusForbidden {
		t.Fatalf("pre-knock authz: got %d want 403", w.Code)
	}
	if w := knock(t, s, svcA, proxyIP, nil, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("knock: got %d want 204", w.Code)
	}
	if w := authz(s, svcA, proxyIP, "/dashboard", nil); w.Code != http.StatusNoContent {
		t.Errorf("post-knock authz: got %d want 204", w.Code)
	}
}

func TestInterstitialCarriesMarkerAndStealthDoesNot(t *testing.T) {
	s := testServer(t, nil)
	w := authz(s, svcA, proxyIP, "/", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d want 403", w.Code)
	}
	if w.Header().Get("X-JIT-Access") != JITMarker {
		t.Errorf("interstitial must carry the detection marker")
	}

	st := testServer(t, func(c *Config) {
		c.Services[svcA] = ServiceConfig{Tokens: []string{testKid}, FailureMode: FailStealth}
	})
	w = authz(st, svcA, proxyIP, "/", nil)
	// 403, NOT 404 — and this assertion used to say 404, which is how the bug
	// survived: it tested /authz as though it were a client-facing response.
	// It is a subrequest. nginx's auth_request accepts ONLY 401 and 403 as a
	// denial and turns anything else into a 500, so a stealth service behind
	// nginx or ingress-nginx answered 500 to every gated request — maximally
	// distinctive, and broken for legitimate users, who could no longer reach
	// the interstitial to knock. Found on ingress-nginx by the five-engine lab.
	if w.Code != http.StatusForbidden {
		t.Errorf("stealth /authz: got %d want 403 (nginx auth_request 500s on anything else)", w.Code)
	}
	if w.Header().Get("X-JIT-Access") != "" {
		t.Error("stealth mode must not advertise the gate")
	}
	// The client-facing surface is unchanged: a direct hit still 404s, because
	// there the Authorizer IS what the client sees.
	if d := do(st, req(http.MethodGet, svcA, "/nope", proxyIP, nil, nil)); d.Code != http.StatusNotFound {
		t.Errorf("stealth direct hit: got %d want 404", d.Code)
	}
}

// The nginx recipes re-proxy a denial to /authz and render THAT body to the
// client, so the interstitial page has to come back from the subrequest. When
// /authz was changed to always deny with 403 the body was dropped with it, and
// interstitial deployments served an empty 403. The lab could not see it: it
// only checks that the marker is present on that path.
func TestAuthzInterstitialStillCarriesThePage(t *testing.T) {
	s := testServer(t, nil) // svcA defaults to interstitial
	w := authz(s, svcA, proxyIP, "/", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d want 403", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Error("interstitial /authz returned no body — the recipes render this to the client")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("interstitial content-type %q, want text/html", ct)
	}

	// Stealth is the opposite: no marker and no body, so the recipe answers with
	// its own generic 404 instead.
	st := testServer(t, func(c *Config) {
		c.Services[svcA] = ServiceConfig{Tokens: []string{testKid}, FailureMode: FailStealth}
	})
	sw := authz(st, svcA, proxyIP, "/", nil)
	if sw.Body.Len() != 0 {
		t.Errorf("stealth /authz returned a body (%d bytes) — it would be rendered to the client", sw.Body.Len())
	}
}

// Every forward-auth denial must be a status nginx's auth_request understands.
// Anything else becomes a 500 at the edge, which is both an outage and a louder
// signal than the interstitial it was trying to avoid.
func TestAuthzDenialsAreAlwaysProxyReadable(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
	}{
		{"interstitial", FailInterstitial},
		{"stealth", FailStealth},
	} {
		s := testServer(t, func(c *Config) {
			c.Services[svcA] = ServiceConfig{Tokens: []string{testKid}, FailureMode: tc.mode}
		})
		for _, probe := range []struct{ name, host, uri string }{
			{"no grant", svcA, "/"},
			{"unknown service", "not-configured.example.com", "/"},
			{"bare prefix, not an endpoint", svcA, s.config().URIPrefix},
		} {
			w := authz(s, probe.host, proxyIP, probe.uri, nil)
			if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
				t.Errorf("%s/%s: /authz answered %d — nginx auth_request turns that into a 500",
					tc.name, probe.name, w.Code)
			}
		}
	}
}

// The knock endpoints must stay reachable on a dark service, or a locked-out
// device could never knock its way in.
func TestProtocolEndpointsReachableWhileDark(t *testing.T) {
	s := testServer(t, nil)
	w := authz(s, svcA, proxyIP, s.config().URIPrefix+"/challenge", nil)
	if w.Code != http.StatusNoContent {
		t.Errorf("authz for a protocol endpoint: got %d want 204", w.Code)
	}
}

// ---- IP provenance (the forward-auth threat model) -------------------------

// A client reaching the Authorizer directly must not be able to nominate its own
// grant key. This is the forged-XFF probe (SECURITY-REVIEW C2/R2) — the reason
// the plugin keys on the TCP peer, restated for the proxy boundary.
func TestForgedXFFFromUntrustedClientIsIgnored(t *testing.T) {
	s := testServer(t, nil)

	// victim knocks legitimately through the proxy, as 198.51.100.9
	victim := map[string]string{"X-Forwarded-For": "198.51.100.9", "X-Forwarded-Host": svcA}
	if w := knock(t, s, svcA, proxyIP, victim, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("victim knock: got %d", w.Code)
	}
	if w := authz(s, svcA, proxyIP, "/", map[string]string{"X-Forwarded-For": "198.51.100.9"}); w.Code != http.StatusNoContent {
		t.Fatalf("victim should be granted: got %d", w.Code)
	}

	// attacker connects DIRECTLY (untrusted peer) and claims the victim's IP,
	// via both the forwarded host and a bare Host header
	for _, r := range []*http.Request{
		req(http.MethodGet, "authorizer.internal", "/authz", directIP,
			map[string]string{"X-Forwarded-For": "198.51.100.9", "X-Forwarded-Host": svcA, "X-Forwarded-Uri": "/"}, nil),
		req(http.MethodGet, svcA, "/authz", directIP,
			map[string]string{"X-Forwarded-For": "198.51.100.9", "X-Forwarded-Uri": "/"}, nil),
	} {
		if w := do(s, r); w.Code == http.StatusNoContent {
			t.Fatal("SECURITY: forged X-Forwarded-For from an untrusted peer inherited a grant")
		}
	}

	// ...and cannot mint one for itself under a forged identity either
	ch := do(s, req(http.MethodGet, svcA, s.config().URIPrefix+"/challenge", directIP,
		map[string]string{"X-Forwarded-For": "198.51.100.9"}, nil))
	if ch.Code != http.StatusNoContent {
		t.Fatalf("direct challenge should still work (keyed on the peer): %d", ch.Code)
	}
	nonceRaw, _ := jitcore.B64uDecode(ch.Header().Get("X-JIT-Nonce"))
	// the nonce is bound to the peer, so it must not verify as the victim IP
	ok, _ := jitcore.VerifyNonce(s.nonceKey, nonceRaw, svcA, "198.51.100.9", s.now(), 60, 128)
	if ok {
		t.Error("SECURITY: nonce minted for a direct client verified under the forged IP")
	}
}

// The internal surfaces must refuse an untrusted peer outright, so an
// accidentally-exposed listener is not immediately exploitable.
func TestInternalSurfacesRefuseUntrustedPeers(t *testing.T) {
	s := testServer(t, nil)
	for _, path := range []string{"/authz", "/admin/grants", "/admin/metrics"} {
		w := do(s, req(http.MethodGet, svcA, path, directIP,
			map[string]string{"Authorization": "Bearer admin-secret"}, nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s from an untrusted peer: got %d want 403", path, w.Code)
		}
	}
}

// Behind a trusted proxy the forwarded header IS the client, and entries the
// client appended itself (which sit to the left) must not win.
func TestRightmostUntrustedWins(t *testing.T) {
	s := testServer(t, nil)
	cfg := s.config()

	r := req(http.MethodGet, "authorizer.internal", "/authz", proxyIP, map[string]string{
		// "1.2.3.4" is what the client injected; 198.51.100.9 is what the real
		// hop appended; 127.0.0.1 is our own proxy.
		"X-Forwarded-For": "1.2.3.4, 198.51.100.9, 127.0.0.1",
	}, nil)
	ip, viaProxy, err := cfg.ClientIP(r)
	if err != nil {
		t.Fatalf("ClientIP: %v", err)
	}
	if !viaProxy {
		t.Error("expected proxy mode")
	}
	if ip != "198.51.100.9" {
		t.Errorf("rightmost-untrusted: got %q want 198.51.100.9", ip)
	}
}

func TestDirectClientUsesPeerNotHeaders(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.finalize(); err != nil {
		t.Fatal(err)
	}
	r := req(http.MethodGet, "authorizer.internal", "/authz", directIP,
		map[string]string{"X-Forwarded-For": "1.2.3.4"}, nil)
	ip, viaProxy, err := cfg.ClientIP(r)
	if err != nil {
		t.Fatalf("ClientIP: %v", err)
	}
	if viaProxy {
		t.Error("peer outside trusted_proxies must not be proxy mode")
	}
	if ip != "203.0.113.5" {
		t.Errorf("direct client: got %q want the TCP peer 203.0.113.5", ip)
	}
}

// ---- knock protocol negatives ----------------------------------------------

func TestReplayRejected(t *testing.T) {
	s := testServer(t, nil)
	prefix := s.config().URIPrefix
	ch := do(s, req(http.MethodGet, svcA, prefix+"/challenge", proxyIP, nil, nil))
	nonceB64 := ch.Header().Get("X-JIT-Nonce")
	nonceRaw, _ := jitcore.B64uDecode(nonceB64)
	tag := jitcore.BuildProof(secretBytes(t), svcA, testKid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: testKid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})

	if w := do(s, req(http.MethodPost, svcA, prefix+"/respond", proxyIP, nil, body)); w.Code != http.StatusNoContent {
		t.Fatalf("first knock: got %d want 204", w.Code)
	}
	if w := do(s, req(http.MethodPost, svcA, prefix+"/respond", proxyIP, nil, body)); w.Code == http.StatusNoContent {
		t.Error("SECURITY: replayed nonce was accepted")
	}
}

func TestCrossServiceProofIsolation(t *testing.T) {
	s := testServer(t, func(c *Config) {
		c.Services[svcB] = ServiceConfig{Tokens: []string{testKid}} // same kid allowed on both
	})
	prefix := s.config().URIPrefix

	// take a nonce for service A, prove it, then present it to service B
	ch := do(s, req(http.MethodGet, svcA, prefix+"/challenge", proxyIP, nil, nil))
	nonceB64 := ch.Header().Get("X-JIT-Nonce")
	nonceRaw, _ := jitcore.B64uDecode(nonceB64)
	tag := jitcore.BuildProof(secretBytes(t), svcA, testKid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: testKid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})

	if w := do(s, req(http.MethodPost, svcB, prefix+"/respond", proxyIP, nil, body)); w.Code == http.StatusNoContent {
		t.Error("SECURITY: a proof minted for service A opened service B")
	}
}

func TestUnknownKidAndBadProofLookIdentical(t *testing.T) {
	s := testServer(t, nil)
	prefix := s.config().URIPrefix

	mk := func(kid string, secret []byte) *httptest.ResponseRecorder {
		ch := do(s, req(http.MethodGet, svcA, prefix+"/challenge", proxyIP, nil, nil))
		nonceB64 := ch.Header().Get("X-JIT-Nonce")
		nonceRaw, _ := jitcore.B64uDecode(nonceB64)
		tag := jitcore.BuildProof(secret, svcA, kid, nonceRaw)
		body, _ := json.Marshal(respondBody{V: 1, Kid: kid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})
		return do(s, req(http.MethodPost, svcA, prefix+"/respond", proxyIP, nil, body))
	}
	unknown := mk("kid_does_not_exist", secretBytes(t))
	badProof := mk(testKid, bytes.Repeat([]byte{0x09}, 32))

	if unknown.Code != badProof.Code {
		t.Errorf("kid-existence oracle: unknown kid %d vs bad proof %d", unknown.Code, badProof.Code)
	}
	if unknown.Body.String() != badProof.Body.String() {
		t.Error("kid-existence oracle: response bodies differ")
	}
}

func TestMalformedRespondNeverOpens(t *testing.T) {
	s := testServer(t, nil)
	prefix := s.config().URIPrefix
	for _, body := range []string{
		``, `{`, `{}`, `[]`, `null`,
		`{"v":1,"kid":"` + testKid + `","nonce":"AAAA","proof":"AAAA"}`,
		`{"v":1,"kid":"","nonce":"","proof":""}`,
		`{"v":1,"kid":"` + testKid + `","nonce":"!!!!","proof":"????"}`,
	} {
		w := do(s, req(http.MethodPost, svcA, prefix+"/respond", proxyIP, nil, []byte(body)))
		if w.Code == http.StatusNoContent {
			t.Errorf("SECURITY: malformed respond opened the gate: %q", body)
		}
	}
	// and nothing was granted
	if w := authz(s, svcA, proxyIP, "/", nil); w.Code == http.StatusNoContent {
		t.Error("SECURITY: a grant exists after only malformed knocks")
	}
}

// A kid that is registered but not on this service's allow-list must not open it.
func TestKidNotAllowedForService(t *testing.T) {
	s := testServer(t, nil) // svcB has an empty allow-list
	if w := knock(t, s, svcB, proxyIP, nil, testKid, secretBytes(t)); w.Code == http.StatusNoContent {
		t.Error("SECURITY: kid opened a service it is not allow-listed for")
	}
}

// ---- ip+cookie binding -----------------------------------------------------

func TestCookieBindingEndToEnd(t *testing.T) {
	s := testServer(t, func(c *Config) {
		c.Services[svcA] = ServiceConfig{Tokens: []string{testKid}, Binding: jitcore.BindingIPCookie}
	})

	w := knock(t, s, svcA, proxyIP, nil, testKid, secretBytes(t))
	if w.Code != http.StatusNoContent {
		t.Fatalf("knock: got %d want 204", w.Code)
	}
	var grantCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == GrantCookieName {
			grantCookie = c
		}
	}
	if grantCookie == nil {
		t.Fatal("ip+cookie binding must set the grant cookie")
	}
	if !grantCookie.HttpOnly || !grantCookie.Secure || grantCookie.SameSite != http.SameSiteStrictMode {
		t.Error("grant cookie must be HttpOnly, Secure and SameSite=Strict")
	}
	if grantCookie.Domain != "" {
		t.Error("grant cookie must be host-only (no Domain attribute)")
	}

	// same IP, no cookie -> denied (this is what ip-only binding would allow)
	if got := authz(s, svcA, proxyIP, "/", nil); got.Code == http.StatusNoContent {
		t.Error("SECURITY: ip+cookie grant honored without the cookie")
	}
	// same IP, wrong cookie -> denied
	if got := authz(s, svcA, proxyIP, "/", map[string]string{"Cookie": GrantCookieName + "=wrong"}); got.Code == http.StatusNoContent {
		t.Error("SECURITY: ip+cookie grant honored with a wrong cookie")
	}
	// same IP, right cookie -> allowed
	got := authz(s, svcA, proxyIP, "/", map[string]string{"Cookie": GrantCookieName + "=" + grantCookie.Value})
	if got.Code != http.StatusNoContent {
		t.Errorf("correct cookie should be admitted: got %d", got.Code)
	}
}

// ---- enrollment ------------------------------------------------------------

func TestEnrollCodeExchangeIsSingleUse(t *testing.T) {
	s := testServer(t, nil)
	prefix := s.config().URIPrefix

	body, _ := json.Marshal(map[string]any{"kid": testKid, "origins": []string{"https://" + svcA}, "server": "https://" + svcA})
	r := req(http.MethodPost, "authorizer.internal", "/admin/enroll-code", proxyIP,
		map[string]string{"Authorization": "Bearer admin-secret"}, body)
	w := do(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll-code: got %d body %s", w.Code, w.Body.String())
	}
	var minted map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	code, _ := minted["code"].(string)
	if code == "" {
		t.Fatal("no code minted")
	}
	if ru, _ := minted["register_url"].(string); !strings.Contains(ru, "/register?code=") {
		t.Errorf("register_url malformed: %q", ru)
	}

	ex, _ := json.Marshal(map[string]string{"code": code})
	first := do(s, req(http.MethodPost, svcA, prefix+"/enroll", proxyIP, nil, ex))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first exchange: got %d", first.Code)
	}
	if first.Header().Get("X-JIT-Secret") != testSecret {
		t.Error("exchange should return the device secret in a header")
	}
	if second := do(s, req(http.MethodPost, svcA, prefix+"/enroll", proxyIP, nil, ex)); second.Code == http.StatusNoContent {
		t.Error("SECURITY: enrollment code was reusable")
	}
}

// ---- admin -----------------------------------------------------------------

func TestAdminRequiresToken(t *testing.T) {
	s := testServer(t, nil)
	if w := do(s, req(http.MethodGet, "authorizer.internal", "/admin/grants", proxyIP, nil, nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated admin: got %d want 401", w.Code)
	}
	if w := do(s, req(http.MethodGet, "authorizer.internal", "/admin/grants", proxyIP,
		map[string]string{"Authorization": "Bearer wrong"}, nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong admin token: got %d want 401", w.Code)
	}
	if w := do(s, req(http.MethodGet, "authorizer.internal", "/admin/grants", proxyIP,
		map[string]string{"Authorization": "Bearer admin-secret"}, nil)); w.Code != http.StatusOK {
		t.Errorf("valid admin token: got %d want 200", w.Code)
	}
}

func TestRevokeTokenEvictsLiveGrants(t *testing.T) {
	s := testServer(t, nil)
	if w := knock(t, s, svcA, proxyIP, nil, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", w.Code)
	}
	if w := authz(s, svcA, proxyIP, "/", nil); w.Code != http.StatusNoContent {
		t.Fatal("precondition: should be granted")
	}
	body, _ := json.Marshal(map[string]string{"kid": testKid})
	w := do(s, req(http.MethodPost, "authorizer.internal", "/admin/revoke-token", proxyIP,
		map[string]string{"Authorization": "Bearer admin-secret"}, body))
	if w.Code != http.StatusOK {
		t.Fatalf("revoke-token: %d", w.Code)
	}
	if got := authz(s, svcA, proxyIP, "/", nil); got.Code == http.StatusNoContent {
		t.Error("SECURITY: grant survived revoke-token")
	}
}

// Removing a token from the registry (config reload) must evict live grants on
// the next request, not at TTL (SPEC §4.3).
func TestReloadDroppingTokenEvictsGrant(t *testing.T) {
	s := testServer(t, nil)
	if w := knock(t, s, svcA, proxyIP, nil, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", w.Code)
	}
	nc := DefaultConfig()
	nc.AdminToken = "admin-secret"
	nc.Tokens = nil // token removed by the admin
	nc.Services = map[string]ServiceConfig{svcA: {Tokens: []string{}}}
	if err := nc.finalize(); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(nc); err != nil {
		t.Fatal(err)
	}
	if got := authz(s, svcA, proxyIP, "/", nil); got.Code == http.StatusNoContent {
		t.Error("SECURITY: grant survived removal of its token from the registry")
	}
}

// An unconfigured service is denied rather than passed through: opting in is
// explicit, and the fail direction is closed.
func TestUnknownServiceDenied(t *testing.T) {
	s := testServer(t, nil)
	if w := authz(s, "not-configured.example.com", proxyIP, "/", nil); w.Code == http.StatusNoContent {
		t.Error("SECURITY: unconfigured service was allowed through")
	}
}

func TestRateLimitOnKnockEndpoints(t *testing.T) {
	s := testServer(t, func(c *Config) { c.RateLimit = 3 })
	prefix := s.config().URIPrefix
	codes := map[int]int{}
	for i := 0; i < 6; i++ {
		w := do(s, req(http.MethodGet, svcA, prefix+"/challenge", proxyIP, nil, nil))
		codes[w.Code]++
	}
	if codes[http.StatusNoContent] > 3 {
		t.Errorf("allowed %d challenges, limit was 3", codes[http.StatusNoContent])
	}
	if codes[http.StatusNoContent] == 6 {
		t.Error("rate limit never triggered")
	}
	// A throttled request is answered like every other rejection, never with a
	// distinctive 429 — see the no-oracle test below.
	if codes[http.StatusTooManyRequests] != 0 {
		t.Errorf("throttling leaked a distinguishable 429 (%d of them)", codes[http.StatusTooManyRequests])
	}
}

// PROTOCOL §2.1: /enroll MUST be rate-limited. It trades a one-time code for a
// long-term device secret, so it is the highest-value endpoint in the protocol,
// and it was the only knock endpoint with no throttle at all.
func TestRateLimitOnEnroll(t *testing.T) {
	s := testServer(t, func(c *Config) { c.RateLimit = 3 })
	prefix := s.config().URIPrefix
	granted := 0
	for i := 0; i < 25; i++ {
		w := do(s, req(http.MethodPost, svcA, prefix+"/enroll", proxyIP,
			map[string]string{"Content-Type": "application/json"}, []byte(`{"code":"guess"}`)))
		if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			granted++
		}
	}
	if granted != 0 {
		t.Errorf("%d enroll attempts were not rejected", granted)
	}
	// The limiter is shared with the other knock endpoints, so a burst against
	// /enroll must consume the same budget rather than running unmetered.
	if s.rl.allow("203.0.113.5", 3, s.now()) == false {
		t.Log("(different IP unaffected, as expected)")
	}
	ip := mustClientIP(t, s, proxyIP)
	if s.rl.allow(ip, 3, s.now()) {
		t.Error("/enroll attempts did not consume the rate-limit budget for that IP")
	}
}

// Stealth mode must not be discoverable by probing: a throttled protocol
// endpoint has to look exactly like any other path. Before this, the protocol
// paths answered 429 while everything else answered 404, so a few requests
// located the gate.
func TestStealthModeGivesNoEndpointOracle(t *testing.T) {
	s := testServer(t, func(c *Config) {
		c.RateLimit = 2
		c.Services[svcA] = ServiceConfig{Tokens: []string{testKid}, FailureMode: FailStealth}
	})
	prefix := s.config().URIPrefix

	var protocolCodes []int
	for i := 0; i < 5; i++ {
		protocolCodes = append(protocolCodes, do(s, req(http.MethodGet, svcA, prefix+"/challenge", proxyIP, nil, nil)).Code)
	}
	unknown := do(s, req(http.MethodGet, svcA, prefix+"/nope", proxyIP, nil, nil)).Code

	for i, c := range protocolCodes {
		if c == http.StatusNoContent {
			continue // a successful challenge is allowed to differ
		}
		if c != unknown {
			t.Errorf("stealth oracle: rejected challenge #%d answered %d but an unknown path answered %d",
				i, c, unknown)
		}
	}
}

func mustClientIP(t *testing.T, s *Server, remoteAddr string) string {
	t.Helper()
	r := req(http.MethodGet, svcA, "/", remoteAddr, nil, nil)
	ip, _, err := s.config().ClientIP(r)
	if err != nil {
		t.Fatalf("client ip: %v", err)
	}
	return ip
}

// ingress-nginx sends its auth subrequest with Host set to the AUTH service's
// address and the real origin only inside X-Original-URL. Without honoring
// that header every Kubernetes deployment resolves to the wrong service name
// and denies everything — found by running the real thing under kind.
func TestIngressNginxOriginalURL(t *testing.T) {
	s := testServer(t, nil)

	// knock the normal way (proxied request carries the real Host)
	if w := knock(t, s, svcA, proxyIP, nil, testKid, secretBytes(t)); w.Code != http.StatusNoContent {
		t.Fatalf("knock: got %d", w.Code)
	}

	// ...then authorize the way ingress-nginx does it
	r := req(http.MethodGet, "jit-authorizer.jit-system.svc.cluster.local", "/authz", proxyIP, map[string]string{
		"X-Original-URL":    "https://" + svcA + "/dashboard?x=1",
		"X-Original-Method": "GET",
		"X-Forwarded-For":   "203.0.113.5",
	}, nil)
	// the knock above came from the proxy peer with no XFF, so key on the same
	r.Header.Del("X-Forwarded-For")
	if w := do(s, r); w.Code != http.StatusNoContent {
		t.Errorf("ingress-nginx style authz: got %d want 204 (X-Original-URL not honored?)", w.Code)
	}

	// and the protocol endpoints must still be recognized through X-Original-URL
	r2 := req(http.MethodGet, "jit-authorizer.jit-system.svc.cluster.local", "/authz", proxyIP, map[string]string{
		"X-Original-URL": "https://" + svcA + s.config().URIPrefix + "/challenge",
	}, nil)
	if w := do(s, r2); w.Code != http.StatusNoContent {
		t.Errorf("protocol endpoint via X-Original-URL: got %d want 204", w.Code)
	}
}

// admin_listen was parsed, documented as isolating the admin API on its own
// listener, and then never read — so an operator who set it silently kept
// /admin/* on the main port alongside the protocol endpoints.
func TestAdminListenMovesAdminOffTheMainListener(t *testing.T) {
	// default: no admin_listen -> /admin is on the main handler
	s := testServer(t, nil)
	w := do(s, req(http.MethodGet, svcA, "/admin/metrics", proxyIP,
		map[string]string{"Authorization": "Bearer admin-secret"}, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("default: /admin/metrics on the main listener: got %d want 200", w.Code)
	}

	// configured: /admin must be GONE from the main handler...
	s2 := testServer(t, func(c *Config) { c.AdminListen = "127.0.0.1:9999" })
	w2 := do(s2, req(http.MethodGet, svcA, "/admin/metrics", proxyIP,
		map[string]string{"Authorization": "Bearer admin-secret"}, nil))
	if w2.Code == http.StatusOK {
		t.Error("admin_listen set but /admin/metrics still served on the main listener")
	}

	// ...and present on the admin handler.
	ah := s2.AdminHandler()
	if ah == nil {
		t.Fatal("admin_listen set but AdminHandler() returned nil")
	}
	rec := httptest.NewRecorder()
	ar := req(http.MethodGet, svcA, "/admin/metrics", proxyIP,
		map[string]string{"Authorization": "Bearer admin-secret"}, nil)
	ah.ServeHTTP(rec, ar)
	if rec.Code != http.StatusOK {
		t.Errorf("admin handler: got %d want 200", rec.Code)
	}

	// The admin listener still refuses untrusted peers and bad tokens.
	rec2 := httptest.NewRecorder()
	ah.ServeHTTP(rec2, req(http.MethodGet, svcA, "/admin/metrics", directIP,
		map[string]string{"Authorization": "Bearer admin-secret"}, nil))
	if rec2.Code == http.StatusOK {
		t.Error("SECURITY: admin listener served an untrusted peer")
	}
	rec3 := httptest.NewRecorder()
	ah.ServeHTTP(rec3, req(http.MethodGet, svcA, "/admin/metrics", proxyIP,
		map[string]string{"Authorization": "Bearer wrong"}, nil))
	if rec3.Code == http.StatusOK {
		t.Error("SECURITY: admin listener accepted a wrong token")
	}
}

// A SIGHUP that changes uri_prefix must actually move the endpoints. The routing
// table used to be captured once at startup, so the mux kept serving the OLD
// prefix while /authz carved out the NEW one — nobody could knock, and the
// service locked itself out until a restart.
func TestReloadRebuildsRoutingTable(t *testing.T) {
	s := testServer(t, nil)
	h := s.Handler() // built once, as main.go does

	serve := func(path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(http.MethodGet, svcA, path, proxyIP, nil, nil))
		return w.Code
	}
	if serve("/.well-known/jit-access/challenge") != http.StatusNoContent {
		t.Fatal("precondition: default prefix should serve a challenge")
	}

	cfg2 := DefaultConfig()
	cfg2.AdminToken = "admin-secret"
	cfg2.URIPrefix = "/.well-known/jit2"
	cfg2.Tokens = []TokenConfig{{Kid: testKid, Secret: testSecret}}
	cfg2.Services = map[string]ServiceConfig{svcA: {Tokens: []string{testKid}}}
	if err := cfg2.finalize(); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg2); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if got := serve("/.well-known/jit2/challenge"); got != http.StatusNoContent {
		t.Errorf("new prefix after reload: got %d want 204 (stale mux)", got)
	}
	if got := serve("/.well-known/jit-access/challenge"); got == http.StatusNoContent {
		t.Error("old prefix still served a challenge after reload")
	}
}

// listen/admin_listen cannot be applied without rebinding sockets, so a reload
// that changes them must be refused rather than silently half-applied.
func TestReloadRefusesListenChange(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mutol func(*Config)
	}{
		{"listen", func(c *Config) { c.Listen = "127.0.0.1:9" }},
		{"admin_listen", func(c *Config) { c.AdminListen = "127.0.0.1:9" }},
	} {
		s := testServer(t, nil)
		cfg2 := DefaultConfig()
		cfg2.AdminToken = "admin-secret"
		cfg2.Tokens = []TokenConfig{{Kid: testKid, Secret: testSecret}}
		cfg2.Services = map[string]ServiceConfig{svcA: {Tokens: []string{testKid}}}
		tc.mutol(cfg2)
		if err := cfg2.finalize(); err != nil {
			t.Fatal(err)
		}
		if err := s.Reload(cfg2); err == nil {
			t.Errorf("%s change: reload should be refused, not half-applied", tc.name)
		}
	}
}

// Stealth mode must be indistinguishable from an unrouted path, including on the
// method-not-allowed and rate-limited paths, and in the BODY not just the status.
func TestStealthIsByteIdenticalToPlatform404(t *testing.T) {
	s := testServer(t, func(c *Config) {
		c.RateLimit = 1
		c.Services[svcA] = ServiceConfig{Tokens: []string{testKid}, FailureMode: FailStealth}
	})
	prefix := s.config().URIPrefix

	shape := func(w *httptest.ResponseRecorder) string {
		return w.Result().Status + "|" + w.Header().Get("Content-Type") +
			"|" + w.Header().Get("Cache-Control") + "|" + w.Body.String()
	}
	unrouted := shape(do(s, req(http.MethodGet, svcA, "/definitely-not-a-route", proxyIP, nil, nil)))

	cases := map[string]*httptest.ResponseRecorder{
		"wrong method on challenge": do(s, req(http.MethodPost, svcA, prefix+"/challenge", proxyIP, nil, nil)),
		"unknown path under prefix": do(s, req(http.MethodGet, svcA, prefix+"/nope", proxyIP, nil, nil)),
	}
	// exhaust the limiter, then a throttled challenge
	for i := 0; i < 4; i++ {
		do(s, req(http.MethodGet, svcA, prefix+"/challenge", proxyIP, nil, nil))
	}
	cases["rate-limited challenge"] = do(s, req(http.MethodGet, svcA, prefix+"/challenge", proxyIP, nil, nil))

	for name, w := range cases {
		if got := shape(w); got != unrouted {
			t.Errorf("%s is distinguishable from an unrouted path:\n  got      %q\n  unrouted %q", name, got, unrouted)
		}
	}
}

// Two json keys that canonicalize alike used to collapse into one map slot, and
// which allow-list / failure_mode survived was decided by Go's randomized map
// iteration — so the effective policy changed from one process start to the next.
func TestCollidingServiceNamesRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tokens = []TokenConfig{{Kid: testKid, Secret: testSecret}}
	cfg.Services = map[string]ServiceConfig{
		"app.example.com":      {Tokens: []string{testKid}, FailureMode: FailStealth},
		"app.example.com:8443": {Tokens: []string{"*"}, FailureMode: FailInterstitial},
	}
	if err := cfg.finalize(); err == nil {
		t.Fatal("two services canonicalizing to one name must be refused, not resolved by map order")
	}
	// a trailing dot is the same collision
	cfg2 := DefaultConfig()
	cfg2.Tokens = []TokenConfig{{Kid: testKid, Secret: testSecret}}
	cfg2.Services = map[string]ServiceConfig{
		"app.example.com":  {Tokens: []string{testKid}},
		"App.Example.com.": {Tokens: []string{"*"}},
	}
	if err := cfg2.finalize(); err == nil {
		t.Error("case/trailing-dot collision must be refused too")
	}
}

// Policy lookup must be deterministic across repeated construction.
func TestServiceLookupIsDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := testServer(t, func(c *Config) {
			c.Services[svcA] = ServiceConfig{Tokens: []string{testKid}, FailureMode: FailStealth}
		})
		svc, ok := s.config().Service(svcA)
		if !ok || svc.FailureMode != FailStealth {
			t.Fatalf("iteration %d: got %+v ok=%v, want stealth", i, svc, ok)
		}
		if !s.registry().AllowedForService(testKid, svcA) {
			t.Fatalf("iteration %d: configured kid not allowed", i)
		}
		if s.registry().AllowedForService("kid_never_listed", svcA) {
			t.Fatalf("iteration %d: unlisted kid was allowed", i)
		}
	}
}

// A registration link is only ever SERVED to a browser without the extension —
// an installed extension intercepts the navigation client-side. So this page is
// the one chance to tell that user how to install it.
func TestRegisterLandingPage(t *testing.T) {
	s := testServer(t, nil)
	prefix := s.config().URIPrefix

	w := do(s, req(http.MethodGet, svcA, prefix+"/register?code=abc123", proxyIP, nil, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("register page: got %d want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, jitcore.ExtensionReleasesURL) {
		t.Error("register page must link to the releases page")
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("the URL carries a single-use code; referrer must be suppressed")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("register page must not be cached")
	}
	// The code is a single-use credential: it must not be reflected into the DOM.
	if strings.Contains(body, "abc123") {
		t.Error("SECURITY: the enrollment code was echoed into the page")
	}

	// No oracle: a bogus, absent or expired code must produce the SAME page.
	for _, q := range []string{"", "?code=", "?code=definitely-not-a-real-code", "?code=abc123&x=<script>"} {
		w2 := do(s, req(http.MethodGet, svcA, prefix+"/register"+q, proxyIP, nil, nil))
		if w2.Code != http.StatusOK || w2.Body.String() != body {
			t.Errorf("register page differs for %q — that is an enrollment-code oracle", q)
		}
	}
}

// /authz must let the registration link through while the service is dark, or
// nobody could reach the install instructions on a gated host.
func TestRegisterReachableWhileDark(t *testing.T) {
	s := testServer(t, nil)
	uri := s.config().URIPrefix + "/register?code=abc"
	w := do(s, req(http.MethodGet, "x", "/authz", proxyIP, map[string]string{
		"X-Forwarded-Host": svcA, "X-Forwarded-Uri": uri,
	}, nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("authz for the register link: got %d want 204", w.Code)
	}
}

// Reclamation. Expiry is lazy on the read path so nothing here is required for
// correctness — but without it the maps only grow, and an unauthenticated client
// controls how fast. Untested until now.
func TestSweepersReclaim(t *testing.T) {
	s := testServer(t, func(c *Config) { c.RateLimit = 2 })
	now := s.now()

	// Rate-limit entries for many distinct sources, as a /64 sweep would create.
	for i := 0; i < 500; i++ {
		s.rl.allow("2001:db8::"+strconv.Itoa(i), 10, now)
	}
	if got := len(s.rl.window); got != 500 {
		t.Fatalf("precondition: %d limiter entries, want 500", got)
	}
	s.rl.sweep(now + 61) // a minute later every window is finished
	if got := len(s.rl.window); got != 0 {
		t.Errorf("rate-limiter sweep left %d entries", got)
	}

	// Grants, spent nonces and enrollment codes.
	s.grants.Put(&jitcore.Grant{V: 1, Kid: testKid, Service: svcA, IP: "1.2.3.4",
		Binding: jitcore.BindingIP, Issued: now, Exp: now + 10})
	s.nonces.Claim("some-nonce", now, 10)
	s.codes.Put("some-code", &jitcore.EnrollCode{Kid: testKid, Exp: now + 10})

	if n := s.grants.Sweep(now + 5); n != 0 {
		t.Errorf("swept %d live grants — expiry is not being respected", n)
	}
	if n := s.grants.Sweep(now + 11); n != 1 {
		t.Errorf("expired grant not reclaimed: swept %d", n)
	}
	if n := s.nonces.Sweep(now + 11); n != 1 {
		t.Errorf("spent nonce not reclaimed: swept %d", n)
	}
	if n := s.codes.Sweep(now + 11); n != 1 {
		t.Errorf("expired enrollment code not reclaimed: swept %d", n)
	}

	// A burned nonce must stay burned for its whole TTL, or replay reopens.
	s2 := testServer(t, nil)
	if !s2.nonces.Claim("n", now, 60) {
		t.Fatal("first claim should succeed")
	}
	if s2.nonces.Claim("n", now+30, 60) {
		t.Error("SECURITY: a spent nonce was reclaimable inside its TTL")
	}
	s2.nonces.Sweep(now + 30) // sweeping must not un-burn it either
	if s2.nonces.Claim("n", now+31, 60) {
		t.Error("SECURITY: sweeping released a nonce still inside its TTL")
	}
}

// StartSweeper wires the above onto a ticker and must stop when told.
func TestStartSweeperStops(t *testing.T) {
	s := testServer(t, nil)
	stop := make(chan struct{})
	s.StartSweeper(stop)
	close(stop)
	// No assertion beyond "does not panic or leak past the stop signal"; the
	// reclamation itself is covered above.
}
