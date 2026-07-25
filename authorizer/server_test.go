// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	if w.Code != http.StatusNotFound {
		t.Errorf("stealth: got %d want 404", w.Code)
	}
	if w.Header().Get("X-JIT-Access") != "" {
		t.Error("stealth mode must not advertise the gate")
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
	if codes[http.StatusTooManyRequests] == 0 {
		t.Error("rate limit never triggered")
	}
	if codes[http.StatusNoContent] > 3 {
		t.Errorf("allowed %d challenges, limit was 3", codes[http.StatusNoContent])
	}
}

// ingress-nginx sends its auth subrequest with Host set to the AUTH service's
// address and the real origin only inside X-Original-URL. Without honouring
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
		t.Errorf("ingress-nginx style authz: got %d want 204 (X-Original-URL not honoured?)", w.Code)
	}

	// and the protocol endpoints must still be recognised through X-Original-URL
	r2 := req(http.MethodGet, "jit-authorizer.jit-system.svc.cluster.local", "/authz", proxyIP, map[string]string{
		"X-Original-URL": "https://" + svcA + s.config().URIPrefix + "/challenge",
	}, nil)
	if w := do(s, r2); w.Code != http.StatusNoContent {
		t.Errorf("protocol endpoint via X-Original-URL: got %d want 204", w.Code)
	}
}
