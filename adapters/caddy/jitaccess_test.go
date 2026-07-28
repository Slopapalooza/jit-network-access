// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

const (
	testKid    = "kid_caddy"
	testSecret = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" // b64u(0x01 * 32)
	site       = "app.example.com"
	peer       = "203.0.113.7:44000"
)

// upstream stands in for the protected site; reaching it means the gate opened.
var upstream = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("UPSTREAM"))
	return nil
})

// The grant/nonce stores are process-wide by design, so that a Caddy config
// reload does not drop live grants. Tests therefore need an explicit reset to
// stay independent of each other's knocks.
func resetShared(t *testing.T) {
	t.Helper()
	if err := shared(); err != nil {
		t.Fatalf("shared init: %v", err)
	}
	sharedGrants = jitcore.NewGrantStore()
	sharedNonces = jitcore.NewNonceStore()
	sharedCodes = jitcore.NewEnrollStore()
	sharedRL = newRateLimiter()
}

func newHandler(t *testing.T, mutate func(*JITAccess)) *JITAccess {
	t.Helper()
	resetShared(t)
	j := &JITAccess{
		Tokens: []Token{{Kid: testKid, Secret: testSecret, Label: "test"}},
		Allow:  []string{testKid},
	}
	if mutate != nil {
		mutate(j)
	}
	if err := j.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := j.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return j
}

func serve(t *testing.T, j *JITAccess, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	if err := j.ServeHTTP(w, r, upstream); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	return w
}

func mkreq(method, path, remote string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, "https://"+site+path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, "https://"+site+path, nil)
	}
	r.RemoteAddr = remote
	return r
}

func secretBytes(t *testing.T) []byte {
	t.Helper()
	b, err := jitcore.B64uDecode(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func knock(t *testing.T, j *JITAccess, remote string, kid string, secret []byte) *httptest.ResponseRecorder {
	t.Helper()
	ch := serve(t, j, mkreq(http.MethodGet, j.Prefix+"/challenge", remote, nil))
	if ch.Code != http.StatusNoContent {
		t.Fatalf("challenge: got %d want 204", ch.Code)
	}
	nonceB64 := ch.Header().Get("X-JIT-Nonce")
	nonceRaw, err := jitcore.B64uDecode(nonceB64)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	tag := jitcore.BuildProof(secret, site, kid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: kid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})
	return serve(t, j, mkreq(http.MethodPost, j.Prefix+"/respond", remote, body))
}

func TestSiteIsDarkUntilKnock(t *testing.T) {
	j := newHandler(t, nil)

	w := serve(t, j, mkreq(http.MethodGet, "/dashboard", peer, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("pre-knock: got %d want 403", w.Code)
	}
	if w.Body.String() == "UPSTREAM" {
		t.Fatal("SECURITY: request reached the upstream while dark")
	}
	if w.Header().Get("X-JIT-Access") != jitMarker {
		t.Error("interstitial must carry the detection marker")
	}

	if r := knock(t, j, peer, testKid, secretBytes(t)); r.Code != http.StatusNoContent {
		t.Fatalf("knock: got %d want 204", r.Code)
	}

	w = serve(t, j, mkreq(http.MethodGet, "/dashboard", peer, nil))
	if w.Code != http.StatusOK || w.Body.String() != "UPSTREAM" {
		t.Errorf("post-knock: got %d %q, want 200 UPSTREAM", w.Code, w.Body.String())
	}
}

// The grant is keyed on the TCP peer, so another client on another address is
// still dark even after someone else knocks.
func TestGrantIsPerClientIP(t *testing.T) {
	j := newHandler(t, nil)
	if r := knock(t, j, "203.0.113.20:1000", testKid, secretBytes(t)); r.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", r.Code)
	}
	if w := serve(t, j, mkreq(http.MethodGet, "/", "203.0.113.20:1000", nil)); w.Code != http.StatusOK {
		t.Fatalf("knocker should be admitted: %d", w.Code)
	}
	if w := serve(t, j, mkreq(http.MethodGet, "/", "198.51.100.77:2000", nil)); w.Code == http.StatusOK {
		t.Error("SECURITY: a different client IP inherited the grant")
	}
}

// A client cannot move its own grant key with a header while trust_forwarded is
// off (the default).
func TestForgedForwardedHeaderIgnoredByDefault(t *testing.T) {
	j := newHandler(t, nil)
	if r := knock(t, j, "203.0.113.30:1000", testKid, secretBytes(t)); r.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", r.Code)
	}
	r := mkreq(http.MethodGet, "/", "198.51.100.99:3000", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.30")
	if w := serve(t, j, r); w.Code == http.StatusOK {
		t.Error("SECURITY: forged X-Forwarded-For inherited a grant")
	}
}

func TestStealthMode(t *testing.T) {
	j := newHandler(t, func(j *JITAccess) { j.FailureMode = failStealth })
	w := serve(t, j, mkreq(http.MethodGet, "/", peer, nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("stealth: got %d want 404", w.Code)
	}
	if w.Header().Get("X-JIT-Access") != "" {
		t.Error("stealth must not advertise the gate")
	}
}

func TestReplayRejected(t *testing.T) {
	j := newHandler(t, nil)
	remote := "203.0.113.40:1000"
	ch := serve(t, j, mkreq(http.MethodGet, j.Prefix+"/challenge", remote, nil))
	nonceB64 := ch.Header().Get("X-JIT-Nonce")
	nonceRaw, _ := jitcore.B64uDecode(nonceB64)
	tag := jitcore.BuildProof(secretBytes(t), site, testKid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: testKid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})

	if w := serve(t, j, mkreq(http.MethodPost, j.Prefix+"/respond", remote, body)); w.Code != http.StatusNoContent {
		t.Fatalf("first knock: %d", w.Code)
	}
	if w := serve(t, j, mkreq(http.MethodPost, j.Prefix+"/respond", remote, body)); w.Code == http.StatusNoContent {
		t.Error("SECURITY: replayed nonce accepted")
	}
}

func TestUnknownKidAndBadProofLookIdentical(t *testing.T) {
	j := newHandler(t, nil)
	mk := func(kid string, secret []byte) *httptest.ResponseRecorder {
		remote := "203.0.113.50:1000"
		ch := serve(t, j, mkreq(http.MethodGet, j.Prefix+"/challenge", remote, nil))
		nonceB64 := ch.Header().Get("X-JIT-Nonce")
		nonceRaw, _ := jitcore.B64uDecode(nonceB64)
		tag := jitcore.BuildProof(secret, site, kid, nonceRaw)
		body, _ := json.Marshal(respondBody{V: 1, Kid: kid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})
		return serve(t, j, mkreq(http.MethodPost, j.Prefix+"/respond", remote, body))
	}
	unknown := mk("kid_nope", secretBytes(t))
	bad := mk(testKid, bytes.Repeat([]byte{9}, 32))
	if unknown.Code != bad.Code || unknown.Body.String() != bad.Body.String() {
		t.Error("kid-existence oracle: unknown kid and bad proof differ")
	}
}

func TestMalformedRespondNeverOpens(t *testing.T) {
	j := newHandler(t, nil)
	remote := "203.0.113.60:1000"
	for _, b := range []string{``, `{`, `{}`, `null`, `[]`,
		`{"v":1,"kid":"` + testKid + `","nonce":"AAAA","proof":"AAAA"}`} {
		if w := serve(t, j, mkreq(http.MethodPost, j.Prefix+"/respond", remote, []byte(b))); w.Code == http.StatusNoContent {
			t.Errorf("SECURITY: malformed respond opened the gate: %q", b)
		}
	}
	if w := serve(t, j, mkreq(http.MethodGet, "/", remote, nil)); w.Code == http.StatusOK {
		t.Error("SECURITY: a grant exists after only malformed knocks")
	}
}

func TestNonAllowedKidRejected(t *testing.T) {
	j := newHandler(t, func(j *JITAccess) {
		j.Tokens = append(j.Tokens, Token{Kid: "kid_other", Secret: testSecret})
		j.Allow = []string{testKid} // kid_other registered but not allowed here
	})
	if r := knock(t, j, "203.0.113.70:1000", "kid_other", secretBytes(t)); r.Code == http.StatusNoContent {
		t.Error("SECURITY: a kid not on the allow-list opened the site")
	}
}

func TestCookieBinding(t *testing.T) {
	j := newHandler(t, func(j *JITAccess) { j.Binding = jitcore.BindingIPCookie })
	remote := "203.0.113.80:1000"

	r := knock(t, j, remote, testKid, secretBytes(t))
	if r.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", r.Code)
	}
	var ck *http.Cookie
	for _, c := range r.Result().Cookies() {
		if c.Name == grantCookieName {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("ip+cookie binding must set the grant cookie")
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Domain != "" {
		t.Error("grant cookie must be HttpOnly, Secure, SameSite=Strict and host-only")
	}

	if w := serve(t, j, mkreq(http.MethodGet, "/", remote, nil)); w.Code == http.StatusOK {
		t.Error("SECURITY: ip+cookie grant honored without the cookie")
	}
	withCookie := mkreq(http.MethodGet, "/", remote, nil)
	withCookie.AddCookie(&http.Cookie{Name: grantCookieName, Value: ck.Value})
	if w := serve(t, j, withCookie); w.Code != http.StatusOK {
		t.Errorf("correct cookie should be admitted: %d", w.Code)
	}
	wrong := mkreq(http.MethodGet, "/", remote, nil)
	wrong.AddCookie(&http.Cookie{Name: grantCookieName, Value: "nope"})
	if w := serve(t, j, wrong); w.Code == http.StatusOK {
		t.Error("SECURITY: wrong cookie admitted")
	}
}

func TestEnrollCodeSingleUse(t *testing.T) {
	j := newHandler(t, nil)
	MintEnrollCode("code-abc", testKid, []string{"https://" + site}, now()+3600)

	body, _ := json.Marshal(map[string]string{"code": "code-abc"})
	first := serve(t, j, mkreq(http.MethodPost, j.Prefix+"/enroll", peer, body))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first exchange: %d", first.Code)
	}
	if first.Header().Get("X-JIT-Secret") != testSecret {
		t.Error("exchange must return the device secret")
	}
	if second := serve(t, j, mkreq(http.MethodPost, j.Prefix+"/enroll", peer, body)); second.Code == http.StatusNoContent {
		t.Error("SECURITY: enrollment code was reusable")
	}
}

// Any other path under the protocol prefix stays dark rather than falling
// through to the upstream.
func TestOtherPrefixPathsStayDark(t *testing.T) {
	j := newHandler(t, nil)
	for _, p := range []string{j.Prefix, j.Prefix + "/", j.Prefix + "/register", j.Prefix + "/../secret"} {
		w := serve(t, j, mkreq(http.MethodGet, p, peer, nil))
		if w.Body.String() == "UPSTREAM" {
			t.Errorf("SECURITY: %s reached the upstream", p)
		}
	}
}

func TestValidateRejectsUnusableConfig(t *testing.T) {
	j := &JITAccess{Tokens: []Token{{Kid: testKid, Secret: testSecret}}} // no allow-list
	if err := j.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if err := j.Validate(); err == nil {
		t.Error("a handler with no allow-list should not validate")
	}

	j2 := &JITAccess{Allow: []string{testKid}} // no tokens
	if err := j2.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if err := j2.Validate(); err == nil {
		t.Error("a handler with no tokens should not validate")
	}
}

func TestCaddyfileParsing(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
jit_access {
    prefix /.well-known/jit-access
    grant_ttl 2h
    nonce_ttl 30s
    failure_mode stealth
    binding ip+cookie
    ipv6_prefix 64
    rate_limit 25
    trust_forwarded
    trusted_proxies 10.0.0.0/8 192.168.1.5
    token kid_a AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE ops laptop
    allow kid_a
}`)
	var j JITAccess
	if err := j.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if j.FailureMode != failStealth || j.Binding != jitcore.BindingIPCookie {
		t.Errorf("mode/binding: %q %q", j.FailureMode, j.Binding)
	}
	if j.IPv6Prefix != 64 || j.RateLimit != 25 || !j.TrustForwarded {
		t.Errorf("numeric/bool options not parsed: %+v", j)
	}
	if len(j.TrustedProxies) != 2 || j.TrustedProxies[0] != "10.0.0.0/8" {
		t.Errorf("trusted_proxies not parsed: %+v", j.TrustedProxies)
	}
	if len(j.Tokens) != 1 || j.Tokens[0].Kid != "kid_a" || j.Tokens[0].Label != "ops laptop" {
		t.Errorf("token not parsed: %+v", j.Tokens)
	}
	if len(j.Allow) != 1 || j.Allow[0] != "kid_a" {
		t.Errorf("allow not parsed: %+v", j.Allow)
	}
	if err := j.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision from caddyfile: %v", err)
	}
	if err := j.Validate(); err != nil {
		t.Fatalf("validate from caddyfile: %v", err)
	}
}
