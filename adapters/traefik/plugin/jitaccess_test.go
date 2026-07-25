// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jitcore "github.com/Slopapalooza/jit-network-access/adapters/traefik/plugin/internal/jitcore"
)

// These run twice: normally under `go test`, and interpreted under
// `yaegi test .` — the latter is what proves the plugin actually works inside
// Traefik, which never compiles it.

const (
	testKid    = "kid_traefik"
	testSecret = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" // b64u(0x01 * 32)
	site       = "app.example.com"
	peer       = "203.0.113.9:44000"
)

func upstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("UPSTREAM"))
	})
}

// The stores are process-wide by design (so a Traefik reload keeps grants), so
// tests must reset them to stay independent.
func reset(t *testing.T) {
	t.Helper()
	if err := shared(); err != nil {
		t.Fatalf("shared: %v", err)
	}
	sharedGrants = jitcore.NewGrantStore()
	sharedNonces = jitcore.NewNonceStore()
	sharedCodes = jitcore.NewEnrollStore()
	sharedRL = newRateLimiter()
}

func build(t *testing.T, mutate func(*Config)) http.Handler {
	t.Helper()
	reset(t)
	cfg := CreateConfig()
	cfg.Tokens = []Token{{Kid: testKid, Secret: testSecret, Label: "test"}}
	cfg.Allow = []string{testKid}
	if mutate != nil {
		mutate(cfg)
	}
	h, err := New(context.Background(), upstream(), cfg, "jit")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
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

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func secretBytes(t *testing.T) []byte {
	t.Helper()
	b, err := jitcore.B64uDecode(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func knock(t *testing.T, h http.Handler, remote, kid string, secret []byte) *httptest.ResponseRecorder {
	t.Helper()
	ch := serve(h, mkreq(http.MethodGet, defaultPrefix+"/challenge", remote, nil))
	if ch.Code != http.StatusNoContent {
		t.Fatalf("challenge: got %d want 204", ch.Code)
	}
	nonceB64 := ch.Header().Get("X-JIT-Nonce")
	nonceRaw, err := jitcore.B64uDecode(nonceB64)
	if err != nil {
		t.Fatalf("nonce decode: %v", err)
	}
	tag := jitcore.BuildProof(secret, site, kid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: kid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})
	return serve(h, mkreq(http.MethodPost, defaultPrefix+"/respond", remote, body))
}

func TestDarkUntilKnock(t *testing.T) {
	h := build(t, nil)

	w := serve(h, mkreq(http.MethodGet, "/dashboard", peer, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("pre-knock: got %d want 403", w.Code)
	}
	if w.Body.String() == "UPSTREAM" {
		t.Fatal("SECURITY: reached the upstream while dark")
	}
	if w.Header().Get("X-JIT-Access") != jitMarker {
		t.Error("interstitial must carry the detection marker")
	}

	if r := knock(t, h, peer, testKid, secretBytes(t)); r.Code != http.StatusNoContent {
		t.Fatalf("knock: got %d want 204", r.Code)
	}
	w = serve(h, mkreq(http.MethodGet, "/dashboard", peer, nil))
	if w.Code != http.StatusOK || w.Body.String() != "UPSTREAM" {
		t.Errorf("post-knock: got %d %q", w.Code, w.Body.String())
	}
}

func TestGrantIsPerClientIP(t *testing.T) {
	h := build(t, nil)
	if r := knock(t, h, "203.0.113.20:1000", testKid, secretBytes(t)); r.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", r.Code)
	}
	if w := serve(h, mkreq(http.MethodGet, "/", "198.51.100.7:2000", nil)); w.Code == http.StatusOK {
		t.Error("SECURITY: a different client IP inherited the grant")
	}
}

func TestForgedForwardedHeaderIgnoredByDefault(t *testing.T) {
	h := build(t, nil)
	if r := knock(t, h, "203.0.113.30:1000", testKid, secretBytes(t)); r.Code != http.StatusNoContent {
		t.Fatalf("knock: %d", r.Code)
	}
	r := mkreq(http.MethodGet, "/", "198.51.100.99:3000", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.30")
	if w := serve(h, r); w.Code == http.StatusOK {
		t.Error("SECURITY: forged X-Forwarded-For inherited a grant")
	}
}

func TestReplayRejected(t *testing.T) {
	h := build(t, nil)
	remote := "203.0.113.40:1000"
	ch := serve(h, mkreq(http.MethodGet, defaultPrefix+"/challenge", remote, nil))
	nonceB64 := ch.Header().Get("X-JIT-Nonce")
	nonceRaw, _ := jitcore.B64uDecode(nonceB64)
	tag := jitcore.BuildProof(secretBytes(t), site, testKid, nonceRaw)
	body, _ := json.Marshal(respondBody{V: 1, Kid: testKid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})

	if w := serve(h, mkreq(http.MethodPost, defaultPrefix+"/respond", remote, body)); w.Code != http.StatusNoContent {
		t.Fatalf("first knock: %d", w.Code)
	}
	if w := serve(h, mkreq(http.MethodPost, defaultPrefix+"/respond", remote, body)); w.Code == http.StatusNoContent {
		t.Error("SECURITY: replayed nonce accepted")
	}
}

func TestMalformedRespondNeverOpens(t *testing.T) {
	h := build(t, nil)
	remote := "203.0.113.60:1000"
	for _, b := range []string{"", "{", "{}", "null", "[]",
		`{"v":1,"kid":"` + testKid + `","nonce":"AAAA","proof":"AAAA"}`} {
		if w := serve(h, mkreq(http.MethodPost, defaultPrefix+"/respond", remote, []byte(b))); w.Code == http.StatusNoContent {
			t.Errorf("SECURITY: malformed respond opened the gate: %q", b)
		}
	}
	if w := serve(h, mkreq(http.MethodGet, "/", remote, nil)); w.Code == http.StatusOK {
		t.Error("SECURITY: a grant exists after only malformed knocks")
	}
}

func TestUnknownKidAndBadProofLookIdentical(t *testing.T) {
	h := build(t, nil)
	mk := func(kid string, secret []byte) *httptest.ResponseRecorder {
		remote := "203.0.113.50:1000"
		ch := serve(h, mkreq(http.MethodGet, defaultPrefix+"/challenge", remote, nil))
		nonceB64 := ch.Header().Get("X-JIT-Nonce")
		nonceRaw, _ := jitcore.B64uDecode(nonceB64)
		tag := jitcore.BuildProof(secret, site, kid, nonceRaw)
		body, _ := json.Marshal(respondBody{V: 1, Kid: kid, Nonce: nonceB64, Proof: jitcore.B64u(tag)})
		return serve(h, mkreq(http.MethodPost, defaultPrefix+"/respond", remote, body))
	}
	unknown := mk("kid_nope", secretBytes(t))
	bad := mk(testKid, bytes.Repeat([]byte{9}, 32))
	if unknown.Code != bad.Code || unknown.Body.String() != bad.Body.String() {
		t.Error("kid-existence oracle: unknown kid and bad proof differ")
	}
}

func TestStealthMode(t *testing.T) {
	h := build(t, func(c *Config) { c.FailureMode = failStealth })
	w := serve(h, mkreq(http.MethodGet, "/", "203.0.113.70:1000", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("stealth: got %d want 404", w.Code)
	}
	if w.Header().Get("X-JIT-Access") != "" {
		t.Error("stealth must not advertise the gate")
	}
}

func TestCookieBinding(t *testing.T) {
	h := build(t, func(c *Config) { c.Binding = jitcore.BindingIPCookie })
	remote := "203.0.113.80:1000"

	r := knock(t, h, remote, testKid, secretBytes(t))
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
		t.Fatal("ip+cookie must set the grant cookie")
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Domain != "" {
		t.Error("grant cookie must be HttpOnly, Secure, SameSite=Strict and host-only")
	}
	if w := serve(h, mkreq(http.MethodGet, "/", remote, nil)); w.Code == http.StatusOK {
		t.Error("SECURITY: ip+cookie grant honored without the cookie")
	}
	good := mkreq(http.MethodGet, "/", remote, nil)
	good.AddCookie(&http.Cookie{Name: grantCookieName, Value: ck.Value})
	if w := serve(h, good); w.Code != http.StatusOK {
		t.Errorf("correct cookie should be admitted: %d", w.Code)
	}
}

func TestNonAllowedKidRejected(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Tokens = append(c.Tokens, Token{Kid: "kid_other", Secret: testSecret})
		c.Allow = []string{testKid}
	})
	if r := knock(t, h, "203.0.113.90:1000", "kid_other", secretBytes(t)); r.Code == http.StatusNoContent {
		t.Error("SECURITY: a kid not on the allow-list opened the router")
	}
}

func TestConfigValidation(t *testing.T) {
	reset(t)
	base := func() *Config {
		c := CreateConfig()
		c.Tokens = []Token{{Kid: testKid, Secret: testSecret}}
		c.Allow = []string{testKid}
		return c
	}
	cases := map[string]func(*Config){
		"no tokens":     func(c *Config) { c.Tokens = nil },
		"no allow-list": func(c *Config) { c.Allow = nil },
		"bad binding":   func(c *Config) { c.Binding = "nonsense" },
		"bad mode":      func(c *Config) { c.FailureMode = "nonsense" },
		"short secret":  func(c *Config) { c.Tokens = []Token{{Kid: testKid, Secret: "AQEB"}} },
		"bad b64":       func(c *Config) { c.Tokens = []Token{{Kid: testKid, Secret: "!!!not-base64!!!"}} },
	}
	for name, mutate := range cases {
		c := base()
		mutate(c)
		if _, err := New(context.Background(), upstream(), c, "jit"); err == nil {
			t.Errorf("%s: expected New() to reject the config", name)
		}
	}
	if _, err := New(context.Background(), upstream(), base(), "jit"); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestOtherPrefixPathsStayDark(t *testing.T) {
	h := build(t, nil)
	for _, p := range []string{defaultPrefix, defaultPrefix + "/", defaultPrefix + "/register"} {
		if w := serve(h, mkreq(http.MethodGet, p, peer, nil)); w.Body.String() == "UPSTREAM" {
			t.Errorf("SECURITY: %s reached the upstream", p)
		}
	}
}
