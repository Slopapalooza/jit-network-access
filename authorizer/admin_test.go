// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

// The admin API mints grants that skip the registry re-check (Manual: true), so
// it is the one surface that can hand out access with no token behind it at all.
// Its handlers had ZERO test coverage — only the auth gate in front of them was
// exercised.

func adminReq(t *testing.T, s *Server, method, path, body string) *http.Response {
	t.Helper()
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	r := req(method, "authorizer.internal", path, proxyIP, map[string]string{
		"Authorization": "Bearer admin-secret",
		"Content-Type":  "application/json",
	}, b)
	return do(s, r).Result()
}

func adminJSON(t *testing.T, s *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	res := adminReq(t, s, method, path, body)
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestAdminGrantCreatesAndRevokesAccess(t *testing.T) {
	s := testServer(t, nil)

	// Dark before.
	if w := authz(s, svcA, proxyIP, "/", nil); w.Code == http.StatusNoContent {
		t.Fatal("precondition: service should be dark")
	}

	code, out := adminJSON(t, s, http.MethodPost, "/admin/grant",
		`{"service":"`+svcA+`","ip":"127.0.0.1","ttl":120}`)
	if code != http.StatusOK || out["granted"] != true {
		t.Fatalf("grant: got %d %v", code, out)
	}
	if out["ip"] != "127.0.0.1" || out["service"] != svcA {
		t.Errorf("grant echoed the wrong target: %v", out)
	}
	if w := authz(s, svcA, proxyIP, "/", nil); w.Code != http.StatusNoContent {
		t.Errorf("after manual grant: got %d want 204", w.Code)
	}

	// A break-glass grant has no kid behind it, so it must survive the registry
	// re-check that would evict a knock-created one.
	s.registry().Tokens = map[string]*jitcore.Token{}
	if w := authz(s, svcA, proxyIP, "/", nil); w.Code != http.StatusNoContent {
		t.Error("a manual grant must not be evicted by an empty registry")
	}

	code, out = adminJSON(t, s, http.MethodPost, "/admin/revoke",
		`{"service":"`+svcA+`","ip":"127.0.0.1"}`)
	if code != http.StatusOK || out["revoked"] != true {
		t.Fatalf("revoke: got %d %v", code, out)
	}
	if w := authz(s, svcA, proxyIP, "/", nil); w.Code == http.StatusNoContent {
		t.Error("revoke did not re-darken the service")
	}

	// Revoking again reports nothing removed rather than lying.
	if _, out2 := adminJSON(t, s, http.MethodPost, "/admin/revoke",
		`{"service":"`+svcA+`","ip":"127.0.0.1"}`); out2["revoked"] != false {
		t.Errorf("second revoke should report false, got %v", out2)
	}
}

// Malformed input must be refused, not turned into a grant on a canonicalized
// guess of what the operator meant.
func TestAdminGrantRejectsBadInput(t *testing.T) {
	s := testServer(t, nil)
	for _, tc := range []struct{ name, body string }{
		{"missing ip", `{"service":"` + svcA + `"}`},
		{"unparseable ip", `{"service":"` + svcA + `","ip":"not-an-ip"}`},
		{"leading-zero ip", `{"service":"` + svcA + `","ip":"192.168.001.005"}`},
		{"zoned ip", `{"service":"` + svcA + `","ip":"fe80::1%eth0"}`},
		{"missing service", `{"ip":"1.2.3.4"}`},
		{"not json", `{`},
	} {
		code, _ := adminJSON(t, s, http.MethodPost, "/admin/grant", tc.body)
		if code == http.StatusOK {
			t.Errorf("%s: accepted (200) — a grant was minted from bad input", tc.name)
		}
	}
	// ...and nothing was created by any of them.
	if _, out := adminJSON(t, s, http.MethodGet, "/admin/grants", ""); out["count"] != float64(0) {
		t.Errorf("bad input created grants: %v", out)
	}
}

// GET-only and POST-only surfaces must not be driveable by the other verb.
func TestAdminMethodEnforcement(t *testing.T) {
	s := testServer(t, nil)
	for _, p := range []string{"/admin/grant", "/admin/revoke", "/admin/revoke-token", "/admin/enroll-code"} {
		if res := adminReq(t, s, http.MethodGet, p, ""); res.StatusCode == http.StatusOK {
			t.Errorf("%s accepted GET", p)
		}
	}
	if res := adminReq(t, s, http.MethodGet, "/admin/nope", ""); res.StatusCode == http.StatusOK {
		t.Error("unknown admin path returned 200")
	}
}

func TestAdminRevokeTokenReportsBlastRadius(t *testing.T) {
	s := testServer(t, nil)
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"} {
		if code, _ := adminJSON(t, s, http.MethodPost, "/admin/grant",
			`{"service":"`+svcA+`","ip":"`+ip+`","kid":"`+testKid+`"}`); code != http.StatusOK {
			t.Fatalf("setup grant for %s failed", ip)
		}
	}
	code, out := adminJSON(t, s, http.MethodPost, "/admin/revoke-token", `{"kid":"`+testKid+`"}`)
	if code != http.StatusOK {
		t.Fatalf("revoke-token: got %d", code)
	}
	// The count is what tells an admin how much access a lost device had.
	if out["grants_removed"] != float64(3) {
		t.Errorf("grants_removed: got %v want 3", out["grants_removed"])
	}
	if _, out2 := adminJSON(t, s, http.MethodPost, "/admin/revoke-token", `{"kid":"`+testKid+`"}`); out2["grants_removed"] != float64(0) {
		t.Errorf("second revoke-token should remove nothing, got %v", out2["grants_removed"])
	}
	if code, _ := adminJSON(t, s, http.MethodPost, "/admin/revoke-token", `{}`); code == http.StatusOK {
		t.Error("revoke-token with no kid was accepted")
	}
}

func TestAdminEnrollCodeMintsUsableSingleUseCode(t *testing.T) {
	s := testServer(t, nil)
	code, out := adminJSON(t, s, http.MethodPost, "/admin/enroll-code",
		`{"kid":"`+testKid+`","origins":["https://`+svcA+`"],"server":"https://`+svcA+`"}`)
	if code != http.StatusOK {
		t.Fatalf("enroll-code: got %d %v", code, out)
	}
	oneTime, _ := out["code"].(string)
	if len(oneTime) < 16 {
		t.Fatalf("enrollment code too short to be unguessable: %q", oneTime)
	}
	if u, _ := out["register_url"].(string); !strings.Contains(u, "/register?code=") {
		t.Errorf("register_url missing or malformed: %q", u)
	}
	// It must work exactly once.
	prefix := s.config().URIPrefix
	body := `{"v":1,"code":"` + oneTime + `"}`
	first := do(s, req(http.MethodPost, svcA, prefix+"/enroll", proxyIP,
		map[string]string{"Content-Type": "application/json"}, []byte(body)))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first exchange: got %d want 204", first.Code)
	}
	if first.Header().Get("X-JIT-Secret") == "" {
		t.Error("first exchange returned no secret")
	}
	second := do(s, req(http.MethodPost, svcA, prefix+"/enroll", proxyIP,
		map[string]string{"Content-Type": "application/json"}, []byte(body)))
	if second.Code == http.StatusNoContent {
		t.Error("SECURITY: the enrollment code was accepted twice")
	}
	// An unknown kid must not mint a code at all.
	if code, _ := adminJSON(t, s, http.MethodPost, "/admin/enroll-code", `{"kid":"no_such_kid"}`); code == http.StatusOK {
		t.Error("minted an enrollment code for an unregistered kid")
	}
}

// ---- LoadConfig ------------------------------------------------------------
//
// Config validation was only ever exercised by calling finalize() directly, so
// the real load path — including the service-name collision check — was
// untested.

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigAcceptsAndNormalizes(t *testing.T) {
	p := writeCfg(t, `{
	  "listen": "127.0.0.1:9999",
	  "uri_prefix": "well-known/jit/",
	  "enroll_ttl": 10,
	  "ipv6_prefix": 999,
	  "services": { "App.Example.COM.": { "tokens": ["kid_test"] } },
	  "tokens": [{ "kid": "kid_test", "secret": "`+testSecret+`" }]
	}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.URIPrefix != "/well-known/jit" {
		t.Errorf("uri_prefix not normalized: %q", cfg.URIPrefix)
	}
	if cfg.EnrollTTL != 300 {
		t.Errorf("enroll_ttl not clamped up: %d", cfg.EnrollTTL)
	}
	if cfg.IPv6Prefix != 128 {
		t.Errorf("out-of-range ipv6_prefix not clamped: %d", cfg.IPv6Prefix)
	}
	// Service lookup must work through the canonical name, not the literal key.
	if _, ok := cfg.Service("app.example.com"); !ok {
		t.Error("service not reachable by its canonical name")
	}
}

func TestLoadConfigRejectsBadFiles(t *testing.T) {
	good := `"tokens": [{ "kid": "kid_test", "secret": "` + testSecret + `" }]`
	for _, tc := range []struct{ name, body string }{
		{"not json", `{`},
		{"unknown field", `{"listen":"x","surprise":1,` + good + `}`},
		{"short secret", `{"tokens":[{"kid":"k","secret":"AQEB"}]}`},
		{"secret not base64url", `{"tokens":[{"kid":"k","secret":"@@@not-b64@@@"}]}`},
		{"empty kid", `{"tokens":[{"kid":"","secret":"` + testSecret + `"}]}`},
		{"duplicate kid", `{"tokens":[{"kid":"k","secret":"` + testSecret + `"},{"kid":"k","secret":"` + testSecret + `"}]}`},
		{"bad failure_mode", `{"services":{"a.example.com":{"failure_mode":"loud"}},` + good + `}`},
		{"bad binding", `{"services":{"a.example.com":{"binding":"ip+vibes"}},` + good + `}`},
		{"bad trusted_proxies", `{"trusted_proxies":["not-a-cidr"],` + good + `}`},
		// The collision check, through the REAL load path this time.
		{"colliding service names",
			`{"services":{"a.example.com":{"tokens":["kid_test"]},"a.example.com:8443":{"tokens":["*"]}},` + good + `}`},
	} {
		if _, err := LoadConfig(writeCfg(t, tc.body)); err == nil {
			t.Errorf("%s: accepted, should have been refused", tc.name)
		}
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing config file was accepted")
	}
}
