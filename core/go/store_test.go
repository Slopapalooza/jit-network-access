// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitcore

import "testing"

// The store is not covered by the shared vectors, but it carries the rules that
// make a grant safe to honor (SPEC §4.3). These assert the fail-closed and
// re-check semantics rather than byte formats.

const now = int64(1_700_000_000)

func testRegistry() *Registry {
	return NewRegistry(
		map[string]*Token{
			"kid_ok":      {Secret: []byte("0123456789abcdef"), Alg: AlgHMACSHA256},
			"kid_expired": {Secret: []byte("0123456789abcdef"), Alg: AlgHMACSHA256, Expires: now - 1},
		},
		map[string]map[string]bool{
			"app.example.com":  {"kid_ok": true},
			"open.example.com": {"*": true},
		},
	)
}

func liveGrant(kid string) *Grant {
	return &Grant{V: 1, Kid: kid, Service: "app.example.com", IP: "1.2.3.4",
		Binding: BindingIP, Issued: now, Exp: now + 3600}
}

func TestGrantHappyPathAndExpiry(t *testing.T) {
	s, reg := NewGrantStore(), testRegistry()
	s.Put(liveGrant("kid_ok"))

	if g := s.IsAllowed("app.example.com", "1.2.3.4", reg, now, ""); g == nil {
		t.Fatal("live grant should be allowed")
	}
	if g := s.IsAllowed("app.example.com", "1.2.3.4", reg, now+3600, ""); g != nil {
		t.Error("grant past its exp must be denied")
	}
	if g := s.IsAllowed("app.example.com", "9.9.9.9", reg, now, ""); g != nil {
		t.Error("grant must not apply to another IP")
	}
	if g := s.IsAllowed("other.example.com", "1.2.3.4", reg, now, ""); g != nil {
		t.Error("grant must not apply to another service")
	}
}

// SECURITY-REVIEW H3: revoking or expiring a token must evict live grants on the
// next request, not merely at TTL.
func TestGrantRechecksRegistryEveryCall(t *testing.T) {
	s, reg := NewGrantStore(), testRegistry()
	s.Put(liveGrant("kid_ok"))
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") == nil {
		t.Fatal("precondition: grant should be live")
	}

	// kid disappears from the registry (admin deleted the token)
	delete(reg.Tokens, "kid_ok")
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") != nil {
		t.Error("grant for an unregistered kid must be denied")
	}

	// token still registered but expired
	s2 := NewGrantStore()
	s2.Put(liveGrant("kid_expired"))
	if s2.IsAllowed("app.example.com", "1.2.3.4", testRegistry(), now, "") != nil {
		t.Error("grant for an expired token must be denied")
	}
}

// Dropping a kid from ONE site's allow-list — while the token stays registered
// because it still serves another site — must evict that site's live grants on
// the next request, exactly like deleting the token does. Otherwise the two
// admin actions look identical from the console but only one of them works.
func TestGrantRechecksServiceAllowListEveryCall(t *testing.T) {
	s, reg := NewGrantStore(), testRegistry()
	s.Put(liveGrant("kid_ok"))
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") == nil {
		t.Fatal("precondition: grant should be live")
	}

	// admin removes kid_ok from app.example.com's allow-list; the token itself
	// survives (it is still allowed on open.example.com).
	delete(reg.Services["app.example.com"], "kid_ok")
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") != nil {
		t.Error("a kid removed from the service allow-list must be denied, not admitted until TTL")
	}
	if reg.Lookup("kid_ok") == nil {
		t.Error("precondition broken: the token itself should still be registered")
	}
}

// A site-scoped registry (Caddy / Traefik build one per site under the "*" key)
// must keep working: the re-check above must not turn every request into a deny
// just because the request's hostname is not a registry key.
func TestSiteScopedRegistryStillAdmits(t *testing.T) {
	s := NewGrantStore()
	reg := NewRegistry(
		map[string]*Token{"kid_site": {Secret: []byte("0123456789abcdef"), Alg: AlgHMACSHA256}},
		map[string]map[string]bool{"*": {"kid_site": true}},
	)
	g := liveGrant("kid_site")
	s.Put(g)
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") == nil {
		t.Fatal("site-scoped registry: a granted kid must still be admitted")
	}
	// and removing it from that single allow-list still evicts
	delete(reg.Services["*"], "kid_site")
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") != nil {
		t.Error("site-scoped registry: a de-authorized kid must be denied")
	}
}

func TestRevokeTokenSweepsEveryGrant(t *testing.T) {
	s, reg := NewGrantStore(), testRegistry()
	for _, ip := range []string{"1.2.3.4", "5.6.7.8", "9.9.9.9"} {
		g := liveGrant("kid_ok")
		g.IP = ip
		s.Put(g)
	}
	other := liveGrant("kid_expired")
	other.IP = "10.0.0.1"
	s.Put(other)

	if n := s.RevokeToken("kid_ok"); n != 3 {
		t.Errorf("revoke_token count: got %d want 3", n)
	}
	for _, ip := range []string{"1.2.3.4", "5.6.7.8", "9.9.9.9"} {
		if s.IsAllowed("app.example.com", ip, reg, now, "") != nil {
			t.Errorf("grant for %s survived revoke_token", ip)
		}
	}
	if s.Get("app.example.com", "10.0.0.1") == nil {
		t.Error("revoke_token must not touch other kids' grants")
	}
	if n := s.RevokeToken("kid_ok"); n != 0 {
		t.Errorf("second revoke should sweep nothing, got %d", n)
	}
}

// ip+cookie binding (SPEC §4.2/§4.3, DESIGN §11 R3). The stored value is a hash,
// and a grant is honored only when the presented cookie reproduces it.
func TestCookieBinding(t *testing.T) {
	s, reg := NewGrantStore(), testRegistry()
	g := liveGrant("kid_ok")
	g.Binding = BindingIPCookie
	g.CookieHash = CookieHash("grant-id-secret-value")
	s.Put(g)

	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "grant-id-secret-value") == nil {
		t.Error("correct cookie should be admitted")
	}
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "wrong-value") != nil {
		t.Error("wrong cookie must be denied")
	}
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") != nil {
		t.Error("missing cookie must be denied for ip+cookie binding")
	}
	// the raw value must never be what we persist
	if g.CookieHash == "grant-id-secret-value" {
		t.Error("cookie stored in cleartext")
	}
	// an ip-bound grant ignores cookies entirely
	s2 := NewGrantStore()
	s2.Put(liveGrant("kid_ok"))
	if s2.IsAllowed("app.example.com", "1.2.3.4", reg, now, "") == nil {
		t.Error("ip-bound grant should not require a cookie")
	}
}

// Two enrolled devices behind ONE NAT egress address — the deployment ip+cookie
// exists for. Both must hold a grant at the same time. Before the key included
// the cookie hash, (service, ip) held exactly one grant, so each knock evicted
// the other device and the two flapped forever.
func TestCookieBindingIsPerDeviceNotPerIP(t *testing.T) {
	const sharedIP = "1.2.3.4"
	s, reg := NewGrantStore(), testRegistry()

	device := func(cookie string) *Grant {
		g := liveGrant("kid_ok")
		g.IP = sharedIP
		g.Binding = BindingIPCookie
		g.CookieHash = CookieHash(cookie)
		return g
	}
	s.Put(device("cookie-laptop"))
	s.Put(device("cookie-phone")) // must NOT evict the laptop

	if s.IsAllowed("app.example.com", sharedIP, reg, now, "cookie-laptop") == nil {
		t.Error("laptop lost its grant when the phone knocked from the same IP")
	}
	if s.IsAllowed("app.example.com", sharedIP, reg, now, "cookie-phone") == nil {
		t.Error("phone was not granted")
	}
	// a third, un-enrolled browser on the same address gets nothing
	if s.IsAllowed("app.example.com", sharedIP, reg, now, "cookie-stranger") != nil {
		t.Error("SECURITY: a co-located client with an unknown cookie was admitted")
	}
	if s.IsAllowed("app.example.com", sharedIP, reg, now, "") != nil {
		t.Error("SECURITY: a co-located client with no cookie was admitted")
	}

	// Revoking the address must clear EVERY device there, not just one.
	if !s.Revoke("app.example.com", sharedIP) {
		t.Fatal("revoke reported nothing removed")
	}
	for _, c := range []string{"cookie-laptop", "cookie-phone"} {
		if s.IsAllowed("app.example.com", sharedIP, reg, now, c) != nil {
			t.Errorf("revoke left %s behind — a silent partial revoke", c)
		}
	}
}

// revoke_token must also reach device-bound grants, whatever key they sit under.
func TestRevokeTokenReachesCookieBoundGrants(t *testing.T) {
	s, reg := NewGrantStore(), testRegistry()
	for _, c := range []string{"c1", "c2", "c3"} {
		g := liveGrant("kid_ok")
		g.Binding = BindingIPCookie
		g.CookieHash = CookieHash(c)
		s.Put(g)
	}
	if n := s.RevokeToken("kid_ok"); n != 3 {
		t.Errorf("revoke_token count: got %d want 3", n)
	}
	for _, c := range []string{"c1", "c2", "c3"} {
		if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, c) != nil {
			t.Errorf("device-bound grant %s survived revoke_token", c)
		}
	}
}

// A break-glass grant has no kid behind it, so it skips the registry re-check —
// but TTL and explicit revoke still bound it.
func TestManualGrantSkipsRegistryButNotTTL(t *testing.T) {
	s := NewGrantStore()
	g := liveGrant("__manual__")
	g.Manual = true
	s.Put(g)

	empty := NewRegistry(nil, nil)
	if s.IsAllowed("app.example.com", "1.2.3.4", empty, now, "") == nil {
		t.Error("manual grant should survive an empty registry")
	}
	if s.IsAllowed("app.example.com", "1.2.3.4", empty, now+3600, "") != nil {
		t.Error("manual grant must still expire")
	}
	if !s.Revoke("app.example.com", "1.2.3.4") {
		t.Error("manual grant should be revocable")
	}
	if s.IsAllowed("app.example.com", "1.2.3.4", empty, now, "") != nil {
		t.Error("revoked manual grant must be denied")
	}
}

func TestNonceSingleUse(t *testing.T) {
	n := NewNonceStore()
	if !n.Claim("abc", now, 60) {
		t.Error("first claim should succeed")
	}
	if n.Claim("abc", now, 60) {
		t.Error("replayed nonce must be rejected")
	}
	if !n.Claim("def", now, 60) {
		t.Error("a different nonce should be claimable")
	}
	// once the spent record ages out, the nonce itself is already stale by TTL,
	// so reuse of the id is harmless
	if !n.Claim("abc", now+61, 60) {
		t.Error("claim should succeed after the spent record expires")
	}
}

func TestEnrollCodeSingleUse(t *testing.T) {
	e := NewEnrollStore()
	e.Put("code1", &EnrollCode{Kid: "kid_ok", Origins: []string{"https://app.example.com"}, Exp: now + 86400})

	if c := e.Consume("code1", now); c == nil || c.Kid != "kid_ok" {
		t.Fatal("first exchange should return the code")
	}
	if c := e.Consume("code1", now); c != nil {
		t.Error("code must be single-use")
	}

	e.Put("code2", &EnrollCode{Kid: "kid_ok", Exp: now + 10})
	if c := e.Consume("code2", now+11); c != nil {
		t.Error("expired code must not be honored")
	}
	if c := e.Consume("nope", now); c != nil {
		t.Error("unknown code must return nil")
	}
}

func TestSweepReclaims(t *testing.T) {
	s := NewGrantStore()
	s.Put(liveGrant("kid_ok"))
	if n := s.Sweep(now); n != 0 {
		t.Errorf("sweep should not drop live grants, dropped %d", n)
	}
	if n := s.Sweep(now + 3600); n != 1 {
		t.Errorf("sweep should drop the expired grant, dropped %d", n)
	}
	if len(s.List(now)) != 0 {
		t.Error("store should be empty after sweep")
	}
}

// A device re-knocking gets a FRESH cookie, hence a different key. Without
// retiring the superseded record, a browser that re-knocks every grant TTL
// leaves one dead record behind per knock until the sweeper runs.
func TestReKnockDoesNotAccumulateRecords(t *testing.T) {
	s, reg := NewGrantStore(), testRegistry()
	mk := func(cookie string) *Grant {
		g := liveGrant("kid_ok")
		g.Binding = BindingIPCookie
		g.CookieHash = CookieHash(cookie)
		return g
	}
	s.Put(mk("cookie-1"))
	for i, c := range []string{"cookie-2", "cookie-3", "cookie-4"} {
		prev := []string{"cookie-1", "cookie-2", "cookie-3"}[i]
		s.Put(mk(c), CookieHash(prev))
	}
	if n := len(s.List(now)); n != 1 {
		t.Errorf("after 4 knocks by one device: %d live records, want 1", n)
	}
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "cookie-4") == nil {
		t.Error("the current cookie should be admitted")
	}
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "cookie-1") != nil {
		t.Error("a superseded cookie must not still open the gate")
	}
	// A DIFFERENT device is untouched by another device's re-knock.
	s.Put(mk("phone"))
	s.Put(mk("cookie-5"), CookieHash("cookie-4"))
	if s.IsAllowed("app.example.com", "1.2.3.4", reg, now, "phone") == nil {
		t.Error("another device's grant was collateral damage of a re-knock")
	}
}

// Keys join fields with ":", and a canonical IPv6 address contains ":" itself,
// so "…:2001:db8::1:" is a prefix of the DIFFERENT client "…:2001:db8::1:2".
// Revoke/Get therefore match on the record's own fields, never on a key prefix.
func TestRevokeDoesNotOverDeleteIPv6Neighbours(t *testing.T) {
	s := NewGrantStore()
	mk := func(ip string) *Grant {
		g := liveGrant("kid_ok")
		g.IP = ip
		return g
	}
	target := mk("2001:db8::1")
	neighbour := mk("2001:db8::1:2") // a DIFFERENT client, not a device of the target
	s.Put(target)
	s.Put(neighbour)

	if !s.Revoke("app.example.com", "2001:db8::1") {
		t.Fatal("revoke reported nothing removed")
	}
	if s.Get("app.example.com", "2001:db8::1") != nil {
		t.Error("the targeted grant was not revoked")
	}
	if s.Get("app.example.com", "2001:db8::1:2") == nil {
		t.Error("SECURITY/AVAILABILITY: revoking 2001:db8::1 also deleted 2001:db8::1:2")
	}

	// Same for the service half of the key: a canonical bracketed-IPv6
	// server_name contains colons too.
	s2 := NewGrantStore()
	a := liveGrant("kid_ok")
	a.Service = "2001:db8::1"
	b := liveGrant("kid_ok")
	b.Service = "2001:db8::1:2"
	s2.Put(a)
	s2.Put(b)
	s2.Revoke("2001:db8::1", "1.2.3.4")
	if s2.Get("2001:db8::1:2", "1.2.3.4") == nil {
		t.Error("revoking one IPv6-named service deleted a different one")
	}
}
