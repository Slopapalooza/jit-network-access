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
