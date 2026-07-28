// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitcore

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
)

// GrantStore + NonceStore (SPEC §4, §5) — the only stateful modules.
//
// Simple profile: in-process, mutex-guarded TTL maps. No Redis, no database.
// Because the store is process-private (nothing outside this process can write
// it) grant values need no MAC — the grant-injection threat (SECURITY-REVIEW C3)
// requires a shared writer. HARDENED/shared-backend swaps the backend behind
// these same methods and MUST then sign values and verify on read.
//
// Grants invert the usual fail direction: a stale or forged grant *opens* a dark
// service. Every path here therefore fails closed — any doubt returns nil.

const (
	BindingIP       = "ip"
	BindingIPCookie = "ip+cookie"
)

// Grant is the stored value (SPEC §4.2).
type Grant struct {
	V          int    `json:"v"`
	Kid        string `json:"kid"`
	Service    string `json:"service"` // canonical
	IP         string `json:"ip"`      // canonical
	Binding    string `json:"binding"`
	CookieHash string `json:"cookie_hash,omitempty"` // hex sha256 of the grant-id cookie
	Issued     int64  `json:"issued"`
	Exp        int64  `json:"exp"`
	Manual     bool   `json:"manual,omitempty"` // admin break-glass: skips the registry re-check
}

// CookieHash is what we persist for ip+cookie binding — never the cookie value
// itself, so a dump of the store does not yield working grant credentials.
func CookieHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// GrantKey is the canonical key schema (SPEC §4.1). Kept identical across
// engines so a later shared backend interoperates with the Lua implementation.
//
// For ip+cookie binding the cookie hash is part of the key. Without it, one
// (service, ip) pair held exactly one grant, so two enrolled devices behind a
// single NAT egress evicted each other on every knock and flapped indefinitely
// — precisely the deployment ip+cookie exists to serve. `ip` binding keeps the
// two-part key, so nothing changes for the default profile.
func GrantKey(serviceCanon, ipCanon string) string {
	return "jit:grant:" + serviceCanon + ":" + ipCanon
}

// GrantKeyCookie is the ip+cookie variant: one entry per device, not per IP.
func GrantKeyCookie(serviceCanon, ipCanon, cookieHash string) string {
	return GrantKey(serviceCanon, ipCanon) + ":" + cookieHash
}

// keyFor picks the schema a grant is stored under from its own binding.
func keyFor(g *Grant) string {
	if g.Binding == BindingIPCookie && g.CookieHash != "" {
		return GrantKeyCookie(g.Service, g.IP, g.CookieHash)
	}
	return GrantKey(g.Service, g.IP)
}

type GrantStore struct {
	mu     sync.RWMutex
	grants map[string]*Grant
	byKid  map[string]map[string]bool // kid -> set of grant keys (SPEC §4.1 index)
}

func NewGrantStore() *GrantStore {
	return &GrantStore{
		grants: map[string]*Grant{},
		byKid:  map[string]map[string]bool{},
	}
}

// Put creates or refreshes a grant.
//
// oldCookieHash, when non-empty, is the hash of a grant cookie the client
// already held for this (service, ip). Because a device-bound key embeds the
// cookie hash, a re-knock that mints a FRESH cookie lands on a different key and
// would leave the previous record behind — so a browser re-knocking every grant
// TTL accumulates one dead record per knock until the sweeper runs. Passing the
// old hash retires that record in the same operation.
func (s *GrantStore) Put(g *Grant, oldCookieHash ...string) {
	if g == nil {
		return
	}
	k := keyFor(g)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, oh := range oldCookieHash {
		if oh == "" || oh == g.CookieHash {
			continue
		}
		ok := GrantKeyCookie(g.Service, g.IP, oh)
		if prev, exists := s.grants[ok]; exists {
			s.unindexLocked(prev.Kid, ok)
			delete(s.grants, ok)
		}
	}
	if old, ok := s.grants[k]; ok {
		s.unindexLocked(old.Kid, k)
	}
	s.grants[k] = g
	if s.byKid[g.Kid] == nil {
		s.byKid[g.Kid] = map[string]bool{}
	}
	s.byKid[g.Kid][k] = true
}

// IsAllowed is the request-path check. Per SPEC §4.3 it re-validates on EVERY
// call that the grant's kid is still registered and unexpired, so revoking a
// token or letting it expire evicts live grants immediately rather than at TTL
// (SECURITY-REVIEW H3). For ip+cookie it also verifies the presented cookie.
//
// cookie is the raw grant-id cookie value ("" when absent). Returns nil = deny.
func (s *GrantStore) IsAllowed(serviceCanon, ipCanon string, reg *Registry, now int64, cookie string) *Grant {
	s.mu.RLock()
	// A device-bound grant lives under a cookie-qualified key, so try that first
	// when the client presented a cookie; fall back to the plain (ip-bound) key.
	// Looking the cookie up rather than scanning also means a device can only
	// ever find its OWN grant.
	var g *Grant
	if cookie != "" {
		g = s.grants[GrantKeyCookie(serviceCanon, ipCanon, CookieHash(cookie))]
	}
	if g == nil {
		g = s.grants[GrantKey(serviceCanon, ipCanon)]
	}
	s.mu.RUnlock()

	if g == nil || now >= g.Exp {
		return nil
	}
	// The key is built by concatenating fields with ":", and a canonical
	// server_name can itself contain ":" (a bracketed IPv6 literal canonicalizes
	// to 2001:db8::1). That makes the key alone a weak identifier, so confirm the
	// record actually describes the request rather than trusting where it was
	// filed. Cheap, and it makes any key-construction ambiguity unexploitable.
	if g.Service != serviceCanon || g.IP != ipCanon {
		return nil
	}
	// Break-glass grants created by an admin have no kid behind them; TTL and
	// explicit revoke still bound them.
	if !g.Manual {
		t := reg.Lookup(g.Kid)
		if t == nil || reg.IsExpired(t, now) {
			return nil
		}
		// The per-service allow-list is re-checked too, not just registry
		// membership. Removing a kid from one site's allow-list while leaving the
		// token registered (because it still serves another site) is a normal
		// admin action, and without this the de-authorized device kept working
		// for the whole grant TTL — while deleting the token outright evicted
		// immediately, so the two admin actions behaved differently for no
		// visible reason.
		if !reg.AllowedForService(g.Kid, serviceCanon) {
			return nil
		}
	}
	if g.Binding == BindingIPCookie {
		if cookie == "" || g.CookieHash == "" {
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(CookieHash(cookie)), []byte(g.CookieHash)) != 1 {
			return nil
		}
	}
	return g
}

// Get returns a grant without policy re-checks (admin/debug only). With
// ip+cookie there may be several at one address; this returns the ip-bound one
// if present, else any device-bound one.
func (s *GrantStore) Get(serviceCanon, ipCanon string) *Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if g, ok := s.grants[GrantKey(serviceCanon, ipCanon)]; ok {
		return g
	}
	// Match on the record's own fields, never on a key prefix: keys join fields
	// with ":" and a canonical IPv6 address contains ":" itself, so
	// "…:2001:db8::1:" is a prefix of the DIFFERENT client "…:2001:db8::1:2".
	for _, g := range s.grants {
		if g.Service == serviceCanon && g.IP == ipCanon {
			return g
		}
	}
	return nil
}

// Revoke removes EVERY grant for (service, ip): the ip-bound one and any
// device-bound ones. An admin revoking an address means "this address loses
// access", not "one of the devices at this address does" — with ip+cookie there
// may be several, and leaving the others behind would be a silent partial
// revoke. Returns true if anything was removed.
func (s *GrantStore) Revoke(serviceCanon, ipCanon string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := false
	// Field comparison, NOT a key-prefix scan. Keys join fields with ":" and a
	// canonical IPv6 address contains ":", so revoking 2001:db8::1 by prefix also
	// deleted the unrelated client 2001:db8::1:2 — a silent over-revoke that
	// looked like a correct one.
	for k, g := range s.grants {
		if g.Service == serviceCanon && g.IP == ipCanon {
			s.unindexLocked(g.Kid, k)
			delete(s.grants, k)
			removed = true
		}
	}
	return removed
}

// RevokeToken deletes every grant carrying kid and returns the count, so the
// admin sees the blast radius of revoking a lost device (SECURITY-REVIEW H3).
func (s *GrantStore) RevokeToken(kid string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.byKid[kid]
	n := 0
	for k := range keys {
		if _, ok := s.grants[k]; ok {
			delete(s.grants, k)
			n++
		}
	}
	delete(s.byKid, kid)
	return n
}

// List returns the live (unexpired) grants, for the admin API.
func (s *GrantStore) List(now int64) []*Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Grant, 0, len(s.grants))
	for _, g := range s.grants {
		if now < g.Exp {
			out = append(out, g)
		}
	}
	return out
}

// Sweep drops expired records. Lazy expiry already makes them unreachable; this
// just reclaims memory and is safe to call on a timer.
func (s *GrantStore) Sweep(now int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, g := range s.grants {
		if now >= g.Exp {
			s.unindexLocked(g.Kid, k)
			delete(s.grants, k)
			n++
		}
	}
	return n
}

func (s *GrantStore) unindexLocked(kid, key string) {
	if m := s.byKid[kid]; m != nil {
		delete(m, key)
		if len(m) == 0 {
			delete(s.byKid, kid)
		}
	}
}

// ---- NonceStore ------------------------------------------------------------

// NonceStore enforces single-use only (SPEC §5); the nonce authenticates itself.
// Kept separate from grants so a burst of knocks can never evict live grants
// (SECURITY-REVIEW H5).
type NonceStore struct {
	mu    sync.Mutex
	spent map[string]int64 // id -> expiry
}

func NewNonceStore() *NonceStore { return &NonceStore{spent: map[string]int64{}} }

// Claim is the atomic check-and-burn: true on first use, false if already spent.
// Called only after the proof verifies, so a bad proof cannot consume a nonce.
func (n *NonceStore) Claim(id string, now, ttl int64) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if exp, ok := n.spent[id]; ok && now < exp {
		return false
	}
	n.spent[id] = now + ttl
	return true
}

func (n *NonceStore) Sweep(now int64) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for k, exp := range n.spent {
		if now >= exp {
			delete(n.spent, k)
			c++
		}
	}
	return c
}

// ---- enrollment codes ------------------------------------------------------

// EnrollCode is a single-use, TTL-bounded code exchanged at /enroll for a device
// secret, so the secret never travels in a registration URL or QR (PROTOCOL
// §6.1 / SECURITY-REVIEW R5).
type EnrollCode struct {
	Kid     string   `json:"kid"`
	Origins []string `json:"origins"`
	Exp     int64    `json:"exp"`
}

type EnrollStore struct {
	mu    sync.Mutex
	codes map[string]*EnrollCode
}

func NewEnrollStore() *EnrollStore { return &EnrollStore{codes: map[string]*EnrollCode{}} }

func (e *EnrollStore) Put(code string, c *EnrollCode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.codes[code] = c
}

// Peek reads a code WITHOUT consuming it, so a caller can reject an unusable
// code (unknown kid, wrong service) before burning it. Consume is
// delete-after-read, so validating afterwards let any hostile POST destroy a
// perfectly good enrollment code.
func (e *EnrollStore) Peek(code string, now int64) *EnrollCode {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.codes[code]
	if !ok || now >= c.Exp {
		return nil
	}
	return c
}

// Consume is delete-after-read: a code works exactly once.
func (e *EnrollStore) Consume(code string, now int64) *EnrollCode {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.codes[code]
	if !ok {
		return nil
	}
	delete(e.codes, code)
	if now >= c.Exp {
		return nil
	}
	return c
}

func (e *EnrollStore) Sweep(now int64) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for k, c := range e.codes {
		if now >= c.Exp {
			delete(e.codes, k)
			n++
		}
	}
	return n
}
