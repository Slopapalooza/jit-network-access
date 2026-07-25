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
func GrantKey(serviceCanon, ipCanon string) string {
	return "jit:grant:" + serviceCanon + ":" + ipCanon
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
func (s *GrantStore) Put(g *Grant) {
	if g == nil {
		return
	}
	k := GrantKey(g.Service, g.IP)
	s.mu.Lock()
	defer s.mu.Unlock()
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
	g := s.grants[GrantKey(serviceCanon, ipCanon)]
	s.mu.RUnlock()

	if g == nil || now >= g.Exp {
		return nil
	}
	// Break-glass grants created by an admin have no kid behind them; TTL and
	// explicit revoke still bound them.
	if !g.Manual {
		t := reg.Lookup(g.Kid)
		if t == nil || reg.IsExpired(t, now) {
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

// Get returns a grant without policy re-checks (admin/debug only).
func (s *GrantStore) Get(serviceCanon, ipCanon string) *Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.grants[GrantKey(serviceCanon, ipCanon)]
}

func (s *GrantStore) Revoke(serviceCanon, ipCanon string) bool {
	k := GrantKey(serviceCanon, ipCanon)
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[k]
	if !ok {
		return false
	}
	s.unindexLocked(g.Kid, k)
	delete(s.grants, k)
	return true
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
