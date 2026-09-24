// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package jitcore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// TokenRegistry (SPEC §3). Pure over its input: the adapter parses backend
// config (BunkerWeb settings, Authorizer config file) into these maps and hands
// them in, so there is no I/O on the request path.

const AlgHMACSHA256 = "HMAC-SHA256"

type Token struct {
	Secret  []byte // raw bytes, not base64
	Alg     string // pinned per kid; a mismatch is failure, never a downgrade
	Label   string
	Expires int64 // unix seconds; 0 = never
}

// Registry is read-only at request time. Swap it wholesale on config reload
// (atomically, from the adapter) rather than mutating it under readers.
type Registry struct {
	Tokens map[string]*Token
	// Services maps canonical server_name -> allowed kids. The key "*" means
	// "any registered token may open this service".
	Services map[string]map[string]bool
}

func NewRegistry(tokens map[string]*Token, services map[string]map[string]bool) *Registry {
	if tokens == nil {
		tokens = map[string]*Token{}
	}
	if services == nil {
		services = map[string]map[string]bool{}
	}
	return &Registry{Tokens: tokens, Services: services}
}

func (r *Registry) Lookup(kid string) *Token {
	if r == nil {
		return nil
	}
	return r.Tokens[kid]
}

func (r *Registry) IsExpired(t *Token, now int64) bool {
	return t != nil && t.Expires != 0 && now >= t.Expires
}

// Fingerprint names WHICH secret a token holds without holding it: the
// lowercase-hex SHA-256 of the raw secret bytes. A grant records the
// fingerprint of the secret that verified its knock, and IsAllowed compares it
// against the registry's current one on every request, so regenerating a
// secret in place (same kid, new bytes) evicts the old device's live grants
// exactly like deleting the kid does. Before this the re-check stopped at "is
// the kid still registered?", so a device holding the OLD secret kept its grant
// for the full grant TTL — and on an engine whose registry reloads a minute
// after the config is saved, could re-knock with the old secret in that window
// and mint a fresh grant that outlived the rotation. Same primitive as
// CookieHash, and identical to registry.fingerprint() in the Lua core.
func (t *Token) Fingerprint() string {
	if t == nil {
		return ""
	}
	sum := sha256.Sum256(t.Secret)
	return hex.EncodeToString(sum[:])
}

// allowKey resolves which key holds the allow-list for a service.
//
// Two registry shapes exist. A MULTI-SERVICE registry (the Authorizer, the
// BunkerWeb plugin, OpenResty) keys allow-lists by canonical server name. A
// SITE-SCOPED registry (Caddy, Traefik) is built fresh per site block / router,
// which does not know its own hostnames, so it stores one allow-list under "*".
//
// Resolving this here rather than at each call site means IsAllowed can re-check
// the allow-list without the store needing to know which shape it was handed.
// The len==1 guard keeps the two shapes unambiguous: a multi-service registry
// only takes the "*" path if the operator configured exactly one service
// literally named "*", which is a deliberate global wildcard anyway.
func (r *Registry) allowKey(serviceCanon string) string {
	if _, ok := r.Services[serviceCanon]; ok {
		return serviceCanon
	}
	if _, ok := r.Services["*"]; ok && len(r.Services) == 1 {
		return "*"
	}
	return serviceCanon
}

// AllowedForService answers the per-service allow-list for an already-canonical
// server name.
func (r *Registry) AllowedForService(kid, serviceCanon string) bool {
	if r == nil {
		return false
	}
	svc, ok := r.Services[r.allowKey(serviceCanon)]
	if !ok {
		return false
	}
	return svc["*"] || svc[kid]
}

var (
	ErrUnknownKid   = errors.New("unknown kid")
	ErrTokenExpired = errors.New("token expired")
	ErrNotAllowed   = errors.New("kid not allowed for service")
	ErrBadAlg       = errors.New("token algorithm is not the pinned one")
)

// Authorize is the full policy check for a knock: known kid, not expired, and
// permitted for this service. The caller still verifies the proof separately —
// and must run the equalized-work dummy verify when this returns an error, so
// the response does not reveal whether the kid exists.
func (r *Registry) Authorize(kid, serviceCanon string, now int64) (*Token, error) {
	t := r.Lookup(kid)
	if t == nil {
		return nil, ErrUnknownKid
	}
	// SPEC §3 pins the algorithm per kid so a future second algorithm can
	// never be negotiated down. The field was written by every loader and read
	// by nobody, which made the pin decorative; it is enforced here and in the
	// grant re-check so an unexpected value fails rather than defaults.
	if t.Alg != AlgHMACSHA256 {
		return nil, ErrBadAlg
	}
	if r.IsExpired(t, now) {
		return nil, ErrTokenExpired
	}
	if !r.AllowedForService(kid, serviceCanon) {
		return nil, ErrNotAllowed
	}
	return t, nil
}
