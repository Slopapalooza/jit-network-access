// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

// Configuration is a single JSON file — no database, no external dependency.
// Deliberately dependency-free (stdlib encoding/json) so the Authorizer stays a
// single static binary that builds offline.

const (
	DefaultURIPrefix = "/.well-known/jit-access"
	FailInterstitial = "interstitial"
	FailStealth      = "stealth"
)

type ServiceConfig struct {
	// Tokens lists the kids allowed to open this service, or ["*"] for any
	// registered token. Empty means no device may open it.
	Tokens      []string `json:"tokens"`
	FailureMode string   `json:"failure_mode"` // interstitial (default) | stealth
	Binding     string   `json:"binding"`      // ip (default) | ip+cookie
	GrantTTL    int64    `json:"grant_ttl"`    // seconds; 0 = inherit global
}

type TokenConfig struct {
	Kid     string `json:"kid"`
	Secret  string `json:"secret"` // base64url, >=16 bytes decoded
	Label   string `json:"label"`
	Expires int64  `json:"expires"` // unix seconds; 0 = never
}

type Config struct {
	// Listen is the protocol + forward-auth listener. It MUST NOT be reachable
	// from the internet: in proxy mode the Authorizer trusts the proxy for the
	// client IP, so a directly reachable listener would let anyone forge it
	// (SECURITY-REVIEW: direct-Authorizer-exposure). Default is loopback.
	Listen      string `json:"listen"`
	AdminListen string `json:"admin_listen"` // "" = serve /admin on Listen
	AdminToken  string `json:"admin_token"`  // required for /admin/*

	URIPrefix string `json:"uri_prefix"`

	// TrustedProxies are the CIDRs the forwarded headers are honored from.
	// A request whose TCP peer is outside these is treated as DIRECT: its
	// X-Forwarded-* headers are ignored entirely.
	TrustedProxies []string `json:"trusted_proxies"`
	RealIPHeader   string   `json:"real_ip_header"` // default X-Forwarded-For

	GrantTTL   int64 `json:"grant_ttl"`
	NonceTTL   int64 `json:"nonce_ttl"`
	EnrollTTL  int64 `json:"enroll_ttl"`
	IPv6Prefix int   `json:"ipv6_prefix"`
	RateLimit  int   `json:"rate_limit_per_min"`

	Services map[string]ServiceConfig `json:"services"`
	Tokens   []TokenConfig            `json:"tokens"`

	trusted       []netip.Prefix           // parsed TrustedProxies
	canonServices map[string]ServiceConfig // Services keyed by canonical name (collision-checked)
}

func DefaultConfig() *Config {
	return &Config{
		Listen:         "127.0.0.1:8998",
		URIPrefix:      DefaultURIPrefix,
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RealIPHeader:   "X-Forwarded-For",
		GrantTTL:       3600,
		NonceTTL:       60,
		EnrollTTL:      86400,
		IPv6Prefix:     128,
		RateLimit:      10,
		Services:       map[string]ServiceConfig{},
	}
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := DefaultConfig()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.finalize(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c *Config) finalize() error {
	if c.URIPrefix == "" {
		c.URIPrefix = DefaultURIPrefix
	}
	c.URIPrefix = "/" + strings.Trim(c.URIPrefix, "/")
	if c.RealIPHeader == "" {
		c.RealIPHeader = "X-Forwarded-For"
	}
	if c.IPv6Prefix <= 0 || c.IPv6Prefix > 128 {
		c.IPv6Prefix = 128
	}
	if c.NonceTTL <= 0 {
		c.NonceTTL = 60
	}
	if c.GrantTTL <= 0 {
		c.GrantTTL = 3600
	}
	if c.EnrollTTL <= 0 {
		c.EnrollTTL = 86400
	}
	// Clamp like the BunkerWeb plugin does, so a typo cannot mint an
	// effectively immortal enrollment link.
	if c.EnrollTTL < 300 {
		c.EnrollTTL = 300
	}
	if c.EnrollTTL > 604800 {
		c.EnrollTTL = 604800
	}

	c.trusted = nil
	for _, s := range c.TrustedProxies {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// allow a bare address as a /32 or /128
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return fmt.Errorf("trusted_proxies %q: %w", s, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c.trusted = append(c.trusted, p)
	}

	seen := map[string]bool{}
	for _, t := range c.Tokens {
		if t.Kid == "" {
			return fmt.Errorf("token with empty kid")
		}
		if seen[t.Kid] {
			return fmt.Errorf("duplicate kid %q", t.Kid)
		}
		seen[t.Kid] = true
		sec, err := jitcore.B64uDecode(t.Secret)
		if err != nil {
			return fmt.Errorf("token %s: secret is not base64url: %w", t.Kid, err)
		}
		if len(sec) < 16 {
			return fmt.Errorf("token %s: secret must be >= 16 bytes", t.Kid)
		}
	}
	// Two DISTINCT json keys can collapse to one canonical name ("app.example.com"
	// and "app.example.com:8443" both canonicalize to the former). Registry() then
	// wrote both into one map slot and Service() returned whichever Go's RANDOMIZED
	// map iteration reached first — so which allow-list and which failure_mode were
	// in effect changed from one process start to the next, with no config change
	// and no log line. Reject the collision instead; duplicate kids are already
	// rejected above for the same reason.
	byCanon := map[string]string{}
	for name := range c.Services {
		canon := jitcore.CanonServerName(name)
		if prev, dup := byCanon[canon]; dup {
			return fmt.Errorf("services %q and %q both canonicalize to %q — "+
				"they would be one service with a nondeterministic policy; keep one", prev, name, canon)
		}
		byCanon[canon] = name
	}
	c.canonServices = make(map[string]ServiceConfig, len(c.Services))
	for name, svc := range c.Services {
		c.canonServices[jitcore.CanonServerName(name)] = svc
	}

	for name, svc := range c.Services {
		switch svc.FailureMode {
		case "", FailInterstitial, FailStealth:
		default:
			return fmt.Errorf("service %s: bad failure_mode %q", name, svc.FailureMode)
		}
		switch svc.Binding {
		case "", jitcore.BindingIP, jitcore.BindingIPCookie:
		default:
			return fmt.Errorf("service %s: bad binding %q", name, svc.Binding)
		}
	}
	return nil
}

// Registry materializes the TokenRegistry from config. Service names are
// canonicalized here so lookups on the request path are already normalized.
func (c *Config) Registry() (*jitcore.Registry, error) {
	tokens := map[string]*jitcore.Token{}
	for _, t := range c.Tokens {
		sec, err := jitcore.B64uDecode(t.Secret)
		if err != nil {
			return nil, err
		}
		tokens[t.Kid] = &jitcore.Token{
			Secret: sec, Alg: jitcore.AlgHMACSHA256, Label: t.Label, Expires: t.Expires,
		}
	}
	// Built from the pre-canonicalized map finalize() produced, which is collision
	// free — so this cannot depend on map iteration order.
	services := map[string]map[string]bool{}
	for canon, svc := range c.canonServices {
		allow := map[string]bool{}
		for _, kid := range svc.Tokens {
			allow[kid] = true
		}
		services[canon] = allow
	}
	return jitcore.NewRegistry(tokens, services), nil
}

// Service returns the config for a canonical service name.
func (c *Config) Service(canon string) (ServiceConfig, bool) {
	svc, ok := c.canonServices[canon]
	return svc, ok
}

// defaultFailureMode is what deny() uses when the request could not be resolved
// to a service at all (unknown host, conventions in conflict). It returns the
// STRICTER of the modes configured, so a deployment that asked for stealth
// anywhere never answers an unresolvable request with the branded interstitial
// and the X-JIT-Access marker — which would advertise a gate the operator
// deliberately made invisible.
func (c *Config) defaultFailureMode() string {
	for _, svc := range c.canonServices {
		if svc.FailureMode == FailStealth {
			return FailStealth
		}
	}
	return FailInterstitial
}

func (c *Config) failureMode(svc ServiceConfig) string {
	if svc.FailureMode == "" {
		return FailInterstitial
	}
	return svc.FailureMode
}

func (c *Config) binding(svc ServiceConfig) string {
	if svc.Binding == "" {
		return jitcore.BindingIP
	}
	return svc.Binding
}

func (c *Config) grantTTL(svc ServiceConfig) int64 {
	if svc.GrantTTL > 0 {
		return svc.GrantTTL
	}
	return c.GrantTTL
}
