// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jitaccess is a native Caddy HTTP handler that gates a site behind the
// JIT Network Access knock — the no-extra-process path for Caddy (DESIGN §3.1).
//
// It embeds core/go, so the wire protocol, canonical grant keys and crypto are
// the same code the standalone Authorizer and (by way of the shared vectors) the
// BunkerWeb Lua plugin run. One extension and one enrolled token work against
// all three.
//
// Because the handler runs in-process it reads the un-forgeable TCP peer
// directly — it has none of the forward-auth boundary's IP-provenance problems.
//
// Build:
//
//	xcaddy build --with github.com/Slopapalooza/jit-network-access/adapters/caddy
package jitaccess

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

const (
	defaultPrefix   = "/.well-known/jit-access"
	jitMarker       = "challenge; v=1"
	grantCookieName = "__Host-jit-grant"

	failInterstitial = "interstitial"
	failStealth      = "stealth"
)

func init() {
	caddy.RegisterModule(JITAccess{})
	httpcaddyfile.RegisterHandlerDirective("jit_access", parseCaddyfile)
	// The gate runs before any authentication handler: the service is dark
	// before inner auth is even attempted, and inner auth (basic_auth,
	// forward_auth, an SSO proxy) still applies behind a valid grant. Declaring
	// the order here means users do not need an `order` global option.
	httpcaddyfile.RegisterDirectiveOrder("jit_access", httpcaddyfile.Before, "basic_auth")
}

// Process-wide state. Kept outside the handler instance so a Caddy config
// reload (which re-provisions handlers) does not drop live grants or rotate the
// nonce key out from under in-flight knocks. Grant keys are service-scoped, so
// sharing one store across sites is safe.
var (
	sharedOnce   sync.Once
	sharedGrants *jitcore.GrantStore
	sharedNonces *jitcore.NonceStore
	sharedCodes  *jitcore.EnrollStore
	sharedRL     *rateLimiter
	nonceKey     []byte
	sharedErr    error
)

func shared() error {
	sharedOnce.Do(func() {
		sharedGrants = jitcore.NewGrantStore()
		sharedNonces = jitcore.NewNonceStore()
		sharedCodes = jitcore.NewEnrollStore()
		sharedRL = newRateLimiter()
		nonceKey, sharedErr = jitcore.RandomBytes(32)
	})
	return sharedErr
}

// Token is one enrolled device.
type Token struct {
	Kid     string `json:"kid"`
	Secret  string `json:"secret"` // base64url
	Label   string `json:"label,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

// JITAccess gates the site it is placed in.
type JITAccess struct {
	// Prefix is the base path of the protocol endpoints.
	Prefix string `json:"prefix,omitempty"`
	// Allow lists the kids permitted to open this site, or ["*"] for any.
	Allow []string `json:"allow,omitempty"`
	// Tokens is the device registry.
	Tokens []Token `json:"tokens,omitempty"`

	GrantTTL    caddy.Duration `json:"grant_ttl,omitempty"`
	NonceTTL    caddy.Duration `json:"nonce_ttl,omitempty"`
	EnrollTTL   caddy.Duration `json:"enroll_ttl,omitempty"`
	FailureMode string         `json:"failure_mode,omitempty"` // interstitial|stealth
	Binding     string         `json:"binding,omitempty"`      // ip|ip+cookie
	IPv6Prefix  int            `json:"ipv6_prefix,omitempty"`
	RateLimit   int            `json:"rate_limit,omitempty"` // per minute, per IP

	// TrustForwarded keys grants on Caddy's resolved client IP instead of the
	// TCP peer. Only safe when Caddy's own trusted_proxies is correctly
	// narrowed; the default (false) is immune to X-Forwarded-For spoofing.
	TrustForwarded bool `json:"trust_forwarded,omitempty"`

	reg    *jitcore.Registry
	logger *zap.Logger
}

func (JITAccess) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jit_access",
		New: func() caddy.Module { return new(JITAccess) },
	}
}

func (j *JITAccess) Provision(ctx caddy.Context) error {
	j.logger = ctx.Logger()
	if err := shared(); err != nil {
		return fmt.Errorf("jit_access: rng: %w", err)
	}
	if j.Prefix == "" {
		j.Prefix = defaultPrefix
	}
	j.Prefix = "/" + strings.Trim(j.Prefix, "/")
	if j.GrantTTL == 0 {
		j.GrantTTL = caddy.Duration(time.Hour)
	}
	if j.NonceTTL == 0 {
		j.NonceTTL = caddy.Duration(60 * time.Second)
	}
	if j.EnrollTTL == 0 {
		j.EnrollTTL = caddy.Duration(24 * time.Hour)
	}
	if j.FailureMode == "" {
		j.FailureMode = failInterstitial
	}
	if j.Binding == "" {
		j.Binding = jitcore.BindingIP
	}
	if j.IPv6Prefix <= 0 || j.IPv6Prefix > 128 {
		j.IPv6Prefix = 128
	}
	if j.RateLimit == 0 {
		j.RateLimit = 10
	}

	tokens := map[string]*jitcore.Token{}
	for _, t := range j.Tokens {
		sec, err := jitcore.B64uDecode(t.Secret)
		if err != nil {
			return fmt.Errorf("jit_access: token %s: secret is not base64url: %w", t.Kid, err)
		}
		if len(sec) < 16 {
			return fmt.Errorf("jit_access: token %s: secret must be >= 16 bytes", t.Kid)
		}
		tokens[t.Kid] = &jitcore.Token{Secret: sec, Alg: jitcore.AlgHMACSHA256, Label: t.Label, Expires: t.Expires}
	}
	// The allow-list is site-scoped: the registry is built per handler with a
	// single wildcard service entry, and the actual service name is checked
	// against the request host at request time.
	allow := map[string]bool{}
	for _, k := range j.Allow {
		allow[k] = true
	}
	j.reg = jitcore.NewRegistry(tokens, map[string]map[string]bool{"*": allow})
	return nil
}

func (j *JITAccess) Validate() error {
	switch j.FailureMode {
	case failInterstitial, failStealth:
	default:
		return fmt.Errorf("jit_access: bad failure_mode %q", j.FailureMode)
	}
	switch j.Binding {
	case jitcore.BindingIP, jitcore.BindingIPCookie:
	default:
		return fmt.Errorf("jit_access: bad binding %q", j.Binding)
	}
	if len(j.Tokens) == 0 {
		return fmt.Errorf("jit_access: no tokens configured — the site would be permanently dark")
	}
	if len(j.Allow) == 0 {
		return fmt.Errorf("jit_access: no allow list — no device could open this site")
	}
	return nil
}

// clientIP is the value grants are keyed on. Default: the TCP peer, which a
// request header cannot move (SECURITY-REVIEW C2/R2).
func (j *JITAccess) clientIP(r *http.Request) (string, error) {
	addr := r.RemoteAddr
	if j.TrustForwarded {
		if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
			if v, ok := repl.GetString("http.request.client_ip"); ok && v != "" {
				addr = v
			}
		}
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		addr = h
	}
	return jitcore.CanonIP(strings.Trim(addr, "[]"), j.IPv6Prefix, 32)
}

func (j *JITAccess) allowedForService(kid string) bool {
	return j.reg.AllowedForService(kid, "*")
}

func (j *JITAccess) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	service := jitcore.CanonServerName(r.Host)
	ip, err := j.clientIP(r)
	if err != nil || service == "" {
		// cannot identify the request — fail closed
		return j.deny(w, "unresolvable request")
	}

	// Protocol endpoints are answered before the grant check: a device that is
	// not yet granted must still be able to knock.
	if p := j.Prefix; r.URL.Path == p || strings.HasPrefix(r.URL.Path, p+"/") {
		switch {
		case r.URL.Path == p+"/challenge" && r.Method == http.MethodGet:
			return j.handleChallenge(w, service, ip)
		case r.URL.Path == p+"/respond" && r.Method == http.MethodPost:
			return j.handleRespond(w, r, service, ip)
		case r.URL.Path == p+"/enroll" && r.Method == http.MethodPost:
			return j.handleEnroll(w, r)
		}
		// any other path under the prefix stays dark
		return j.deny(w, "protocol endpoint")
	}

	cookie := ""
	if ck, err := r.Cookie(grantCookieName); err == nil {
		cookie = ck.Value
	}
	if g := sharedGrants.IsAllowed(service, ip, j.reg, now(), cookie); g != nil {
		return next.ServeHTTP(w, r)
	}
	return j.deny(w, "no grant")
}

func (j *JITAccess) handleChallenge(w http.ResponseWriter, service, ip string) error {
	if !sharedRL.allow(ip, j.RateLimit, now()) {
		w.WriteHeader(http.StatusTooManyRequests)
		return nil
	}
	rnd, err := jitcore.RandomBytes(16)
	if err != nil {
		return j.deny(w, "rng")
	}
	ts := now()
	nonce, err := jitcore.IssueNonce(nonceKey, uint64(ts), rnd, service, ip, j.IPv6Prefix)
	if err != nil {
		return j.deny(w, "nonce mint")
	}
	w.Header().Set("X-JIT-Nonce", jitcore.B64u(nonce))
	w.Header().Set("X-JIT-TS", fmt.Sprint(ts))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type respondBody struct {
	V     int    `json:"v"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
	Proof string `json:"proof"`
}

var dummySecret = make([]byte, 32)

func (j *JITAccess) handleRespond(w http.ResponseWriter, r *http.Request, service, ip string) error {
	if !sharedRL.allow(ip, j.RateLimit, now()) {
		w.WriteHeader(http.StatusTooManyRequests)
		return nil
	}
	var body respondBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		return j.deny(w, "malformed body")
	}
	nonceRaw, err1 := jitcore.B64uDecode(body.Nonce)
	tag, err2 := jitcore.B64uDecode(body.Proof)
	if err1 != nil || err2 != nil || len(nonceRaw) != jitcore.NonceLen || len(tag) != 32 {
		return j.deny(w, "malformed nonce/proof")
	}

	n := now()
	ok, rnd := jitcore.VerifyNonce(nonceKey, nonceRaw, service, ip, n, int64(time.Duration(j.NonceTTL).Seconds()), j.IPv6Prefix)
	if !ok {
		return j.deny(w, "bad or stale nonce")
	}

	// Equalized work: an unknown kid runs the same HMAC as a wrong proof, so the
	// response is not an existence oracle (PROTOCOL §6).
	token := j.reg.Lookup(body.Kid)
	secret := dummySecret
	if token != nil {
		secret = token.Secret
	}
	proofOK := jitcore.VerifyProof(secret, service, body.Kid, nonceRaw, tag)
	if token == nil || j.reg.IsExpired(token, n) || !j.allowedForService(body.Kid) || !proofOK {
		return j.deny(w, "rejected")
	}

	// verify-then-burn
	if !sharedNonces.Claim(jitcore.B64u(rnd), n, int64(time.Duration(j.NonceTTL).Seconds())) {
		return j.deny(w, "nonce replay")
	}

	ttl := int64(time.Duration(j.GrantTTL).Seconds())
	g := &jitcore.Grant{
		V: 1, Kid: body.Kid, Service: service, IP: ip,
		Binding: j.Binding, Issued: n, Exp: n + ttl,
	}
	if j.Binding == jitcore.BindingIPCookie {
		idBytes, err := jitcore.RandomBytes(32)
		if err != nil {
			return j.deny(w, "rng")
		}
		id := jitcore.B64u(idBytes)
		g.CookieHash = jitcore.CookieHash(id)
		http.SetCookie(w, &http.Cookie{
			Name: grantCookieName, Value: id, Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(ttl),
		})
	}
	sharedGrants.Put(g)

	if j.logger != nil {
		j.logger.Info("jit knock accepted", zap.String("service", service), zap.String("kid", body.Kid))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (j *JITAccess) handleEnroll(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Code == "" {
		return j.deny(w, "bad enroll body")
	}
	code := sharedCodes.Consume(body.Code, now())
	if code == nil {
		return j.deny(w, "code rejected")
	}
	token := j.reg.Lookup(code.Kid)
	if token == nil {
		return j.deny(w, "kid gone")
	}
	w.Header().Set("X-JIT-Kid", code.Kid)
	w.Header().Set("X-JIT-Secret", jitcore.B64u(token.Secret))
	w.Header().Set("X-JIT-Origins", strings.Join(code.Origins, ","))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (j *JITAccess) deny(w http.ResponseWriter, _ string) error {
	w.Header().Set("Cache-Control", "no-store")
	if j.FailureMode == failStealth {
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	w.Header().Set("X-JIT-Access", jitMarker)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(interstitialHTML)
	return nil
}

// MintEnrollCode registers a single-use enrollment code (used by tests and by
// out-of-band admin tooling; the secret never travels in the registration URL).
func MintEnrollCode(code, kid string, origins []string, exp int64) {
	_ = shared()
	sharedCodes.Put(code, &jitcore.EnrollCode{Kid: kid, Origins: origins, Exp: exp})
}

var now = func() int64 { return time.Now().Unix() }

// ---- rate limiting ---------------------------------------------------------

type rateLimiter struct {
	mu sync.Mutex
	m  map[string]*rlEntry
}
type rlEntry struct {
	start int64
	n     int
}

func newRateLimiter() *rateLimiter { return &rateLimiter{m: map[string]*rlEntry{}} }

func (l *rateLimiter) allow(ip string, perMin int, now int64) bool {
	if perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[ip]
	if !ok || now-e.start >= 60 {
		l.m[ip] = &rlEntry{start: now, n: 1}
		return true
	}
	e.n++
	return e.n <= perMin
}

// ---- caddyfile -------------------------------------------------------------

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var j JITAccess
	if err := j.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &j, nil
}

// UnmarshalCaddyfile parses:
//
//	jit_access {
//	    prefix /.well-known/jit-access
//	    grant_ttl 1h
//	    nonce_ttl 60s
//	    enroll_ttl 24h
//	    failure_mode interstitial
//	    binding ip
//	    ipv6_prefix 128
//	    rate_limit 10
//	    trust_forwarded
//	    token <kid> <secret-b64url> [label]
//	    allow <kid> [<kid>...]
//	}
func (j *JITAccess) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "prefix":
				if !d.NextArg() {
					return d.ArgErr()
				}
				j.Prefix = d.Val()
			case "failure_mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				j.FailureMode = d.Val()
			case "binding":
				if !d.NextArg() {
					return d.ArgErr()
				}
				j.Binding = d.Val()
			case "grant_ttl", "nonce_ttl", "enroll_ttl":
				key := d.Val()
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("%s: %v", key, err)
				}
				switch key {
				case "grant_ttl":
					j.GrantTTL = caddy.Duration(dur)
				case "nonce_ttl":
					j.NonceTTL = caddy.Duration(dur)
				case "enroll_ttl":
					j.EnrollTTL = caddy.Duration(dur)
				}
			case "ipv6_prefix", "rate_limit":
				key := d.Val()
				if !d.NextArg() {
					return d.ArgErr()
				}
				var n int
				if _, err := fmt.Sscanf(d.Val(), "%d", &n); err != nil {
					return d.Errf("%s: %v", key, err)
				}
				if key == "ipv6_prefix" {
					j.IPv6Prefix = n
				} else {
					j.RateLimit = n
				}
			case "trust_forwarded":
				j.TrustForwarded = true
			case "token":
				args := d.RemainingArgs()
				if len(args) < 2 {
					return d.Err("token requires <kid> <secret-b64url> [label]")
				}
				t := Token{Kid: args[0], Secret: args[1]}
				if len(args) > 2 {
					t.Label = strings.Join(args[2:], " ")
				}
				j.Tokens = append(j.Tokens, t)
			case "allow":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.Err("allow requires at least one kid (or *)")
				}
				j.Allow = append(j.Allow, args...)
			default:
				return d.Errf("unknown jit_access option %q", d.Val())
			}
		}
	}
	return nil
}

// interface guards
var (
	_ caddy.Provisioner           = (*JITAccess)(nil)
	_ caddy.Validator             = (*JITAccess)(nil)
	_ caddyhttp.MiddlewareHandler = (*JITAccess)(nil)
	_ caddyfile.Unmarshaler       = (*JITAccess)(nil)
)
