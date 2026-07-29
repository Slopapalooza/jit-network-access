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
	"net/netip"
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

// Expiry is lazy on the read path, so nothing here is required for correctness —
// but without reclamation the maps only ever grow, and an unauthenticated client
// controls how fast (one spent nonce per successful knock, one rate-limit entry
// per source address, one grant per address). Sweeping is driven from the
// request path rather than a goroutine + ticker: the module has no shutdown hook
// to stop a background loop on config reload, and Caddy rebuilds handlers freely.
const sweepEvery = 60 // seconds

var (
	sweepMu   sync.Mutex
	lastSweep int64
)

func maybeSweep(now int64) {
	sweepMu.Lock()
	if now-lastSweep < sweepEvery {
		sweepMu.Unlock()
		return
	}
	lastSweep = now
	sweepMu.Unlock()

	sharedGrants.Sweep(now)
	sharedNonces.Sweep(now)
	sharedCodes.Sweep(now)
	sharedRL.sweep(now)
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

	// TrustForwarded derives the client IP from X-Forwarded-For instead of the
	// TCP peer. It REQUIRES TrustedProxies; see clientIP for why.
	TrustForwarded bool `json:"trust_forwarded,omitempty"`

	// TrustedProxies are the CIDRs (or bare addresses) our own infrastructure
	// occupies. Deliberately NOT inherited from Caddy's server-level
	// trusted_proxies: that defaults to a left-most X-Forwarded-For read unless
	// trusted_proxies_strict is also set, which would let any client behind the
	// proxy nominate its own grant key. Keeping our own list makes the safe
	// behavior the only behavior.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	reg     *jitcore.Registry
	logger  *zap.Logger
	trusted []netip.Prefix // parsed TrustedProxies
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
	// <= 0, not == 0: a negative value used to survive Provision and then disable
	// the limiter entirely at allow(), silently removing the only knock throttle.
	if j.RateLimit <= 0 {
		j.RateLimit = 10
	}

	// A grant is keyed on the client IP, so whatever decides that value decides
	// who the grant belongs to. Refuse the unsafe combination outright rather
	// than ship a switch that reads as safe and is not.
	trusted, err := parsePrefixes(j.TrustedProxies)
	if err != nil {
		return fmt.Errorf("jit_access: trusted_proxies: %w", err)
	}
	j.trusted = trusted
	if j.TrustForwarded && len(j.trusted) == 0 {
		return fmt.Errorf("jit_access: trust_forwarded requires trusted_proxies " +
			"(the CIDRs your proxies occupy) — without it any client can choose its own grant key")
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

// parsePrefixes accepts CIDRs and bare addresses (treated as /32 or /128).
func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("%q is not a CIDR or address: %w", s, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p)
	}
	return out, nil
}

func (j *JITAccess) isTrusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range j.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseHostAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

// clientIP is the value grants are keyed on.
//
// Default: the TCP peer, which no request header can move (SECURITY-REVIEW
// C2/R2).
//
// With TrustForwarded (which Provision only permits alongside TrustedProxies):
// walk X-Forwarded-For from the RIGHT and take the first address that is not one
// of our own proxies. Entries a client appends sit to the LEFT of the ones our
// trusted hops appended, so they cannot win.
//
// This deliberately does NOT use Caddy's http.request.client_ip placeholder.
// That resolves to the LEFT-most X-Forwarded-For entry — the client-supplied one
// — unless the operator also sets trusted_proxies_strict, so delegating to it
// made the safety of the gate depend on a separate directive most operators
// never set.
func (j *JITAccess) clientIP(r *http.Request) (string, error) {
	peer, err := parseHostAddr(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("jit_access: unparseable peer %q: %w", r.RemoteAddr, err)
	}
	if !j.TrustForwarded || !j.isTrusted(peer) {
		return jitcore.CanonIP(peer.String(), j.IPv6Prefix, 32)
	}
	// Flatten every X-Forwarded-For line before walking backwards: with repeated
	// header lines the right-most entry overall is the most recently appended.
	var chain []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		chain = append(chain, strings.Split(v, ",")...)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		a, err := parseHostAddr(chain[i])
		if err != nil {
			continue
		}
		if j.isTrusted(a) {
			continue // another hop of our own infrastructure
		}
		return jitcore.CanonIP(a.String(), j.IPv6Prefix, 32)
	}
	// A trusted peer that forwarded nothing usable (health check, direct hit).
	return jitcore.CanonIP(peer.String(), j.IPv6Prefix, 32)
}

func (j *JITAccess) allowedForService(kid string) bool {
	return j.reg.AllowedForService(kid, "*")
}

func (j *JITAccess) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	maybeSweep(now())
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
			return j.handleEnroll(w, r, ip)
		case r.URL.Path == p+"/register" && r.Method == http.MethodGet:
			return j.handleRegister(w)
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
		// deny(), not a bare 429: PROTOCOL §6 requires every rejection at these
		// endpoints to be the SAME generic response. A 429 here was a free
		// endpoint-discovery oracle — in stealth mode the protocol paths answered
		// 429 while every other path answered 404, so three requests located the
		// gate.
		return j.deny(w, "rate limited")
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
		// deny(), not a bare 429: PROTOCOL §6 requires every rejection at these
		// endpoints to be the SAME generic response. A 429 here was a free
		// endpoint-discovery oracle — in stealth mode the protocol paths answered
		// 429 while every other path answered 404, so three requests located the
		// gate.
		return j.deny(w, "rate limited")
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
	oldHash := ""
	if ck, err := r.Cookie(grantCookieName); err == nil && ck.Value != "" {
		oldHash = jitcore.CookieHash(ck.Value)
	}
	sharedGrants.Put(g, oldHash)

	if j.logger != nil {
		j.logger.Info("jit knock accepted", zap.String("service", service), zap.String("kid", body.Kid))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleRegister answers a registration link for a browser WITHOUT the
// extension; an installed one intercepts that navigation client-side and never
// reaches here. Identical for any code value, so it is no enrollment-code oracle.
func (j *JITAccess) handleRegister(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer") // the URL carries a single-use code
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jitcore.RegisterHTML)
	return nil
}

func (j *JITAccess) handleEnroll(w http.ResponseWriter, r *http.Request, ip string) error {
	// PROTOCOL §2.1 requires this endpoint to be rate-limited, and it is the
	// highest-value target in the protocol: it trades a code for a long-term
	// device secret. It was the one knock endpoint with no throttle at all.
	if !sharedRL.allow(ip, j.RateLimit, now()) {
		return j.deny(w, "rate limited")
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Code == "" {
		return j.deny(w, "bad enroll body")
	}
	// Look the kid up BEFORE consuming: Consume is delete-after-read, so doing it
	// first let any hostile POST destroy a valid code for a kid this site does
	// not serve. Peek, validate, then burn.
	peek := sharedCodes.Peek(body.Code, now())
	if peek == nil || j.reg.Lookup(peek.Kid) == nil {
		return j.deny(w, "code rejected")
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

// sweep drops finished windows. Without it every distinct source address left a
// permanent entry: with the default ipv6_prefix of 128 an attacker sourcing from
// a routed /64 could add one per request forever and eventually OOM the proxy
// fronting every site, not just the gated one.
func (l *rateLimiter) sweep(now int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.m {
		if now-e.start >= 60 {
			delete(l.m, k)
		}
	}
}

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
//	    trusted_proxies 10.0.0.0/8 192.168.0.0/16
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
			case "trusted_proxies":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.Err("trusted_proxies requires at least one CIDR or address")
				}
				j.TrustedProxies = append(j.TrustedProxies, args...)
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
