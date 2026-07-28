// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jitaccess is a native Traefik middleware plugin that keeps a service
// dark until a paired browser extension answers the knock.
//
// Traefik plugins are not compiled — Traefik interprets them with Yaegi at
// runtime. That imposes two constraints this package is written to satisfy:
// no external dependencies (the portable core is vendored into
// internal/jitcore by build-vendor.sh), and no reflection- or cgo-heavy code.
// The primitives it relies on — HMAC-SHA256, SHA-256, base64url, encoding/binary
// and net/netip masking — were verified to run correctly under Yaegi before this
// was written.
//
// Running in-process means it reads the real client address from the request
// rather than trusting a forwarded header, so it has none of the IP-provenance
// caveats of the forward-auth Authorizer.
package jitaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	jitcore "github.com/Slopapalooza/jit-network-access/adapters/traefik/plugin/internal/jitcore"
)

const (
	defaultPrefix   = "/.well-known/jit-access"
	jitMarker       = "challenge; v=1"
	grantCookieName = "__Host-jit-grant"

	failInterstitial = "interstitial"
	failStealth      = "stealth"
)

// Token is one enrolled device.
type Token struct {
	Kid     string `json:"kid,omitempty"`
	Secret  string `json:"secret,omitempty"` // base64url, >= 16 bytes decoded
	Label   string `json:"label,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

// Config is the middleware's Traefik configuration.
type Config struct {
	// Allow lists the kids permitted to open this router, or ["*"] for any.
	Allow  []string `json:"allow,omitempty"`
	Tokens []Token  `json:"tokens,omitempty"`

	Prefix      string `json:"prefix,omitempty"`
	FailureMode string `json:"failureMode,omitempty"` // interstitial | stealth
	Binding     string `json:"binding,omitempty"`     // ip | ip+cookie

	GrantTTL   int `json:"grantTtl,omitempty"`   // seconds
	NonceTTL   int `json:"nonceTtl,omitempty"`   // seconds
	IPv6Prefix int `json:"ipv6Prefix,omitempty"` // 128 = exact address
	RateLimit  int `json:"rateLimit,omitempty"`  // knocks/min/IP

	// TrustForwarded derives the client IP from X-Forwarded-For instead of the
	// TCP peer. It REQUIRES TrustedProxies; see clientIP for why.
	TrustForwarded bool `json:"trustForwarded,omitempty"`

	// TrustedProxies are the CIDRs (or bare addresses) that our own infrastructure
	// occupies. Both the TCP peer and every X-Forwarded-For entry are checked
	// against this list, and the first address from the RIGHT that is not in it
	// is the client. Without it, TrustForwarded cannot be made safe and New()
	// refuses the configuration.
	TrustedProxies []string `json:"trustedProxies,omitempty"`
}

// CreateConfig returns the default configuration. Traefik calls this before
// unmarshalling the user's values over it.
func CreateConfig() *Config {
	return &Config{
		Prefix:      defaultPrefix,
		FailureMode: failInterstitial,
		Binding:     jitcore.BindingIP,
		GrantTTL:    3600,
		NonceTTL:    60,
		IPv6Prefix:  128,
		RateLimit:   10,
	}
}

// Process-wide state, so a Traefik config reload (which rebuilds middleware
// instances) does not drop live grants or rotate the nonce key mid-knock.
// Grant keys are service-scoped, so one store across routers is correct.
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
// per source address, one grant per address).
//
// Driven from the request path rather than a goroutine + time.Ticker on purpose:
// the plugin is interpreted by Yaegi and has no shutdown hook, so a background
// loop would be both a portability risk and impossible to stop across the config
// reloads that rebuild middleware instances.
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

// JITAccess is the middleware handler.
type JITAccess struct {
	next    http.Handler
	name    string
	cfg     *Config
	reg     *jitcore.Registry
	trusted []netip.Prefix // parsed cfg.TrustedProxies
}

// New builds the middleware. Traefik calls this per router.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if err := shared(); err != nil {
		return nil, fmt.Errorf("jitaccess: rng: %w", err)
	}
	if len(cfg.Tokens) == 0 {
		return nil, fmt.Errorf("jitaccess: no tokens configured — the router would be permanently dark")
	}
	if len(cfg.Allow) == 0 {
		return nil, fmt.Errorf("jitaccess: no allow list — no device could open this router")
	}
	switch cfg.FailureMode {
	case "", failInterstitial, failStealth:
	default:
		return nil, fmt.Errorf("jitaccess: bad failureMode %q", cfg.FailureMode)
	}
	switch cfg.Binding {
	case "", jitcore.BindingIP, jitcore.BindingIPCookie:
	default:
		return nil, fmt.Errorf("jitaccess: bad binding %q", cfg.Binding)
	}

	// normalize (Traefik may hand us a partially-filled Config)
	if cfg.Prefix == "" {
		cfg.Prefix = defaultPrefix
	}
	cfg.Prefix = "/" + strings.Trim(cfg.Prefix, "/")
	if cfg.FailureMode == "" {
		cfg.FailureMode = failInterstitial
	}
	if cfg.Binding == "" {
		cfg.Binding = jitcore.BindingIP
	}
	if cfg.GrantTTL <= 0 {
		cfg.GrantTTL = 3600
	}
	if cfg.NonceTTL <= 0 {
		cfg.NonceTTL = 60
	}
	if cfg.IPv6Prefix <= 0 || cfg.IPv6Prefix > 128 {
		cfg.IPv6Prefix = 128
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 10
	}

	// A grant is keyed on the client IP, so whatever decides that value decides
	// who the grant belongs to. Trusting X-Forwarded-For without knowing which
	// hops are ours is not merely weak, it is inverted: Traefik PRESERVES an
	// incoming X-Forwarded-For and appends the peer, so the left-most entry is
	// precisely the part the client wrote. Refuse the combination rather than
	// ship a switch that looks safe and is not.
	trusted, err := parsePrefixes(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("jitaccess: trustedProxies: %w", err)
	}
	if cfg.TrustForwarded && len(trusted) == 0 {
		return nil, fmt.Errorf("jitaccess: trustForwarded requires trustedProxies " +
			"(the CIDRs your proxies occupy) — without it any client can choose its own grant key")
	}

	tokens := map[string]*jitcore.Token{}
	for _, t := range cfg.Tokens {
		sec, err := jitcore.B64uDecode(t.Secret)
		if err != nil {
			return nil, fmt.Errorf("jitaccess: token %s: secret is not base64url: %w", t.Kid, err)
		}
		if len(sec) < 16 {
			return nil, fmt.Errorf("jitaccess: token %s: secret must be >= 16 bytes", t.Kid)
		}
		tokens[t.Kid] = &jitcore.Token{
			Secret: sec, Alg: jitcore.AlgHMACSHA256, Label: t.Label, Expires: t.Expires,
		}
	}
	allow := map[string]bool{}
	for _, k := range cfg.Allow {
		allow[k] = true
	}
	// The allow-list is router-scoped; the actual host is checked at request time.
	reg := jitcore.NewRegistry(tokens, map[string]map[string]bool{"*": allow})

	return &JITAccess{next: next, name: name, cfg: cfg, reg: reg, trusted: trusted}, nil
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
// Default: the TCP peer, which no request header can move.
//
// With TrustForwarded (which New() only permits alongside TrustedProxies): walk
// X-Forwarded-For from the RIGHT and take the first address that is not one of
// our own proxies. Entries a client appends sit to the LEFT of the ones our
// trusted hops appended, so they can never win. Taking the left-most entry — as
// this did before — hands every client the ability to nominate its own grant
// key, and Traefik makes that worse by preserving an incoming header verbatim.
//
// Anything unparseable, or a peer that is not itself trusted, falls back to the
// peer: never to a client-supplied value.
func (j *JITAccess) clientIP(r *http.Request) (string, error) {
	peer, err := parseHostAddr(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("jitaccess: unparseable peer %q: %w", r.RemoteAddr, err)
	}
	if !j.cfg.TrustForwarded || !j.isTrusted(peer) {
		return jitcore.CanonIP(peer.String(), j.cfg.IPv6Prefix, 32)
	}
	// Flatten every X-Forwarded-For line into one ordered list before walking it
	// backwards: with repeated header lines the right-most entry overall is the
	// most recently appended, so per-line walking would pick the wrong one.
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
		return jitcore.CanonIP(a.String(), j.cfg.IPv6Prefix, 32)
	}
	// A trusted peer that forwarded nothing usable (health check, direct hit).
	return jitcore.CanonIP(peer.String(), j.cfg.IPv6Prefix, 32)
}

func (j *JITAccess) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	maybeSweep(now())
	service := jitcore.CanonServerName(r.Host)
	ip, err := j.clientIP(r)
	if err != nil || service == "" {
		j.deny(w) // cannot identify the request: fail closed
		return
	}

	// Protocol endpoints answer before the grant check — a device that is not
	// yet granted must still be able to knock.
	if p := j.cfg.Prefix; r.URL.Path == p || strings.HasPrefix(r.URL.Path, p+"/") {
		switch {
		case r.URL.Path == p+"/challenge" && r.Method == http.MethodGet:
			j.challenge(w, service, ip)
		case r.URL.Path == p+"/respond" && r.Method == http.MethodPost:
			j.respond(w, r, service, ip)
		case r.URL.Path == p+"/enroll" && r.Method == http.MethodPost:
			j.enroll(w, r, ip)
		default:
			j.deny(w) // any other path under the prefix stays dark
		}
		return
	}

	cookie := ""
	if ck, err := r.Cookie(grantCookieName); err == nil {
		cookie = ck.Value
	}
	if g := sharedGrants.IsAllowed(service, ip, j.reg, now(), cookie); g != nil {
		j.next.ServeHTTP(w, r)
		return
	}
	j.deny(w)
}

func (j *JITAccess) challenge(w http.ResponseWriter, service, ip string) {
	if !sharedRL.allow(ip, j.cfg.RateLimit, now()) {
		// deny(), not a bare 429: PROTOCOL §6 requires every rejection at these
		// endpoints to be the SAME generic response. A 429 here was a free
		// endpoint-discovery oracle — in stealth mode the protocol paths answered
		// 429 while every other path answered 404, so three requests located the
		// gate.
		j.deny(w)
		return
	}
	rnd, err := jitcore.RandomBytes(16)
	if err != nil {
		j.deny(w)
		return
	}
	ts := now()
	nonce, err := jitcore.IssueNonce(nonceKey, uint64(ts), rnd, service, ip, j.cfg.IPv6Prefix)
	if err != nil {
		j.deny(w)
		return
	}
	w.Header().Set("X-JIT-Nonce", jitcore.B64u(nonce))
	w.Header().Set("X-JIT-TS", fmt.Sprint(ts))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

type respondBody struct {
	V     int    `json:"v"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
	Proof string `json:"proof"`
}

var dummySecret = make([]byte, 32)

func (j *JITAccess) respond(w http.ResponseWriter, r *http.Request, service, ip string) {
	if !sharedRL.allow(ip, j.cfg.RateLimit, now()) {
		// deny(), not a bare 429: PROTOCOL §6 requires every rejection at these
		// endpoints to be the SAME generic response. A 429 here was a free
		// endpoint-discovery oracle — in stealth mode the protocol paths answered
		// 429 while every other path answered 404, so three requests located the
		// gate.
		j.deny(w)
		return
	}
	var body respondBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		j.deny(w)
		return
	}
	nonceRaw, err1 := jitcore.B64uDecode(body.Nonce)
	tag, err2 := jitcore.B64uDecode(body.Proof)
	if err1 != nil || err2 != nil || len(nonceRaw) != jitcore.NonceLen || len(tag) != 32 {
		j.deny(w)
		return
	}

	n := now()
	ok, rnd := jitcore.VerifyNonce(nonceKey, nonceRaw, service, ip, n, int64(j.cfg.NonceTTL), j.cfg.IPv6Prefix)
	if !ok {
		j.deny(w)
		return
	}

	// Equalized work: an unknown kid costs the same HMAC as a wrong proof, so
	// the response is not a device-existence oracle.
	token := j.reg.Lookup(body.Kid)
	secret := dummySecret
	if token != nil {
		secret = token.Secret
	}
	proofOK := jitcore.VerifyProof(secret, service, body.Kid, nonceRaw, tag)
	if token == nil || j.reg.IsExpired(token, n) || !j.reg.AllowedForService(body.Kid, "*") || !proofOK {
		j.deny(w)
		return
	}

	// verify-then-burn: a bad proof never consumes a nonce
	if !sharedNonces.Claim(jitcore.B64u(rnd), n, int64(j.cfg.NonceTTL)) {
		j.deny(w)
		return
	}

	ttl := int64(j.cfg.GrantTTL)
	g := &jitcore.Grant{
		V: 1, Kid: body.Kid, Service: service, IP: ip,
		Binding: j.cfg.Binding, Issued: n, Exp: n + ttl,
	}
	if j.cfg.Binding == jitcore.BindingIPCookie {
		idBytes, err := jitcore.RandomBytes(32)
		if err != nil {
			j.deny(w) // fail closed rather than silently downgrading to ip-only
			return
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

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (j *JITAccess) enroll(w http.ResponseWriter, r *http.Request, ip string) {
	// PROTOCOL §2.1 requires this endpoint to be rate-limited, and it is the
	// highest-value target in the protocol: it trades a code for a long-term
	// device secret. It was the one knock endpoint with no throttle at all.
	if !sharedRL.allow(ip, j.cfg.RateLimit, now()) {
		j.deny(w)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Code == "" {
		j.deny(w)
		return
	}
	// Look the kid up BEFORE consuming: Consume is delete-after-read, so doing it
	// first let any hostile POST destroy a valid code for a kid this router does
	// not serve. Peek, validate, then burn.
	if peek := sharedCodes.Peek(body.Code, now()); peek == nil || j.reg.Lookup(peek.Kid) == nil {
		j.deny(w)
		return
	}
	code := sharedCodes.Consume(body.Code, now())
	if code == nil {
		j.deny(w)
		return
	}
	token := j.reg.Lookup(code.Kid)
	if token == nil {
		j.deny(w)
		return
	}
	w.Header().Set("X-JIT-Kid", code.Kid)
	w.Header().Set("X-JIT-Secret", jitcore.B64u(token.Secret))
	w.Header().Set("X-JIT-Origins", strings.Join(code.Origins, ","))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (j *JITAccess) deny(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	if j.cfg.FailureMode == failStealth {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("X-JIT-Access", jitMarker)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(interstitialHTML)
}

// MintEnrollCode registers a single-use enrollment code, so the device secret
// never travels in the registration URL.
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
// permanent entry: with the default ipv6Prefix of 128 an attacker sourcing from
// a routed /64 could add one per request forever and eventually OOM the proxy
// fronting every router, not just the gated one.
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
