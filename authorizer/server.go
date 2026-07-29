// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

// The Authorizer's two faces (DESIGN §3.1):
//
//	1. the L1 protocol endpoints, proxied through on the protected origin
//	   under <uri_prefix>/ — byte-identical behavior to the BunkerWeb plugin, so
//	   the same extension and the same enrolled token work against either.
//	2. GET /authz — the forward-auth endpoint: 204 granted, or deny.
//
// Fail-closed is the invariant (SPEC §7): every error path denies.

type Server struct {
	mu     sync.RWMutex
	cfg    *Config
	reg    *jitcore.Registry
	grants *jitcore.GrantStore
	nonces *jitcore.NonceStore
	codes  *jitcore.EnrollStore

	nonceKey []byte
	rl       *rateLimiter
	metrics  *metrics
	now      func() int64 // injectable for tests

	mux http.Handler // routing table for the CURRENT config; rebuilt by Reload
}

func NewServer(cfg *Config) (*Server, error) {
	reg, err := cfg.Registry()
	if err != nil {
		return nil, err
	}
	// Ephemeral per-process nonce key: nonces do not need to survive a restart
	// (they live ~60s), and generating it here means no key material on disk.
	nk, err := jitcore.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, reg: reg,
		grants:   jitcore.NewGrantStore(),
		nonces:   jitcore.NewNonceStore(),
		codes:    jitcore.NewEnrollStore(),
		nonceKey: nk,
		rl:       newRateLimiter(),
		metrics:  &metrics{},
		now:      func() int64 { return time.Now().Unix() },
	}, nil
}

func (s *Server) config() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Server) registry() *jitcore.Registry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reg
}

// Reload swaps config + registry atomically; live grants survive but are
// re-checked against the new registry on their next request (SPEC §4.3).
//
// The routing table is rebuilt too. It used to be captured once at startup, so a
// SIGHUP that changed uri_prefix left the mux serving the OLD prefix while
// /authz carved out the NEW one — the knock endpoints became unreachable and the
// service locked itself out until someone restarted it.
//
// listen/admin_listen cannot be applied without rebinding sockets, so a reload
// that changes them is REFUSED rather than half-applied.
func (s *Server) Reload(cfg *Config) error {
	reg, err := cfg.Registry()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Listen != s.cfg.Listen {
		return fmt.Errorf("listen changed (%q -> %q): restart required, not a reload", s.cfg.Listen, cfg.Listen)
	}
	if cfg.AdminListen != s.cfg.AdminListen {
		return fmt.Errorf("admin_listen changed (%q -> %q): restart required, not a reload", s.cfg.AdminListen, cfg.AdminListen)
	}
	s.cfg, s.reg = cfg, reg
	s.mux = s.buildMuxLocked()
	return nil
}

// Handler is the main listener: the protocol endpoints plus forward-auth.
//
// /admin/* is mounted here ONLY when admin_listen is empty. Configuring
// admin_listen moves it to its own listener (see AdminHandler) so the admin API
// can be bound somewhere the proxy cannot reach at all — the field was
// previously parsed, documented as doing exactly that, and then never read, so
// an operator who set it silently kept the admin API on the main port.
// Handler returns a STABLE handler that dispatches through whatever routing
// table the current config implies, so http.Server can be built once while
// SIGHUP still takes effect.
func (s *Server) Handler() http.Handler {
	s.mu.Lock()
	if s.mux == nil {
		s.mux = s.buildMuxLocked()
	}
	s.mu.Unlock()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		h := s.mux
		s.mu.RUnlock()
		h.ServeHTTP(w, r)
	})
}

// buildMuxLocked constructs the routing table. Caller holds s.mu.
func (s *Server) buildMuxLocked() http.Handler {
	mux := http.NewServeMux()
	prefix := s.cfg.URIPrefix

	mux.HandleFunc(prefix+"/challenge", s.handleChallenge)
	mux.HandleFunc(prefix+"/respond", s.handleRespond)
	mux.HandleFunc(prefix+"/enroll", s.handleEnroll)
	mux.HandleFunc(prefix+"/register", s.handleRegister)
	mux.HandleFunc("/authz", s.handleAuthz)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	if s.cfg.AdminListen == "" {
		mux.HandleFunc("/admin/", s.handleAdmin)
	}
	// Anything else reaching the Authorizer directly is not part of the
	// protocol; answer 404 rather than leaking that this is a JIT gate.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// AdminHandler serves only /admin/* and /healthz, for the separate admin
// listener. Returns nil when admin_listen is not configured.
func (s *Server) AdminHandler() http.Handler {
	if s.config().AdminListen == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/", s.handleAdmin)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// ---- request context -------------------------------------------------------

type reqCtx struct {
	service string
	ip      string
	uri     string // normalized path of the ORIGINAL request
	svc     ServiceConfig
	known   bool
}

// resolve identifies the request: who the client is, which service it is for,
// and what path it asked for. Anything ambiguous returns false, and every caller
// treats that as a denial — including the case where two forwarding conventions
// disagree about the target, which means a client appended a header the proxy
// also sets (see Config.resolveTarget).
func (s *Server) resolve(r *http.Request) (*reqCtx, bool) {
	cfg := s.config()
	ip, _, err := cfg.ClientIP(r)
	if err != nil || ip == "" {
		return nil, false
	}
	service, uri, conflict := cfg.resolveTarget(r)
	if conflict || service == "" {
		return nil, false
	}
	svc, known := cfg.Service(service)
	return &reqCtx{service: service, ip: ip, uri: uri, svc: svc, known: known}, true
}

// ---- protocol: challenge ---------------------------------------------------

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	c, ok := s.resolve(r)
	if !ok || !c.known {
		s.deny(w, r, c, "unknown service")
		return
	}
	// Wrong method answers the SAME generic response as everything else. A 405
	// here told a prober "this exact path exists" — in stealth mode the protocol
	// paths returned 405 while every other path returned 404, so the gate was
	// locatable in a handful of requests (PROTOCOL §6).
	if r.Method != http.MethodGet {
		s.deny(w, r, c, "method")
		return
	}
	cfg := s.config()
	if !s.rl.allow(c.ip, cfg.RateLimit, s.now()) {
		// deny(), not a bare 429: PROTOCOL §6 requires every rejection at these
		// endpoints to be the SAME generic response. A 429 here was a free
		// endpoint-discovery oracle — in stealth mode the protocol paths answered
		// 429 while every other path answered 404, so a handful of requests
		// located the gate.
		s.knockFail(w, r, c, "rate limited")
		return
	}
	rnd, err := jitcore.RandomBytes(16)
	if err != nil {
		s.deny(w, r, c, "rng")
		return
	}
	ts := s.now()
	nonce, err := jitcore.IssueNonce(s.nonceKey, uint64(ts), rnd, c.service, c.ip, cfg.IPv6Prefix)
	if err != nil {
		s.deny(w, r, c, "nonce mint")
		return
	}
	w.Header().Set("X-JIT-Nonce", jitcore.B64u(nonce))
	w.Header().Set("X-JIT-TS", strconv.FormatInt(ts, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// ---- protocol: respond (the knock) -----------------------------------------

type respondBody struct {
	V     int    `json:"v"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
	Proof string `json:"proof"`
}

func (s *Server) handleRespond(w http.ResponseWriter, r *http.Request) {
	c, ok := s.resolve(r)
	if !ok || !c.known {
		s.deny(w, r, c, "unknown service")
		return
	}
	if r.Method != http.MethodPost {
		s.deny(w, r, c, "method") // generic response, never a distinguishable 405
		return
	}
	cfg := s.config()
	if !s.rl.allow(c.ip, cfg.RateLimit, s.now()) {
		// deny(), not a bare 429: PROTOCOL §6 requires every rejection at these
		// endpoints to be the SAME generic response. A 429 here was a free
		// endpoint-discovery oracle — in stealth mode the protocol paths answered
		// 429 while every other path answered 404, so a handful of requests
		// located the gate.
		s.knockFail(w, r, c, "rate limited")
		return
	}

	var body respondBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.knockFail(w, r, c, "malformed body")
		return
	}
	nonceRaw, err1 := jitcore.B64uDecode(body.Nonce)
	tag, err2 := jitcore.B64uDecode(body.Proof)
	if err1 != nil || err2 != nil || len(nonceRaw) != jitcore.NonceLen || len(tag) != 32 {
		s.knockFail(w, r, c, "malformed nonce/proof")
		return
	}

	now := s.now()
	okNonce, rnd := jitcore.VerifyNonce(s.nonceKey, nonceRaw, c.service, c.ip, now, cfg.NonceTTL, cfg.IPv6Prefix)
	if !okNonce {
		s.knockFail(w, r, c, "bad or stale nonce")
		return
	}

	// Equalized work for an unknown kid: always run a full HMAC so a probe
	// cannot distinguish "no such kid" from "wrong proof" by timing
	// (PROTOCOL §6). The dummy key is a fixed all-zero secret.
	reg := s.registry()
	token, authErr := reg.Authorize(body.Kid, c.service, now)
	secret := dummySecret
	if token != nil {
		secret = token.Secret
	}
	proofOK := jitcore.VerifyProof(secret, c.service, body.Kid, nonceRaw, tag)
	if authErr != nil || !proofOK {
		s.knockFail(w, r, c, "rejected")
		return
	}

	// Verify-then-burn: a bad proof never consumes the nonce.
	if !s.nonces.Claim(jitcore.B64u(rnd), now, cfg.NonceTTL) {
		s.knockFail(w, r, c, "nonce replay")
		return
	}

	ttl := cfg.grantTTL(c.svc)
	g := &jitcore.Grant{
		V: 1, Kid: body.Kid, Service: c.service, IP: c.ip,
		Binding: cfg.binding(c.svc), Issued: now, Exp: now + ttl,
	}
	// ip+cookie binding: mint an opaque grant id, store only its hash, and set
	// it host-only + SameSite=Strict so a cross-site navigation cannot ride it
	// (SECURITY-REVIEW H11 / DESIGN §11 R3).
	if g.Binding == jitcore.BindingIPCookie {
		idBytes, err := jitcore.RandomBytes(32)
		if err != nil {
			s.knockFail(w, r, c, "rng")
			return
		}
		id := jitcore.B64u(idBytes)
		g.CookieHash = jitcore.CookieHash(id)
		http.SetCookie(w, &http.Cookie{
			Name:     GrantCookieName,
			Value:    id,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(ttl),
		})
	}
	// If this browser already held a grant cookie for this (service, ip), its
	// record lives under a different key — retire it rather than leaving a dead
	// record behind on every re-knock.
	oldHash := ""
	if ck, err := r.Cookie(GrantCookieName); err == nil && ck.Value != "" {
		oldHash = jitcore.CookieHash(ck.Value)
	}
	s.grants.Put(g, oldHash)
	s.metrics.inc(&s.metrics.knockOK)

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

var dummySecret = make([]byte, 32)

func (s *Server) knockFail(w http.ResponseWriter, r *http.Request, c *reqCtx, reason string) {
	s.metrics.inc(&s.metrics.knockFail)
	// Uniform response for every failure: no oracle for kid existence, nonce
	// validity, or proof correctness.
	s.deny(w, r, c, reason)
}

// ---- protocol: enroll (one-time code -> secret) ----------------------------

type enrollBody struct {
	Code string `json:"code"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	c, ok := s.resolve(r)
	if !ok || !c.known {
		s.deny(w, r, c, "unknown service")
		return
	}
	if r.Method != http.MethodPost {
		s.deny(w, r, c, "method") // generic response, never a distinguishable 405
		return
	}
	// PROTOCOL §2.1 requires this endpoint to be rate-limited, and it is the
	// highest-value target in the protocol: it trades a code for a long-term
	// device secret. It was the one knock endpoint with no throttle at all.
	if !s.rl.allow(c.ip, s.config().RateLimit, s.now()) {
		s.knockFail(w, r, c, "rate limited")
		return
	}
	var body enrollBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Code == "" {
		s.deny(w, r, c, "bad enroll body")
		return
	}
	// Validate BEFORE consuming: Consume is delete-after-read, so checking the
	// kid afterwards let any hostile POST destroy a valid enrollment code.
	if peek := s.codes.Peek(body.Code, s.now()); peek == nil || s.registry().Lookup(peek.Kid) == nil {
		s.metrics.inc(&s.metrics.knockFail)
		s.deny(w, r, c, "code rejected")
		return
	}
	code := s.codes.Consume(body.Code, s.now()) // single-use, delete-after-read
	if code == nil {
		s.metrics.inc(&s.metrics.knockFail)
		s.deny(w, r, c, "code rejected")
		return
	}
	token := s.registry().Lookup(code.Kid)
	if token == nil {
		s.deny(w, r, c, "kid gone")
		return
	}
	w.Header().Set("X-JIT-Kid", code.Kid)
	w.Header().Set("X-JIT-Secret", jitcore.B64u(token.Secret))
	w.Header().Set("X-JIT-Origins", strings.Join(code.Origins, ","))
	w.Header().Set("Cache-Control", "no-store")
	s.metrics.inc(&s.metrics.enrollOK)
	w.WriteHeader(http.StatusNoContent)
}

// handleRegister answers the registration link for a browser WITHOUT the
// extension. With the extension installed, its service worker intercepts that
// navigation before the request leaves the browser, so this handler is only ever
// reached by someone who needs to install it — see registerHTML.
//
// It is served on the protected origin (inside the prefix carve-out) so it works
// while the service is dark, and it is deliberately identical whatever code is
// in the URL: no oracle for whether an enrollment code exists or is still valid.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The URL carries a single-use code; keep it out of the referrer of anything
	// the page links to.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jitcore.RegisterHTML)
}

// ---- forward-auth ----------------------------------------------------------

// authzDeny answers a forward-auth SUBREQUEST, where the status is consumed by
// the proxy rather than the client.
//
// nginx's auth_request treats ONLY 401 and 403 as a denial and turns any other
// status into a 500. deny()'s stealth branch answers 404 — right when the
// Authorizer is serving the client directly, fatal here: every gated request to
// a stealth service came back 500. That is worse than the leak it was trying to
// avoid, because 500 is maximally distinctive AND the service is broken for
// legitimate users, who can no longer reach the interstitial in order to knock.
// Found by the five-engine lab on ingress-nginx.
//
// The failure mode still decides what the CLIENT sees. On forward-auth that is
// the proxy's error page, and the marker is how the shipped recipes tell a JIT
// denial from any other 403 — so stealth withholds it and interstitial sets it.
// Turning that 403 into a 404 for a stealth service is the proxy's job; see
// adapters/nginx and adapters/kubernetes.
func (s *Server) authzDeny(w http.ResponseWriter, r *http.Request, c *reqCtx, reason string) {
	mode := s.config().defaultFailureMode()
	if c != nil && c.known {
		mode = s.config().failureMode(c.svc)
	}
	w.Header().Set("Cache-Control", "no-store")
	if mode == FailStealth {
		// No marker and no body: the recipes read the marker's absence as
		// "stealth" and answer the client with their own generic 404, which is
		// what has to be indistinguishable from an unrouted path.
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// The interstitial page is served FROM here. The nginx recipes re-proxy a
	// denial to /authz and render this body to the client, so dropping it left
	// interstitial deployments serving an empty 403 — invisible to the lab,
	// which only checks the marker on that path.
	w.Header().Set("X-JIT-Access", JITMarker)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(interstitialHTML)
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	// /authz is an internal surface: a legitimate call always originates from
	// the proxy. Refusing untrusted peers outright means that even if the
	// listener is accidentally exposed, an attacker cannot drive the grant
	// check with headers of their choosing (direct-Authorizer-exposure probe).
	if peer, err := peerAddr(r); err != nil || !s.config().isTrusted(peer) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	c, ok := s.resolve(r)
	if !ok {
		// cannot identify the client — deny, never allow on ambiguity
		s.authzDeny(w, r, nil, "unresolved request")
		return
	}
	cfg := s.config()

	// The knock endpoints must stay reachable on a dark service, so a subrequest
	// for them is allowed through to the Authorizer's own protocol handlers.
	// c.uri is normalized and comes from a conventions-agree-or-deny resolution,
	// so this is the same path the proxy will route on.
	uri := c.uri
	// Only paths BELOW the prefix are carved out, never the bare prefix itself.
	// The shipped recipes route `location /.well-known/jit-access/` (with the
	// trailing slash) to the Authorizer, so the bare path falls into `location /`
	// — gated — and answering 204 for it made it an ungated pass-through to the
	// backend on that one path, with attacker-chosen method, query and body.
	// Nothing needs the bare form: it is not an endpoint.
	if p := cfg.URIPrefix; strings.HasPrefix(uri, p+"/") {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// A service with no config is not gated by us. Answering 204 here would be
	// the fail-open choice; instead the operator opts a service in explicitly
	// and anything else is denied.
	if !c.known {
		s.authzDeny(w, r, c, "service not configured")
		return
	}

	cookie := ""
	if ck, err := r.Cookie(GrantCookieName); err == nil {
		cookie = ck.Value
	}
	if g := s.grants.IsAllowed(c.service, c.ip, s.registry(), s.now(), cookie); g != nil {
		s.metrics.inc(&s.metrics.granted)
		w.Header().Set("X-JIT-Kid", g.Kid)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.metrics.inc(&s.metrics.denied)
	s.authzDeny(w, r, c, "no grant")
}

// deny renders the configured failure mode. interstitial = 403 + marker header
// (the extension's detection hook); stealth = bare 404.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, c *reqCtx, reason string) {
	cfg := s.config()
	mode := cfg.defaultFailureMode()
	// c.known matters, not just c != nil: an unrecognised Host resolves fine but
	// carries a ZERO ServiceConfig, and failureMode("") reads as interstitial —
	// so on a stealth-only deployment any request with an unknown Host answered
	// with the branded page and the X-JIT-Access marker, advertising a gate the
	// operator made invisible.
	if c != nil && c.known {
		mode = cfg.failureMode(c.svc)
	}
	if mode == FailStealth {
		// Must be INDISTINGUISHABLE from the platform's own 404 (PROTOCOL §6),
		// so no Cache-Control and no empty body: http.NotFound is exactly what
		// the mux serves for an unrouted path, headers and body alike.
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-JIT-Access", JITMarker)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(interstitialHTML)
}

// ---- rate limiting ---------------------------------------------------------

// Fixed-window per-IP counter on the knock endpoints. Knock failures never feed
// the WAF's abuse counters (SECURITY-REVIEW R4) — this is the only throttle.
type rateLimiter struct {
	mu     sync.Mutex
	window map[string]*rlEntry
}

type rlEntry struct {
	start int64
	n     int
}

func newRateLimiter() *rateLimiter { return &rateLimiter{window: map[string]*rlEntry{}} }

func (l *rateLimiter) allow(ip string, perMin int, now int64) bool {
	if perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.window[ip]
	if !ok || now-e.start >= 60 {
		l.window[ip] = &rlEntry{start: now, n: 1}
		return true
	}
	e.n++
	return e.n <= perMin
}

func (l *rateLimiter) sweep(now int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.window {
		if now-e.start >= 60 {
			delete(l.window, k)
		}
	}
}

// ---- metrics ---------------------------------------------------------------

type metrics struct {
	mu        sync.Mutex
	knockOK   int64
	knockFail int64
	granted   int64
	denied    int64
	enrollOK  int64
}

func (m *metrics) inc(p *int64) {
	m.mu.Lock()
	*p++
	m.mu.Unlock()
}

func (m *metrics) snapshot() map[string]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]int64{
		"jit_knock_ok":   m.knockOK,
		"jit_knock_fail": m.knockFail,
		"jit_granted":    m.granted,
		"jit_denied":     m.denied,
		"jit_enroll_ok":  m.enrollOK,
	}
}

// ---- background sweep ------------------------------------------------------

func (s *Server) StartSweeper(stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				now := s.now()
				s.grants.Sweep(now)
				s.nonces.Sweep(now)
				s.codes.Sweep(now)
				s.rl.sweep(now)
			}
		}
	}()
}

func logf(format string, args ...any) { log.Printf(format, args...) }
