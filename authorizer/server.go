// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
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
func (s *Server) Reload(cfg *Config) error {
	reg, err := cfg.Registry()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg, s.reg = cfg, reg
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	prefix := s.config().URIPrefix

	mux.HandleFunc(prefix+"/challenge", s.handleChallenge)
	mux.HandleFunc(prefix+"/respond", s.handleRespond)
	mux.HandleFunc(prefix+"/enroll", s.handleEnroll)
	mux.HandleFunc("/authz", s.handleAuthz)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/admin/", s.handleAdmin)
	// Anything else reaching the Authorizer directly is not part of the
	// protocol; answer 404 rather than leaking that this is a JIT gate.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// ---- request context -------------------------------------------------------

type reqCtx struct {
	service string
	ip      string
	svc     ServiceConfig
	known   bool
}

func (s *Server) resolve(r *http.Request) (*reqCtx, bool) {
	cfg := s.config()
	ip, _, err := cfg.ClientIP(r)
	if err != nil || ip == "" {
		return nil, false
	}
	service := cfg.ServiceName(r)
	if service == "" {
		return nil, false
	}
	svc, known := cfg.Service(service)
	return &reqCtx{service: service, ip: ip, svc: svc, known: known}, true
}

// ---- protocol: challenge ---------------------------------------------------

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.resolve(r)
	if !ok || !c.known {
		s.deny(w, r, c, "unknown service")
		return
	}
	cfg := s.config()
	if !s.rl.allow(c.ip, cfg.RateLimit, s.now()) {
		s.metrics.inc(&s.metrics.knockFail)
		http.Error(w, "", http.StatusTooManyRequests)
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
	if r.Method != http.MethodPost {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.resolve(r)
	if !ok || !c.known {
		s.deny(w, r, c, "unknown service")
		return
	}
	cfg := s.config()
	if !s.rl.allow(c.ip, cfg.RateLimit, s.now()) {
		s.metrics.inc(&s.metrics.knockFail)
		http.Error(w, "", http.StatusTooManyRequests)
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
	s.grants.Put(g)
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
	if r.Method != http.MethodPost {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.resolve(r)
	if !ok || !c.known {
		s.deny(w, r, c, "unknown service")
		return
	}
	var body enrollBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Code == "" {
		s.deny(w, r, c, "bad enroll body")
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

// ---- forward-auth ----------------------------------------------------------

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
		s.deny(w, r, nil, "unresolved request")
		return
	}
	cfg := s.config()

	// The knock endpoints must stay reachable on a dark service, so a subrequest
	// for them is allowed through to the Authorizer's own protocol handlers.
	uri := OriginalURI(r)
	if p := cfg.URIPrefix; uri == p || strings.HasPrefix(uri, p+"/") {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// A service with no config is not gated by us. Answering 204 here would be
	// the fail-open choice; instead the operator opts a service in explicitly
	// and anything else is denied.
	if !c.known {
		s.deny(w, r, c, "service not configured")
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
	s.deny(w, r, c, "no grant")
}

// deny renders the configured failure mode. interstitial = 403 + marker header
// (the extension's detection hook); stealth = bare 404.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, c *reqCtx, reason string) {
	mode := FailInterstitial
	if c != nil {
		mode = s.config().failureMode(c.svc)
	}
	w.Header().Set("Cache-Control", "no-store")
	if mode == FailStealth {
		w.WriteHeader(http.StatusNotFound)
		return
	}
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
