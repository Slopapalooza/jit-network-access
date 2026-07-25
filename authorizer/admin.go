package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

// Admin API — the Authorizer's equivalent of the BunkerWeb plugin's internal
// api() endpoints, so the same operational runbook and the conformance suite's
// revocation steps work against either engine.
//
// Bearer-token authenticated and intended for an internal listener only.

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	cfg := s.config()
	// Internal surface: refuse untrusted peers before even considering the
	// token, so a leaked token is not sufficient from the outside.
	if peer, err := peerAddr(r); err != nil || !cfg.isTrusted(peer) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if cfg.AdminToken == "" {
		http.Error(w, "admin API disabled (no admin_token configured)", http.StatusForbidden)
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(cfg.AdminToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.URL.Path {
	case "/admin/grants":
		s.adminGrants(w, r)
	case "/admin/grant":
		s.adminGrant(w, r)
	case "/admin/revoke":
		s.adminRevoke(w, r)
	case "/admin/revoke-token":
		s.adminRevokeToken(w, r)
	case "/admin/enroll-code":
		s.adminEnrollCode(w, r)
	case "/admin/metrics":
		writeJSON(w, http.StatusOK, s.metrics.snapshot())
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return false
	}
	return true
}

func (s *Server) adminGrants(w http.ResponseWriter, r *http.Request) {
	list := s.grants.List(s.now())
	writeJSON(w, http.StatusOK, map[string]any{"count": len(list), "grants": list})
}

func (s *Server) adminGrant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
		IP      string `json:"ip"`
		TTL     int64  `json:"ttl"`
		Kid     string `json:"kid"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	cfg := s.config()
	service := jitcore.CanonServerName(body.Service)
	ip, err := jitcore.CanonIP(body.IP, cfg.IPv6Prefix, 32)
	if err != nil || service == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "service and valid ip required"})
		return
	}
	ttl := body.TTL
	if ttl <= 0 {
		ttl = cfg.GrantTTL
	}
	kid := body.Kid
	manual := false
	if kid == "" {
		kid, manual = "__manual__", true
	}
	now := s.now()
	g := &jitcore.Grant{
		V: 1, Kid: kid, Service: service, IP: ip, Binding: jitcore.BindingIP,
		Issued: now, Exp: now + ttl, Manual: manual,
	}
	s.grants.Put(g)
	writeJSON(w, http.StatusOK, map[string]any{"granted": true, "service": service, "ip": ip, "exp": g.Exp})
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
		IP      string `json:"ip"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	cfg := s.config()
	service := jitcore.CanonServerName(body.Service)
	ip, err := jitcore.CanonIP(body.IP, cfg.IPv6Prefix, 32)
	if err != nil || service == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "service and valid ip required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": s.grants.Revoke(service, ip)})
}

func (s *Server) adminRevokeToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kid string `json:"kid"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Kid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kid required"})
		return
	}
	n := s.grants.RevokeToken(body.Kid)
	writeJSON(w, http.StatusOK, map[string]any{"revoked_token": body.Kid, "grants_removed": n})
}

// adminEnrollCode mints the single-use code that backs a registration link, so
// the device secret never travels in the URL (PROTOCOL §6.1 / R5).
func (s *Server) adminEnrollCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kid     string   `json:"kid"`
		Origins []string `json:"origins"`
		Server  string   `json:"server"`
		TTL     int64    `json:"ttl"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if s.registry().Lookup(body.Kid) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "known kid required"})
		return
	}
	cfg := s.config()
	ttl := body.TTL
	if ttl <= 0 {
		ttl = cfg.EnrollTTL
	}
	if ttl < 300 {
		ttl = 300
	}
	if ttl > 604800 {
		ttl = 604800
	}
	rnd, err := jitcore.RandomBytes(12)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rng"})
		return
	}
	code := jitcore.B64u(rnd)
	s.codes.Put(code, &jitcore.EnrollCode{Kid: body.Kid, Origins: body.Origins, Exp: s.now() + ttl})

	resp := map[string]any{"code": code, "kid": body.Kid, "ttl": ttl, "origins": body.Origins}
	if strings.HasPrefix(body.Server, "https://") {
		base := strings.TrimRight(body.Server, "/")
		u := base + cfg.URIPrefix + "/register?code=" + code
		if len(body.Origins) > 0 {
			u += "&origins=" + strings.Join(body.Origins, ",")
		}
		resp["register_url"] = u
	}
	writeJSON(w, http.StatusOK, resp)
}
