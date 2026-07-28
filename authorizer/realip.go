// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"

	jitcore "github.com/Slopapalooza/jit-network-access/core/go"
)

// Client-IP and service resolution across the forward-auth boundary.
//
// This is the one place where the Authorizer's threat model differs from the
// in-process BunkerWeb plugin. The plugin reads the un-forgeable TCP peer
// ($realip_remote_addr). The Authorizer, sitting behind a proxy, has the PROXY
// as its TCP peer, so it can only learn the real client from a header the proxy
// sets — which inverts R2's "never trust a client-supplied IP" into "trust
// exactly one header, from exactly the hops we configured."
//
// The rules that keep that safe:
//
//  1. DIRECT mode — the TCP peer is not in trusted_proxies. Every forwarded
//     header is ignored and the peer is used. A client that reaches the
//     Authorizer directly therefore cannot forge its own grant key, which is
//     what the forged-XFF probe in the security suite asserts.
//  2. PROXY mode — the peer IS trusted. The configured header is walked
//     right-to-left and the first address that is not itself a trusted proxy
//     wins (rightmost-untrusted). Client-appended entries sit to the LEFT of
//     the ones the trusted hops appended, so they cannot win.
//  3. Anything unparseable fails closed: no IP, no grant.
//
// The listener should still be bound to loopback/an internal interface — these
// rules are the second line, not the first (M6 adds an authenticated
// proxy->Authorizer boundary).

var errNoClientIP = errors.New("no usable client ip")

func (c *Config) isTrusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range c.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peerAddr is the TCP peer of the request.
func peerAddr(r *http.Request) (netip.Addr, error) {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

// ClientIP returns the canonical client address to key grants on, plus whether
// the request arrived through a trusted proxy.
func (c *Config) ClientIP(r *http.Request) (string, bool, error) {
	peer, err := peerAddr(r)
	if err != nil {
		return "", false, errNoClientIP
	}
	if !c.isTrusted(peer) {
		// DIRECT: forwarded headers are not evidence.
		canon, err := jitcore.CanonIP(peer.String(), c.IPv6Prefix, 32)
		if err != nil {
			return "", false, err
		}
		return canon, false, nil
	}

	// PROXY: rightmost-untrusted walk over the configured header.
	candidates := forwardedList(r, c.RealIPHeader)
	for i := len(candidates) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(candidates[i])
		if err != nil {
			continue
		}
		a = a.Unmap()
		if c.isTrusted(a) {
			continue // another hop of our own infrastructure
		}
		canon, err := jitcore.CanonIP(a.String(), c.IPv6Prefix, 32)
		if err != nil {
			return "", true, err
		}
		return canon, true, nil
	}
	// A trusted proxy that forwarded nothing usable (e.g. a health check).
	canon, err := jitcore.CanonIP(peer.String(), c.IPv6Prefix, 32)
	if err != nil {
		return "", true, err
	}
	return canon, true, nil
}

func forwardedList(r *http.Request, header string) []string {
	var out []string
	for _, v := range r.Header.Values(header) {
		for _, part := range strings.Split(v, ",") {
			p := strings.TrimSpace(part)
			// tolerate [v6]:port / v4:port forms
			if h, _, err := net.SplitHostPort(p); err == nil {
				p = h
			}
			p = strings.Trim(p, "[]")
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// A forward-auth subrequest describes the ORIGINAL request using one of several
// conventions, and which one is authoritative is a property of the proxy, not of
// this code:
//
//	forwarded     X-Forwarded-Host  + X-Forwarded-Uri    (nginx auth_request, Traefik)
//	original-url  X-Original-URL                          (ingress-nginx; absolute URL)
//	original      X-Original-Host   + X-Original-Uri      (some Envoy/ext_authz setups)
//
// Picking a fixed global precedence CANNOT be made safe, and trying twice proved
// it: preferring X-Forwarded-Host let a Kubernetes client name its own service
// (ingress-nginx does not set that header but does forward the client's), while
// preferring X-Original-URL let a plain-nginx client do the same (that recipe
// sets X-Forwarded-Host authoritatively but never blanks X-Original-URL). Each
// ordering is safe on one deployment and exploitable on the other.
//
// So we do not order them. Every convention present is read, and if two of them
// DISAGREE the request is refused. The proxy sets exactly one authoritatively, so
// a client that appends another creates a disagreement and gets denied — without
// this code having to know which proxy it is behind. Blanking the unused headers
// at the proxy (the shipped recipes do) remains good practice, but is no longer
// what stands between a client and someone else's grant.
type forwardedView struct {
	name string
	host string // "" when this convention supplied none
	uri  string // "" when this convention supplied none
}

func forwardedViews(r *http.Request) []forwardedView {
	var out []forwardedView

	fwHost := firstHostInChain(r.Header.Get("X-Forwarded-Host"))
	fwURI := r.Header.Get("X-Forwarded-Uri")
	if fwHost != "" || fwURI != "" {
		out = append(out, forwardedView{"forwarded", fwHost, fwURI})
	}

	if v := r.Header.Get("X-Original-URL"); v != "" {
		vw := forwardedView{name: "original-url"}
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			vw.host = u.Host
			vw.uri = u.EscapedPath() // still-escaped: cleanURIPath decodes once
		} else {
			// Unparseable, or relative. Treat it as a path-only claim rather than
			// ignoring it, so a malformed value cannot be used to dodge the
			// conflict check.
			vw.uri = v
		}
		out = append(out, vw)
	}

	oHost := firstHostInChain(r.Header.Get("X-Original-Host"))
	oURI := r.Header.Get("X-Original-Uri")
	if oHost != "" || oURI != "" {
		out = append(out, forwardedView{"original", oHost, oURI})
	}

	return out
}

func firstHostInChain(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.Index(v, ","); i != -1 {
		v = v[:i] // a comma-joined chain: the first entry is the original host
	}
	return strings.TrimSpace(v)
}

// resolveTarget returns the canonical service and normalized path the request is
// really for. conflict is true when two present conventions disagree, which every
// caller MUST treat as a denial.
//
// Forwarded headers are evidence only from a trusted peer; a direct client is
// described by its own request line and nothing else.
func (c *Config) resolveTarget(r *http.Request) (service, uri string, conflict bool) {
	service = jitcore.CanonServerName(r.Host)
	uri = cleanURIPath(r.URL.EscapedPath())

	peer, err := peerAddr(r)
	if err != nil || !c.isTrusted(peer) {
		return service, uri, false
	}

	var host, pathClaim, hostFrom, pathFrom string
	for _, v := range forwardedViews(r) {
		if v.host != "" {
			h := jitcore.CanonServerName(v.host)
			if host != "" && h != host {
				logf("jitaccess: forwarded host conflict: %s=%q vs %s=%q — denying", hostFrom, host, v.name, h)
				return "", "", true
			}
			host, hostFrom = h, v.name
		}
		if v.uri != "" {
			u := cleanURIPath(v.uri)
			if pathClaim != "" && u != pathClaim {
				logf("jitaccess: forwarded uri conflict: %s=%q vs %s=%q — denying", pathFrom, pathClaim, v.name, u)
				return "", "", true
			}
			pathClaim, pathFrom = u, v.name
		}
	}
	if host != "" {
		service = host
	}
	if pathClaim != "" {
		uri = pathClaim
	}
	return service, uri, false
}

// ServiceName returns ONLY the service, discarding the path. It exists for tests
// and callers that genuinely need just the host; a conflict yields "" so the
// caller still denies (no configured service is named "").
//
// Prefer resolveTarget: it returns the conflict flag explicitly, and a caller
// that ignores an ambiguous request is exactly the bug this whole mechanism
// exists to prevent.
func (c *Config) ServiceName(r *http.Request) string {
	service, _, conflict := c.resolveTarget(r)
	if conflict {
		return ""
	}
	return service
}

// cleanURIPath reduces a forwarded request URI to the path the proxy will
// actually route on: query/fragment stripped, percent-escapes decoded, and dot
// segments resolved.
//
// nginx decodes %XX (including %2F) and resolves "." / ".." in
// ngx_http_parse_complex_uri before matching a location, while $request_uri and
// $scheme://$http_host$request_uri keep the raw form. Normalizing here is what
// keeps the verifier's view of the request identical to the proxy's.
func cleanURIPath(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i != -1 {
		uri = uri[:i]
	}
	dec, err := url.PathUnescape(uri)
	if err != nil {
		// A malformed escape; nginx answers those with 400, so a well-behaved
		// proxy never forwards one. Fail closed: "/" cannot match the protocol
		// prefix, so the request falls through to the normal grant check.
		return "/"
	}
	// Any '%' surviving one decode means the input was double-encoded
	// ("%252e%252e" -> "%2e%2e", or "%25" -> "%"). nginx decodes once, so today
	// its view and ours still agree — but that agreement is a property of the
	// proxy, not of this function, and a component in front that decodes twice
	// (some CDNs and WAFs do) would resolve "%252e%252e" to ".." while we would
	// not. Rather than depend on every upstream decoding exactly once, refuse.
	//
	// '?' and '#' are refused for the same reason: an encoded "%3f" decodes to a
	// literal '?' AFTER the query strip above, so it too is a character whose
	// meaning depends on when you look.
	//
	// Costs nothing: the protocol prefix contains none of these, so a path that
	// does can never be a protocol endpoint. It falls through to the normal
	// grant check, which is the right answer for a path we cannot confidently
	// normalize — and it is what makes this function idempotent.
	//
	// Both the double-encoding and the idempotency break were found by
	// FuzzCleanURIPath, not by review.
	if strings.ContainsAny(dec, "%?#") {
		return "/"
	}
	if !strings.HasPrefix(dec, "/") {
		dec = "/" + dec
	}
	return path.Clean(dec)
}
