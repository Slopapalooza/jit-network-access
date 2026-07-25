package main

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
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

// ServiceName returns the canonical service the request is for. Behind a trusted
// proxy the forwarded host wins (the Host header on a forward-auth subrequest is
// the Authorizer's own address, not the origin); otherwise only Host is trusted.
func (c *Config) ServiceName(r *http.Request) string {
	if peer, err := peerAddr(r); err == nil && c.isTrusted(peer) {
		for _, h := range []string{"X-Forwarded-Host", "X-Original-Host"} {
			if v := r.Header.Get(h); v != "" {
				// a comma-joined chain: the first entry is the original host
				if i := strings.Index(v, ","); i != -1 {
					v = v[:i]
				}
				return jitcore.CanonServerName(strings.TrimSpace(v))
			}
		}
	}
	return jitcore.CanonServerName(r.Host)
}

// OriginalURI is the path the client actually requested, which on a forward-auth
// subrequest is not this request's own path.
func OriginalURI(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-Uri", "X-Original-Uri", "X-Original-URL"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	return r.URL.Path
}
