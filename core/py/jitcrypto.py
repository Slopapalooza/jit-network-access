# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
JIT Network Access — Python reference crypto (L3).

The single source of truth for the byte-level constructions, shared by the
conformance-vector generator and the knock client. Mirrors core/lua/jitaccess/core
and is pinned by core/testdata/vectors.json. See docs/PROTOCOL.md.
"""

import base64
import hashlib
import hmac
import ipaddress

PROOF_DOMAIN = b"jitaccess-v1"
NONCE_DOMAIN = b"jitaccess-nonce-v1"

# ---- base64url (no padding) -----------------------------------------------

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# ---- PAE (PASETO-compatible) ----------------------------------------------

def le64(n: int) -> bytes:
    if n < 0:
        raise ValueError("le64: negative length")
    b = bytearray(n.to_bytes(8, "little"))
    b[7] &= 0x7F
    return bytes(b)

def pae(pieces) -> bytes:
    out = bytearray(le64(len(pieces)))
    for p in pieces:
        out += le64(len(p))
        out += p
    return bytes(out)

# ---- canonicalization ------------------------------------------------------

# Lua's "%s" class. str.strip()/str.lower() are Unicode-aware and Lua's are not,
# so a Host carrying U+00A0 or a non-ASCII letter canonicalized one way here and
# another on the Lua engines. Hostnames are ASCII by IDNA, so pinning both to
# ASCII costs nothing real and makes all four references byte-identical.
_ASCII_SPACE = " \t\n\x0b\x0c\r"
_ASCII_LOWER = bytes.maketrans(bytes(range(65, 91)), bytes(range(97, 123)))


def _trim_dots_and_space(s: str) -> str:
    """Trim whitespace and trailing dots to a fixpoint BEFORE the port strip as
well as after. Doing it only after meant removing a trailing dot could
expose a port that then survived to the next pass: "[:0." became "[:0"
became "[", and "example.com:443." became "example.com:443" became
"example.com". Two layers canonicalizing the same Host a different number
of times would hold two different names for one service.
    """
    while True:
        t = s.strip(_ASCII_SPACE)
        if t.endswith("."):
            t = t[:-1]
        if t == s:
            return s
        s = t


def canon_server_name(host: str) -> str:
    h = _trim_dots_and_space(host)

    # A bracketed literal delimits its own host. The port strip below is guarded
    # by colon count alone rather than by "was it bracketed": no valid IPv6
    # address has exactly one colon, so the guard only ever protected malformed
    # input like "[a:80]" - which then canonicalized to "a:80" and, on a second
    # pass, to "a".
    if h.startswith("["):
        end = h.find("]")
        if end != -1:
            h = _trim_dots_and_space(h[1:end])

    # Strip a trailing :port - but ONLY when the host has exactly one colon.
    #
    # An unbracketed host with several colons is an IPv6 literal: RFC 3986
    # requires brackets to carry a port, so there is no port to strip. Stripping
    # anyway truncated "2001:db8::1" to "2001:db8:" - and "2001:db8::2" to the
    # SAME value, which is a cross-service collision in both the grant key and
    # the MAC input, the exact class PAE framing exists to prevent. It also made
    # the bracketed and unbracketed spellings of one host canonicalize
    # differently, so a grant made via one would not match a request via the
    # other.
    #
    # isascii() matters: bare isdigit() is true for Unicode digits, so a host
    # ending in Arabic-Indic digits lost its port here and kept it in the Go,
    # Lua and JS references, which all match ASCII only.
    if h.count(":") == 1:
        left, sep, right = h.rpartition(":")
        if sep and right.isascii() and right.isdigit():
            h = left

    h = _trim_dots_and_space(h)
    return h.encode("utf-8", "surrogatepass").translate(_ASCII_LOWER).decode("utf-8", "surrogatepass")

def canon_ip(addr: str, v6_prefix: int = 128, v4_prefix: int = 32) -> str:
    # Prefix bounds are validated, not silently clamped. Go and this reference
    # used to treat any prefix >= the address width as "exact host", so a config
    # typo of 1280 behaved as /128 here while the Lua core rejected it outright —
    # the same registry admitting a client on one engine and denying it on
    # another. Fail closed on nonsense config in all three.
    if not 0 <= v6_prefix <= 128:
        raise ValueError(f"canon_ip: v6_prefix {v6_prefix} out of range")
    if not 0 <= v4_prefix <= 32:
        raise ValueError(f"canon_ip: v4_prefix {v4_prefix} out of range")
    ip = ipaddress.ip_address(addr)
    # A zone ("fe80::1%eth0") is a link-scope selector, not part of the address.
    # Go rejects it and Lua cannot parse it; accepting it here let the reference
    # canonicalize something the verifiers refuse — and for ::ffff:1.2.3.4%eth0
    # the mapped-collapse below would silently DISCARD the zone, which is exactly
    # the ambiguity PROTOCOL §4 step 1 says to reject.
    if getattr(ip, "scope_id", None) is not None:
        raise ValueError(f"canon_ip {addr!r}: zoned address")
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        if v4_prefix >= 32:
            return ip.compressed
        return ipaddress.ip_network(f"{ip.compressed}/{v4_prefix}", strict=False).network_address.compressed
    if v6_prefix >= 128:
        return ip.compressed
    return ipaddress.ip_network(f"{ip.compressed}/{v6_prefix}", strict=False).network_address.compressed

# ---- proof -----------------------------------------------------------------

def proof_canonical(server_name: str, kid: str, nonce_raw: bytes) -> bytes:
    return pae([PROOF_DOMAIN, canon_server_name(server_name).encode("ascii"),
                kid.encode("utf-8"), nonce_raw])

def build_proof(secret: bytes, server_name: str, kid: str, nonce_raw: bytes):
    canonical = proof_canonical(server_name, kid, nonce_raw)
    return hmac.new(secret, canonical, hashlib.sha256).digest(), canonical

def verify_proof(secret: bytes, server_name: str, kid: str, nonce_raw: bytes, tag: bytes) -> bool:
    expect, _ = build_proof(secret, server_name, kid, nonce_raw)
    return hmac.compare_digest(expect, tag)

# ---- stateless nonce -------------------------------------------------------

def nonce_mac_input(ts: int, rand: bytes, server_name: str, ip: str, v6_prefix: int = 128) -> bytes:
    return pae([NONCE_DOMAIN, ts.to_bytes(8, "big"), rand,
                canon_server_name(server_name).encode("ascii"),
                canon_ip(ip, v6_prefix).encode("ascii")])

def build_nonce(nonce_key: bytes, ts: int, rand: bytes, server_name: str, ip: str, v6_prefix: int = 128) -> bytes:
    if len(rand) != 16:
        raise ValueError("nonce rand must be 16 bytes")
    mac = hmac.new(nonce_key, nonce_mac_input(ts, rand, server_name, ip, v6_prefix), hashlib.sha256).digest()
    return ts.to_bytes(8, "big") + rand + mac

def verify_nonce(nonce_key: bytes, nonce: bytes, server_name: str, ip: str,
                 now: int, ttl: int, v6_prefix: int = 128):
    if len(nonce) != 56:
        return False, None
    ts = int.from_bytes(nonce[:8], "big")
    rand, mac = nonce[8:24], nonce[24:]
    expect = hmac.new(nonce_key, nonce_mac_input(ts, rand, server_name, ip, v6_prefix), hashlib.sha256).digest()
    if not hmac.compare_digest(expect, mac):
        return False, None
    if now < ts or now - ts >= ttl:
        return False, None
    return True, rand
