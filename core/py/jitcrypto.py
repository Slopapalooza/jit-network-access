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

def canon_server_name(host: str) -> str:
    h = host.strip()
    if h.startswith("["):
        end = h.find("]")
        if end != -1:
            return h[1:end].strip().lower()
    left, sep, right = h.rpartition(":")
    if sep and right.isdigit():
        h = left
    if h.endswith("."):
        h = h[:-1]
    return h.lower()

def canon_ip(addr: str, v6_prefix: int = 128, v4_prefix: int = 32) -> str:
    ip = ipaddress.ip_address(addr)
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
