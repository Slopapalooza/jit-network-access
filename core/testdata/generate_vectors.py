#!/usr/bin/env python3
"""
Authoritative reference implementation + conformance-vector generator for the
JIT Network Access portable core (L3).

This is the "third witness": an independent implementation of the byte-level
constructions (PAE, canonicalization, the proof HMAC, the stateless nonce) that
the Lua and Go reference libraries MUST match, byte for byte. The vectors it
emits (vectors.json) are the shared contract; any adapter that diverges fails
conformance.

Run:  python generate_vectors.py            # writes vectors.json next to this file
      python generate_vectors.py --check    # regenerate in memory and diff vs the file

Deterministic: all "random" inputs are fixed test values, so output is stable
and reviewable in git. Nothing here uses os.urandom.
"""

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import sys

PROOF_DOMAIN = b"jitaccess-v1"          # domain separator inside the proof MAC
NONCE_DOMAIN = b"jitaccess-nonce-v1"    # distinct separator inside the nonce MAC

# ---------------------------------------------------------------------------
# base64url (no padding) — the only on-the-wire binary encoding
# ---------------------------------------------------------------------------

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# ---------------------------------------------------------------------------
# PAE — Pre-Authentication Encoding (PASETO-compatible)
#
#   LE64(n)  = 8-byte little-endian, high bit of the last byte cleared
#   PAE(ps)  = LE64(len(ps)) || for each p:  LE64(len(p)) || p
#
# Makes the concatenation of variable-length fields injective: no two distinct
# field lists can serialize to the same byte string. This is the fix for the
# "un-framed concatenation" finding (SECURITY-REVIEW H1).
# ---------------------------------------------------------------------------

def le64(n: int) -> bytes:
    if n < 0:
        raise ValueError("le64: negative length")
    b = bytearray(n.to_bytes(8, "little"))
    b[7] &= 0x7F  # clear top bit, per PASETO PAE
    return bytes(b)

def pae(pieces) -> bytes:
    out = bytearray(le64(len(pieces)))
    for p in pieces:
        if not isinstance(p, (bytes, bytearray)):
            raise TypeError("pae pieces must be bytes")
        out += le64(len(p))
        out += p
    return bytes(out)

# ---------------------------------------------------------------------------
# Canonicalization — one normative form each, applied identically everywhere,
# so grant keys computed by different adapters are byte-identical (H1 / C10).
# ---------------------------------------------------------------------------

def canon_server_name(host: str) -> str:
    """
    Canonical service identity.

    - lowercased (ASCII)
    - trailing dot stripped
    - :port stripped
    - IDN is expected to already be an A-label (xn--...) as browsers send in the
      Host header; we NEVER Unicode-decode. This keeps client and server agreeing
      without shipping an IDNA library into every adapter.

    server_name is a hostname (services are named, not addressed); a bracketed
    IPv6 literal is tolerated defensively but is not an expected input.
    """
    h = host.strip()
    if h.startswith("["):  # [v6]:port defensive path
        end = h.find("]")
        if end != -1:
            return h[1:end].strip().lower()
    # strip a trailing :port (host has no ':', so rpartition is safe)
    left, sep, right = h.rpartition(":")
    if sep and right.isdigit():
        h = left
    if h.endswith("."):
        h = h[:-1]
    return h.lower()

def canon_ip(addr: str, v6_prefix: int = 128, v4_prefix: int = 32) -> str:
    """
    Canonical client-IP string for the grant key.

    - parsed to bytes, prefix-masked (defaults = exact host: /32, /128)
    - rendered in one canonical textual form (RFC 5952 for IPv6 via ipaddress)
    - IPv4-mapped IPv6 (::ffff:1.2.3.4) is normalized to its IPv4 form so the
      same client can't hold two differently-keyed grants.
    """
    ip = ipaddress.ip_address(addr)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        if v4_prefix >= 32:
            return ip.compressed
        net = ipaddress.ip_network(f"{ip.compressed}/{v4_prefix}", strict=False)
        return net.network_address.compressed
    if v6_prefix >= 128:
        return ip.compressed
    net = ipaddress.ip_network(f"{ip.compressed}/{v6_prefix}", strict=False)
    return net.network_address.compressed

# ---------------------------------------------------------------------------
# Proof (the knock response)
#
#   canonical = PAE([ "jitaccess-v1", server_name_canon, kid, nonce_raw ])
#   proof     = HMAC-SHA256(secret, canonical)          # full 32-byte tag
#
# kid is bound as its exact UTF-8/ASCII bytes (the same bytes used for registry
# lookup); nonce_raw is the base64url-decoded nonce the client received.
# ---------------------------------------------------------------------------

def proof_canonical(server_name: str, kid: str, nonce_raw: bytes) -> bytes:
    return pae([PROOF_DOMAIN,
                canon_server_name(server_name).encode("ascii"),
                kid.encode("utf-8"),
                nonce_raw])

def build_proof(secret: bytes, server_name: str, kid: str, nonce_raw: bytes):
    canonical = proof_canonical(server_name, kid, nonce_raw)
    tag = hmac.new(secret, canonical, hashlib.sha256).digest()
    return tag, canonical

def verify_proof(secret: bytes, server_name: str, kid: str, nonce_raw: bytes, tag: bytes) -> bool:
    expect, _ = build_proof(secret, server_name, kid, nonce_raw)
    return hmac.compare_digest(expect, tag)

# ---------------------------------------------------------------------------
# Stateless signed nonce
#
#   ts        = 8-byte big-endian unix seconds
#   rand      = 16 random bytes
#   mac       = HMAC-SHA256(nonce_key, PAE(["jitaccess-nonce-v1", ts, rand,
#                                            server_name_canon, ip_canon]))
#   nonce     = ts || rand || mac            (56 bytes) → base64url on the wire
#
# Self-authenticating: /challenge stores nothing (no store to flood — H5).
# Single-use is enforced at redemption by an atomic add of `rand` to a spent-set.
# nonce_key is a per-instance ephemeral key.
# ---------------------------------------------------------------------------

def nonce_mac_input(ts: int, rand: bytes, server_name: str, ip: str, v6_prefix: int = 128) -> bytes:
    return pae([NONCE_DOMAIN,
                ts.to_bytes(8, "big"),
                rand,
                canon_server_name(server_name).encode("ascii"),
                canon_ip(ip, v6_prefix).encode("ascii")])

def build_nonce(nonce_key: bytes, ts: int, rand: bytes, server_name: str, ip: str, v6_prefix: int = 128) -> bytes:
    if len(rand) != 16:
        raise ValueError("nonce rand must be 16 bytes")
    mac = hmac.new(nonce_key, nonce_mac_input(ts, rand, server_name, ip, v6_prefix), hashlib.sha256).digest()
    return ts.to_bytes(8, "big") + rand + mac

def verify_nonce(nonce_key: bytes, nonce: bytes, server_name: str, ip: str,
                 now: int, ttl: int, v6_prefix: int = 128):
    """Returns (ok, rand_or_None). Does NOT enforce single-use (that's the store's job)."""
    if len(nonce) != 56:
        return False, None
    ts = int.from_bytes(nonce[:8], "big")
    rand = nonce[8:24]
    mac = nonce[24:]
    expect = hmac.new(nonce_key, nonce_mac_input(ts, rand, server_name, ip, v6_prefix), hashlib.sha256).digest()
    if not hmac.compare_digest(expect, mac):
        return False, None
    if now < ts or now - ts >= ttl:
        return False, None
    return True, rand

# ---------------------------------------------------------------------------
# Vector generation
# ---------------------------------------------------------------------------

def hexs(b: bytes) -> str:
    return b.hex()

def build_vectors() -> dict:
    v = {
        "_comment": "Conformance vectors for JIT Network Access L3. Generated by "
                    "generate_vectors.py. Lua and Go reference libs MUST reproduce "
                    "every output below byte-for-byte. Do not hand-edit.",
        "constants": {
            "proof_domain": PROOF_DOMAIN.decode(),
            "nonce_domain": NONCE_DOMAIN.decode(),
            "hash": "SHA-256",
            "nonce_len_bytes": 56,
            "encoding": "base64url-nopad",
        },
        "pae": [],
        "canon_server_name": [],
        "canon_ip": [],
        "proof": [],
        "nonce": [],
    }

    # --- PAE ---
    pae_cases = [
        [],
        [b""],
        [b"", b""],
        [b"jitaccess-v1"],
        [b"a", b"bb", b"ccc"],
        # the classic canonicalization-collision pair must NOT collide under PAE:
        [b"aa", b"bb"],
        [b"aab", b"b"],
    ]
    for pieces in pae_cases:
        v["pae"].append({
            "pieces": [b64u(p) for p in pieces],
            "pieces_utf8": [p.decode("latin-1") for p in pieces],
            "out_hex": hexs(pae(pieces)),
        })

    # --- server_name canonicalization ---
    for host in ["grafana.example.com", "Grafana.Example.COM", "grafana.example.com.",
                 "grafana.example.com:8443", "GRAFANA.example.com.:443",
                 "wiki.internal", "xn--caf-dma.example.com", "9wiki.internal"]:
        v["canon_server_name"].append({"in": host, "out": canon_server_name(host)})

    # --- ip canonicalization ---
    ip_cases = [
        ("1.2.3.4", 128, 32),
        ("192.168.001.005", 128, 32),           # ipaddress rejects leading zeros -> see note
        ("2001:db8:0:0:0:0:0:1", 128, 32),
        ("2001:0DB8::1", 128, 32),
        ("::ffff:1.2.3.4", 128, 32),            # v4-mapped normalizes to v4
        ("2001:db8:abcd:1234::1", 64, 32),      # /64 grant -> network address
        ("2001:db8:abcd:1234:5678::9", 64, 32),
    ]
    for addr, p6, p4 in ip_cases:
        try:
            out = canon_ip(addr, p6, p4)
        except ValueError as e:
            out = f"<invalid: {e}>"
        v["canon_ip"].append({"in": addr, "v6_prefix": p6, "v4_prefix": p4, "out": out})

    # --- proof ---
    secret = bytes(range(32))  # 00,01,...,1f
    proof_cases = [
        ("grafana.example.com", "kid_AAAAAAAAAAAAAAAAAAAA", bytes(range(56))),
        ("wiki.internal",       "kid_BBBBBBBBBBBBBBBBBBBB", bytes([0x11]) * 56),
        # cross-service isolation witness: same secret+kid+nonce, different service
        ("grafana.example.com", "kid_shared",              bytes([0x22]) * 56),
        ("9wiki.internal",      "kid_shared",              bytes([0x22]) * 56),
    ]
    for server_name, kid, nonce_raw in proof_cases:
        tag, canonical = build_proof(secret, server_name, kid, nonce_raw)
        v["proof"].append({
            "secret_hex": hexs(secret),
            "server_name": server_name,
            "server_name_canon": canon_server_name(server_name),
            "kid": kid,
            "nonce_raw_hex": hexs(nonce_raw),
            "nonce_b64url": b64u(nonce_raw),
            "canonical_hex": hexs(canonical),
            "proof_b64url": b64u(tag),
        })

    # --- nonce ---
    nonce_key = bytes([0xAB]) * 32
    nonce_cases = [
        (1_700_000_000, bytes(range(16)),          "grafana.example.com", "1.2.3.4",   128),
        (1_700_000_000, bytes([0xCD]) * 16,        "wiki.internal",       "2001:db8::1", 128),
        (1_700_000_000, bytes([0xEF]) * 16,        "app.example.com",     "2001:db8:abcd:1234::99", 64),
    ]
    for ts, rand, server_name, ip, p6 in nonce_cases:
        nonce = build_nonce(nonce_key, ts, rand, server_name, ip, p6)
        ok, got_rand = verify_nonce(nonce_key, nonce, server_name, ip, ts + 5, 60, p6)
        v["nonce"].append({
            "nonce_key_hex": hexs(nonce_key),
            "ts": ts,
            "rand_hex": hexs(rand),
            "server_name": server_name,
            "server_name_canon": canon_server_name(server_name),
            "ip": ip,
            "ip_canon": canon_ip(ip, p6),
            "v6_prefix": p6,
            "nonce_hex": hexs(nonce),
            "nonce_b64url": b64u(nonce),
            "verify_at_ts_plus_5_ttl_60": ok,
        })

    return v


def openssl_cross_check(vectors: dict) -> None:
    """Independently recompute the first proof tag with the openssl CLI as a
    second witness that our HMAC is standard HMAC-SHA256 over the canonical bytes."""
    import shutil, subprocess, tempfile
    if not shutil.which("openssl"):
        print("  (openssl not found; skipping cross-check)")
        return
    case = vectors["proof"][0]
    canonical = bytes.fromhex(case["canonical_hex"])
    key_hex = case["secret_hex"]
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(canonical)
        path = f.name
    try:
        out = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-mac", "HMAC", "-macopt", f"hexkey:{key_hex}", path],
            text=True,
        )
        tag_hex = out.strip().rsplit(" ", 1)[-1]
        ours_hex = b64u_dec(case["proof_b64url"]).hex()
        status = "MATCH" if tag_hex == ours_hex else "MISMATCH"
        print(f"  openssl HMAC cross-check: {status}")
        if tag_hex != ours_hex:
            print(f"    openssl={tag_hex}\n    ours   ={ours_hex}")
            sys.exit(1)
    finally:
        os.unlink(path)


def self_test() -> None:
    """A few invariants that must hold regardless of the vectors."""
    # PAE injectivity on the classic collision pair
    assert pae([b"aa", b"bb"]) != pae([b"aab", b"b"]), "PAE not injective!"
    # proof verify round-trip
    secret = b"\x01" * 32
    tag, _ = build_proof(secret, "svc.example.com", "kid_x", b"\x00" * 56)
    assert verify_proof(secret, "svc.example.com", "kid_x", b"\x00" * 56, tag)
    # wrong service must not verify (cross-service isolation)
    assert not verify_proof(secret, "other.example.com", "kid_x", b"\x00" * 56, tag)
    # nonce round-trip + binding
    nk = b"\x02" * 32
    n = build_nonce(nk, 1000, b"\x03" * 16, "svc.example.com", "1.2.3.4")
    ok, rand = verify_nonce(nk, n, "svc.example.com", "1.2.3.4", 1005, 60)
    assert ok and rand == b"\x03" * 16
    # wrong IP must fail the nonce binding
    ok2, _ = verify_nonce(nk, n, "svc.example.com", "9.9.9.9", 1005, 60)
    assert not ok2
    # expired nonce fails
    ok3, _ = verify_nonce(nk, n, "svc.example.com", "1.2.3.4", 2000, 60)
    assert not ok3
    print("  self-test: PASS (PAE injective, proof binds service, nonce binds ip+ttl)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="diff against the committed vectors.json")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, "vectors.json")

    print("Generating JIT Network Access conformance vectors...")
    self_test()
    vectors = build_vectors()
    openssl_cross_check(vectors)
    rendered = json.dumps(vectors, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        with open(out_path, encoding="utf-8") as f:
            existing = f.read()
        if existing != rendered:
            print("  DRIFT: vectors.json does not match the generator output.")
            sys.exit(1)
        print("  vectors.json is up to date.")
        return

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"  wrote {out_path}")
    print(f"  pae={len(vectors['pae'])} canon_server_name={len(vectors['canon_server_name'])} "
          f"canon_ip={len(vectors['canon_ip'])} proof={len(vectors['proof'])} nonce={len(vectors['nonce'])}")


if __name__ == "__main__":
    main()
