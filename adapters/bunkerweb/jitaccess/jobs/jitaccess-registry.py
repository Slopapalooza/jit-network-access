#!/usr/bin/env python3
"""
jitaccess-registry — BunkerWeb scheduler job (every: once, reload: true).

Validates the JIT_ACCESS_TOKEN_* registry entries at (re)load time so that
misconfiguration fails LOUDLY here, not silently at knock time, and materializes
a normalized registry the Lua init phase reads. Runs before each config
generation.

Entry format:  kid:base64url_secret:label[:expiry_unix]

The parse/validate helpers below are pure and unit-testable without BunkerWeb
(see the __main__ self-test). The BunkerWeb-specific caching via the Job class
is done in main() and is exercised by the docker harness (M1).
"""

import base64
import os
import sys

MIN_SECRET_BYTES = 16   # a 32-byte secret is standard; refuse anything trivially short


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse_token(entry: str) -> dict:
    """Parse one 'kid:secret:label[:expiry]' entry. Raises ValueError on bad input."""
    parts = entry.split(":")
    if len(parts) < 3:
        raise ValueError(f"expected kid:secret:label[:expiry], got {entry!r}")
    kid, secret_b64, label = parts[0], parts[1], parts[2]
    expiry = None
    if len(parts) >= 4 and parts[3] != "":
        if not parts[3].isdigit():
            raise ValueError(f"expiry must be a unix timestamp, got {parts[3]!r}")
        expiry = int(parts[3])
    if not kid or not all(c.isalnum() or c in "_-" for c in kid):
        raise ValueError(f"kid must be non-empty base64url-ish, got {kid!r}")
    try:
        secret = _b64url_decode(secret_b64)
    except Exception as e:
        raise ValueError(f"secret is not valid base64url: {e}")
    if len(secret) < MIN_SECRET_BYTES:
        raise ValueError(f"secret too short ({len(secret)} bytes; need >= {MIN_SECRET_BYTES})")
    return {"kid": kid, "secret_b64url": secret_b64, "label": label,
            "expires": expiry, "alg": "HMAC-SHA256"}


def collect_token_entries(getenv=os.getenv) -> list:
    """Gather JIT_ACCESS_TOKEN, JIT_ACCESS_TOKEN_1, _2, ... (BunkerWeb 'multiple')."""
    entries = []
    base = getenv("JIT_ACCESS_TOKEN")
    if base:
        entries.append(base)
    i = 1
    while True:
        v = getenv(f"JIT_ACCESS_TOKEN_{i}")
        if v is None:
            break
        if v:
            entries.append(v)
        i += 1
    return entries


def build_registry(entries: list) -> dict:
    """Validate all entries; enforce kid uniqueness. Returns the normalized registry."""
    tokens = {}
    for e in entries:
        tok = parse_token(e)
        if tok["kid"] in tokens:
            raise ValueError(f"duplicate kid {tok['kid']!r}")
        tokens[tok["kid"]] = tok
    return {"v": 1, "tokens": tokens}


def main() -> int:
    # BunkerWeb job plumbing (paths appended by the scheduler at runtime).
    for p in ("/usr/share/bunkerweb/deps/python", "/usr/share/bunkerweb/utils",
              "/usr/share/bunkerweb/db", "/usr/share/bunkerweb/api"):
        if p not in sys.path and os.path.isdir(p):
            sys.path.append(p)
    try:
        from logger import setup_logger            # type: ignore
        from jobs import Job                        # type: ignore
    except Exception:
        print("jitaccess-registry: BunkerWeb job environment not present", file=sys.stderr)
        return 0

    logger = setup_logger("JITACCESS-REGISTRY")
    try:
        entries = collect_token_entries()
        registry = build_registry(entries)
    except ValueError as e:
        logger.error(f"invalid JIT_ACCESS_TOKEN registry: {e}")
        return 2   # hard error -> scheduler surfaces it; service stays fail-closed

    import json
    job = Job(logger, __file__)
    # TODO(hardened): encrypt this cache at rest under a KEK; lock perms to worker UID.
    job.cache_file("registry.json", json.dumps(registry).encode("utf-8"))
    logger.info(f"jitaccess registry validated: {len(registry['tokens'])} token(s)")
    return 1 if entries else 0   # 1 = changed -> reload; 0 = nothing to do


# ---- self-test (pure, runs anywhere) --------------------------------------
def _self_test() -> int:
    ok = True
    good = "kid_AAAA:" + base64.urlsafe_b64encode(b"\x00" * 32).decode().rstrip("=") + ":Jamie laptop"
    reg = build_registry([good])
    ok &= "kid_AAAA" in reg["tokens"]
    for bad in ["nope", "kid::label", "kid_x:@@@notb64@@@:l",
                "kid_y:" + base64.urlsafe_b64encode(b"short").decode().rstrip("=") + ":l"]:
        try:
            build_registry([bad]); ok = False; print(f"  should have rejected: {bad!r}")
        except ValueError:
            pass
    try:
        dup = [good, good]; build_registry(dup); ok = False; print("  should reject duplicate kid")
    except ValueError:
        pass
    print("self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
