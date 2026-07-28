#!/usr/bin/env python3
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later

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
import json
import os
import sys

MIN_SECRET_BYTES = 16   # a 32-byte secret is standard; refuse anything trivially short
MAX_TOKEN_SLOTS = 256   # JIT_ACCESS_TOKEN_1.._N window to validate


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
    # Scan a fixed window rather than stopping at the first gap. The Lua side
    # enumerates settings with pairs(), so it loads EVERY slot regardless of
    # numbering; breaking at the first missing index meant a token in a
    # non-contiguous slot (_1, _3) was live in the gate but never validated here
    # — which defeats a job whose whole purpose is to make misconfiguration fail
    # loudly rather than at knock time.
    for i in range(1, MAX_TOKEN_SLOTS + 1):
        v = getenv(f"JIT_ACCESS_TOKEN_{i}")
        if v:
            entries.append(v)
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


def redacted_report(registry: dict) -> dict:
    """The validation result, with every secret stripped.

    registry["tokens"] is keyed by kid and each value carries `secret_b64url`.
    Only the non-secret fields are reported.
    """
    return {
        "v": registry.get("v", 1),
        "count": len(registry["tokens"]),
        "tokens": [
            {k: tok[k] for k in ("kid", "label", "expires", "alg") if k in tok}
            for tok in registry["tokens"].values()
        ],
    }


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

    job = Job(logger, __file__)
    # The cached report deliberately carries NO secrets.
    #
    # This file used to include every device's `secret_b64url` in cleartext, with
    # a TODO about encrypting it later. It was pure liability: the Lua never
    # reads this file — jitaccess:init() parses JIT_ACCESS_TOKEN_* from the
    # settings itself — so the secrets bought nothing and simply spread the most
    # sensitive material in the system into another file (and into BunkerWeb's
    # database-backed cache). What the job is actually for is validation, and
    # kid/label/expiry/count is all a human needs to read the result.
    job.cache_file("registry.json", json.dumps(redacted_report(registry)).encode("utf-8"))
    logger.info(f"jitaccess registry validated: {len(registry['tokens'])} token(s)")
    return 1 if entries else 0   # 1 = changed -> reload; 0 = nothing to do


# ---- self-test (pure, runs anywhere) --------------------------------------
def _self_test() -> int:
    ok = True
    good = "kid_AAAA:" + base64.urlsafe_b64encode(b"\x00" * 32).decode().rstrip("=") + ":Ops laptop"
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

    # The cached report must never carry key material: this file lands in
    # /var/cache/bunkerweb and in BunkerWeb's database-backed cache, and nothing
    # reads it back (the Lua parses the settings itself), so a secret in here is
    # pure liability.
    report = redacted_report(reg)
    blob = json.dumps(report)
    if "secret" in blob:
        ok = False
        print("  report leaks a secret field")
    secret_b64 = base64.urlsafe_b64encode(b"\x00" * 32).decode().rstrip("=")
    if secret_b64 in blob:
        ok = False
        print("  report leaks the secret value")
    if report["count"] != 1 or report["tokens"][0]["kid"] != "kid_AAAA":
        ok = False
        print(f"  report lost the non-secret fields: {report!r}")
    if report["tokens"][0].get("label") != "Ops laptop":
        ok = False
        print(f"  report lost the label: {report!r}")

    print("self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
