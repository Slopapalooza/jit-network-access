#!/usr/bin/env python3
"""
JIT Network Access — knock client (conformance / test tool).

Performs the full challenge/respond handshake against a JIT-gated service:
  1. GET  <prefix>/challenge   -> read X-JIT-Nonce
  2. compute proof = HMAC(secret, PAE("jitaccess-v1", server_name, kid, nonce))
  3. POST <prefix>/respond     -> 204 on success (grant created)

Crypto is the shared reference (core/py/jitcrypto). Transport is curl, so
--resolve and self-signed certs work on a test box. This is NOT the production
client — that's the browser extension (M3) — it's the conformance driver.

Prints machine-checkable lines: KNOCK <code>, and (optionally) SERVICE <code>,
REPLAY <code>. Exit 0 iff the knock was accepted (204).
"""
import argparse
import json
import os
import subprocess
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "core", "py"))
import jitcrypto as J  # noqa: E402

PREFIX = "/.well-known/jit-access"


def _curl(method, url, resolve=None, insecure=True, headers=None, data=None, dump_headers=False):
    cmd = ["curl", "-s", "--max-time", "10", "-X", method]
    if insecure:
        cmd.append("-k")
    if resolve:
        cmd += ["--resolve", resolve]
    for h in headers or []:
        cmd += ["-H", h]
    if data is not None:
        cmd += ["--data", data]
    if dump_headers:
        cmd += ["-D", "-", "-o", os.devnull]
    else:
        cmd += ["-o", os.devnull, "-w", "%{http_code}"]
    return subprocess.run(cmd + [url], capture_output=True, text=True).stdout


def _parse_headers(raw):
    status, hdrs = None, {}
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        elif ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="base URL, e.g. https://app-a.local")
    ap.add_argument("--kid", required=True)
    ap.add_argument("--secret", required=True, help="token secret, base64url")
    ap.add_argument("--resolve", help="curl --resolve, e.g. app-a.local:443:127.0.0.1")
    ap.add_argument("--host", help="override server_name used in the proof")
    ap.add_argument("--check-service", action="store_true", help="GET / after the knock")
    ap.add_argument("--replay", action="store_true", help="replay the same nonce+proof")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    server_name = args.host or urlparse(base).hostname
    secret = J.b64u_dec(args.secret)

    # 1. challenge
    raw = _curl("GET", base + PREFIX + "/challenge", resolve=args.resolve, dump_headers=True)
    st, hdrs = _parse_headers(raw)
    nonce_b64 = hdrs.get("x-jit-nonce")
    if not nonce_b64:
        print(f"KNOCK no-nonce (challenge HTTP {st})")
        return 1
    nonce_raw = J.b64u_dec(nonce_b64)

    # 2. proof + 3. respond
    tag, _ = J.build_proof(secret, server_name, args.kid, nonce_raw)
    body = json.dumps({"v": 1, "kid": args.kid, "nonce": nonce_b64, "proof": J.b64u(tag)})
    code = _curl("POST", base + PREFIX + "/respond", resolve=args.resolve,
                 headers=["Content-Type: application/json"], data=body).strip()
    print(f"KNOCK {code}")

    if args.check_service:
        svc = _curl("GET", base + "/", resolve=args.resolve).strip()
        print(f"SERVICE {svc}")

    if args.replay:
        rp = _curl("POST", base + PREFIX + "/respond", resolve=args.resolve,
                   headers=["Content-Type: application/json"], data=body).strip()
        print(f"REPLAY {rp}")

    return 0 if code == "204" else 1


if __name__ == "__main__":
    sys.exit(main())
