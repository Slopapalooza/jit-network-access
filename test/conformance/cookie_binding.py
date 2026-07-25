#!/usr/bin/env python3
"""
JIT Network Access — ip+cookie binding conformance probe.

Engine-agnostic: point it at any gate configured with JIT_ACCESS_BINDING /
binding = "ip+cookie" (BunkerWeb plugin, standalone Authorizer, Caddy module).
Transport is curl so --resolve and self-signed certs work.

What ip+cookie buys you: with plain `ip` binding every client behind the same
egress IP (office NAT, CGNAT, VPN) inherits a grant that any one of them earned.
Binding additionally to an opaque, host-only cookie means only the browser that
actually knocked is admitted (SECURITY-REVIEW C5/H11, DESIGN §11 R3).

Asserts:
  1. a successful knock returns Set-Cookie __Host-jit-grant
  2. the cookie carries Secure, HttpOnly, SameSite=Strict, Path=/ and NO Domain
  3. the stored value is opaque (not the kid, not the proof)
  4. requesting the service WITHOUT the cookie is denied      <- the whole point
  5. requesting it with a WRONG cookie value is denied
  6. requesting it WITH the cookie is admitted

Exit 0 iff every assertion holds.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "core", "py"))
import jitcrypto as J  # noqa: E402

PREFIX = "/.well-known/jit-access"
COOKIE = "__Host-jit-grant"

passed = failed = 0


def check(desc, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  PASS: {desc}")
    else:
        failed += 1
        print(f"  FAIL: {desc}{(' — ' + detail) if detail else ''}")


def curl(method, url, resolve=None, headers=None, data=None, dump=False):
    cmd = ["curl", "-s", "-k", "--max-time", "10", "-X", method]
    if resolve:
        cmd += ["--resolve", resolve]
    for h in headers or []:
        cmd += ["-H", h]
    if data is not None:
        cmd += ["--data", data]
    if dump:
        cmd += ["-D", "-", "-o", os.devnull]
    else:
        cmd += ["-o", os.devnull, "-w", "%{http_code}"]
    return subprocess.run(cmd + [url], capture_output=True, text=True).stdout


def status(raw):
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                st = int(parts[1])
    return st if "st" in dir() else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="base URL of the gated service")
    ap.add_argument("--kid", required=True)
    ap.add_argument("--secret", required=True, help="token secret, base64url")
    ap.add_argument("--resolve", help="curl --resolve, e.g. app.local:443:127.0.0.1")
    ap.add_argument("--host", help="override server_name used in the proof")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    server_name = args.host or urlparse(base).hostname
    secret = J.b64u_dec(args.secret)

    print(f"== ip+cookie binding against {base} ==")

    # --- knock -------------------------------------------------------------
    raw = curl("GET", base + PREFIX + "/challenge", resolve=args.resolve, dump=True)
    nonce_b64 = None
    for line in raw.splitlines():
        if line.lower().startswith("x-jit-nonce:"):
            nonce_b64 = line.split(":", 1)[1].strip()
    if not nonce_b64:
        print("  FATAL: no nonce from /challenge (is the service gated?)")
        return 1

    tag, _ = J.build_proof(secret, server_name, args.kid, J.b64u_dec(nonce_b64))
    body = json.dumps({"v": 1, "kid": args.kid, "nonce": nonce_b64, "proof": J.b64u(tag)})
    raw = curl("POST", base + PREFIX + "/respond", resolve=args.resolve,
               headers=["Content-Type: application/json"], data=body, dump=True)

    st = None
    set_cookie = None
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            p = line.split()
            if len(p) >= 2 and p[1].isdigit():
                st = int(p[1])
        if line.lower().startswith("set-cookie:") and COOKIE in line:
            set_cookie = line.split(":", 1)[1].strip()

    check("knock accepted (204)", st == 204, f"got {st}")
    check(f"knock sets {COOKIE}", set_cookie is not None,
          "no Set-Cookie — is binding actually ip+cookie?")
    if not set_cookie:
        print(f"\n{passed} passed, {failed} failed")
        return 1

    # --- cookie attributes --------------------------------------------------
    low = set_cookie.lower()
    check("cookie is Secure", "secure" in low)
    check("cookie is HttpOnly", "httponly" in low)
    check("cookie is SameSite=Strict", "samesite=strict" in low,
          "Lax would let a cross-site navigation ride the grant (H11)")
    check("cookie is Path=/", "path=/" in low)
    check("cookie is host-only (no Domain)", "domain=" not in low,
          "a Domain attribute would share the grant with sibling subdomains")

    m = re.match(rf"{re.escape(COOKIE)}=([^;]+)", set_cookie)
    value = m.group(1) if m else ""
    check("cookie value is opaque", bool(value) and args.kid not in value and J.b64u(tag) not in value)
    check("cookie value has >=128 bits of entropy", len(value) >= 22, f"len {len(value)}")

    # --- enforcement --------------------------------------------------------
    no_cookie = curl("GET", base + "/", resolve=args.resolve).strip()
    check("service DENIES the same IP without the cookie", no_cookie not in ("200", "204", "301", "302"),
          f"got {no_cookie} — ip+cookie is not being enforced")

    wrong = curl("GET", base + "/", resolve=args.resolve,
                 headers=[f"Cookie: {COOKIE}=not-the-right-value"]).strip()
    check("service DENIES a wrong cookie", wrong not in ("200", "204", "301", "302"), f"got {wrong}")

    right = curl("GET", base + "/", resolve=args.resolve,
                 headers=[f"Cookie: {COOKIE}={value}"]).strip()
    check("service ADMITS the correct cookie", right in ("200", "204", "301", "302"), f"got {right}")

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
