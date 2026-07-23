#!/usr/bin/env python3
"""
JIT Network Access — security conformance suite (M2.5).

Adversarial probes against a deployed JIT-gated stack. An adapter is "supported"
only when it passes these, not just the functional knock (DESIGN §9 M2.5).

Probes (all must hold):
  1. malformed /respond          -> never 204, and the gate still works after (fail-closed)
  2. tampered proof / nonce      -> rejected
  3. unknown kid                 -> rejected (and indistinguishable generic response)
  4. cross-service proof reuse   -> a valid (nonce,proof) for A is rejected at B
  5. replayed nonce              -> second use rejected (single-use)
  6. forged X-Forwarded-For      -> does not move the grant key (Simple = TCP peer)
  7. well-known path traversal   -> never reaches the upstream

Transport is curl (so --resolve / self-signed work); crypto is core/py/jitcrypto.
Revocation between probes uses the instance internal API (--api + --api-token),
so probes start from a known grant state.

Exit 0 iff every probe passes.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "core", "py"))
import jitcrypto as J  # noqa: E402

PREFIX = "/.well-known/jit-access"


def curl(method, url, resolve=None, headers=None, data=None, dump_headers=False, path_as_is=False, want_body=False):
    cmd = ["curl", "-s", "-k", "--max-time", "10", "-X", method]
    if path_as_is:
        cmd.append("--path-as-is")
    if resolve:
        cmd += ["--resolve", resolve]
    for h in headers or []:
        cmd += ["-H", h]
    if data is not None:
        cmd += ["--data", data]
    if want_body:
        pass                                   # return the response body
    elif dump_headers:
        cmd += ["-D", "-", "-o", os.devnull]
    else:
        cmd += ["-o", os.devnull, "-w", "%{http_code}"]
    return subprocess.run(cmd + [url], capture_output=True, text=True).stdout


def parse_status_nonce(raw):
    status, nonce = None, None
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            p = line.split()
            if len(p) >= 2 and p[1].isdigit():
                status = int(p[1])
        elif line.lower().startswith("x-jit-nonce:"):
            nonce = line.split(":", 1)[1].strip()
    return status, nonce


class Svc:
    def __init__(self, url, resolve, kid, secret, server_name):
        self.url, self.resolve, self.kid = url.rstrip("/"), resolve, kid
        self.secret = J.b64u_dec(secret)
        self.sn = server_name

    def challenge(self):
        return parse_status_nonce(curl("GET", self.url + PREFIX + "/challenge", self.resolve, dump_headers=True))

    def respond(self, body):
        return curl("POST", self.url + PREFIX + "/respond", self.resolve,
                    headers=["Content-Type: application/json"], data=body).strip()

    def get(self, headers=None, path="/"):
        return curl("GET", self.url + path, self.resolve, headers=headers, path_as_is=True).strip()

    def valid_body(self, nonce_b64, kid=None, secret=None):
        if not nonce_b64:
            return "{}"   # challenge failed to yield a nonce; produce an obviously-bad body
        kid = kid or self.kid
        secret = secret if secret is not None else self.secret
        tag, _ = J.build_proof(secret, self.sn, kid, J.b64u_dec(nonce_b64))
        return json.dumps({"v": 1, "kid": kid, "nonce": nonce_b64, "proof": J.b64u(tag)})


def _api_headers(token):
    return ["Host: bwapi", f"Authorization: Bearer {token}", "Content-Type: application/json"]


def _api_inner(raw):
    """The internal API wraps payloads as {"msg": "<json string>", "status": ...}."""
    try:
        outer = json.loads(raw)
        return json.loads(outer.get("msg", "{}"))
    except Exception:
        return {}


def revoke(api, token, service, ip):
    if not api or not token:
        return
    curl("POST", api + "/jitaccess/revoke", headers=_api_headers(token),
         data=json.dumps({"service": service, "ip": ip}))


def list_grants(api, token):
    if not api or not token:
        return []
    raw = curl("GET", api + "/jitaccess/grants", headers=_api_headers(token), want_body=True)
    return _api_inner(raw).get("grants", [])


def manual_grant(api, token, service, ip, ttl=120):
    curl("POST", api + "/jitaccess/grant", headers=_api_headers(token),
         data=json.dumps({"service": service, "ip": ip, "ttl": ttl}))


def revoke_all(api, token, service):
    """Clear every grant for `service`, whatever IP form it was stored under."""
    if not api or not token:
        return
    for g in list_grants(api, token):
        if g.get("service") == service:
            revoke(api, token, service, g.get("ip"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a-url", required=True); ap.add_argument("--a-resolve", required=True)
    ap.add_argument("--a-kid", required=True); ap.add_argument("--a-secret", required=True)
    ap.add_argument("--a-name", required=True, help="service A server_name (for the proof)")
    ap.add_argument("--b-url", required=True); ap.add_argument("--b-resolve", required=True)
    ap.add_argument("--b-name", required=True)
    ap.add_argument("--api"); ap.add_argument("--api-token")
    ap.add_argument("--peer-ip", default="127.0.0.1", help="client IP as the server sees it")
    args = ap.parse_args()

    A = Svc(args.a_url, args.a_resolve, args.a_kid, args.a_secret, args.a_name)
    B = Svc(args.b_url, args.b_resolve, "unused", J.b64u(b"\0" * 32), args.b_name)
    rev = lambda: revoke(args.api, args.api_token, args.a_name, args.peer_ip)

    passed, failed = 0, 0
    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            print(f"  PASS: {name}"); passed += 1
        else:
            print(f"  FAIL: {name} {detail}"); failed += 1

    # 1. malformed /respond -> never 204, then gate still works
    rev()
    bad_bodies = [
        "", "not json", "{}", '{"v":1}', '{"v":1,"kid":"x"}',
        '{"v":1,"kid":"x","nonce":"@@@","proof":"@@@"}',
        '{"nonce":123,"proof":[],"kid":null}',
        '{"v":1,"kid":"x","nonce":"' + "A" * 20000 + '","proof":"AAAA"}',
        '[1,2,3]', '{"kid":"x","nonce":"","proof":""}',
    ]
    all_denied = all(A.respond(b) != "204" for b in bad_bodies)
    check("malformed /respond never returns 204", all_denied)
    st, nonce = A.challenge()
    survived = nonce is not None and A.respond(A.valid_body(nonce)) == "204"
    check("gate still works after malformed flood (fail-closed, not crash-open)", survived)
    rev()

    # 2. tampered proof / nonce
    st, nonce = A.challenge()
    body = json.loads(A.valid_body(nonce))
    p = bytearray(J.b64u_dec(body["proof"])); p[0] ^= 0x01
    body_tp = dict(body, proof=J.b64u(bytes(p)))
    check("tampered proof rejected", A.respond(json.dumps(body_tp)) != "204")
    st, nonce2 = A.challenge()
    body2 = json.loads(A.valid_body(nonce2))
    n = bytearray(J.b64u_dec(body2["nonce"])); n[10] ^= 0x01
    body_tn = dict(body2, nonce=J.b64u(bytes(n)))
    check("tampered nonce rejected", A.respond(json.dumps(body_tn)) != "204")
    rev()

    # 3. unknown kid (generic rejection)
    st, nonce = A.challenge()
    unk = json.dumps({"v": 1, "kid": "no_such_kid_xyz", "nonce": nonce, "proof": J.b64u(b"\x00" * 32)})
    unk_code = A.respond(unk)
    st, nonce_b = A.challenge()
    badproof = json.loads(A.valid_body(nonce_b)); bp = bytearray(J.b64u_dec(badproof["proof"])); bp[0] ^= 1
    badproof_code = A.respond(json.dumps(dict(badproof, proof=J.b64u(bytes(bp)))))
    check("unknown kid rejected", unk_code != "204")
    check("unknown-kid response matches bad-proof response (no oracle)", unk_code == badproof_code,
          f"(unknown={unk_code} badproof={badproof_code})")
    rev()

    # 4. cross-service proof reuse: valid (nonce,proof) for A submitted to B
    st, nonceA = A.challenge()
    bodyA = A.valid_body(nonceA)
    check("A's proof rejected at B (server_name binding)", B.respond(bodyA) != "204")
    rev()

    # 5. replay
    rev()
    st, nonce = A.challenge()
    body = A.valid_body(nonce)
    first = A.respond(body)
    second = A.respond(body)
    check("replay: first accepted", first == "204", f"(got {first})")
    check("replay: second (same nonce) rejected", second != "204", f"(got {second})")
    rev()

    # 6. forged X-Forwarded-For cannot inherit another IP's grant (Simple = TCP peer).
    # Use service B: the peer never performs a valid knock on B, so B is naturally
    # dark for the peer regardless of grant-cleanup timing on A.
    victim_ip = "198.51.100.7"
    manual_grant(args.api, args.api_token, args.b_name, victim_ip)      # grant victim on B
    spoof = B.get(headers=[f"X-Forwarded-For: {victim_ip}", f"X-Real-IP: {victim_ip}"])
    check("forged XFF/X-Real-IP cannot inherit another IP's grant", spoof in ("403", "404"), f"(got {spoof})")
    revoke(args.api, args.api_token, args.b_name, victim_ip)
    # XFF isn't consulted downward either: knock-grant the peer on A, bogus XFF still 200
    st, nonce = A.challenge(); A.respond(A.valid_body(nonce))
    lit = A.get(headers=["X-Forwarded-For: 203.0.113.99"])
    check("peer-granted request ignores XFF (still 200)", lit == "200", f"(got {lit})")
    rev()

    # 7. well-known path traversal must not reach the upstream
    trav = ["/.well-known/jit-access/../", "/.well-known/jit-access/..%2f",
            "/.well-known/jit-access/respond/../../", "/.well-known/jit-access/./challenge/../.."]
    rev()
    codes = [A.get(path=t) for t in trav]
    check("path traversal never reaches upstream (no 200)", all(c != "200" for c in codes), f"(codes={codes})")

    print(f"\nRESULT: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
