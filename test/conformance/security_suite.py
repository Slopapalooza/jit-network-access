#!/usr/bin/env python3
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
JIT Network Access — security conformance suite (M2.5).

Adversarial probes against a deployed JIT-gated stack. An adapter is "supported"
only when it passes these, not just the functional knock (DESIGN §9 M2.5).

Probes (all must hold):
  1. malformed /respond          -> never 204, denies DELIBERATELY (403/404, not 5xx),
                                    and the gate still works after (fail-closed)
  2. tampered proof / nonce      -> rejected
  3. unknown kid                 -> rejected (and indistinguishable generic response)
  4. server_name binding         -> a proof computed for A's server_name is rejected at B
                                    even with B's own nonce and a kid B allows
                                    (needs --b-kid/--b-secret; without them the probe
                                    is confounded by B's allow-list and reports SKIPPED)
  5. replayed nonce              -> second use rejected (single-use)
  6. forged X-Forwarded-For      -> does not move the grant key (Simple = TCP peer)
                                    (needs --api/--api-token to create the victim grant;
                                    without them it reports SETUP FAILED, never a pass)
  7. well-known path traversal   -> never reaches the upstream, including payloads that
                                    normalize onto a path the upstream really serves

A rejection is asserted as the CONFIGURED generic response, not merely "not 204":
a 500 from an unhandled error satisfies `!= 204` just as well as a correct deny.

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
    """Returns True iff the grant was actually created.

    The caller MUST check this. Several probes work by granting a victim IP and
    then showing a spoofed request cannot inherit it — if the grant silently
    never happened (no --api, wrong token, unreachable API) the assertion holds
    trivially and a gate that fully honours X-Forwarded-For scores a PASS.
    """
    if not api or not token:
        return False
    curl("POST", api + "/jitaccess/grant", headers=_api_headers(token),
         data=json.dumps({"service": service, "ip": ip, "ttl": ttl}))
    return any(g.get("ip") == ip and g.get("service") == service
               for g in list_grants(api, token))


def discover_peer_ip(api, token, service, fallback):
    """Learn the client IP as the SERVER sees it, by reading back a grant.

    A hard-coded default cannot be right: driven from the host against a
    published port, BunkerWeb sees the Docker bridge gateway, not 127.0.0.1. When
    that guess was wrong every revoke() targeted a key that did not exist, so the
    suite silently ran on accumulating grant state and probes that assume "dark
    before this step" were measured against an already-open gate.
    """
    if not api or not token:
        return fallback
    for g in list_grants(api, token):
        if g.get("service") == service and g.get("ip"):
            return g["ip"]
    return fallback


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
    ap.add_argument("--b-kid", help="a kid service B ACCEPTS (needed for the server_name-binding probe)")
    ap.add_argument("--b-secret", help="that kid's secret, base64url")
    ap.add_argument("--api"); ap.add_argument("--api-token")
    ap.add_argument("--peer-ip", default="127.0.0.1", help="client IP as the server sees it")
    args = ap.parse_args()

    A = Svc(args.a_url, args.a_resolve, args.a_kid, args.a_secret, args.a_name)
    B = Svc(args.b_url, args.b_resolve, "unused", J.b64u(b"\0" * 32), args.b_name)
    peer_ip = args.peer_ip
    rev = lambda: revoke(args.api, args.api_token, args.a_name, peer_ip)

    passed, failed = 0, 0
    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            print(f"  PASS: {name}"); passed += 1
        else:
            print(f"  FAIL: {name} {detail}"); failed += 1

    # A rejection has to be a DELIBERATE denial, not a crash. Every negative
    # assertion in this suite used to be `!= "204"`, which a 500 from an
    # unhandled error satisfies just as well as a correct deny — so a gate that
    # threw on every malformed input scored full marks. PROTOCOL §6 requires the
    # configured generic response, so check for exactly that.
    DENY_CODES = ("403", "404")

    def check_denied(name, code, detail=""):
        check(name, code in DENY_CODES, f"(got {code}) {detail}".strip())

    # 1. malformed /respond -> never 204, then gate still works
    rev()
    bad_bodies = [
        "", "not json", "{}", '{"v":1}', '{"v":1,"kid":"x"}',
        '{"v":1,"kid":"x","nonce":"@@@","proof":"@@@"}',
        '{"nonce":123,"proof":[],"kid":null}',
        '{"v":1,"kid":"x","nonce":"' + "A" * 20000 + '","proof":"AAAA"}',
        '[1,2,3]', '{"kid":"x","nonce":"","proof":""}',
    ]
    bad_codes = [A.respond(b) for b in bad_bodies]
    check("malformed /respond never returns 204", all(c != "204" for c in bad_codes),
          f"(codes={bad_codes})")
    # ...and each rejection is the configured generic denial, not a 500 from an
    # unhandled parse error. `!= 204` alone passed for a gate that crashed.
    check("malformed /respond denies deliberately (no 5xx)",
          all(c in DENY_CODES for c in bad_codes), f"(codes={bad_codes})")
    st, nonce = A.challenge()
    survived = nonce is not None and A.respond(A.valid_body(nonce)) == "204"
    check("gate still works after malformed flood (fail-closed, not crash-open)", survived)
    # That knock just created a grant, so this is the moment to learn what the
    # server thinks our address is. Everything after here depends on rev()
    # actually revoking something.
    if survived:
        discovered = discover_peer_ip(args.api, args.api_token, args.a_name, peer_ip)
        if discovered != peer_ip:
            print(f"  NOTE: peer ip is {discovered} (not {peer_ip}); using the discovered value")
            peer_ip = discovered
    if args.api and args.api_token:
        # Assert on the STORE, not on rev()'s return value — revoke() returns None
        # unconditionally, so `rev() is None` was a tautology and this probe could
        # only ever pass. Every later probe assumes "dark before this step", so if
        # revocation is silently a no-op the whole suite is measuring an open gate.
        rev()
        still_there = any(g.get("service") == args.a_name and g.get("ip") == peer_ip
                          for g in list_grants(args.api, args.api_token))
        check("revocation actually works (every later probe depends on it)",
              not still_there,
              f"(grant for {args.a_name}/{peer_ip} survived revoke — is --peer-ip right?)")
    rev()

    # 2. tampered proof / nonce
    st, nonce = A.challenge()
    body = json.loads(A.valid_body(nonce))
    p = bytearray(J.b64u_dec(body["proof"])); p[0] ^= 0x01
    body_tp = dict(body, proof=J.b64u(bytes(p)))
    check_denied("tampered proof rejected", A.respond(json.dumps(body_tp)))
    st, nonce2 = A.challenge()
    body2 = json.loads(A.valid_body(nonce2))
    n = bytearray(J.b64u_dec(body2["nonce"])); n[10] ^= 0x01
    body_tn = dict(body2, nonce=J.b64u(bytes(n)))
    check_denied("tampered nonce rejected", A.respond(json.dumps(body_tn)))
    rev()

    # 3. unknown kid (generic rejection)
    st, nonce = A.challenge()
    unk = json.dumps({"v": 1, "kid": "no_such_kid_xyz", "nonce": nonce, "proof": J.b64u(b"\x00" * 32)})
    unk_code = A.respond(unk)
    st, nonce_b = A.challenge()
    badproof = json.loads(A.valid_body(nonce_b)); bp = bytearray(J.b64u_dec(badproof["proof"])); bp[0] ^= 1
    badproof_code = A.respond(json.dumps(dict(badproof, proof=J.b64u(bytes(bp)))))
    check_denied("unknown kid rejected", unk_code)
    check("unknown-kid response matches bad-proof response (no oracle)", unk_code == badproof_code,
          f"(unknown={unk_code} badproof={badproof_code})")
    rev()

    # 4. cross-service proof reuse.
    #
    # This probe exists to prove the PROOF is bound to server_name (PROTOCOL §5:
    # server_name_canon is inside the PAE input). Submitting A's kid to B does
    # NOT prove that: B rejects on its per-service allow-list before any MAC is
    # computed, so the check passed for a reason that has nothing to do with the
    # binding — an adapter that dropped server_name from proof_canonical, the
    # exact H1/C10 regression the vectors exist to prevent, still scored a PASS.
    #
    # Use a kid B DOES accept, and a nonce B itself minted, so the allow-list and
    # the nonce binding are both satisfied and server_name is the only thing left
    # that can reject it.
    if args.b_kid and args.b_secret:
        B_real = Svc(args.b_url, args.b_resolve, args.b_kid, args.b_secret, args.b_name)
        st, nonceB = B_real.challenge()
        if not nonceB:
            # A silent skip is indistinguishable from a pass in the summary line.
            check("proof bound to server_name", False,
                  f"(SETUP FAILED: B issued no nonce, status={st} — rate limited? "
                  "raise the knock rate limit for the suite)")
        if nonceB:
            # A proof computed over A's server_name, but presented to B with B's
            # own nonce and a kid B allows. Only the server_name binding can
            # reject this.
            tag, _ = J.build_proof(B_real.secret, args.a_name, args.b_kid, J.b64u_dec(nonceB))
            wrong_sn = json.dumps({"v": 1, "kid": args.b_kid, "nonce": nonceB, "proof": J.b64u(tag)})
            code = B_real.respond(wrong_sn)
            check("proof computed for A's server_name is rejected at B (PAE server_name binding)",
                  code != "204", f"(got {code})")
            # control: the same construction with B's own server_name MUST work,
            # otherwise the probe above proves nothing.
            st, nonceB2 = B_real.challenge()
            ok_code = B_real.respond(B_real.valid_body(nonceB2))
            check("control: correct server_name is accepted at B", ok_code == "204", f"(got {ok_code})")
            # That control knock GRANTED this peer on B. Probe 6 below asserts B
            # is dark for the peer, so the grant has to go or probe 6 fails for a
            # reason that has nothing to do with X-Forwarded-For.
            revoke(args.api, args.api_token, args.b_name,
                   discover_peer_ip(args.api, args.api_token, args.b_name, peer_ip))
    else:
        check("proof bound to server_name", False,
              "(SKIPPED: pass --b-kid/--b-secret; without them this probe is confounded "
              "by B's allow-list and proves nothing)")
    # Per-service allow-list, isolated the same way probe 4 was.
    #
    # The previous shape submitted a body built from A's nonce, which B rejects at
    # NONCE verification — before the allow-list is ever consulted. To actually
    # exercise the allow-list, the request has to be valid in every other respect:
    # B's own nonce, and a proof computed over B's server_name, with A's kid.
    if args.a_kid and args.a_secret:
        st, nonceB3 = B.challenge()
        if not nonceB3:
            check("A's kid is not accepted at B (per-service allow-list)", False,
                  f"(SETUP FAILED: B issued no nonce, status={st})")
        else:
            tag, _ = J.build_proof(J.b64u_dec(args.a_secret), args.b_name, args.a_kid, J.b64u_dec(nonceB3))
            body = json.dumps({"v": 1, "kid": args.a_kid, "nonce": nonceB3, "proof": J.b64u(tag)})
            code = B.respond(body)
            check_denied("A's kid is not accepted at B (per-service allow-list)", code)
    rev()

    # 5. replay
    rev()
    st, nonce = A.challenge()
    body = A.valid_body(nonce)
    first = A.respond(body)
    second = A.respond(body)
    check("replay: first accepted", first == "204", f"(got {first})")
    check_denied("replay: second (same nonce) rejected", second)
    rev()

    # 6. forged X-Forwarded-For cannot inherit another IP's grant (Simple = TCP peer).
    # Use service B: the peer never performs a valid knock on B, so B is naturally
    # dark for the peer regardless of grant-cleanup timing on A.
    victim_ip = "198.51.100.7"
    granted = manual_grant(args.api, args.api_token, args.b_name, victim_ip)   # grant victim on B
    if not granted:
        # Without the victim grant this probe proves nothing: "the spoofed
        # request was denied" is true of a gate that never had anything to
        # inherit. Report it as a failure rather than a silent PASS.
        check("forged XFF/X-Real-IP cannot inherit another IP's grant", False,
              "(SETUP FAILED: no victim grant created — pass a reachable --api and --api-token)")
    else:
        spoof = B.get(headers=[f"X-Forwarded-For: {victim_ip}", f"X-Real-IP: {victim_ip}"])
        check("forged XFF/X-Real-IP cannot inherit another IP's grant", spoof in ("403", "404"), f"(got {spoof})")
    revoke(args.api, args.api_token, args.b_name, victim_ip)
    # XFF isn't consulted downward either: knock-grant the peer on A, bogus XFF still 200
    st, nonce = A.challenge(); A.respond(A.valid_body(nonce))
    lit = A.get(headers=["X-Forwarded-For: 203.0.113.99"])
    check("peer-granted request ignores XFF (still 200)", lit == "200", f"(got {lit})")
    rev()

    # 7. well-known path traversal must not reach the upstream.
    #
    # The protocol prefix is the one path a verifier lets through WITHOUT a
    # grant, so if its view of the path can be made to differ from the proxy's,
    # that carve-out becomes a bypass for every path. This is not hypothetical:
    # the forward-auth adapters forwarded the RAW request URI while the proxy
    # routed on the NORMALIZED one, so "<prefix>/../../index.html" was authorized
    # as a knock endpoint and then served as "/index.html".
    #
    # Payloads MUST normalize to a path the upstream actually serves. The
    # original set all collapsed to "/.well-known/" — which 404s — so the probe
    # passed against a fully bypassable gate.
    trav = [
        # collapse to the site root / a real document
        "/.well-known/jit-access/../../",
        "/.well-known/jit-access/../../index.html",
        "/.well-known/jit-access/../../../../",
        # percent-encoded separators and dot segments
        "/.well-known/jit-access/..%2f..%2f",
        "/.well-known/jit-access/%2e%2e/%2e%2e/",
        "/.well-known/jit-access/./../../",
        # the original shallow set, kept as regression cover
        "/.well-known/jit-access/../",
        "/.well-known/jit-access/respond/../../",
        "/.well-known/jit-access/./challenge/../..",
    ]
    rev()
    codes = [A.get(path=t) for t in trav]
    bad = [f"{p} -> {c}" for p, c in zip(trav, codes) if c == "200"]
    check("path traversal never reaches upstream (no 200)", not bad, f"(reached upstream: {bad})")

    print(f"\nRESULT: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
