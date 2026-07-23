# JIT Network Access — Wire Protocol (L1)

**Status:** normative, `v=1` · vendor-neutral (no engine name appears on the wire) · all binary is **base64url without padding**, all HMAC is **HMAC-SHA256**.

This document defines what travels between the **client** (the Chromium extension) and the **verifier** (whatever enforces the gate: the BunkerWeb plugin, a native Caddy module, or the standalone Authorizer behind a forward-auth proxy). A conforming client and a conforming verifier interoperate regardless of engine. Byte-level constructions are pinned by [`../core/testdata/vectors.json`](../core/testdata/vectors.json); the reference implementation that generates them is [`../core/testdata/generate_vectors.py`](../core/testdata/generate_vectors.py).

Key words **MUST**, **SHOULD**, **MAY** are per RFC 2119.

---

## 1. Terminology

| Term | Meaning |
|---|---|
| **service** | A protected origin, identified by its canonical host (`server_name`, §4). |
| **token** | A per-device credential: an opaque `kid` + a 32-byte secret (v1 symmetric; v3 asymmetric). |
| **kid** | Opaque key identifier, sent in the clear, maps server-side to a secret + policy. |
| **knock** | The challenge/response exchange that, on success, creates a grant. |
| **grant** | A short-lived server-side "this client may reach this service" entry, keyed by `(service, client-ip)`, TTL set by the admin. |
| **verifier** | The component that issues challenges, checks proofs, and writes grants. |

All endpoints live under a single base path on the protected origin itself, default `/.well-known/jit-access/`. The client treats it as opaque and configurable; the verifier routes it internally however it likes.

---

## 2. Endpoints

### 2.1 `POST /.well-known/jit-access/enroll` — device enrollment (one-time code)

The **only** way a secret reaches a device. The long-term secret is **never** placed in a QR code or URL (see SECURITY-REVIEW C7/C8). Enrollment is a live TLS exchange of a single-use code for the secret.

Request (over TLS to the real origin):
```
POST /.well-known/jit-access/enroll
Content-Type: application/json

{ "v": 1, "code": "<one-time-code>" }
```

Response on success (`200`):
```
{ "v": 1, "kid": "<opaque kid>", "secret": "<base64url 32 bytes>",
  "alg": "HMAC-SHA256", "policy": { "origins": ["grafana.example.com"] } }
```

Rules:
- The code **MUST** be single-use and short-TTL. The verifier **MUST** mark it consumed atomically and reject (and SHOULD alert on) any second use.
- The client **MUST** import the secret as a non-extractable key and discard the raw bytes (§7).
- `policy.origins` is **advisory** — a hint for which origins to knock at. Authority over which `kid` may open which service lives with the verifier, never the client. The client **MUST** confirm origins with the user (per-origin permission) before auto-knocking (SECURITY-REVIEW Ext-7).
- Any failure returns the generic error response (§6). The endpoint is served **before** the grant check (an enrolling device is by definition not yet granted) and **MUST** be rate-limited.

> **v3 (asymmetric, future):** the client generates a non-extractable keypair and sends only its public key in the enroll request; the response carries no secret. The wire shape is otherwise identical. Enrollment key-type is pinned per `kid`; a verifier **MUST NOT** accept an HMAC proof for a kid enrolled as asymmetric, or vice versa (no downgrade — SECURITY-REVIEW CR-7).

### 2.2 `GET /.well-known/jit-access/challenge` — obtain a nonce

```
GET /.well-known/jit-access/challenge
→ 204 No Content
   X-JIT-Nonce: <base64url nonce, §3>
   X-JIT-TS: <verifier unix seconds>
   Cache-Control: no-store
```

- The verifier **MUST NOT** persist anything at challenge time. The nonce is self-authenticating (§3), so a flood of `/challenge` costs only CPU and has no store to exhaust (SECURITY-REVIEW H5). The endpoint **MUST** be rate-limited.
- `X-JIT-TS` lets the client avoid trusting its own clock; the client **MUST NOT** use its local clock for any part of the proof.
- The verifier **MUST** bind the nonce to the request's canonical `server_name` and the client IP as the verifier determines it (§4, §5).

### 2.3 `POST /.well-known/jit-access/respond` — the knock

```
POST /.well-known/jit-access/respond
Content-Type: application/json

{ "v": 1, "kid": "<kid>", "nonce": "<echoed X-JIT-Nonce>", "proof": "<base64url, §5>" }
```

- There is **no** `step`/timestamp field. Freshness comes entirely from the nonce (a client-supplied time field was removed as a malleable input — SECURITY-REVIEW CR-1/CR-5).
- On success: `204 No Content`, the grant is created (§ verifier writes `(service, ip)` → TTL), and in Hardened `ip+cookie` mode a `Set-Cookie` with an opaque grant-id is added. On failure: the generic error response (§6).
- The verifier **MUST** parse JSON strictly (reject duplicate keys) and use the exact `kid`/`nonce` bytes for both lookup and MAC input (no "normalize for lookup, MAC the raw" split).

---

## 3. Nonce format (stateless, self-authenticating)

The nonce is an opaque 56-byte token the client never interprets:

```
nonce = ts(8) || rand(16) || mac(32)          # 56 bytes; wire = base64url(nonce)

ts   = unix seconds, 8-byte BIG-endian
rand = 16 CSPRNG bytes
mac  = HMAC-SHA256( nonce_key,
                    PAE([ "jitaccess-nonce-v1", ts, rand,
                          server_name_canon, ip_canon ]) )
```

- `nonce_key` is a per-verifier-instance ephemeral key (regenerated on reload; a nonce that outlives a reload merely forces a re-challenge). It is **never** shared with the client.
- `PAE` is Pre-Authentication Encoding (§5.1). `server_name_canon`/`ip_canon` are the canonical forms (§4).
- The domain string `"jitaccess-nonce-v1"` is distinct from the proof's `"jitaccess-v1"` so a nonce MAC and a proof MAC can never coincide.

**Verification** (at `/respond`): split `ts|rand|mac`; recompute `mac` from the *request's* `server_name_canon` and `ip_canon`; constant-time compare; require `0 ≤ now − ts < NONCE_TTL`. This re-derives the `(service, ip)` binding without any stored state. Single-use is enforced separately at claim time (§ core SPEC): the verifier atomically records `rand` (or a hash of the nonce) in a spent-set with TTL = `NONCE_TTL`; a second redemption of the same nonce **MUST** fail.

> Note the two endiannesses, both pinned by vectors: the `ts` *payload* is big-endian (network order for a timestamp); the *length prefixes inside PAE* are little-endian (PASETO convention, §5.1). Implementations must not conflate them.

---

## 4. Canonicalization

Two normative functions, applied identically by every implementation so that MAC inputs and grant keys are byte-identical across engines (the fix for SECURITY-REVIEW H1/C10). Vectors: `canon_server_name`, `canon_ip`.

**`canon_server_name(host)`** →
1. If bracketed IPv6 literal `[..]`, take the inner text. Otherwise strip a trailing `:port` (a hostname contains no `:`).
2. Strip a single trailing `.`.
3. Lowercase (ASCII).
4. IDN is assumed already an **A-label** (`xn--…`), as browsers send in the `Host` header; implementations **MUST NOT** Unicode-decode. (This avoids shipping IDNA into every adapter while keeping both ends in agreement.)

**`canon_ip(addr, v6_prefix=128, v4_prefix=32)`** →
1. Parse to bytes. Reject ambiguous forms (e.g. leading-zero IPv4 octets) — a canonical input is a parsed address, not a string to re-interpret.
2. Normalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to its IPv4 form.
3. Apply the prefix mask (defaults = exact host).
4. Render one canonical text form: dotted-decimal (v4) / RFC 5952 compressed lowercase (v6).

The default `v6_prefix` is **128** (Simple). `v6_prefix=64` is a Hardened option and widens a grant to a whole /64 — see DESIGN §4.4.

---

## 5. Proof

```
canonical = PAE([ "jitaccess-v1", server_name_canon, kid, nonce_raw ])
proof     = HMAC-SHA256( secret, canonical )      # full 32-byte tag, base64url

  server_name_canon : §4, ASCII bytes
  kid               : exact UTF-8 bytes as sent (same bytes used for lookup)
  nonce_raw         : base64url-decode(nonce) — the 56 raw bytes
  secret            : the device's 32-byte token secret
```

No truncation. The verifier recomputes `canonical` from the request's canonical `server_name`, the looked-up secret for `kid`, and the decoded `nonce`, then constant-time-compares (§6).

### 5.1 PAE — Pre-Authentication Encoding (PASETO-compatible)

```
LE64(n)   = 8-byte little-endian of n, with the top bit of the last byte cleared
PAE(parts) = LE64(count(parts)) || for each p:  LE64(len(p)) || p
```

PAE makes the field list injective: no two distinct `(count, fields)` serialize alike, so `("aa","bb")` and `("aab","b")` — and, crucially, two different `(server_name, kid, nonce)` triples — cannot collide inside the MAC. Vectors: `pae` (includes the classic collision pair as a non-collision witness).

---

## 6. Failure semantics (no oracle)

Every rejection at `/challenge`, `/respond`, and `/enroll` — unknown `kid`, wrong service, bad proof, expired/spent/forged nonce, unknown code — **MUST** return an **identical generic response** and **MUST NOT** distinguish the reason via status, body, headers, timing, or side effect. Concretely:

- Default `interstitial` mode: `403` with a fixed HTML body and the marker header `X-JIT-Access: challenge; v=1`.
- `stealth` mode (Hardened): the platform's generic `404`, no marker, endpoints indistinguishable from "not found."
- The verifier **MUST** perform equal work on every path: always decode the proof and gate on length `== 32`, always compute exactly one HMAC (against a fixed dummy key if the `kid` is unknown), always run the constant-time compare, then branch to the generic response last. This closes the kid-enumeration timing oracle (SECURITY-REVIEW CR-4).
- Constant-time comparison **MUST** be a real constant-time primitive (e.g. `CRYPTO_memcmp`), never a language `==`.
- The nonce is burned **only on a fully successful** proof (verify-then-burn), so a bad proof does not consume a victim's in-flight nonce.

The marker header (`interstitial` mode only) is the extension's fallback trigger; the client **MUST** ignore it on any origin whose *final response origin* is not one the user enrolled (§7).

---

## 7. Client requirements (normative summary)

The full client design is DESIGN §7; the load-bearing wire-facing rules:

- Auto-knock **only** on top-level, main-frame, user-initiated navigations (`frameId==0`), never on subframes/`window.open`/redirect-only chains (confused-deputy fix, SECURITY-REVIEW C5).
- The service worker derives `server_name` from the **authenticated tab URL**, fetches its own nonce, and **MUST NOT** return a proof or signature across any message boundary; `externally_connectable` is closed (`{ids:[],matches:[]}`) (signing-oracle fix, C6).
- Origin matching is **exact** (scheme+host+port, lowercased, IDNA-normalized) with a public-suffix guard; never substring or implicit-subdomain.
- All enrolled origins and all knock fetches are **HTTPS-only**; `http://` enrollment is refused.
- The secret is a non-extractable key; `storage.session` for ephemeral state, `storage.local` for non-secret config, **never** `storage.sync`.

---

## 8. Versioning

The wire `v` field and the in-MAC domain strings (`jitaccess-v1`, `jitaccess-nonce-v1`) bind the version. A verifier **MUST** pin key-type per `kid` and **MUST NOT** accept a deprecated version's proof for a kid once migrated (no parallel-acceptance downgrade). New versions bump the domain string so cross-version MAC confusion is impossible.

---

## 9. Conformance

An implementation is conformant when it reproduces every entry in `vectors.json` byte-for-byte **and** passes the security conformance profile (DESIGN §9 M2.5): forged-`X-Forwarded-*` rejection, direct-verifier-exposure refusal, fail-closed on verifier/backend error, cross-engine grant-key equality, nonce single-use across instances, well-known routing traversal resistance, and malformed-`/respond` never reaching upstream. Functional pass alone is **not** sufficient (SECURITY-REVIEW Port-7).
