# JIT Network Access — Portable Core (L3) Specification

**Status:** normative contract for the reference libraries (`core/lua/`, `core/go/`) and for any adapter that embeds them. Where L1 ([`../docs/PROTOCOL.md`](../docs/PROTOCOL.md)) defines the bytes on the wire, this defines the **programming interfaces** and the **state semantics** behind them. Byte-level constructions are pinned by [`testdata/vectors.json`](testdata/vectors.json).

The guiding split (DESIGN §1.1): **Simple = process-local state, zero external dependencies.** Everything a shared backend (Redis) requires — value signing, AUTH/ACL, namespacing, atomic cross-node claims — is **Hardened** and lives behind the same interfaces so the adapters above are unaware of the backend.

---

## 1. Module surface

Each reference library exposes these modules with identical semantics:

| Module | Responsibility | Pure? |
|---|---|---|
| `pae` | Pre-Authentication Encoding (L1 §5.1) | pure |
| `canon` | `server_name` / `ip` canonicalization (L1 §4) | pure |
| `crypto` | proof build/verify, nonce issue/verify, constant-time compare | pure (key material in, bytes out) |
| `registry` | `TokenRegistry` — kid → {secret, alg, expiry, allowed services} | pure over its input |
| `store` | `GrantStore` + `NonceStore` — the only stateful modules; backend-pluggable | stateful |

`pae`, `canon`, and `crypto` are **pure and fully covered by `vectors.json`** — they are the parts that must match across languages exactly, and the parts a reviewer can verify without a running edge server.

---

## 2. `crypto` — the verification core

Functions (names may be idiomatic per language; semantics are fixed):

```
proof_canonical(server_name, kid, nonce_raw) -> bytes          # PAE(["jitaccess-v1", canon, kid, nonce_raw])
build_proof(secret, server_name, kid, nonce_raw) -> tag(32)
verify_proof(secret, server_name, kid, nonce_raw, tag) -> bool # constant-time

issue_nonce(nonce_key, ts, rand16, server_name, ip, v6_prefix) -> nonce(56)
verify_nonce(nonce_key, nonce, server_name, ip, now, ttl, v6_prefix) -> (ok, rand|nil)  # no single-use here
```

Normative:
- `verify_proof` and the nonce MAC check **MUST** use a constant-time comparison primitive.
- `build_proof`/`verify_proof` **MUST** operate on the exact `kid`/`nonce_raw` bytes handed in — no internal normalization.
- The dummy-key path for unknown `kid` (L1 §6) is the **caller's** responsibility (the equalized-work verifier in the adapter), but `crypto` **MUST** offer a `build_proof` that runs identically for a dummy key so the caller can keep timing flat.
- RNG for `rand16` and for `nonce_key` **MUST** be a CSPRNG and **MUST** fail closed on error (no low-entropy fallback).

---

## 3. `TokenRegistry`

```
lookup(kid) -> { secret|pubkey, alg, expires?, } | nil
allowed_for_service(kid, server_name_canon) -> bool     # per-service allow-list (or wildcard)
```

- Backends: static config (BunkerWeb settings / Authorizer config file). The interface is read-only at request time; mutation happens out of band (admin action → reload/refresh).
- `alg` pins the key type per kid; a mismatch between `alg` and the presented proof type **MUST** be treated as failure (no downgrade, L1 §8).
- `expires` (optional) is enforced **at grant time and on every grant re-check** (§4), not only at enrollment.
- **HARDENED:** secrets returned here come from a KEK-decrypted store; in Simple mode they come from settings/config as-is (documented trade-off, DESIGN §11 R5). The interface is identical.

---

## 4. `GrantStore`

A grant means "this client IP may reach this service until `exp`." Grants invert the ban fail-direction (a forged/stale grant *opens* a service), so the semantics below are stricter than BunkerWeb's ban store even though the local plumbing is shared.

### 4.1 Key schema

```
grant key   = "jit:grant:" || server_name_canon || ":" || ip_canon
bykid index = "jit:grantsbykid:" || kid
spent nonce = "jit:nonce:" || base64url(rand)        # NonceStore, §5

HARDENED (shared backend): all keys are tenant-namespaced -> "jit:{tenant}:grant:..."
```

`server_name_canon` and `ip_canon` are the L1 §4 canonical forms — **always applied**, even in Simple mode, so the schema is uniform and a later switch to a shared backend "just works" and matches across engines.

### 4.2 Value

```
{ v:1, kid, service, ip, exp, binding:"ip"|"ip+cookie", cookie_hash?, issued }

HARDENED (shared backend): add  mac = HMAC/AEAD(grant_sign_key, canonical(value))
```

- **Simple/local backend:** the store is a `lua_shared_dict` (in-process, worker-shared) or an in-process TTL map. It is **process-private — no external party can write it** — so the value carries **no `mac`** and needs none. The grant-injection threat (SECURITY-REVIEW C3) does not exist without a shared writer.
- **HARDENED/shared backend:** the value **MUST** carry `mac` and readers **MUST** verify it before honoring the grant, so a bare `SET jit:grant:… …` by any other Redis client is rejected. Plus Redis AUTH + ACL scoped to `jit:*` + TLS + tenant namespacing.

### 4.3 Operations

```
is_allowed(server_name, ip, [cookie]) -> grant | nil
grant(server_name, ip, kid, ttl, binding, [cookie_hash]) -> ok
revoke(server_name, ip) -> ok
revoke_token(kid) -> count            # sweep every grant for kid via the bykid index
list() -> [grant]                     # admin/API
```

Normative:
- `is_allowed` **MUST** re-check, on every call, that the grant's `kid` is still in the registry and the token's `expires` has not passed — so a `revoke_token` or an expiry evicts within the cache window even if the record's TTL has not elapsed (SECURITY-REVIEW H3). In `ip+cookie` binding it **MUST** also verify the presented cookie against `cookie_hash`.
- `revoke_token(kid)` **MUST** delete every grant carrying that kid (via the bykid index) and return the count (blast radius for the admin).
- **Fail closed:** any backend/store error in `is_allowed` **MUST** return `nil` (deny), never "allow on error." (Local backends cannot network-fail; this rule bites for shared backends.)
- **Local mode:** TTL handles time-expiry; `revoke`/`revoke_token` delete immediately (no propagation window). **HARDENED:** a revoke also writes a short-lived tombstone that the ≤30 s positive cache must honor, so cross-node revocation is prompt.

---

## 5. `NonceStore` (single-use claim)

The nonce itself is stateless and self-authenticating (L1 §3); the store exists **only** to enforce single-use.

```
claim(rand_or_hash, ttl) -> true (first time) | false (already spent)
```

- **Simple/local:** an atomic add into a **dedicated `lua_shared_dict`, isolated from grants and from BunkerWeb's ban dict** — `dict:add(key, true, ttl)` returns false if the key already exists. `add` is atomic across workers, giving check-and-burn with no read-then-delete race and no external dependency. Because `/challenge` stores nothing, this set is bounded by *actual successful-knock volume × NONCE_TTL*, not by challenge volume — it cannot be flooded (SECURITY-REVIEW H5/H2).
- **HARDENED/shared backend:** `SET key 1 NX EX ttl`; a `nil`/error return (backend unreachable) **MUST** be treated as "cannot guarantee single-use" → **fail closed** (reject the knock), never local-only burn (SECURITY-REVIEW DoS-2).
- The claim happens **only after** a fully successful proof verification (verify-then-burn), so a bad proof never consumes a nonce.

---

## 6. Tiering summary

| Interface | Simple (default, no deps) | Hardened (opt-in) |
|---|---|---|
| `GrantStore` backend | `lua_shared_dict` / in-process map | Redis (AUTH/ACL/TLS, namespaced) |
| Grant value integrity | none needed (process-private) | `mac` signed + verified on read |
| `NonceStore` claim | `dict:add` (atomic, local) | `SET NX EX`; fail-closed on error |
| Client IP | TCP peer (`remote_addr`); XFF ignored | trusted-proxy real-IP chain |
| Grant binding | `ip` | `ip+cookie` (opaque grant-id, host-only, `SameSite=Strict`) |
| Secret at rest (registry) | settings/config (documented trade-off) | KEK-encrypted, or asymmetric (no secret) |
| Cross-node revoke | immediate local delete | delete + tombstone honored by cache |

The adapters (`adapters/*`, `authorizer/`) select the backend via config; the reference libraries expose one interface and hide which is in play. **HARDENED behavior is present as stubs from the start** (`-- HARDENED:` / `TODO(hardened)`), so wiring a shared backend later does not touch the adapters.

---

## 7. Fail-closed invariants (apply in every tier)

1. Any error, exception, or ambiguous state on the verification path resolves to **deny**. Adapters wrap their access hook so a thrown error cannot fall through to "allow" (BunkerWeb's chain does the opposite by default — SECURITY-REVIEW C1).
2. A missing/invalid token registry ⇒ deny (never open a service because config failed to load).
3. `is_allowed` returns deny on any store error.
4. Nonce single-use unverifiable ⇒ reject the knock.
5. RNG failure ⇒ reject (no low-entropy nonce/key).

---

## 8. Conformance

The pure modules (`pae`, `canon`, `crypto`) **MUST** reproduce every `vectors.json` entry byte-for-byte. Run the generator's self-check to detect drift:

```bash
python core/testdata/generate_vectors.py --check
```

Each reference library ships a test that loads `vectors.json` and asserts equality (Lua: run under the harness; Go: `go test`). Stateful modules (`store`) are exercised by the functional + security conformance suites in `test/conformance/` against a live stack.
