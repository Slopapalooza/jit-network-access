# JIT Network Access — Design Plan

**Status:** Draft v1.2 — 2026-07-23 · hardened after adversarial review · two deployment profiles (Simple = zero external deps, Hardened = opt-in)
**Targets:** Engine-agnostic protocol + portable core · **BunkerWeb 1.6.x** as the flagship enforcement adapter (verified against v1.6.13 source) · Chromium **Manifest V3** extension

> ⚠️ **Security gate — consult the project's internal adversarial security review before building.** A six-lens adversarial review found ~10 Critical issues, several exploitable as designed, whose through-line is that the system as originally drafted **fails open more often than closed**. The blocking fixes are consolidated in **§11** and folded into the sections below (look for **[SEC]** markers). Do not start M1 until §11's gate items are reflected in the spec.

---

## 1. Goal

Services behind BunkerWeb are **dark by default**: an unauthorized visitor gets a deny page (or, in stealth mode, a generic 404). A Chromium extension holds a per-device secret enrolled ahead of time. When the browser navigates to a protected site, the extension silently answers a time-based challenge ("knock"). On a valid answer, BunkerWeb creates a **temporary allow entry** for that client and that service (TTL configured by the admin: 1 h, 2 h, 24 h, …). The entry expires automatically; the next visit re-knocks transparently.

This is effectively **Single Packet Authorization (fwknop-style) re-imagined for HTTPS + a browser**.

**Portability is a first-class goal.** The wire protocol, the token/grant model, and the verification core are engine-agnostic; BunkerWeb is the *first enforcement adapter*, not the foundation. The same extension and the same enrolled tokens must work behind plain NGINX/OpenResty, Traefik, Caddy, Envoy, HAProxy, or any proxy that supports a forward-auth/ext-authz subrequest — via a native module where possible, or a small standalone **Authorizer** service. See §3.1.

**Simplicity is a first-class goal too.** The default experience targets a **home user self-hosting**: install/enable the plugin (or module) on whatever edge server they run, switch it on for the site(s) they want protected, install the Chromium extension, enroll once. **No external dependencies** — no Redis, no separate database, no KMS. Deeper hardening (clustering, stealth mode, device-bound cookies, encrypted-at-rest secrets, asymmetric keys) is available but strictly opt-in for advanced users. See §1.1.

Non-goals for v1: stream (TCP/UDP) mode, non-Chromium browsers, interactive human login (this is device authorization, not user SSO — it composes with authbasic/Authentik/etc. which keep running behind it).

### 1.1 Deployment profiles: Simple (default) vs Hardened

The design has **two profiles**. Everything that keeps the gate *fundamentally sound* is baseline and on in both. Everything that only matters once you add a shared component, face a harsher threat model, or run multiple nodes is opt-in. A Simple deployment pulls in **zero external services**.

| Concern | **Simple** (default, home/self-host) | **Hardened** (opt-in, advanced) |
|---|---|---|
| Grant + nonce state | Process-local: `lua_shared_dict` (BunkerWeb/OpenResty) or in-process TTL map (Authorizer/Caddy module) | Redis (or shared backend) **only if** >1 enforcement node must share grants |
| External dependencies | **None** | Redis w/ AUTH+ACL+TLS; optionally KMS/KEK |
| Client IP source | The TCP peer (`remote_addr`); **XFF not trusted** — safe by default when the edge server faces the internet directly | Trusted-proxy real-IP config (explicit CIDRs) when behind a CDN/LB |
| Grant binding | IP-only (fine for a single user/household) | `ip+cookie` device-bound; shorter TTLs; `/64`-aware IPv6 rules |
| Failure mode | `interstitial` (clear UX) | `stealth` (generic 404, gate invisible) |
| Secret at rest | Symmetric secret stored like any other edge-server secret (protect it as you protect your TLS keys) | KEK-encrypted at rest, or **v3 asymmetric** (server stores only public keys — nothing secret at rest) |
| Setup steps | enable → configure site(s) → install & enroll extension | + Redis wiring, real-IP tuning, cookie/stealth/KEK config |

**Crucially, the security review's mandatory fixes are almost all baseline and require no external service** — they are code/config properties, not infrastructure:

- **Fail-closed** (plugin self-`pcall`, conf-layer default-deny) — always on. A home user's dark service must never fail open.
- **Atomic single-use nonce** — achieved locally with a stateless signed nonce + an atomic "spent" set (`dict:add`, which fails if the key already exists), so there is no cross-node race to lose and no nonce store to flood (§6.3). Redis is not needed for correctness here.
- **Locked-down extension** (top-level-only knocks, closed `externally_connectable`, worker-derived origin, exact-origin matching) — always on; it's in the client.
- **Canonical PAE proof + normative key canonicalization** — always on; spec correctness.
- **Not trusting XFF** — the *safe* default in Simple mode is `USE_REAL_IP=no` (trust the peer). The XFF-spoofing risk from the review only appears when you deliberately enable real-IP behind a proxy, which is a Hardened step with explicit trusted-CIDR config.

The Redis-specific findings from the review (unsigned grants injectable via shared Redis, cross-node nonce replay, fail-open on Redis error) **only exist once you add Redis** — so their fixes (signed grant values, atomic `GETDEL`, fail-closed-on-backend-error, AUTH/ACL/TLS, namespacing) are **Hardened-tier requirements**, not Simple-tier. Going local-by-default doesn't weaken the Simple profile; it removes those attack surfaces entirely.

---

## 2. Background: what BunkerWeb gives us (research summary)

Facts verified against the v1.6.13 source that shape this design:

- **Everything in BunkerWeb is a plugin.** External plugins are structurally identical to core ones: a folder with `plugin.json`, a Lua file named `<id>.lua` hooking NGINX phases (`access`, `set`, `init`, …), optional Python `jobs/`, optional `ui/` pages for the web UI, installed via `EXTERNAL_PLUGIN_URLS` or by dropping the folder into the scheduler's `/data/plugins` volume.
- **The access chain** (`src/common/confs/server-http/access-lua.conf`) runs plugins in order. A plugin returning `status = ngx.OK` short-circuits the rest of the chain and lets the request through (this is how **whitelist** skips everything); returning a deny status stops the request; returning no status lets the chain continue (how **greylist** admits a client but still subjects it to the WAF and every other check).
- **Temporary bans are pure runtime state — no config reload.** `utils.add_ban()` writes `bans_ip_<ip>` / `bans_service_<svc>_ip_<ip>` JSON values into the shm **datastore** with a native TTL and mirrors them to **Redis** (`SET … EX`) when `USE_REDIS=yes`. `utils.is_banned()` checks locally first, falls back to Redis, and caches the Redis answer locally for ≤30 s. **Our temporary allow entries mirror this mechanism exactly** — it is proven, cluster-safe, and TTL-expiry is native.
- **Plugins can extend the instance's internal API.** `api.lua`'s dispatcher falls through to any plugin exposing an `api()` method, on the same vhost that already serves `/ban`, `/unban`, `/bans` (guarded by `API_WHITELIST_IP` / `API_TOKEN`). We get `/jit/grants`, `/jit/revoke`, etc. for free — no core patches.
- **Multisite:** one NGINX `server` block per service; `context: "multisite"` settings resolve per-service automatically in `self.variables`; per-site state is conventionally keyed by `server_name`. This is the natural axis for per-service granularity.
- **Storage tiers available to Lua:** `datastore` (shm, instance-wide, TTL), `cachestore` (mlcache: worker LRU → shm → optional Redis), `clusterstore` (raw Redis). **Our default (Simple) uses `datastore` (shm) only — no external dependency;** grants fall back to `clusterstore` (Redis) *only* when the operator runs a cluster. Nonces are stateless-signed (§6.3), so they need no store at all at issue time.
- **The antibot plugin** already demonstrates a plugin serving its own challenge endpoints/pages from the access phase — precedent for our challenge/knock URIs.

And the Chromium MV3 constraints that shape the client:

- **`webRequest` is observational only** (blocking requires enterprise force-install). The extension can *see* a response's status/headers on a main-frame navigation but cannot hold or mutate the request in flight.
- **`declarativeNetRequest` header values are static strings** — a per-request signature is impossible; a rotating header is possible (session rules replaced by a `chrome.alarms` tick, min period 30 s) but is a bearer token, not a signature.
- Therefore the primary flow must be a **proactive `fetch()` knock** to a well-known endpoint, triggered by `webNavigation.onBeforeNavigate`, with an **interstitial-detection fallback** for cold starts and expired grants. The grant lives server-side (allow entry keyed by client IP, optionally bound to a cookie), so all subsequent traffic — subresources, XHR, WebSockets — passes with zero extension involvement.
- **Secrets:** import the enrolled secret as a **non-extractable WebCrypto HMAC key** stored in IndexedDB; after import no JavaScript (even compromised extension code) can read key bytes — only request HMACs. Raw secret is discarded post-enrollment. Never `storage.sync`.

---

## 3. System overview

```
┌────────────────────────┐         ┌───────────────────────────────────────────┐
│  Chromium browser      │         │  BunkerWeb instance(s)                    │
│                        │         │                                           │
│  ┌──────────────────┐  │  (1)    │  ┌─────────────────────────────────────┐  │
│  │ JIT extension    │──┼─────────┼─▶│ jitaccess plugin (Lua, access phase)│  │
│  │  service worker  │  │ knock   │  │  · challenge/respond endpoints      │  │
│  │  non-extractable │◀─┼─────────┼──│  · grant check (datastore/Redis)    │  │
│  │  HMAC key (IDB)  │  │ (2)     │  │  · deny/interstitial when no grant  │  │
│  └──────────────────┘  │ grant   │  └─────────────────────────────────────┘  │
│           │            │         │        │ datastore (shm, TTL)             │
│  (3) normal browsing ──┼─────────┼─▶      │ clusterstore (Redis, TTL) ◀──────┼── other
│      passes for TTL    │         │        ▼                                  │   instances
└────────────────────────┘         │  upstream service (app1.example.com)      │
                                   └───────────────────────────────────────────┘
         Scheduler: token-registry job (parses settings → DB/cache)
         Web UI:    plugin page — token CRUD, QR enrollment, active grants, audit
```

### 3.1 Layered architecture: portable core, pluggable enforcement

Everything engine-specific is quarantined in the bottom layer. The layers, top to bottom:

| Layer | Contents | Engine-specific? |
|---|---|---|
| **L1 — Protocol** (`docs/PROTOCOL.md`) | Wire format: `/.well-known/jit-access/*` endpoints, enrollment payload, challenge/response HMAC scheme, marker header, error semantics. Versioned (`v=1`), vendor-neutral naming (no "bw" anywhere on the wire). | No |
| **L2 — Client** (`extension/`) | The Chromium extension. Speaks only L1; has no idea what serves the origin. Works unmodified against every adapter. | No |
| **L3 — Core** (`core/`) | The verification + policy logic as a portable specification and reference libraries: token registry model (kid → secret, label, expiry), per-service kid allow-lists, nonce mint/burn, proof verification, grant CRUD with TTL. Defines two abstract interfaces: **GrantStore** (get/set/delete with TTL) and **TokenRegistry** (static config, file, or DB backed). **The default GrantStore backend is process-local with zero external dependencies** — a `lua_shared_dict` in BunkerWeb/OpenResty, an in-process TTL map in the Go Authorizer; **Redis is one optional backend** selected only for multi-node clustering (§1.1). Reference implementations: **Lua** (`core/lua/`, `resty.*`) and **Go** (`core/go/`), both conformance-tested against a shared vector suite (`core/testdata/vectors.json`). | No |
| **L4 — Enforcement adapters** (`adapters/`) | The thin engine-specific shims that (a) route L1 endpoints to the core, (b) ask the core "is (service, client) granted?" on every request, (c) deny/interstitial when not. | Yes — by design the *only* layer that is |

**Adapter catalog:**

| Adapter | Mechanism | Status |
|---|---|---|
| **BunkerWeb** (`adapters/bunkerweb/`) | Native plugin (this doc §5). Embeds `core/lua`. **Simple mode uses `lua_shared_dict` only — no Redis.** Deep integration: `is_jit_allowed` variable for CRS, internal API `api()` endpoints, web UI page, bwcli. Redis used only if the operator already runs a BunkerWeb cluster. | v1 flagship |
| **Standalone Authorizer** (`authorizer/`) | A **single static Go binary** embedding `core/go`. Two faces: (1) serves the L1 protocol endpoints; (2) serves a **forward-auth endpoint** `GET /authz` that answers 204 (granted) or 403/404 + interstitial (not). Plus an admin REST API and minimal UI. **State is in-process by default (no Redis)**; a config file or env holds the token registry. Redis is opt-in for running multiple replicas. Deployed as a co-located systemd unit / sidecar container — no external datastore for a Simple setup. | v1.x — makes every non-embedded proxy below work |
| **Caddy** (`adapters/caddy/`) | Preferred: a **native Caddy module** (compiled in via `xcaddy`) embedding `core/go` — "enable the module", no separate process. Fallback: `forward_auth` → Authorizer. | v1.x |
| Plain NGINX | `auth_request /authz` → Authorizer; `location /.well-known/jit-access/ { proxy_pass authorizer; }` | config recipe |
| OpenResty | Either the Authorizer recipe, or embed `core/lua` directly in `access_by_lua` for subrequest-free checks | config recipe / thin shim |
| Traefik | `forwardAuth` middleware → Authorizer | config recipe |
| Envoy | `ext_authz` HTTP filter → Authorizer | config recipe |
| HAProxy | SPOE agent (later; or route via an Authorizer-fronted backend) | backlog |

Design rules that keep it portable:

1. **The extension never sees the engine.** All engine variance is behind the L1 protocol served on the protected origin itself (adapters route `/.well-known/jit-access/*` wherever they like internally).
2. **State is process-local by default; a shared backend is opt-in for clustering.** The GrantStore/NonceStore interface hides the backend. A single BunkerWeb instance or a single Authorizer keeps grants and spent-nonces in `lua_shared_dict` / an in-process TTL map — **no Redis, no external database.** Redis (or any shared backend) is selected only when more than one enforcement node must share grants; the canonical key schema and the *extra* hardening it then requires (signed values, AUTH/ACL/TLS, tenant namespacing) live in the L3 spec and apply **only to shared backends** (§11 tiering).
3. **Policy lives in L3, expression of policy lives in L4.** BunkerWeb expresses "which kids may open this service" as multisite settings; the Authorizer expresses it as a config file; both feed the same TokenRegistry interface. No adapter invents semantics.
4. **Conformance tests, not documentation, define compatibility.** An adapter is "supported" when it passes both the functional and the **security** conformance suites (§9 M2.5).

Components to build:

| # | Component | Tech |
|---|-----------|------|
| 1 | Protocol spec (L1, §6) | HTTPS + JSON, HMAC-SHA256 |
| 2 | Portable core + conformance vectors (L3) | Lua lib + Go lib, shared test vectors |
| 3 | `jitaccess` BunkerWeb plugin (L4, §5) | Lua (access/init/set phases, `api()` extension), `plugin.json`, Python job(s), `ui/` page |
| 4 | Standalone Authorizer (L4) | Go daemon: protocol endpoints, forward-auth `/authz`, admin API/UI |
| 5 | Chromium extension "JIT Access" (L2, §7) | MV3: service worker, popup, options page |

---

## 4. Identity, tokens, and granularity model

### 4.1 Token = per-device secret with a key ID

Each enrolled browser profile ("device") gets one **token**:

- `kid` — opaque 128-bit random ID, base64url. Sent on the wire; maps to the secret and policy server-side only. Never derived from user identity (privacy in logs / to passive observers).
- `secret` — 32 random bytes (base64). Used as an HMAC-SHA256 key on both ends.
- `label` — human-readable ("Jamie – work laptop"), server-side only.
- Optional `expires` — absolute expiry of the token itself (contractor use case).

Multiple tokens per human are expected (one per device) → per-device revocation without resetting the user.

### 4.2 Granularity: which token opens which service

Two-layer model, mapping cleanly onto BunkerWeb's global/multisite split:

1. **Global token registry** (global-context settings, or UI-managed): defines the tokens (kid, secret, label, expiry).
2. **Per-service allow list** (multisite-context setting `JIT_ACCESS_TOKENS`): a space-separated list of `kid`s (or `*` = any registered token) permitted to unlock *that* service.

So on a BunkerWeb instance serving `grafana.example.com`, `wiki.example.com`, and `public-blog.example.com`:

```
grafana.example.com_USE_JIT_ACCESS=yes
grafana.example.com_JIT_ACCESS_TOKENS=kid_A kid_B          # only admins
wiki.example.com_USE_JIT_ACCESS=yes
wiki.example.com_JIT_ACCESS_TOKENS=*                        # any enrolled device
public-blog.example.com_USE_JIT_ACCESS=no                   # stays public
```

A valid knock with `kid_C` at `grafana.example.com` fails **exactly like an invalid knock** (no oracle revealing "right token, wrong service"). Grants are scoped per `(service, client)` — unlocking the wiki never unlocks Grafana, mirroring the ban system's `ban_scope: "service"`.

### 4.3 What a grant admits

Default: a grant **admits the client into the normal security pipeline** — the JIT plugin returns success *without* `ngx.OK`, so blacklist, ModSecurity/CRS, antibot, authbasic, rate limiting all still run (greylist semantics: "may pass the gate, still gets screened"). A setting `JIT_ACCESS_SKIP_CHECKS=yes` opts into whitelist semantics (`ngx.OK` short-circuit) for admins who want it. Secure default: keep the checks.

### 4.4 Grant binding: IP, plus cookie

The grant key is the **client IP** per service (`jit:grant:<service>:<ip>`) — it covers the whole browser session, other tabs, WebSockets, and non-extension subresource fetches with zero client work.

**[SEC] The IP must come from the trusted real-IP chain (§11 R2).** BunkerWeb's default `REAL_IP_FROM` trusts all of RFC1918 with recursive XFF, so behind Docker/K8s/a mesh an attacker's `X-Forwarded-For` becomes the grant key — send `X-Forwarded-For: <a_granted_ip>` and inherit a live grant with no token (SECURITY-REVIEW C2). Hardened real-IP (explicit trusted CIDRs = the exact front-door hops, right-most-untrusted XFF, never a raw client header) is a **hard prerequisite**; a harness self-test asserts a forged XFF cannot move the grant key.

Known trade-offs of IP binding, and the mitigations:

- **Shared egress / CGNAT:** everyone behind the same NAT inherits the *admission* (not credentials — inner auth still applies) for the TTL. Mitigation: **cookie binding** (`JIT_ACCESS_BINDING=ip|ip+cookie`), which is the **default for `SKIP_CHECKS=yes` / no-downstream-auth services** (SECURITY-REVIEW C5/H11). **[SEC §11 R3]** the cookie is an **opaque, high-entropy server-side grant id** (not a stateless signed claims token), `HttpOnly; Secure; SameSite=Strict`, **host-only (no `Domain`)**, path-scoped; its hash lives in the grant record so revoking the grant kills the cookie instantly and no shared cluster signing key is needed. `SameSite=Strict` (not `Lax`) is required — `Lax` sends the cookie on cross-site top-level GET navigations, letting a malicious page drive the victim's browser through the gate (H11).
- **Roaming / IP change mid-grant:** grant silently stops matching → extension's interstitial fallback re-knocks. Self-healing.
- IPv6 privacy-extension churn: default `JIT_ACCESS_IPV6_PREFIX=128`. **[SEC §11 R3]** `=64` grants an **entire /64** (a whole LAN segment / shared-subnet tenants — H10); if set it requires `ip+cookie` and a short TTL. Prefer solving churn client-side (the extension re-knocks on IP change) over widening the server grant.

---

## 5. The BunkerWeb plugin: `jitaccess`

### 5.1 Repository layout (monorepo)

```
jit-network-access/
├── docs/
│   └── PROTOCOL.md                  # L1: wire protocol, normative, versioned
├── core/                            # L3: portable verification/policy core
│   ├── SPEC.md                      # interfaces: GrantStore, TokenRegistry; Redis key schema
│   ├── testdata/vectors.json        # shared conformance vectors (proofs, canonical strings)
│   ├── lua/                         # resty-based reference lib (BunkerWeb/OpenResty adapters)
│   │   ├── crypto.lua               # HMAC verify (resty.openssl.hmac), constant-time compare
│   │   ├── registry.lua             # token registry parsing/lookup
│   │   └── store.lua                # grant/nonce CRUD (pluggable backends)
│   └── go/                          # Go reference lib (Authorizer)
├── adapters/
│   ├── bunkerweb/                   # L4 flagship: the BunkerWeb plugin (zip target for EXTERNAL_PLUGIN_URLS)
│   │   └── jitaccess/
│   │       ├── plugin.json
│   │       ├── jitaccess.lua        # phases: init, set, access, header, log + api(); embeds core/lua
│   │       ├── confs/server-http/jitaccess.conf   # declares set $is_jit_allowed 'no'; etc.
│   │       ├── jobs/jitaccess-registry.py         # validates token settings → cached registry per service
│   │       ├── bwcli/               # bwcli jitaccess grants|revoke|token new
│   │       └── ui/                  # template.html + actions.py (token CRUD, QR, grants, audit)
│   ├── nginx/                       # auth_request recipe → Authorizer
│   ├── traefik/                     # forwardAuth recipe
│   ├── caddy/                       # forward_auth recipe
│   └── envoy/                       # ext_authz recipe
├── authorizer/                      # L4: standalone Go daemon (protocol + /authz + admin API/UI)
├── extension/                       # L2: Chromium MV3 extension (§7)
└── test/
    ├── conformance/                 # black-box protocol suite (scripted knock client)
    └── harness/                     # docker-compose: bunkerweb stack, traefik+authorizer stack, redis, dummy upstreams
```

The BunkerWeb plugin's build step vendors `core/lua` into the plugin folder (BunkerWeb plugins are self-contained archives; `require "jitaccess.core.crypto"` resolves inside the plugin directory).

### 5.2 `plugin.json` settings

| Setting | Context | Default | Purpose |
|---|---|---|---|
| `USE_JIT_ACCESS` | multisite | `no` | Enable JIT gating for the service |
| `JIT_ACCESS_TOKENS` | multisite | `` | Space-separated kids allowed for this service, or `*` |
| `JIT_ACCESS_GRANT_TIME` | multisite | `3600` | Grant TTL seconds (1 h; admin sets 7200, 86400, …) |
| `JIT_ACCESS_BINDING` | multisite | `ip` | `ip` or `ip+cookie` |
| `JIT_ACCESS_SKIP_CHECKS` | multisite | `no` | Grant short-circuits remaining security plugins (whitelist semantics) |
| `JIT_ACCESS_FAILURE_MODE` | multisite | `interstitial` | `interstitial` (marker page, best UX) or `stealth` (generic 404, fwknop-style invisibility) |
| `JIT_ACCESS_URI_PREFIX` | multisite | `/.well-known/jit-access` | Base path for challenge/respond endpoints |
| `JIT_ACCESS_TOKEN` (`multiple` group) | global | `` | Token registry entries: `kid:base64secret:label[:expiry]` — `JIT_ACCESS_TOKEN_1`, `_2`, … `type: password` |
| `JIT_ACCESS_TIME_STEP` | global | `30` | TOTP-style step seconds |
| `JIT_ACCESS_TIME_WINDOW` | global | `1` | ± steps accepted (clock skew) |
| `JIT_ACCESS_NONCE_TTL` | global | `60` | Challenge nonce validity seconds |
| `JIT_ACCESS_RATELIMIT` | global | `10r/m` | Knock endpoint rate limit per source IP |
| `JIT_ACCESS_IPV6_PREFIX` | global | `128` | Grant granularity for IPv6 clients |

**[SEC] Secret storage (§11 R5).** `type: password` is a UI mask only — the plaintext symmetric secret is recoverable from the settings DB/backups (SECURITY-REVIEW C9). **Simple tier:** this is an accepted, documented trade-off — the secret is protected exactly like the other secrets the edge server already holds (TLS private keys, API tokens); a home user's threat model is "protect the box and its backups." **Hardened tier:** encrypt secrets at rest under an out-of-band KEK (env/KMS), lock the registry-cache-file perms to the worker UID. **v3 asymmetric enrollment** (server stores only public keys) removes server-side secret storage entirely — no KEK needed — and is the recommended path for anyone who finds the symmetric trade-off unacceptable. Note this is about *storage*; the *transit* fix (one-time code, never the secret in a QR) is baseline in both tiers.

### 5.3 Lua phase logic

**`init`** — parse `JIT_ACCESS_TOKEN_*` via `get_multiple_variables`, build `{kid → {secret, label, expiry}}`, store in `internalstore` as `plugin_jitaccess_registry`. Parse per-service allowed-kid lists into `plugin_jitaccess_tokens_<server_name>`.

**`set`** — default `ngx.var.is_jit_allowed = "no"` (declared in `confs/server-http/jitaccess.conf`), consult grant cache so downstream conf/ModSecurity can see the flag early (mirrors whitelist's `is_whitelisted` pattern).

**[SEC] Fail-closed wrapper (§11 R1).** BunkerWeb's access chain fails **open** on a plugin error — it `pcall`-wraps `access()`, logs-and-continues on a thrown error, and ends the loop with `return true` (request proceeds upstream). Verified against v1.6.13 source (SECURITY-REVIEW C1). Therefore the *entire* `access()` body is wrapped in the plugin's own `pcall`; on **any** internal error it returns an explicit deny (`{ret=true, status=deny}`), never throws. Independently, `is_jit_allowed` is promoted from a CRS hint to an **actual conf-layer enforcement gate** on protected locations (default `no` → deny) so that a plugin that fails to *load* still fails closed. Harness tests assert "corrupt the registry / delete the plugin file / send malformed `/respond` → must deny, never 200".

**`access`** — the core, in order (all wrapped per above):

1. If `USE_JIT_ACCESS ≠ yes` → `ret(true, "disabled")` (chain continues).
2. **Protocol endpoints** (URI under `JIT_ACCESS_URI_PREFIX`) — handled *before* the grant check, since knockers are by definition not yet granted:
   - `GET  <prefix>/challenge` → issue a **stateless signed nonce**: `nonce = ts || rand16 || HMAC(server_nonce_key, ts || rand16 || server || ip)` (32-byte rand via `resty.openssl.rand`, **fail closed if `RAND_bytes` errors**). **[SEC §11 R4]** because the nonce is self-authenticating, `/challenge` **writes nothing** — an unauthenticated flood costs only CPU (rate-limited), and there is no nonce store to exhaust or to LRU-evict live grants/bans from (H5 dissolved). `server_nonce_key` is a per-instance ephemeral key (regenerated on reload; a nonce outliving a reload just forces a re-challenge). Single-use is enforced at burn time, not by storing every issued nonce.
   - `POST <prefix>/respond` → validate (§6.3). Success: write signed grant (§5.4), return `204` (+ `Set-Cookie` in `ip+cookie` mode). Failure: **generic 404 after equalized constant-time work**. **[SEC §11 R1]** knock failures/denies are **excluded from badbehavior accounting** — feeding them in lets a cold-start burst or a hostile `<img src=dark-origin>` ban a legitimate/shared IP for 24 h instance-wide (H6); brute-force detection is a **separate JIT-owned counter scoped to the knock endpoints only**.
3. **Grant check** — `store.is_allowed(ip, server_name)`: **[SEC §11]** `ip` is the local peer in Simple mode (trusted real-IP chain only when real-IP is deliberately enabled — R2); the grant's `kid` is re-checked against the current registry + token expiry so a revoked token stops admitting promptly (R3, H3). Simple/local: read the `lua_shared_dict` — a process-private store no external party can write, so no value-signing is needed. Hardened/shared-backend: the grant value's **signature is verified** (an unsigned Redis write by a bare client is rejected — C3), reads use an atomic `EVAL` GET+TTL cached locally ≤30 s (grants only, never nonces), and **any backend error → fail closed (deny)**. In `ip+cookie` mode also verify the opaque grant-id cookie against `cookie_hash`.
4. **Allowed** → set `ngx.var.is_jit_allowed = "yes"`, `set_metric("counters", "jit_passed", 1)`; return `ret(true, "jit grant valid")` — or with `ngx.OK` when `JIT_ACCESS_SKIP_CHECKS=yes`.
5. **Not allowed** →
   - `interstitial` mode: serve a minimal branded HTML page, status `403`, with marker header `X-JIT-Access: challenge; v=1` (the extension's detection hook; humans see "This service requires device authorization").
   - `stealth` mode: return `404` with a body indistinguishable from the platform's generic 404. No marker. (Extension relies purely on its enrolled-origins list + proactive knock.)

**`header`** — strip/attach nothing on granted traffic; ensure interstitial responses carry `Cache-Control: no-store`.

**`log`** — metrics (`jit_denied`, `jit_granted`, `jit_knock_fail`) via `self:set_metric`, which the UI page surfaces.

**`api()`** — management endpoints on the already-authenticated internal API vhost (fans out through the 1.6 FastAPI control plane exactly like `/bans`):

- `GET  /jitaccess/grants` — list active grants (key, service, ip, ttl, kid).
- `POST /jitaccess/revoke` — `{ip, service?}` delete grant(s) (mirrors `/unban`).
- `POST /jitaccess/revoke-token` — **[SEC §11 R3]** `{kid}` atomically deletes the registry entry **and** sweeps every live grant with that `kid` (via the `jit:grantsbykid:<kid>` reverse index), returning a count so the admin sees the blast radius. Without this, "revoke a lost device" leaves up to `GRANT_TIME` (≤24 h) of continued access (H3).
- `POST /jitaccess/grant` — manual grant `{ip, service, ttl}` (break-glass, admin tooling).

### 5.4 Grant storage (local by default; shared backend opt-in)

**[SEC] Grants invert the ban fail-direction (§11 R3).** A forged/stale ban costs a block (fail-safe); a forged/stale grant opens a dark service (fail-dangerous). The TTL/mirroring plumbing is borrowed from bans, hardened for the inverted risk.

- **Simple/local (default, no Redis):** grants live in a `lua_shared_dict` (BunkerWeb/OpenResty) or an in-process TTL map (Authorizer/Caddy module). The store is **process-private — no external party can write it**, so the grant-injection threat (C3) does not exist and values need no signature. Native TTL handles *time* expiry.
- Key: `jit:grant:<server_name_canon>:<ip_canon>` — the **canonical L3 schema**. **[SEC §11 R6]** both components use the one normative canonicalization (lowercase punycode A-label, no port/trailing-dot; IP parsed to bytes, prefix-masked, RFC 5952 rendering) with **shared test vectors**, so any two adapters compute *byte-identical* keys — otherwise cross-adapter grant sharing silently mismatches or over-matches (C10). This matters only when a shared backend is in play, but the canonicalization is always applied so the schema is uniform.
- Value: JSON `{v, kid, label, date, ip, service, binding, cookie_hash?}`. **Hardened/shared-backend adds `mac = HMAC/AEAD(server_key, value)`**, verified on read, so a bare Redis writer (co-tenant app, SSRF, flat network — Redis is unauthenticated by default) cannot inject admission (C3); plus Redis AUTH + an ACL user scoped to `jit:*` + TLS + tenant-namespaced keys (`jit:<tenant>:grant:…`).
- Reverse index `…grantsbykid:<kid>` (a shm list locally, a Redis set when shared) supports the revoke sweep.
- Expiry: native TTL for time expiry. **A `revoke-token` sweep is still required** for credential revocation — TTL alone does not evict a compromised kid.
- Revoke: local delete (+ backend `DEL` when shared). In the shared/cached case the ≤30 s positive cache briefly over-admits after a revoke; push a short-lived tombstone the cache must honor. (Local mode has no such window — the delete is immediate.)

### 5.5 Python job & UI page

- **`jitaccess-registry.py`** (`every: once`, `reload: true`): validates token entries (base64, kid uniqueness, expiry format), materializes a normalized registry file via `Job.cache_file()` so misconfiguration fails loudly at reload time, not at knock time.
- **UI page** (`ui/template.html` + `actions.py`):
  - `pre_render`: pull metrics + active grants (via internal API fan-out helper `bw_instances_utils`), list registry tokens (labels + kids, never secrets).
  - POST actions: create token (server-side generation of kid+secret → shown once as QR + setup string), revoke token, revoke grant.
  - QR content = the enrollment payload (§6.1).

---

## 6. Protocol (`docs/PROTOCOL.md` — normative summary)

All endpoints are HTTPS **on the protected origin itself**, under `/.well-known/jit-access/` — deliberately engine-agnostic: the client can't tell whether a BunkerWeb Lua plugin, an OpenResty shim, or a proxied standalone Authorizer is answering. HMAC = HMAC-SHA256. Encoding = base64url, no padding. All names/strings on the wire are vendor-neutral and versioned.

### 6.1 Enrollment — **one-time code exchange (baseline; the secret is never in the QR)**

**[SEC] (§11 R5).** The original draft put the long-term `secret=` in the `jitaccess://enroll?...` QR/URL. That is exploitable as designed: a QR *is* the secret (photographable), it lands in clipboard history / cloud-synced clipboards / logs (C7), and the static string is a **replayable, untracked shared secret** that can be silently enrolled on N devices, breaking per-device revocation (C8). So the secret-in-QR flow is **dropped from the shipping baseline** — it is prototype-only. The baseline is the former "v2":

Admin creates a token; the UI/`bwcli` shows once a **short-lived, single-use enrollment code** (QR or copyable), carrying **no long-term secret**:

```
jitaccess://enroll?v=1&server=https://gate.example&code=<one-time-code>&origins=grafana.example.com,wiki.example.com
```

The extension exchanges it over TLS at `POST <prefix>/enroll` with the real origin:
1. Server validates the code (unexpired, **single-use — second use fails and alerts**), returns `{kid, secret, policy}` inside TLS.
2. Extension imports `secret` as a **non-extractable** `CryptoKey` (`HMAC-SHA256`, `["sign"]`) → IndexedDB, then discards the raw bytes and ACKs; server marks the code consumed and activates the kid.
3. `kid`, label, origins → `chrome.storage.local` (non-secret config).

Properties: the secret transits exactly once inside TLS (never in a QR/clipboard/log); a captured code is worthless after first use and its reuse is *detectable*; the live TLS exchange gives the extension server authentication the static string lacked. **[SEC]** *Non-extractable* means the raw key can't be *exported* — it can still be *used* to sign, so runtime protection comes from the messaging lockdown in §7, not from non-extractability alone.

`origins` is an *advisory* upper bound the user confirms per-origin (never auto-applied — a malicious string must not make the extension knock broadly); authority lives server-side in `JIT_ACCESS_TOKENS`. **v3 (target):** the extension generates a non-extractable **ECDSA P-256 keypair** in-browser and sends only the public key at enrollment; challenges are answered by signature. Nothing secret is ever in the QR, in transit, or at rest server-side — DB/backup compromise leaks no usable credential (removes C9 and most of R5). Enrollment version/key-type is pinned **per kid** with a hard cutover, so an attacker can't downgrade a v3 kid to a symmetric proof.

### 6.2 Challenge

```
GET /.well-known/jit-access/challenge
→ 204 No Content
   X-JIT-Nonce: <b64 nonce>
   X-JIT-TS: <unix seconds, server clock>
```

The nonce is a **stateless self-authenticating token** (§6.3 step 2): it embeds `ts` and an HMAC over `(ts, rand, server_name, client_ip)` under a per-instance key, so the server stores nothing at issue time and validates it on redemption without a lookup. It is single-use (enforced at burn), bound to `(server_name, client_ip)`, and valid for `JIT_ACCESS_NONCE_TTL`. The returned `X-JIT-TS` lets the client avoid trusting its own clock.

### 6.3 Response ("the knock")

```
POST /.well-known/jit-access/respond
Content-Type: application/json

{ "v": 1, "kid": "<kid>", "step": <floor(server_ts / TIME_STEP)>,
  "nonce": "<echoed nonce>",
  "proof": "<b64url HMAC-SHA256(secret, PAE(["jitaccess-v1", server_name_canon, kid_bytes, nonce_raw]))>" }
```

**[SEC] Canonical proof construction (§11 R6/R4).** The MAC input is **not** raw concatenation — un-framed concatenation of variable-length fields is non-injective and allows a cross-service proof collision (SECURITY-REVIEW H1). Use PASETO/DSSE-style **Pre-Authentication Encoding**: `PAE(parts) = LE64(#parts) ‖ for each p: LE64(len(p)) ‖ p`. `server_name_canon` = lowercase punycode A-label, no port, no trailing dot (one normative form, shared vectors). `nonce_raw` = the 32 decoded bytes. **The client-supplied `step` field is removed** from the wire and the MAC — it carried no information the server didn't already hold and was the malleable field enabling the collision; freshness is enforced server-side from the stored nonce's mint timestamp. Full 32-byte tag, no truncation.

Server verification — **equalized work on every path** so wrong-kid / wrong-service / wrong-proof / expired-nonce are genuinely indistinguishable (the original short-circuit ordering leaked a kid-enumeration timing oracle, H4). Always fetch the nonce, always compute exactly one HMAC (against a fixed dummy key when the kid is unknown), always run the constant-time compare, then branch to the generic 404 only at the end:

1. Rate limit (knock endpoints excluded from badbehavior — §11 R1).
2. **Verify the nonce's own HMAC** (`server_nonce_key`) and its `(server_name, ip)` binding and freshness (`now − ts < NONCE_TTL`) — no lookup, self-authenticating; decode proof, gate on `len == 32`.
3. Look up `kid` → secret (fixed dummy key if absent); check token unexpired and `kid ∈ JIT_ACCESS_TOKENS` (or `*`). No client `step`.
4. Recompute the proof HMAC over the PAE canonical string; constant-time compare (`CRYPTO_memcmp`, not Lua `==`). Equalized work on every path so unknown-kid ≈ wrong-proof (no timing oracle — H4).
5. **On success only, atomically claim single-use:** `spent.add(nonce_id, true, ttl=NONCE_TTL)` — `dict:add` **fails if the id is already present**, giving an atomic check-and-burn with no read-then-delete race and no Redis (H2). Already-spent → reject. The "spent" set is bounded by *actual knock volume × NONCE_TTL*, not challenge volume, and is a **dedicated `lua_shared_dict` isolated from grants/bans**. (Clustered/Hardened: the same claim is a Redis `SET NX EX`; backend unavailable → fail closed.)
6. Write the grant (§5.4) + `204` (+ opaque grant cookie in `ip+cookie` mode).

Why nonce (not bare TOTP): a bare TOTP code is a bearer value replayable for the whole window from any IP; a single-use, atomically-burned server nonce reduces the replay window to zero and binds the proof to the requesting IP (whose value must come only from the trusted real-IP chain — §11 R2), at the cost of one round-trip, once per TTL per service.

### 6.4 Detection marker (interstitial mode)

Any response the enforcement layer denies carries `X-JIT-Access: challenge; v=1` — the extension's `webRequest.onHeadersReceived` fallback trigger. Stealth mode omits it by design.

---

## 7. The Chromium extension

### 7.1 Manifest / permissions

```jsonc
{
  "manifest_version": 3,
  "permissions": ["storage", "alarms", "webNavigation", "webRequest"],
  "optional_host_permissions": ["https://*/*"],   // user grants per enrolled origin at enrollment
  "externally_connectable": { "ids": [], "matches": [] },   // [SEC §11 R6] closed: no other extension/page may connect
  "background": { "service_worker": "sw.js" },
  "action": { "default_popup": "popup.html" },
  "options_page": "options.html"
}
```

Host permissions are requested **per enrolled origin** via `chrome.permissions.request` during enrollment — no scary blanket install warning, and `onHeadersReceived` only fires where granted.

### 7.2 Service-worker logic (event-driven; survives MV3's 30 s idle termination)

**[SEC] Two client attacks defeat the gate without forging a proof (§11 R6). Both fixes are spec-level, not later hardening:**
- **Confused-deputy forced knock (C5):** a hidden `<iframe src="https://grafana.example.com">` on any attacker page fires `onBeforeNavigate`, the extension knocks, and a grant lands on the *victim's* IP that the attacker's same-IP requests ride. So auto-knock is restricted to **top-level, main-frame, user-initiated** navigations only: `details.frameId === 0 && details.parentFrameId === -1`, and suppressed on redirect-only chains and programmatic `window.open`. The `onHeadersReceived` fallback is likewise filtered to `type === 'main_frame'`.
- **Signing oracle (C6):** the non-extractable key is still *usable*. `externally_connectable` is locked to `{ids:[], matches:[]}` with **no** `onMessageExternal`/`onConnectExternal` listeners; internal `onMessage` validates `sender.id === chrome.runtime.id`; the worker **derives `server_name` from the authenticated `sender.tab.url`**, fetches its own nonce, and **never returns a proof/signature across a message boundary**. Callers may only say "knock the origin of this tab."

- **Primary path — proactive knock:** on a qualifying top-level navigation to an enrolled origin → if no fresh local grant record (`chrome.storage.session` cache of "granted until T") → `fetch(challenge)` → `crypto.subtle.sign` with the IndexedDB `CryptoKey` → `fetch(respond)`. **Single-flight per origin** (concurrent triggers collapse to one knock). Typically completes within the page's own connection setup; user sees nothing.
- **Fallback — interstitial recovery:** `webRequest.onHeadersReceived` (observational, `main_frame` only) sees `X-JIT-Access: challenge` on a response whose **final origin** exactly matches an enrolled origin → knock → `chrome.tabs.reload(tabId)`. **[SEC §11 R6]** hard **per-tab attempt cap (≤2) + exponential backoff**; after the cap, stop and show a "couldn't unlock" popup state instead of reloading — otherwise a persistent marker (wrong-service kid, or a compromised origin returning the marker on every response) yields an infinite knock/reload storm that also trips server auto-ban (H12).
- **Grant bookkeeping:** on successful knock, record `{origin, expiresAt}` in `storage.session`; pre-expiry re-knock via a `chrome.alarms` alarm set to fire a minute before `expiresAt` **only if** a tab for that origin is open.
- **Kid selection:** local map origin → kid (from enrollment). **[SEC §11 R6]** matching is **exact origin** (scheme+host+port, lowercased, IDNA-normalized) with a public-suffix guard — never substring/implicit-subdomain, so `evil-grafana.example.com` can't match `grafana.example.com` (H13). HTTPS-only; `http://` origins are refused.
- No content scripts required for the core flow; any "unlocking…" spinner content script is **purely cosmetic** with no path to a signing operation.

### 7.3 UI surfaces

- **Popup:** per-current-tab status — Not protected / Locked (knock now button) / Unlocked (time remaining, revoke-my-grant button which calls a future self-service revoke endpoint or just lets it lapse).
- **Options page:** enroll (paste setup string / scan QR), list enrolled tokens (label, origins, kid — never key material), remove token (deletes `CryptoKey` + config), per-origin toggle for auto-knock vs manual-only.

### 7.4 Client security notes

- Secret handling per §6.1 — non-extractable key, `storage.session` for ephemeral state, `storage.local` for non-secret config, **never** `storage.sync`.
- Knock `fetch` uses `credentials: "include"` only in `ip+cookie` mode; `cache: "no-store"`.
- The extension must ignore `X-JIT-Access` markers on origins the user hasn't enrolled (a hostile site must not be able to make the extension knock anywhere, and proofs are origin-bound anyway because `server_name` is inside the HMAC).

---

## 8. Security analysis (summary)

Full adversarial analysis and findings ledger: maintained internally (not published in this repo). This table reflects the **hardened** design (§11), not the original draft.

| Threat | Mitigation (hardened) |
|---|---|
| Replay of observed knock | Single-use, **atomically-burned** server nonce (verify-then-`GETDEL`, never cached) bound to canonical (service, IP); PAE canonical proof string |
| Forged proof / cross-service reuse | HMAC over **PAE-framed** canonical string incl. normative `server_name`; per-service `JIT_ACCESS_TOKENS` allow-list; no client-supplied `step` |
| Stolen token secret | Per-device tokens → **`revoke-token(kid)` sweeps live grants**; per-access kid/expiry recheck; token expiry; **secrets encrypted at rest under external KEK**; v3 keypair removes server-side secret entirely |
| Spoofed client IP (grant/nonce key) | Hardened real-IP a **hard prerequisite**; IP from trusted-hop chain only, never a raw client header (§11 R2) |
| Grant injection via shared Redis | **Signed grant values** verified on read; Redis AUTH+ACL+TLS, tenant-namespaced keys (§11 R3) |
| Brute force on knock endpoint | **Equalized-work** generic 404 (genuine no-oracle: dummy-key HMAC on unknown kid); knock-only abuse counter **excluded from badbehavior**; per-IP + global nonce budget |
| Service enumeration | Stealth mode: deny = platform-generic 404, endpoints silent |
| CGNAT neighbor inherits admission | Full security chain runs behind the grant; **`ip+cookie` default** for high-value services; opaque host-only `SameSite=Strict` cookie; short TTLs |
| Confused-deputy / signing oracle (browser) | Top-level-only user-initiated knocks; locked `externally_connectable`; worker-derived `server_name`; no proof returned across message boundary (§11 R6) |
| Compromised extension code | Non-extractable key stops *export* not *use* → runtime protection is the messaging lockdown + short TTLs; v3 keypair limits blast radius |
| Fail-open under fault/flood | Plugin self-`pcall` + explicit deny; conf-layer `is_jit_allowed` default-deny; fail-closed on every store/Redis error; nonce dict isolated from grants/bans (§11 R1) |
| Clock skew | Server-authoritative time; **widened window (±2–3) or soft/log-only** (nonce is the real anti-replay); NTP slew + skew alerting (H8) |
| Cluster consistency | Signed grants in Redis with TTL, ≤30 s cache **for grants only**; nonces never cached |
| Admin lockout (extension broken/lost) | Manual grant via authenticated internal API / `bwcli`; static whitelist honored ahead of JIT (survives Redis outage); nonce memory isolated so a flood can't evict the emergency grant |

Ordering note: `jitaccess` must run in the access chain **after** `whitelist` (so admin whitelists still bypass) and before content-serving; external plugins append alphabetically to `order.json`'s list, so ship a documented `PLUGINS_ORDER_ACCESS` recommendation and verify placement in the test harness.

---

## 9. Implementation roadmap

**M0 — Protocol + core spec + security hardening, ~week 1-2**
`PROTOCOL.md` (L1) and `core/SPEC.md` (L3 interfaces incl. the **local-default GrantStore/NonceStore** contract and the canonical key schema) written first, **incorporating the §11 [BASELINE] gate items** — PAE canonical proof (no client `step`); stateless signed nonce + atomic `add`-based single-use; normative `server_name`/`ip` canonicalization; fail-closed contract; local-store semantics. Conformance vectors (`core/testdata/vectors.json`) cover the **key derivation**, not just the proof; `core/lua` skeleton passes them. Everything downstream implements against these. **This milestone is the security gate — do not start M1 until it reflects §11's baseline items.**

**M1 — BunkerWeb plugin core (gate + grants), Simple profile, ~week 1-2**
Plugin skeleton loads in a docker-compose harness (bunkerweb + scheduler + two dummy upstreams — **no Redis**). `USE_JIT_ACCESS=yes` denies (fail-closed wrapper + conf-layer default-deny); manual grants via `api()` endpoints (`/jitaccess/grant|revoke|revoke-token|grants`) admit for TTL using the local `lua_shared_dict` GrantStore; interstitial + stealth modes. **Exit test:** curl matrix across two services × grant/no-grant; corrupt-registry/deleted-plugin → still denies (never 200). Redis is *not* part of this milestone.

**M2 — Challenge/knock protocol, ~week 2-3**
Nonce mint/burn, registry parsing from settings, HMAC verify, rate limiting, constant-time/uniform-404 behavior — all in `core/lua`, plugin as thin shim. The scripted knock client doubles as the start of `test/conformance/`. **Exit test:** knock client unlocks service A but never B; replayed captures fail; skewed clocks within window pass; conformance suite green.

**M2.5 — Security conformance suite (new; gates M3+)**
Build `test/conformance/security/` alongside the functional suite: forged-`X-Forwarded-*` (must not move service/IP/grant key), direct-Authorizer-exposure probe, kill-verifier fail-mode assertion (must fail closed on every engine), cross-engine byte-exact key-equality, nonce single-use across two instances, well-known routing traversal/encoding matrix, un-adapted-route probe, malformed-`/respond` fuzz (must never 200). **An adapter is "supported" only when it passes this, not just the happy-path suite** (SECURITY-REVIEW H15).

**M3 — Extension MVP, ~week 3-4**
Manifest (locked `externally_connectable`), **one-time-code enrollment** (§6.1 baseline — no secret in the QR), IndexedDB non-extractable key, top-level-only single-flight knock, capped/backed-off interstitial recovery, exact-origin matching, popup status. **Exit test:** fresh profile → enroll via one-time code → navigate → service opens invisibly; wait past TTL → transparent re-knock; **hidden-iframe attacker page does NOT mint a grant; a second extension cannot obtain a signed proof.**

**M4 — Admin experience + Simple-setup polish (BunkerWeb), ~week 4-5**
UI page (token CRUD + one-time-code/QR display, live grants with revoke, `revoke-token(kid)` with blast-radius count, metrics), `bwcli` commands, registry-validation job, and the **"enable → configure site → enroll" Simple quickstart** as the headline docs path (no Redis, no real-IP config). `PLUGINS_ORDER_ACCESS` guidance.

**M5 — Standalone Authorizer + Caddy module (Simple, no Redis), ~week 5-7**
`core/go` passing the same vectors (incl. key derivation); **Authorizer as a single static binary with in-process state (no Redis)** — protocol endpoints, forward-auth `/authz`, config-file registry; plus the **native Caddy module** (`xcaddy`) for a no-extra-process Caddy path. Plain-NGINX/Traefik `auth_request`/`forwardAuth` recipes. **Exit test:** the *same* extension profile/token unlocks a service behind BunkerWeb and one behind Caddy — each standalone, neither running Redis.

**M6 — Hardened profile + more adapters, ~week 7+**
Redis (shared-backend) GrantStore with signed values + AUTH/ACL/TLS; the **proxy→Authorizer authenticator** (mTLS/shared-secret) + inbound `X-Forwarded-*` stripping + internal-only listener; real-IP hardening docs; `ip+cookie`/stealth/KEK config; **security conformance suite** green across a multi-node BunkerWeb+Caddy+Redis stack (the same token honored across both). Then: v3 ECDSA client-keygen; sliding-TTL; Envoy (pin `failure_mode_allow: false`)/HAProxy; Firefox port; submission to `bunkerity/bunkerweb-plugins`.

---

## 10. Open questions for the admin/user to decide

1. **Failure-mode default** — `interstitial` (better UX, discloses the gate's existence) vs `stealth` (fwknop philosophy, worse first-visit UX). Current draft defaults to `interstitial`.
2. **Should a grant renew on activity** (sliding TTL) or be strictly fixed-length? Draft: fixed, with the extension re-knocking near expiry while a tab is open — effectively sliding but client-driven and visible in audit logs as discrete knocks.
3. Do we need **grant-all-services-for-kid** convenience knocks (one knock unlocking every service the kid may access on that instance)? Draft: no — per-service knocks keep scoping explicit and cost one silent round-trip per service.
4. **Authorizer implementation language** — draft says Go (single static binary, easy sidecar/container, mature Redis + HTTP ecosystem); Rust is the alternative if the team prefers it. The L3 spec + shared vectors make this swappable.
5. **How far to take BunkerWeb-specific niceties** (shm fast path, `is_jit_allowed` CRS integration, UI page) vs pushing admins toward the Authorizer even on BunkerWeb — draft: keep the native plugin first-class; the portability layer is about *also* running elsewhere, not lowest-common-denominator everywhere.

> Resolved (no longer open): secrets-in-settings (→ accepted trade-off in Simple tier, KEK/v3 in Hardened, §11 R5); default grant binding (→ IP-only in Simple, `ip+cookie` in Hardened, §1.1); symmetric-secret-in-QR enrollment (→ one-time-code baseline, both tiers); Redis-as-requirement (→ **local-by-default, Redis opt-in for clustering**, §1.1).

---

## 11. Security hardening requirements (blocking — must be in the spec before M1)

Distilled from the internal adversarial security review. Six root causes. **Each is tagged [BASELINE] (always on, both profiles, no external dependency) or [HARDENED] (opt-in, or only relevant once a shared backend / real-IP / harsher threat model is introduced — §1.1).** The baseline items are what make even a zero-dependency home setup sound; the hardened items are the deeper lockdown for advanced users.

**R1 — Fail CLOSED everywhere. [BASELINE]** BunkerWeb's access chain fails *open* on a plugin error (verified). Wrap the whole `access()` body in the plugin's own `pcall` → explicit deny on any error; promote `is_jit_allowed` to a conf-layer default-deny gate independent of the Lua; fail closed on any store error; harness tests for corrupt-registry / deleted-plugin / malformed-input → must deny. **[HARDENED]** the network invariant "origin accepts traffic only from its JIT adapter" with default-deny recipe scaffolds (matters most for multi-path/multi-node topologies).

**R2 — Never trust a client-supplied IP.** **[BASELINE]** the safe default is `USE_REAL_IP=no` — key on the TCP peer, ignore XFF entirely (correct when the edge server faces the internet directly). **[HARDENED]** when deliberately behind a CDN/LB, real-IP is configured with explicit trusted CIDRs (right-most-untrusted XFF), never broad defaults; forged-XFF harness assertion.

**R3 — Grants are fail-dangerous. [BASELINE]** `revoke-token(kid)` sweeps live grants via a reverse index + per-access kid/expiry recheck; IPv6 default `/128`; immediate local delete on revoke. Local store is process-private, so no value-signing is needed. **[HARDENED]** on a shared backend: **sign every grant value** (verified on read) + Redis AUTH/ACL/TLS + tenant-namespaced keys + revoke tombstone for the cache window; opaque host-only `SameSite=Strict` grant-id cookie + `ip+cookie` binding for high-value/shared-egress services.

**R4 — Single-use nonces, done right. [BASELINE]** Stateless signed nonce (no store to flood); atomic single-use claim via `dict:add` (fails if present); dedicated `lua_shared_dict` for the spent-set, isolated from grants/bans; knock endpoints excluded from badbehavior (separate knock-only abuse counter). **[HARDENED]** on a shared backend the claim is `SET NX EX`; backend unavailable → fail closed.

**R5 — Fix enrollment custody. [BASELINE]** One-time-code exchange (no long-term secret in the QR/transit); per-kid key-type pinning (no downgrade); token-creation audit log; rotation flow. **[HARDENED]** secrets encrypted at rest under an external KEK; **v3 client-keygen** (server stores only public keys — the recommended path to eliminate at-rest secrets).

**R6 — Lock the client and prove portability. [BASELINE]** Frame-scoped/user-initiated knocks only; locked `externally_connectable` + sender-validated non-oracle messaging + worker-derived `server_name`; exact-origin matching + public-suffix guard; per-tab knock caps + single-flight + backoff; PAE canonical proof (drop client `step`); normative `server_name`/`ip` canonicalization with shared **key** vectors. **[HARDENED]** authenticated + network-isolated proxy↔Authorizer boundary; **security conformance profile** as the definition of a supported multi-component adapter.

Also fold in: widen/soften the clock window + NTP-slew + skew alerting [BASELINE]; treat `origins=` as advisory with per-origin confirmation [BASELINE]; quantify CGNAT blast radius in docs [BASELINE]; HTTPS-only enrolled origins [BASELINE]; pin the EVP HMAC path and fail closed on RNG error [BASELINE]; state the `is_jit_allowed`/CRS parity gap for non-BunkerWeb adapters [HARDENED].
