# JIT Network Access

Make self-hosted services **dark by default**. A service behind a supported edge server (BunkerWeb first; Caddy/NGINX/Traefik/Envoy via a portable Authorizer) is unreachable until a paired Chromium extension silently answers a time-based challenge ("knock"). A valid knock creates a **temporary allow entry** for that client and that service, which expires on its own. It's Single Packet Authorization (fwknop-style) re-imagined for HTTPS and the browser.

**Start here:** [`docs/how-it-works.md`](docs/how-it-works.md) — the whole system in diagrams

**Usage guides (with screenshots):**
- **BunkerWeb plugin (admin):** [`docs/bunkerweb-plugin-guide.md`](docs/bunkerweb-plugin-guide.md) — enable the gate, issue tokens, hand out enrollment links
- **Chrome extension (device):** [`docs/chrome-extension-guide.md`](docs/chrome-extension-guide.md) — install, enroll, day-to-day use

**Reference:**
- **Design:** [`DESIGN.md`](DESIGN.md)
- **Wire protocol (normative):** [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- **Portable core contract:** [`core/SPEC.md`](core/SPEC.md)

## Two deployment profiles

| | **Simple** (default) | **Hardened** (opt-in) |
|---|---|---|
| Audience | Home user / self-hoster | Multi-node / higher threat model |
| External dependencies | **None** — no Redis, no DB, no KMS | Redis (AUTH+ACL+TLS), optionally KMS/KEK |
| Grant + nonce state | Process-local (`lua_shared_dict` / in-process map) | Shared backend (Redis) with signed grant values |
| Client IP source | The TCP peer (XFF ignored) | Trusted-proxy real-IP behind a CDN/LB |
| Grant binding | IP-only | `ip+cookie` device-bound |
| Failure mode | `interstitial` (clear page) | `stealth` (generic 404) |
| Secret at rest | Symmetric secret, protected like TLS keys | KEK-encrypted, or asymmetric (no secret at rest) |
| Setup | enable → configure site(s) → enroll extension | + backend/real-IP/cookie/stealth config |

**We are building Simple mode first, with Hardened paths stubbed** (look for `-- HARDENED:` / `# HARDENED:` / `TODO(hardened)` markers). The security review's *mandatory* fixes are all in the Simple baseline — they are code/config properties, not infrastructure (fail-closed gate, locked-down extension, PAE-framed proof, canonicalization, XFF-not-trusted-by-default). The Redis-specific hardening only applies once a shared backend is actually introduced.

## Repository layout

```
docs/PROTOCOL.md          L1 — the wire protocol (vendor-neutral, versioned)
core/SPEC.md              L3 — GrantStore/NonceStore/TokenRegistry contract, canonicalization, crypto
core/testdata/           shared conformance vectors + the Python generator that produces them
core/lua/jitaccess/core/ L3 reference lib in Lua (BunkerWeb/OpenResty adapters vendor this)
core/go/                 L3 reference lib in Go (Authorizer + Caddy module); passes the shared vectors
adapters/bunkerweb/      L4 flagship: native BunkerWeb plugin
adapters/caddy/           L4 native Caddy module (jit_access) — in-process, no sidecar
adapters/traefik/          L4 native Traefik plugin (Yaegi) + forwardAuth recipe
adapters/openresty/        L4 native OpenResty gate (embeds core/lua)
adapters/kubernetes/       L4 ingress-nginx manifests + the client-IP caveat
adapters/nginx/            L4 auth_request recipe for the standalone Authorizer
adapters/envoy/           L4 ext_authz recipe — later
authorizer/              standalone Go daemon (single binary, in-process state)
extension/               Chromium MV3 extension
test/conformance/        black-box functional + security suites
test/harness/            docker-compose stacks for real end-to-end runs
```

Portability rule: the only engine-specific layer is `adapters/`. The extension speaks only L1 and never knows what serves the origin. Compatibility is defined by passing the conformance suites, not by documentation.

## Build status

Roadmap lives in [`DESIGN.md` §9](DESIGN.md). Current increment:

- [x] **M0** — protocol + core spec + verified conformance vectors + Lua core library
- [x] **M1** — BunkerWeb plugin gate + local grants (Simple, no Redis). **Validated end-to-end on a real BunkerWeb instance** (1.6.10 at the time; the plugin now runs on 1.6.13 — see *Tested BunkerWeb versions* below) (5/5 matrix: dark-by-default, interstitial marker, grant admits, protocol-endpoint stays dark, revoke re-darkens; `api()` grant/revoke working; no impact on co-hosted services). Docker harness in `test/harness/` for reproducing locally.
- [x] **M2** — challenge/knock protocol end-to-end. **Validated on real BunkerWeb** (1.6.10 at the time): the Python knock client (`core/py/jitcrypto`) completes the challenge→HMAC-proof→respond handshake against the Lua server (`core/lua`), unlocking service A but not B (per-service token allow-list), with replay of a used nonce rejected. Cross-language conformance proven, not just vector-matched.
- [x] **M2.5** — security conformance suite (`test/conformance/security_suite.py`), **12/12 green on real BunkerWeb**. Probes: malformed `/respond` (never opens the gate), tampered proof/nonce, cross-service proof isolation, replay, unknown-kid no-oracle, forged `X-Forwarded-For`/`X-Real-IP`, path traversal. **This suite caught a real vulnerability** on the test server (`USE_REAL_IP` with broad RFC1918 trust let a forged XFF inherit another IP's grant — SECURITY-REVIEW C2/R2); fixed by keying on the un-forgeable TCP peer (`$realip_remote_addr`), with `JIT_ACCESS_TRUST_REALIP` as the Hardened opt-in.
- [x] **M3** — Chromium MV3 extension (`extension/`): silent knock on top-level navigation to enrolled origins, enrollment (non-extractable WebCrypto key), popup status. Its WebCrypto reproduces the shared vectors byte-for-byte (proof identical to the Python client and Lua server — 3-language interop). Security rules from §11 R6 baked in (frame-scoped knocks, locked `externally_connectable`, worker-derived origin, no proof across the message boundary, exact-origin, HTTPS-only). MV3 browser plumbing is manual-test (load unpacked); crypto + knock logic are validated.
- [x] **M4** — admin UX. One-time-code enrollment (`POST /enroll` exchanges a single-use code for the secret via headers — **validated 5/5 on real BunkerWeb**: mint → exchange → single-use → knock with the enrolled secret unlocks), extension code-exchange enrollment, `bwcli jitaccess token`, UI metrics page (`ui/actions.py`), and the Simple quickstart + plugin-ordering guidance in `adapters/bunkerweb/README.md`.
- [x] **M5** — **portability proved: one token, three engines.** `core/go` reproduces all 29 shared vectors byte-for-byte (`go test ./core/go`), so Go and Lua compute identical proofs and identical grant keys. Built on it: the **standalone Authorizer** (single static binary — protocol endpoints, forward-auth `/authz`, admin API, in-process state, no Redis) and a **native Caddy module** (`jit_access`, in-process, no extra hop). **Exit test run locally:** the same kid+secret and the same knock client unlock a site behind the Caddy module (dark 403 → knock 204 → content 200 → replay 403) *and* a service behind the Authorizer (403 → knock 204 → authz 204) — and that same client is what validated the BunkerWeb/Lua plugin on a live instance. Plain-NGINX (`auth_request`) and Traefik (`forwardAuth`) recipes included.
- [x] **`ip+cookie` binding** (pulled forward out of M6). A grant can now be bound to the **browser** that knocked, not just its IP — so behind a shared egress (office NAT, CGNAT, VPN) a co-located client no longer inherits access someone else earned. The knock returns an opaque `__Host-jit-grant` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, host-only); only its SHA-256 is stored and the comparison is constant-time. Implemented across all four engines (`core/go`, Authorizer, Caddy module, BunkerWeb/Lua). **Validated 12/12 on a live BunkerWeb service** from a clean vantage via `test/conformance/cookie_binding.py`, and 12/12 against the Caddy module. Requires extension **v0.2.1+** — earlier builds knocked with credentials omitted, so the browser discarded the cookie and the grant could never be satisfied.
- [ ] **M6** — remaining Hardened profile (Redis shared backend + signed grant values, KEK/at-rest encryption, v3 client-keygen, authenticated proxy↔Authorizer boundary) + more adapters

### What is machine-verified in this repo vs. not

This project is being developed on a host **without Lua or Docker**. Therefore:

- **Verified here:** the conformance vectors are produced by the Python reference implementation (`core/testdata/generate_vectors.py`) and cross-checked with `openssl`; the crypto constructions (PAE, canonicalization, HMAC proof, nonce) are additionally reproduced by independent Node ports of the Lua algorithms. **The Go stack is fully executable on this host** — `core/go` (14 tests, all 29 vectors), the Authorizer (19 tests incl. forged-XFF, direct-exposure, replay, cross-service proof isolation, kid-existence oracle, malformed-`/respond` fuzz) and the Caddy module (13 tests) all run under `go test`, and both binaries were driven end-to-end by the Python knock client. Non-Lua artifacts are linted (compose YAML, bash `-n`, plugin.json, the registry job's self-test) and the plugin vendor/packaging step is exercised.
- **Not run here, but validated on a live instance:** the Lua core and the BunkerWeb plugin cannot be *executed* locally (no Lua/Docker). They are syntax-checked against the Lua 5.1 grammar, written to match the shared vectors, and each milestone's behavior is confirmed on a real deployment. If a Lua assertion fails, the likely suspects are BunkerWeb-integration details (the `api()` response envelope, internal-API host/whitelist, plugin ordering), not the crypto core, which is pinned by the vectors in three languages.

#### Tested BunkerWeb versions

| Version | What was exercised |
|---|---|
| **1.6.13** (current) | Running in production. Re-verified after the 1.6.10→1.6.13 upgrade: the plugin loads and parses its token registry, keeps its place in the access chain (now `…antibot, jitaccess, mtls`), and the **full knock plus `ip+cookie` enforcement passes 12/12** from a clean network vantage — challenge → proof → grant → cookie-bound admission, with stealth denials returning 404. No Lua errors. |
| 1.6.10 | Where the milestone matrices were originally run: M1 gate 5/5, M2 knock + per-service isolation + replay, **M2.5 security suite 12/12**, M4 enrollment 5/5, and `ip+cookie` 12/12. |

The M2.5 security suite needs **two** JIT-enabled services (it proves a proof minted for one cannot open the other), so re-running it end-to-end wants the two-service docker harness in [`test/harness/`](test/harness/) — whose compose file already pins 1.6.13 — rather than a single-service production host.

## Status of the concept

Early-stage. The design has been through a six-lens adversarial security review; its findings are consolidated in [`DESIGN.md` §11](DESIGN.md) and the code has been built to satisfy them from the start. Comments throughout the codebase cite individual findings by id (`SECURITY-REVIEW C1`, `H11`, …) so each defensive measure is traceable to the reason it exists — §11 is the published index of those ids.

## License

**[GNU Affero General Public License v3.0 or later](LICENSE)** (AGPL-3.0-or-later).

You may use, run, modify and redistribute this software freely, including inside
a commercial product and for commercial purposes. The condition is reciprocity:
if you modify it and make it available to others — **including over a network** —
you must release your modified source under the same license.

In practice:

| | |
|---|---|
| Run it to protect your own services, commercial or not | ✅ no obligations |
| Modify it for internal use only | ✅ no obligation to publish |
| Ship it inside a product you sell | ✅ but your modifications must be published under AGPL |
| Offer a hosted/managed JIT Access service | ✅ but your fork's source must be published |
| Take it closed-source | ❌ |

AGPL-3.0 was chosen deliberately: it keeps the project genuinely open source, it
matches [BunkerWeb](https://github.com/bunkerity/bunkerweb)'s own license (so the
plugin can be contributed upstream), and its network clause is what prevents the
work being absorbed into a closed product without anything flowing back.

The wire protocol itself ([`docs/PROTOCOL.md`](docs/PROTOCOL.md)) is a
specification, not code — independent implementations are welcome and the shared
conformance vectors exist precisely so they can prove interoperability.
