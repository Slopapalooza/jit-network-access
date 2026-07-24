# JIT Network Access

Make self-hosted services **dark by default**. A service behind a supported edge server (BunkerWeb first; Caddy/NGINX/Traefik/Envoy via a portable Authorizer) is unreachable until a paired Chromium extension silently answers a time-based challenge ("knock"). A valid knock creates a **temporary allow entry** for that client and that service, which expires on its own. It's Single Packet Authorization (fwknop-style) re-imagined for HTTPS and the browser.

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
core/go/                 L3 reference lib in Go (standalone Authorizer) — later
adapters/bunkerweb/      L4 flagship: native BunkerWeb plugin
adapters/{nginx,traefik,caddy,envoy}/   L4 recipes / native module — later
authorizer/              standalone Go daemon (single binary, in-process state) — later
extension/               Chromium MV3 extension
test/conformance/        black-box functional + security suites
test/harness/            docker-compose stacks for real end-to-end runs
```

Portability rule: the only engine-specific layer is `adapters/`. The extension speaks only L1 and never knows what serves the origin. Compatibility is defined by passing the conformance suites, not by documentation.

## Build status

Roadmap lives in [`DESIGN.md` §9](DESIGN.md). Current increment:

- [x] **M0** — protocol + core spec + verified conformance vectors + Lua core library
- [x] **M1** — BunkerWeb plugin gate + local grants (Simple, no Redis). **Validated end-to-end on a real BunkerWeb 1.6.10 instance** (5/5 matrix: dark-by-default, interstitial marker, grant admits, protocol-endpoint stays dark, revoke re-darkens; `api()` grant/revoke working; no impact on co-hosted services). Docker harness in `test/harness/` for reproducing locally.
- [x] **M2** — challenge/knock protocol end-to-end. **Validated on real BunkerWeb 1.6.10**: the Python knock client (`core/py/jitcrypto`) completes the challenge→HMAC-proof→respond handshake against the Lua server (`core/lua`), unlocking service A but not B (per-service token allow-list), with replay of a used nonce rejected. Cross-language conformance proven, not just vector-matched.
- [x] **M2.5** — security conformance suite (`test/conformance/security_suite.py`), **12/12 green on real BunkerWeb**. Probes: malformed `/respond` (never opens the gate), tampered proof/nonce, cross-service proof isolation, replay, unknown-kid no-oracle, forged `X-Forwarded-For`/`X-Real-IP`, path traversal. **This suite caught a real vulnerability** on the test server (`USE_REAL_IP` with broad RFC1918 trust let a forged XFF inherit another IP's grant — SECURITY-REVIEW C2/R2); fixed by keying on the un-forgeable TCP peer (`$realip_remote_addr`), with `JIT_ACCESS_TRUST_REALIP` as the Hardened opt-in.
- [x] **M3** — Chromium MV3 extension (`extension/`): silent knock on top-level navigation to enrolled origins, enrollment (non-extractable WebCrypto key), popup status. Its WebCrypto reproduces the shared vectors byte-for-byte (proof identical to the Python client and Lua server — 3-language interop). Security rules from §11 R6 baked in (frame-scoped knocks, locked `externally_connectable`, worker-derived origin, no proof across the message boundary, exact-origin, HTTPS-only). MV3 browser plumbing is manual-test (load unpacked); crypto + knock logic are validated.
- [x] **M4** — admin UX. One-time-code enrollment (`POST /enroll` exchanges a single-use code for the secret via headers — **validated 5/5 on real BunkerWeb**: mint → exchange → single-use → knock with the enrolled secret unlocks), extension code-exchange enrollment, `bwcli jitaccess token`, UI metrics page (`ui/actions.py`), and the Simple quickstart + plugin-ordering guidance in `adapters/bunkerweb/README.md`.
- [ ] **M5** — standalone Authorizer + native Caddy module (Simple, no Redis)
- [ ] **M6** — Hardened profile (Redis, cookie, stealth, KEK, v3 keys) + more adapters

### What is machine-verified in this repo vs. not

This project is being developed on a host **without Lua or Docker**. Therefore:

- **Verified here:** the conformance vectors are produced by the Python reference implementation (`core/testdata/generate_vectors.py`) and cross-checked with `openssl`; the crypto constructions (PAE, canonicalization, HMAC proof, nonce) are additionally reproduced by independent Node ports of the Lua algorithms. Non-Lua artifacts are linted (compose YAML, bash `-n`, plugin.json, the registry job's self-test) and the plugin vendor/packaging step is exercised.
- **Not yet run here:** the Lua core and the BunkerWeb plugin cannot be executed locally (no Lua/Docker) — they are written to match the vectors and validated by the docker harness (`test/harness/`) on a Docker-capable Linux host. Treat them as reviewed-but-not-yet-executed until the harness is run; if an M1 assertion fails, the likely suspects are BunkerWeb-integration details (the `api()` response envelope, internal-API host/whitelist, plugin ordering), not the crypto core.

## Status of the concept

Early-stage. The design has been through a six-lens adversarial review (see `SECURITY-REVIEW.md`); the findings are folded into `DESIGN.md` §11 and the code is being built to satisfy them from the start.
