# jitaccess-authorizer

A single static Go binary that brings JIT Network Access to **any proxy that can
make a forward-auth subrequest** — NGINX (`auth_request`), Traefik
(`forwardAuth`), Caddy (`forward_auth`), Envoy (`ext_authz`).

It embeds [`core/go`](../core/go), so the wire protocol, the canonical grant
keys, and the crypto are the same code path the BunkerWeb plugin runs. The same
extension and the *same enrolled token* work against either engine.

**Simple profile: all state is in-process.** No Redis, no database, no external
service. One binary, one JSON config file.

> Prefer the [native Caddy module](../adapters/caddy) if you run Caddy — it does
> the same job in-process with no extra hop and no forward-auth boundary.

## Build & run

```bash
cd authorizer && go build -o jitaccess-authorizer .
./jitaccess-authorizer -config config.json -check   # validate, then:
./jitaccess-authorizer -config config.json
```

`SIGHUP` reloads the config (tokens and services) without dropping live grants;
they are re-checked against the new registry on their next request, so removing
a token evicts its grants immediately.

## Two faces

| Endpoint | Who calls it | Purpose |
|---|---|---|
| `<uri_prefix>/challenge` (GET) | the extension, proxied through | mint a nonce → `204` + `X-JIT-Nonce` |
| `<uri_prefix>/respond` (POST) | the extension, proxied through | verify the proof → `204` + grant |
| `<uri_prefix>/enroll` (POST) | the extension, proxied through | exchange a one-time code for the device secret |
| `/authz` (GET) | **the proxy** | `204` = admit, `403`+interstitial / `404` stealth = deny |
| `/admin/*` | you | grants, revoke, revoke-token, enroll-code, metrics |
| `/healthz` | your supervisor | `204` |

## Security model — read this before deploying

The BunkerWeb plugin runs *in-process* and keys grants on the un-forgeable TCP
peer. The Authorizer sits **behind** a proxy, so its TCP peer is the proxy and it
can only learn the real client from a header. That inverts the usual rule into
"trust exactly one header, from exactly the hops you configured":

1. **Bind to loopback or an internal interface.** The default `listen` is
   `127.0.0.1`. The Authorizer must never be reachable from the internet — a
   directly reachable `/authz` would let anyone drive the grant check.
   As a second line, `/authz` and `/admin/*` refuse any peer outside
   `trusted_proxies` outright.
2. **`trusted_proxies` is the trust boundary.** A request whose TCP peer is
   *outside* it is treated as direct: every `X-Forwarded-*` header is ignored and
   the peer is used. A request from *inside* it has `real_ip_header` walked
   right-to-left, taking the first address that is not itself a trusted proxy —
   so entries a client appended (which sit to the left) can never win.
3. **Strip inbound `X-Forwarded-*` at the edge** anyway; see the recipes in
   [`../adapters/nginx`](../adapters/nginx) and
   [`../adapters/traefik`](../adapters/traefik).

An authenticated proxy↔Authorizer channel (mTLS/shared secret) is the Hardened
(M6) addition; the rules above are the Simple baseline.

## Configuration

See [`config.example.json`](config.example.json). Keys:

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8998` | protocol + `/authz` listener. Keep it internal. |
| `admin_token` | — | bearer token for `/admin/*`; the API is disabled when empty |
| `trusted_proxies` | `127.0.0.0/8`, `::1/128` | CIDRs whose forwarded headers are honored |
| `real_ip_header` | `X-Forwarded-For` | header walked in proxy mode |
| `uri_prefix` | `/.well-known/jit-access` | base path of the protocol endpoints |
| `grant_ttl` | `3600` | grant lifetime (seconds); per-service override available |
| `nonce_ttl` | `60` | challenge freshness window |
| `enroll_ttl` | `86400` | enrollment link lifetime; clamped to 300–604800 |
| `ipv6_prefix` | `128` | IPv6 grant granularity (`64` admits a whole /64) |
| `rate_limit_per_min` | `10` | per-IP limit on the knock endpoints |
| `services.<name>.tokens` | — | allowed kids, or `["*"]` for any registered token |
| `services.<name>.failure_mode` | `interstitial` | or `stealth` (generic 404) |
| `services.<name>.binding` | `ip` | or `ip+cookie` (device-bound; see below) |

### `ip+cookie` binding

With `binding: "ip+cookie"` a successful knock also sets an opaque, host-only
`__Host-jit-grant` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`) and stores
only its **hash**. The grant is then honored only when the same browser presents
the cookie — so on shared egress (office NAT, CGNAT, VPN) a co-located client
that merely shares the IP does not inherit access. Recommended for services with
no downstream authentication, and required if you enable grant-skips-checks
semantics on another engine.

## Admin API

All require `Authorization: Bearer <admin_token>` and a peer inside
`trusted_proxies`.

```bash
curl -H "Authorization: Bearer $T" localhost:8998/admin/grants
curl -H "Authorization: Bearer $T" localhost:8998/admin/metrics
curl -X POST -H "Authorization: Bearer $T" -d '{"kid":"kid_x"}' localhost:8998/admin/revoke-token
curl -X POST -H "Authorization: Bearer $T" \
     -d '{"service":"app.example.com","ip":"203.0.113.5","ttl":3600}' localhost:8998/admin/grant
# mint a registration link to hand a user (single-use, no secret in the URL)
curl -X POST -H "Authorization: Bearer $T" \
     -d '{"kid":"kid_x","server":"https://app.example.com","origins":["https://app.example.com"]}' \
     localhost:8998/admin/enroll-code
```

## Tests

```bash
go test ./...            # includes the forged-XFF and direct-exposure probes
```

The engine-agnostic suites in [`../test/conformance`](../test/conformance) run
against this binary the same way they run against BunkerWeb — an adapter counts
as supported only once it passes them.
