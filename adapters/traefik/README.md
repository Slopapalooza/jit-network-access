# JIT Network Access — Traefik

Two ways to gate Traefik. **Prefer the native plugin** unless you need one
Authorizer shared across several proxies.

| | [Native plugin](plugin) | forwardAuth recipe (this page) |
|---|---|---|
| Extra process | none — runs inside Traefik | an Authorizer container |
| Client IP | the real TCP peer, directly | a header from Traefik, needs `trusted_proxies` |
| Protocol endpoints | served by the middleware | need their own ungated router |
| Shared across proxies | no | yes — one Authorizer, many front-ends |

---

## forwardAuth recipe

Traefik delegates to the [standalone Authorizer](../../authorizer) via a
`forwardAuth` middleware. Two pieces of config: the middleware, and a router
that exposes the protocol endpoints.

See [`dynamic.yml`](dynamic.yml) for a complete file-provider example and
[`docker-compose.yml`](docker-compose.yml) for a labels-based one.

## How it fits together

```
browser ──HTTPS──> traefik ──forwardAuth──> authorizer:8998/authz
                      │
                      ├─ /.well-known/jit-access/* ──> authorizer:8998  (higher priority router)
                      └─ everything else ───────────> your service      (only on 204)
```

Two rules make it work:

1. **The protocol endpoints need their own router at a higher priority**, with
   *no* `jit-access` middleware attached. Otherwise a device that is not yet
   granted could never reach `/challenge` to become granted.
2. **`authResponseHeaders` must include `Set-Cookie`** if you use
   `binding: ip+cookie`, or the grant cookie never reaches the browser.

## Security notes

- Put the Authorizer on an **internal network only** (no published ports, no
  Traefik router of its own). It refuses `/authz` and `/admin/*` from peers
  outside `trusted_proxies`, but not being reachable is the real control.
- Set the Authorizer's `trusted_proxies` to the network Traefik connects from
  (e.g. the Docker bridge subnet `172.16.0.0/12`), **not** `0.0.0.0/0`.
- Traefik sets `X-Forwarded-For` itself and, by default, appends to a
  client-supplied value. Ensure Traefik's own
  `entryPoints.<name>.forwardedHeaders.trustedIPs` is narrow (or unset) so a
  client cannot inject entries; the Authorizer's rightmost-untrusted walk then
  resolves the correct address.
