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
[`docker-compose.yml`](docker-compose.yml) for a labels-based one. The compose
file reads [`authorizer-config.json`](authorizer-config.json) next to it:
replace the placeholder token secret and the hostname before `docker compose
up` (the Authorizer refuses to start on the placeholder).

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
2. **`authResponseHeaders` does NOT carry the grant cookie.** It copies headers
   from the auth response onto the request forwarded UPSTREAM, not onto the
   response sent to the browser. The grant cookie is set by the knock (`POST
   <prefix>/respond`), which the recipe routes to the Authorizer through the
   ungated high-priority router, so it reaches the browser directly. Listing
   `Set-Cookie` here injects a meaningless request header into your backend;
   it is harmless but it is not what makes `ip+cookie` work.

## Security notes

- Put the Authorizer on an **internal network only**: no published ports, and
  no Traefik router beyond the protocol prefix, so `/authz` and `/admin/*` are
  never routable from outside. It also refuses them from peers outside
  `trusted_proxies`, but not being reachable is the real control.
- Set the Authorizer's `trusted_proxies` to the network Traefik connects from,
  **not** `0.0.0.0/0`. The compose file pins its internal network to
  `172.28.0.0/24` and `authorizer-config.json` names exactly that.
- Traefik sets `X-Forwarded-For` itself and, by default, appends to a
  client-supplied value. Ensure Traefik's own
  `entryPoints.<name>.forwardedHeaders.trustedIPs` is narrow (or unset) so a
  client cannot inject entries; the Authorizer's rightmost-untrusted walk then
  resolves the correct address.
