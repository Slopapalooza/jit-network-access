# JIT Network Access — native Traefik plugin

A Traefik **middleware plugin** that keeps a router dark until a paired browser
extension answers the knock. No Authorizer sidecar, no forward-auth hop — the
gate runs inside Traefik.

> Prefer this over the [`forwardAuth` recipe](..) unless you need one Authorizer
> shared by several proxies.

## Install

### Plugin catalog / remote

```yaml
# static configuration
experimental:
  plugins:
    jitaccess:
      moduleName: github.com/Slopapalooza/jit-network-access/adapters/traefik/plugin
      version: v0.1.0
```

### Local

```bash
mkdir -p plugins-local/src/github.com/Slopapalooza/jit-network-access/adapters/traefik
cp -r adapters/traefik/plugin \
      plugins-local/src/github.com/Slopapalooza/jit-network-access/adapters/traefik/
```

```yaml
experimental:
  localPlugins:
    jitaccess:
      moduleName: github.com/Slopapalooza/jit-network-access/adapters/traefik/plugin
```

## Use

```yaml
http:
  middlewares:
    jit:
      plugin:
        jitaccess:
          allow:
            - kid_abc123
          tokens:
            - kid: kid_abc123
              secret: <base64url-secret>     # openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
              label: ops laptop
          binding: ip                        # or ip+cookie
          failureMode: interstitial          # or stealth
          grantTtl: 3600

  routers:
    app:
      rule: "Host(`app.example.com`)"
      middlewares: [jit]
      service: app-backend
```

The knock endpoints are served by the middleware itself, so — unlike the
forwardAuth recipe — **no second router is needed**. `/.well-known/jit-access/*`
stays reachable while the site is dark.

Docker labels work the same way:

```yaml
labels:
  - traefik.http.middlewares.jit.plugin.jitaccess.allow[0]=kid_abc123
  - traefik.http.middlewares.jit.plugin.jitaccess.tokens[0].kid=kid_abc123
  - traefik.http.middlewares.jit.plugin.jitaccess.tokens[0].secret=<base64url-secret>
  - traefik.http.middlewares.jit.plugin.jitaccess.binding=ip
  - traefik.http.routers.app.middlewares=jit
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `tokens` | — | enrolled devices: `kid`, `secret` (base64url ≥16 bytes), `label`, `expires` |
| `allow` | — | kids permitted on this router, or `["*"]` for any registered token |
| `prefix` | `/.well-known/jit-access` | base path of the protocol endpoints |
| `grantTtl` | `3600` | seconds a knock admits the client |
| `nonceTtl` | `60` | challenge freshness window |
| `failureMode` | `interstitial` | or `stealth` (generic 404) |
| `binding` | `ip` | or `ip+cookie` (device-bound; see below) |
| `ipv6Prefix` | `128` | `64` admits a whole /64 |
| `rateLimit` | `10` | knock attempts per minute per IP |
| `trustForwarded` | `false` | key grants on `X-Forwarded-For` instead of the TCP peer |

`New()` refuses to start with no tokens, no allow-list, a short/invalid secret,
or an unknown `binding`/`failureMode` — a misconfigured gate fails loudly at
startup rather than quietly admitting everyone.

### `binding: ip+cookie`

A successful knock also sets an opaque, host-only `__Host-jit-grant` cookie
(`Secure`, `HttpOnly`, `SameSite=Strict`); only its SHA-256 is stored. The grant
is then honored only for the browser that knocked — the right choice behind
office NAT, CGNAT or a VPN, where an IP is not one person.

### `trustForwarded`

Off by default, and that default is the safe one: grants key on the TCP peer,
which a request header cannot move. Enable it **only** when the entryPoint's
`forwardedHeaders.trustedIPs` is correctly narrowed — otherwise anyone can set
`X-Forwarded-For` and nominate their own grant key.

## Development

The portable core is **vendored** into `internal/jitcore` by
[`build-vendor.sh`](build-vendor.sh) — Traefik interprets plugin source directly
and never resolves dependencies, so the module must be self-contained. It has
zero external dependencies by design. `core/go` remains the single source of
truth; re-run the script after changing it.

```bash
./build-vendor.sh
go test ./...                    # compiled
yaegi test -v .                  # interpreted — how Traefik actually runs it
```

Both are meaningful: a plugin can compile cleanly and still fail under Yaegi.
The test suite covers dark-until-knock, per-IP grant scoping, forged
`X-Forwarded-For`, replay, the kid-existence oracle, malformed-`/respond` fuzz,
allow-list enforcement, `ip+cookie`, stealth mode, and config validation — and
passes under **both**.
