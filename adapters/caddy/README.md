# JIT Network Access — native Caddy module

A Caddy HTTP handler (`jit_access`) that keeps a site **dark** until a paired
browser extension answers the knock. It embeds [`core/go`](../../core/go), so the
protocol, canonical grant keys and crypto are the same code the standalone
Authorizer runs — and, via the shared vectors, the same constructions the
BunkerWeb Lua plugin implements. One extension, one enrolled token, any engine.

See [How it works](../../docs/how-it-works.md) for the protocol in diagrams.

**No extra process and no forward-auth hop.** Because the handler runs
in-process it reads the un-forgeable TCP peer directly, so it has none of the
IP-provenance caveats that apply to the [Authorizer](../../authorizer).

## Build

```bash
xcaddy build --with github.com/Slopapalooza/jit-network-access/adapters/caddy
```

or, without xcaddy (a Caddy build with the module already imported):

```bash
go build -o caddy-jit ./cmd/caddy-jit
./caddy-jit list-modules | grep jit      # http.handlers.jit_access
```

## Use

```caddy
app.example.com {
	jit_access {
		token kid_abc123 <base64url-secret> ops laptop
		allow kid_abc123
	}
	reverse_proxy localhost:3000
}
```

That's the whole Simple setup: no Redis, no database, no sidecar. See
[`Caddyfile.example`](Caddyfile.example) for every option.

`jit_access` registers itself to run **before** `basic_auth`, so the site is dark
before any inner authentication is attempted — and your existing auth still runs
behind a valid grant. No `order` global option is needed.

## Options

| Option | Default | Meaning |
|---|---|---|
| `token <kid> <secret> [label]` | — | one enrolled device; repeatable |
| `allow <kid>...` | — | kids permitted to open this site, or `*` for any |
| `prefix` | `/.well-known/jit-access` | base path of the protocol endpoints |
| `grant_ttl` | `1h` | how long a knock admits the client |
| `nonce_ttl` | `60s` | challenge freshness window |
| `enroll_ttl` | `24h` | enrollment code lifetime |
| `failure_mode` | `interstitial` | or `stealth` (generic 404, gate invisible) |
| `binding` | `ip` | or `ip+cookie` (also requires the device's grant cookie) |
| `ipv6_prefix` | `128` | `64` admits a whole /64 segment |
| `rate_limit` | `10` | knock attempts per minute per IP |
| `trust_forwarded` | off | key grants on Caddy's resolved client IP instead of the TCP peer |

### `binding ip+cookie`

A successful knock also sets an opaque, host-only `__Host-jit-grant` cookie
(`HttpOnly`, `Secure`, `SameSite=Strict`); only its hash is stored. The grant is
then honored only for the browser that knocked, so on shared egress (office NAT,
CGNAT, VPN) a co-located client that merely shares the IP does not inherit
access. `SameSite=Strict` is required, not incidental: `Lax` would let a
cross-site top-level navigation ride the cookie through the gate.

### `trust_forwarded`

Off by default, and that default is the safe one — grants key on the TCP peer,
which a request header cannot move. Enable it **only** when Caddy is genuinely
behind a trusted proxy with its own `trusted_proxies` correctly narrowed;
otherwise anyone can set `X-Forwarded-For` and nominate their own grant key.

## Operations

- **State is process-wide and survives a config reload** (`caddy reload`), so
  reloading does not lock out already-knocked clients.
- **Revoking a device:** remove its `token` line and reload. Grants are
  re-checked against the registry on every request, so the removed device is
  evicted on its next request rather than at TTL.
- Grants and spent nonces are in-memory only: a full Caddy **restart** clears
  them and clients transparently re-knock.

## Tests

```bash
go test ./...
```

Covers the gate (dark until knock, upstream never reached while dark), per-IP
grant scoping, forged-`X-Forwarded-For`, replay, the kid-existence oracle,
malformed-`/respond` fuzz, allow-list enforcement, `ip+cookie` binding, and
Caddyfile parsing.
