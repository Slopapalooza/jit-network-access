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

`jit_access` registers itself to run **before** `redir`, which in Caddy's
directive order also puts it ahead of `rewrite`, `uri`, `try_files` and every
authentication handler (`basic_auth`, `forward_auth`). So the site is dark before
a redirect can answer, before an SPA-style `try_files` can rewrite the knock
endpoints away, and before any inner authentication is attempted — and your
existing auth still runs behind a valid grant. No `order` global option is
needed.

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
| `rate_limit` | `10` | knock attempts per minute per source address (IPv6 by /64), per site |
| `trust_forwarded` | off | derive the client IP from `X-Forwarded-For` instead of the TCP peer; requires `trusted_proxies` |
| `trusted_proxies` | — | CIDRs/addresses your own proxies occupy; mandatory with `trust_forwarded` |

### `binding ip+cookie`

A successful knock also sets an opaque, host-only `__Host-jit-grant` cookie
(`HttpOnly`, `Secure`, `SameSite=Strict`); only its hash is stored. The grant is
then honored only for the browser that knocked, so on shared egress (office NAT,
CGNAT, VPN) a co-located client that merely shares the IP does not inherit
access. `SameSite=Strict` is required, not incidental: `Lax` would let a
cross-site top-level navigation ride the cookie through the gate.

### `trust_forwarded` + `trusted_proxies`

Off by default, and that default is the safe one — grants key on the TCP peer,
which a request header cannot move.

If Caddy really is behind another proxy, enable it **together with**
`trusted_proxies`, listing the CIDRs your own infrastructure occupies:

```
jit_access {
	trust_forwarded
	trusted_proxies 10.0.0.0/8 192.168.0.0/16
	...
}
```

`trust_forwarded` without `trusted_proxies` is rejected at provision time, so a
half-configured gate fails to start rather than silently letting every client
choose its own grant key.

A trusted peer whose chain names **no** untrusted address (the header missing,
or every hop in it trusted) is denied rather than keyed on the peer. Keying on
the peer would hand every client behind that proxy one shared grant, silently;
a denial is a misconfiguration you notice. If every request is denied after
enabling this, the upstream proxy is not setting `X-Forwarded-For`, or your
clients live inside `trusted_proxies`.

The handler keeps its **own** trusted-proxy list rather than reading Caddy's
server-level `trusted_proxies`. That is deliberate: Caddy's
`http.request.client_ip` resolves to the *left-most* `X-Forwarded-For` entry —
the one the client wrote — unless the operator also sets
`trusted_proxies_strict`. Depending on a separate directive that most
deployments never set would make the gate's safety silently conditional. With
its own list the handler always walks the header from the right and takes the
first address that is not one of your proxies, so a client-appended entry can
never win.

## Enrolling a device

This engine has no admin API, so nothing on it mints enrollment codes and its
`/enroll` endpoint only ever denies. Enroll a browser with the extension's
manual setup string instead: the `kid` and `secret` from the `token` line, as
described in the [extension guide](../../docs/chrome-extension-guide.md#enroll-a-device-manual-setup-string).
The `enroll_ttl` option exists for parity with the other engines and has no
effect here.

## Secrets and Caddy's admin API

Every `token` secret is plain configuration. Caddy serves the full running
config, secrets included, from its admin endpoint (`GET /config/` on
`localhost:2019` by default) and writes it to `autosave.json` on every load.
Treat both as you would the Caddyfile itself: keep the admin endpoint on
localhost or `admin off`, and consider `persist_config off` if the autosave
location is more exposed than the Caddyfile.

## Operations

- **State is process-wide and survives a config reload** (`caddy reload`), so
  reloading does not lock out already-knocked clients.
- **Revoking a device:** remove its `token` line, or give the kid a new secret,
  and reload. Grants are re-checked against the registry on every request,
  including the secret they were minted under, so the removed or rotated device
  is evicted on its next request rather than at TTL.
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
