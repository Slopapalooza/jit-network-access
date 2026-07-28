# JIT Network Access — OpenResty module

A native OpenResty gate: the same portable core (`core/lua/jitaccess/core`) the
BunkerWeb plugin runs, wired straight into an `access_by_lua` phase.

**In-process, so no sidecar and no forward-auth boundary.** It reads the
un-forgeable TCP peer directly and has none of the IP-provenance caveats that
apply to the [standalone Authorizer](../../authorizer).

> Running plain NGINX rather than OpenResty? Use the
> [`auth_request` recipe](../nginx) with the Authorizer instead — no Lua needed.

## Install

```bash
# 1. the portable core + this adapter
sudo mkdir -p /usr/local/share/jitaccess
sudo cp -r core/lua/jitaccess            /usr/local/share/jitaccess/
sudo cp -r adapters/openresty/lib        /usr/local/share/jitaccess/

# 2. the http-block config
sudo cp adapters/openresty/conf/jitaccess.conf /etc/openresty/conf.d/
```

Include it inside `http { }`, edit the token and service lists, then add one
line to each server you want gated:

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    access_by_lua_block { require("jitaccess.openresty").access() }

    location / { proxy_pass http://127.0.0.1:3000; }
}
```

That is the whole setup. The knock endpoints are answered by the access phase
itself, so they need no location block and stay reachable while the site is dark.

## Requirements

- OpenResty (or NGINX + ngx_lua) with **lua-resty-openssl**, used for HMAC-SHA256,
  SHA-256 and the CSPRNG. It ships with OpenResty's opm (`opm get fffonion/lua-resty-openssl`).
- The two shared dicts declared in `conf/jitaccess.conf`.

## Options

Passed to `init()`; see [`conf/jitaccess.conf`](conf/jitaccess.conf) for a
complete annotated example.

| Option | Default | Meaning |
|---|---|---|
| `tokens` | — | `{ kid, secret (base64url ≥16 bytes), label, expires }` per device |
| `services` | — | per-site `tokens` allow-list (`{"*"}` for any), `binding`, `failure_mode`, `grant_ttl` |
| `uri_prefix` | `/.well-known/jit-access` | base path of the protocol endpoints |
| `grant_ttl` | `3600` | how long a knock admits the client |
| `nonce_ttl` | `60` | challenge freshness window |
| `enroll_ttl` | `86400` | enrollment code lifetime |
| `ipv6_prefix` | `128` | `64` admits a whole /64 segment |
| `rate_limit` | `10` | knock attempts per minute per IP |
| `trust_forwarded` | `false` | key grants on the realip-resolved client instead of the TCP peer |

`binding = "ip+cookie"` additionally binds a grant to the browser that knocked
via an opaque `__Host-jit-grant` cookie — the right choice behind office NAT,
CGNAT or a VPN. See the [protocol overview](../../docs/how-it-works.md#5-grant-binding-why-ip-isnt-always-enough).

## Enrollment

Mint a single-use code, then hand the user the registration link:

```lua
-- e.g. from an admin-only location protected by your own auth
local jit = require "jitaccess.openresty"
local code = jit.mint_enroll_code("kid_REPLACE", { "https://app.example.com" })
ngx.say("https://app.example.com/.well-known/jit-access/register?code=" .. code)
```

The device secret is never in the link — the extension exchanges the code for it
over TLS at `/enroll`.

## Operational notes

- **State is per worker process.** Grants and spent nonces live in the shared
  dicts, so they are shared across workers and survive a `reload`, but a full
  **restart** clears them and clients transparently re-knock.
- **Revoking a device:** remove its `token` entry and reload. Grants are
  re-checked against the registry on every request, so the device is evicted on
  its next request rather than at TTL.
- **Fail-closed:** the whole access path is wrapped in `pcall`, so any thrown
  error denies. A `pcall` cannot see a clean early return, so the "`init()`
  never ran" case — a missing or mistyped `init_by_lua_block` include — is
  checked explicitly and denies with an `ERR` log line. If you see
  `jitaccess: not initialized` in the error log, the gate is refusing everything
  because it was never configured, not because the client failed the knock.

## Status

Written against the vector-verified core and syntax-checked, but **not yet
executed** — the development host has no OpenResty. The crypto it calls is the
same code validated end-to-end on BunkerWeb (which is OpenResty underneath), and
the protocol is covered by the engine-agnostic suites in
[`test/conformance`](../../test/conformance). Point them at a real deployment to
certify it:

```bash
python test/conformance/knock_client.py    --url https://app.example.com --kid ... --secret ... --check-service --replay
python test/conformance/security_suite.py  --a-url https://app.example.com ...
python test/conformance/cookie_binding.py  --url https://app.example.com ...   # if binding=ip+cookie
```
