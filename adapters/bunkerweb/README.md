# BunkerWeb adapter — `jitaccess` plugin

The flagship L4 adapter: a native BunkerWeb plugin that embeds the portable core
(`core/lua/jitaccess/core`) and gates services in **Simple mode with no external
dependencies** (state lives in `lua_shared_dict`; no Redis).

## Layout

```
jitaccess/
  plugin.json                     metadata + settings (Simple defaults)
  jitaccess.lua                   plugin main — fail-closed access wrapper (M0 skeleton; protocol in M1)
  confs/http/jitaccess.conf       declares the jit_grants / jit_nonces shared dicts
  confs/server-http/jitaccess.conf  sets $is_jit_allowed for CRS visibility
  jobs/jitaccess-registry.py      validates JIT_ACCESS_TOKEN_* at reload (fail loud)
  core/                           VENDORED copy of core/lua/jitaccess/core (git-ignored)
  bwcli/  ui/                     admin CLI + web UI page (M4)
```

## Build & install

```bash
adapters/bunkerweb/build-vendor.sh      # copies core in, produces jitaccess.tar.gz
```

Then either mount the `jitaccess/` folder into the scheduler's `/data/plugins`
volume, or set `EXTERNAL_PLUGIN_URLS=file:///path/to/jitaccess.tar.gz`.

## Status

- **M0 (done):** metadata, settings, shared-dict + `$is_jit_allowed` conf,
  registry-validation job, and the **fail-closed `access()` wrapper**. With the
  protocol not yet implemented, a service with `USE_JIT_ACCESS=yes` is
  intentionally **dark** (denies) — never accidentally open.
- **M1 (next):** the full challenge/respond/grant-check access phase, the local
  `GrantStore`/`NonceStore` wiring, the `api()` management endpoints
  (`/jitaccess/grant|revoke|revoke-token|grants`), and the docker harness.

## Simple-mode quickstart (target UX, wired in M1/M4)

1. Install the plugin (above).
2. Per service: `USE_JIT_ACCESS=yes` and `JIT_ACCESS_TOKENS=<kid>` (or `*`).
3. Create a token (UI/bwcli) → enroll the browser extension with the one-time code.

No Redis, no database, no real-IP tuning. Hardening (cookie binding, stealth,
shared backend, KEK) is opt-in later — see `../../DESIGN.md` §1.1 and §11.
