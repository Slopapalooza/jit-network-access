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

Access phase (M1/M2), knock protocol + one-time-code `/enroll` (M2/M4), and the
security suite (M2.5) are implemented and **validated on real BunkerWeb 1.6.x**.
The plugin embeds the vector-verified core. The **UI page** (Plugins → **JIT
Access**) is a full token manager: it lists tokens, creates them against a
checkbox list of your JIT-enabled services, **regenerates** (device replaced) and
**deletes** them, and mints a **registration URL** to hand a user — all by editing
the same `JIT_ACCESS_TOKEN_*` / per-service `JIT_ACCESS_TOKENS` config the
scheduler already reads (via the DB, method `ui`, like the Global Config page).
`bwcli jitaccess token` remains for the CLI.

> The plugin's display name is **"JIT Access"** on purpose: BunkerWeb only renders
> a plugin page when the plugin is "used", which it detects from `USE_<NAME>`
> (name → `USE_JIT_ACCESS`). So the management page appears once **at least one
> service has `USE_JIT_ACCESS=yes`** — enable it on a service first.

## Simple-mode quickstart (no Redis, no database, no real-IP tuning)

1. **Install** the plugin (build/install above), and confirm it loaded:
   `journalctl -u bunkerweb-scheduler | grep -i jitaccess`.
2. **Protect a service** — on the service's settings, turn on **Enable JIT Network
   Access** (`<server>_USE_JIT_ACCESS=yes`). The service goes dark until a valid
   knock, and the **JIT Access** plugin page now appears.
3. **Create + wire a token** — Plugins → **JIT Access** → *Create a device token*:
   enter a label, tick the site(s) it may open (at least one is required — tokens
   can't be edited after creation), **Create**. This writes the token and adds its
   `kid` to each selected service's allow-list. (It activates on the next reload,
   ~1 min.)
4. **Enroll the device** — in the token list, click **Enroll device**: the
   **registration URL** (secret never in the link) appears right on the page with
   a copy button. Hand it to the user; with the extension installed they browse
   to it, click **Enroll**, and the site then opens after a silent knock. Links
   are single-use and live for `JIT_ACCESS_ENROLL_TTL` seconds (default
   **24 hours**, clamped 5 min–7 days) so a user can still enroll the next day;
   they survive config reloads (a full nginx restart voids outstanding links).
   **Regenerate** issues a fresh secret for a replaced device (old one revoked
   immediately); **Delete** removes the token, strips it from every allow-list,
   and evicts live grants. All page actions render inline (create/enroll/
   regenerate/delete) — no separate result pages when JS is available.

CLI/API equivalents (headless): `bwcli jitaccess token`, and
`POST /jitaccess/enroll-code {kid,origins,server}` on the instance API returns the
`register_url`.

Hardening (cookie binding, stealth, shared backend, KEK, real-IP trust) is opt-in
— see `../../DESIGN.md` §1.1 and §11.

## Operations

- **Grants / revocation** (instance internal API, `Host: bwapi` + `API_TOKEN`):
  `GET /jitaccess/grants`, `POST /jitaccess/revoke {service,ip}`,
  `POST /jitaccess/revoke-token {kid}` (evicts every grant for a lost device),
  `POST /jitaccess/grant {service,ip,ttl}` (break-glass),
  `POST /jitaccess/enroll-code {kid,origins,ttl[,server]}` (returns `code`, plus a
  `register_url` when `server` is given).
- **Metrics** appear on the plugin's UI page (knocks accepted/rejected, requests
  admitted/denied, enrollments).

## Plugin ordering (important)

`jitaccess` runs **last** in the access phase (after `whitelist`, `blacklist`,
`greylist`, `reversescan`, `limit`, `antibot`, …). This is correct — a JIT grant
admits the client *into* the rest of the pipeline (greylist semantics), so the
WAF still screens granted traffic, and an admin `whitelist` still bypasses JIT.
Two consequences to know:

- **`reversescan`** runs before jitaccess and denies clients with well-known open
  ports *before* the knock is reached — a factor when testing from a host that
  has e.g. port 22 open. Not a jitaccess issue.
- If you need a specific order, set `PLUGINS_ORDER_ACCESS` explicitly. The default
  (external plugins appended) already places jitaccess last, which is what you want.
