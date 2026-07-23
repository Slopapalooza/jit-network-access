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
security suite (M2.5) are implemented and **validated on real BunkerWeb 1.6.10**.
The plugin embeds the vector-verified core; metrics show on the UI page; token
generation is in `bwcli jitaccess token`.

## Simple-mode quickstart (no Redis, no database, no real-IP tuning)

1. **Install** the plugin (build/install above), and confirm it loaded:
   `journalctl -u bunkerweb-scheduler | grep -i jitaccess`.
2. **Create a token** (prints the setting line + enrollment options):
   ```bash
   bwcli jitaccess token "Jamie laptop"
   ```
   Add the printed `JIT_ACCESS_TOKEN=<kid>:<secret>:<label>` to your **global**
   config.
3. **Protect a service** (multisite settings):
   ```
   app.example.com_USE_JIT_ACCESS=yes
   app.example.com_JIT_ACCESS_TOKENS=<kid>        # or * for any registered token
   ```
   The service is now dark until a valid knock.
4. **Enroll the browser** — recommended (secret never in the string): mint a
   one-time code and hand the user a setup string:
   ```bash
   curl -s -H "Host: bwapi" -H "Authorization: Bearer $API_TOKEN" \
     -X POST http://127.0.0.1:5000/jitaccess/enroll-code \
     -d '{"kid":"<kid>","origins":["https://app.example.com"]}'
   # -> {"code":"..."} ; give the user:
   # jitaccess://enroll?v=1&server=https://app.example.com&code=<code>&origins=https://app.example.com
   ```
   They paste it into the extension's options page (see `../../extension`).
   Visiting `https://app.example.com` then opens after a silent knock.

Hardening (cookie binding, stealth, shared backend, KEK, real-IP trust) is opt-in
— see `../../DESIGN.md` §1.1 and §11.

## Operations

- **Grants / revocation** (instance internal API, `Host: bwapi` + `API_TOKEN`):
  `GET /jitaccess/grants`, `POST /jitaccess/revoke {service,ip}`,
  `POST /jitaccess/revoke-token {kid}` (evicts every grant for a lost device),
  `POST /jitaccess/grant {service,ip,ttl}` (break-glass),
  `POST /jitaccess/enroll-code {kid,origins,ttl}`.
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
