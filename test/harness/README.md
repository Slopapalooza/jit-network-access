# M1 docker harness

End-to-end validation of the BunkerWeb `jitaccess` plugin in **Simple mode (no
Redis)**. Requires **Docker + docker compose on a Linux host** (BunkerWeb doesn't
run on the dev machine this repo was authored on, so this harness is how M1 is
actually verified).

## What it stands up

| Service | Upstream | JIT mode |
|---|---|---|
| `app-a.local` | `whoami-a` | interstitial (403 + `X-JIT-Access` marker) |
| `app-b.local` | `whoami-b` | stealth (generic 404, no marker) |

Plus a `tester` container on the `bw-universe` network that drives every request,
so the source IP (what a grant is keyed to in Simple mode) is stable.

## Run

```bash
cd test/harness
./run.sh      # vendors + stages the plugin, brings the stack up, waits for ready
./test.sh     # runs the M1 curl matrix
```

Expected: `test.sh` ends with **`M1 exit test GREEN`**.

## What `test.sh` asserts (DESIGN §9 M1 exit test)

- **Dark by default:** `app-a` → 403, `app-b` → 404 with no grant.
- **Failure modes:** interstitial sets `X-JIT-Access`; stealth does not.
- **Grant admits, per-service:** a manual grant (`POST /jitaccess/grant`) for the
  tester's IP flips `app-a` to 200 while `app-b` stays dark (grants are scoped).
- **Protocol endpoints never pass through:** `/.well-known/jit-access/*` denies
  even for a granted client (the knock protocol is M2; the stub must not leak).
- **Revoke re-darkens:** `POST /jitaccess/revoke` returns `app-a` to 403.

## Fail-closed checks (DESIGN §11 R1)

The gate must fail **closed** (deny), never open, under fault:

- **Enabled + no grant → deny.** Covered by the baseline assertions above.
- **Corrupt registry → still denies.** Set a bad token and reload; the
  registry-validation job exits non-zero and no grants exist, so the service
  keeps denying:
  ```bash
  docker compose exec -T bw-scheduler sh -c 'export app-a.local_JIT_ACCESS_TOKEN="not-valid"; true'
  # (or edit docker-compose.yml to add an invalid *_JIT_ACCESS_TOKEN and `docker compose up -d`)
  ./test.sh   # app-a must still be 403 with no grant
  ```
- **Runtime error in access() → deny.** Guaranteed by the self-`pcall` wrapper in
  `jitaccess.lua` (it returns an explicit deny on any thrown error rather than
  relying on BunkerWeb's chain, which fails open — SECURITY-REVIEW C1).

### Known residual (honest caveat)

If the **entire plugin fails to load** (files missing/corrupt so BunkerWeb skips
it), its `confs/` are also not applied, so there is no gate at all — a load
failure of the whole plugin is the one case the self-`pcall` can't cover, because
the Lua never runs. A true conf-layer default-deny that survives total plugin
absence is awkward in NGINX (phase ordering) and is deferred with a
`TODO(R1-conf-gate)` marker. Operationally: confirm the plugin loaded
(`docker compose logs bw-scheduler | grep -i jitaccess`) after install. Runtime
errors, corrupt registry, and enabled-without-grant all fail closed today.

## Caveats

- **Image tags** pin BunkerWeb `1.6.13`; adjust in `docker-compose.yml` if needed.
- The Lua was written to the vector-verified core but **not executed on the dev
  host** — this harness is its first real run. If an assertion fails, the likely
  suspects are BunkerWeb-integration details (the `api()` response envelope, the
  internal-API `Host`/whitelist, or plugin ordering), not the crypto core.
- **Plugin ordering:** `jitaccess` should run after `whitelist` so an admin IP
  whitelist still bypasses. External plugins append alphabetically; if ordering
  matters for your setup, set `PLUGINS_ORDER_ACCESS` accordingly.

## Tear down

```bash
docker compose down -v
```

## Validated on a real BunkerWeb instance (1.6.10, systemd)

M1 was run end-to-end against a live BunkerWeb 1.6.10 (Linux-package) install, installing the plugin via the control API and testing a disposable `jittest.local` vhost. Result: **5/5** — dark-by-default (403), `X-JIT-Access` interstitial marker present, manual grant admits (200), `/.well-known/jit-access/*` stays dark even when granted, revoke re-darkens. The `api()` grant/revoke endpoints worked on the instance internal API, and installing the plugin did not change any co-hosted service's responses.

**Deployment finding — plugin ordering matters.** `jitaccess` runs **last** in BunkerWeb's access phase (order: `ssl, whitelist, …, reversescan, limit, …, antibot, jitaccess`). This is correct for the greylist-semantics default (a grant admits the client *into* the pipeline; the other security plugins still apply). But two consequences to document for operators:

- **`reversescan`** runs before `jitaccess` and denies clients that have well-known ports open. Testing from `localhost` fails at `reversescan` (the host has port 22 open) *before* `jitaccess` is reached — disable it on the test vhost (`USE_REVERSE_SCAN=no`) or test from a client without open ports. This is not a jitaccess issue; it confirms jitaccess sits behind the rest of the chain.
- **`limit`** (request rate limiter) can return 429 under rapid testing; disable (`USE_LIMIT_REQ=no`) or pace requests when scripting the matrix.

Everything installed for the test (plugin, `jittest.local` service, temp upstream) is removable via the control API (`DELETE /services/{name}`, `DELETE /plugins/jitaccess`), which restores the instance to its prior state.
