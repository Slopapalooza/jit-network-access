# Deploying the Authorizer on Debian / Ubuntu

The Authorizer is one static binary with no runtime dependencies — no database,
no Redis, no shared state. This directory installs it as a systemd service.

```bash
VER=$(curl -fsSL https://api.github.com/repos/Slopapalooza/jit-network-access/releases/latest | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
curl -fsSLO "https://github.com/Slopapalooza/jit-network-access/releases/download/$VER/jitaccess-deploy-$VER.tar.gz"
tar xzf "jitaccess-deploy-$VER.tar.gz" && cd deploy
sudo ./debian/install.sh
```

Or, if you built the binary yourself:

```bash
sudo ./debian/install.sh --binary ./jitaccess-authorizer
```

| Flag | |
|---|---|
| `--version vX.Y.Z` | install a specific release instead of the latest |
| `--binary PATH` | install a local binary; skips download and checksum |
| `--no-start` | install but do not enable/start the service |
| `--uninstall` | stop, disable, and remove the binary and unit |

## What it installs

| Path | |
|---|---|
| `/usr/local/bin/jitaccess-authorizer` | the binary |
| `/etc/jitaccess/config.json` | `0640 root:jitaccess` — **device secrets live here** |
| `/etc/systemd/system/jit-authorizer.service` | hardened unit |
| user `jitaccess` | system user, no shell, no home |

Re-running is safe: an existing config is never overwritten and the user is not
recreated. `--uninstall` deliberately leaves the config and the user behind,
because the config holds device secrets that may still be enrolled in browsers —
revoke them server-side before deleting it.

## Things worth knowing

**The generated config has a real token in it.** Shipping a placeholder secret
would mean the service fails its own `-check` on first boot, and the usual
answer to that is to paste in something weak. The installer generates a kid, a
32-byte secret and an admin token, then validates the file with the binary
before starting anything.

**Reload, don't restart.** `systemctl reload jit-authorizer` sends SIGHUP, which
swaps the token registry and services in place. Live grants survive, so nobody
is kicked out mid-session. A restart drops every grant — everyone re-knocks.

**Minting an enrollment code needs `server`.** Without it the admin API returns
the bare code and no `register_url`, which is the thing you actually hand to a
user:

```bash
curl -s -X POST http://127.0.0.1:8998/admin/enroll-code \
  -H "Authorization: Bearer $(sudo sed -n 's/.*"admin_token": *"\([^"]*\)".*/\1/p' /etc/jitaccess/config.json)" \
  -H 'Content-Type: application/json' \
  -d '{"kid":"<kid>","origins":["https://app.example.com"],"server":"https://app.example.com"}'
```

**It listens on 127.0.0.1 only.** The Authorizer is an internal surface; the web
server in front of it is what faces the network. If you move `listen` below port
1024 do not add `CAP_NET_BIND_SERVICE` to the unit — put a proxy in front, which
is the deployment shape anyway.

**The installer does not touch your web server config.** Gating a site is a
decision about that site. See [`adapters/nginx/`](../adapters/nginx/) for the
snippet to include in a `server { }` block.

## Verified

`install.sh` was exercised end to end on Debian 13: fresh install, idempotent
re-run, config validation, SIGHUP reload, admin API enrollment, and uninstall.
`systemd-analyze security jit-authorizer.service` scores **1.3 OK**.
