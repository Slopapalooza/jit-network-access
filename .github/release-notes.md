Keep a service dark until a paired browser answers a time-based challenge. A
valid knock creates a short-lived, self-expiring allow entry for that client.

## Install (Debian / Ubuntu)

```bash
VER=$(curl -fsSL https://api.github.com/repos/Slopapalooza/jit-network-access/releases/latest | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
curl -fsSLO "https://github.com/Slopapalooza/jit-network-access/releases/download/$VER/jitaccess-deploy-$VER.tar.gz"
tar xzf "jitaccess-deploy-$VER.tar.gz" && cd deploy
sudo ./debian/install.sh
```

(The asset name carries the version, so there is no fixed `latest/download`
URL for it — resolve the tag first, as above.)

The installer verifies the binary against `SHA256SUMS` before it executes
anything, creates a shell-less system user, installs a hardened systemd unit,
and generates a config with a real device token already in it. See
[`deploy/README.md`](https://github.com/Slopapalooza/jit-network-access/blob/main/deploy/README.md).

## Artifacts

| | |
|---|---|
| `jitaccess-authorizer-*-linux-{amd64,arm64}` | the Authorizer — one static binary, no runtime dependencies |
| `caddy-jit-*-linux-{amd64,arm64}` | Caddy with the `jit_access` handler compiled in |
| `jitaccess-openresty-*.tar.gz` | Lua core + adapter shim + conf snippet |
| `jitaccess-bunkerweb-*.tar.gz` | plugin tarball for `EXTERNAL_PLUGIN_URLS` |
| `jitaccess-kubernetes-*.tar.gz` | manifests; pair with the image below |
| `jitaccess-deploy-*.tar.gz` | `install.sh` + systemd unit |
| `SHA256SUMS` | verify everything above |

Container image for the Kubernetes adapter:
`ghcr.io/slopapalooza/jit-network-access/authorizer`

**Traefik has no artifact by design.** Traefik fetches the plugin from source at
the git tag and interprets it with Yaegi, so the tag itself is the release —
point `moduleName` at this repository and pin `version` to this tag.

## Verify before you install

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

## Scope

This is the **Simple profile**: no Redis, no shared state, no external
dependencies. Each engine keeps grants in-process. The Hardened profile — shared
Redis backend, proxy→Authorizer mTLS, KEK-wrapped secrets, v3 asymmetric device
keys — is the next milestone and is not in this release.

The wire protocol carries its own version field (`"v":1`), independent of these
release numbers, so a future protocol revision does not invalidate a deployment
running this one.

The browser extension is versioned and released separately.
