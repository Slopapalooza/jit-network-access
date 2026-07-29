# Multi-engine adapter lab

Five different engines gating the **same** service with the **same** device
token, driven by the **same** knock client. This is the portability claim made
executable rather than asserted.

| Engine | Port | How it gates |
|---|---|---|
| Caddy | 8081 | native `jit_access` handler, in-process |
| NGINX + Authorizer | 8082 | `auth_request` → the standalone Authorizer |
| Traefik | 8083 | native plugin, Yaegi-interpreted, in-process |
| OpenResty | 8084 | `access_by_lua` with `core/lua`, in-process |
| Kubernetes (ingress-nginx) | 8085 | `auth-url` annotation → Authorizer, in a kind cluster |

## Run it

```bash
# the four container-based engines
docker compose up -d --build

# Kubernetes (separate: it needs its own cluster)
./kind/setup.sh

# knock every engine that is up
./run.sh
```

`run.sh` asserts per engine: the service is dark before knocking, the deny
carries the `X-JIT-Access` marker, the knock is accepted (204), the service then
opens (200), and a replayed nonce is rejected. It restarts the gates first so
grants from a previous run cannot mask a broken gate.

Tear down with `docker compose down` and `./kind/setup.sh --destroy`.

## Requirements

Docker with the Compose v2 and buildx plugins, plus `kind` and `kubectl` for the
Kubernetes stack. Debian's `docker.io` package ships neither Compose v2 nor
buildx — install both as CLI plugins into `/usr/local/lib/docker/cli-plugins/`.

## What this lab has already caught

Running the adapters for real found three defects that reading the code did not:

1. **NGINX recipe wouldn't start.** `proxy_pass` with a URI part is illegal
   inside a *named* location, so `location @jit_denied { proxy_pass .../authz; }`
   failed at config test. Fixed with `rewrite ^ /authz break;` and a
   URI-less `proxy_pass`, in both the lab and the shipped recipe.

2. **Traefik plugin wouldn't load.** Traefik derives the Go symbol it evaluates
   from the last path element of `import` (`…/traefik/plugin` → `plugin`), but
   the package is named `jitaccess` — so it failed with
   `failed to eval New: undefined: plugin`. Fixed by declaring `basePkg` in
   `.traefik.yml`. Compiling and `yaegi test` both passed beforehand; only
   loading it in real Traefik surfaced this.

3. **Kubernetes denied everything, and the knock endpoint left the cluster.**
   The `ExternalName` service used to reach across namespaces resolved to a
   *public* address, so `/.well-known/jit-access/*` was proxied to the internet.
   And ingress-nginx sets `Host:` on its auth subrequest to the *auth service's*
   address, carrying the real origin only in `X-Original-URL` — which the
   Authorizer did not read, so every request resolved to an unconfigured service
   name and was denied. Fixed by putting the protocol Ingress in the Authorizer's
   own namespace and by honoring `X-Original-URL` (with a regression test).

## Notes

- **Plain HTTP on purpose.** The protocol does not depend on TLS, and the probes
  read `Set-Cookie` directly, so no certificates are needed. Deploy with TLS.
- **One token, five gates.** `kid_lab` with a fixed all-`0x01` secret is
  configured identically everywhere; a green run means one enrolled device would
  open all five.
- **ingress-nginx strips the deny marker** — expected, and reported as `NOTE`
  rather than a failure. See [`adapters/kubernetes`](../../../adapters/kubernetes).
