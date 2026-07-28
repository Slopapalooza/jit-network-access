# JIT Network Access on Kubernetes (ingress-nginx)

`ingress-nginx` is NGINX underneath, so it gates via `auth_request` — which the
[standalone Authorizer](../../authorizer) already speaks. No new code: one
Deployment, one Service, and two annotations.

```
client ──HTTPS──> ingress-nginx ──auth_request──> jit-authorizer (ClusterIP)
                       │
                       ├─ /.well-known/jit-access/* ──> jit-authorizer   (separate Ingress, NOT gated)
                       └─ everything else ───────────> your Service      (only on 204)
```

Apply the manifests, then point an Ingress at it:

```bash
kubectl apply -f authorizer.yaml
kubectl apply -f ingress-example.yaml
```

---

## ⚠️ Read this first: client IP preservation

**This is the one thing that will silently break the security model on
Kubernetes.** JIT Access keys every grant on the client's IP address. By default
a `LoadBalancer` Service uses `externalTrafficPolicy: Cluster`, which SNATs
incoming traffic to a **node IP** before ingress-nginx ever sees it.

The consequence: every external client appears to come from one of a handful of
node addresses. One user knocks, and **every other internet client sharing that
node IP inherits the grant.** The gate looks like it is working while admitting
strangers.

Pick one of these before going to production:

| Approach | How | Trade-off |
|---|---|---|
| `externalTrafficPolicy: Local` | set it on the ingress-nginx Service | preserves the real client IP; traffic only reaches nodes running a controller pod |
| PROXY protocol | enable on the LB **and** in the controller ConfigMap (`use-proxy-protocol: "true"`) | preserves the real IP through L4 LBs; both sides must agree or every request breaks |
| Cloud LB with IP preservation | e.g. GKE container-native LB / NLB with IP targets | provider-specific |

Verify before you trust it — the address in the log must be a real client, not a
node or pod address:

```bash
kubectl logs -n ingress-nginx deploy/ingress-nginx-controller | tail -5
```

Then, as a belt-and-braces check, confirm two different clients get *different*
grants:

```bash
kubectl exec -n jit-system deploy/jit-authorizer -- \
  wget -qO- --header "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8998/admin/grants
```

If every grant shows the same IP, client-IP preservation is not working.

**Belt and braces:** as a second line, set `ipv6_prefix: 128` (the default) and
prefer `binding: "ip+cookie"` for anything sensitive. Cookie binding means a
shared source IP is no longer sufficient on its own — see the
[protocol overview](../../docs/how-it-works.md#5-grant-binding-why-ip-isnt-always-enough).

---

## Why two Ingresses

The knock endpoints must stay reachable **while the service is dark**, or a
device could never knock its way in. So `/.well-known/jit-access/` gets its own
Ingress that routes straight to the Authorizer and carries **no** auth
annotation. ingress-nginx matches the more specific path first.

## trusted_proxies — narrow it, do not paste RFC1918

The Authorizer sees the **ingress controller pod** as its TCP peer, not the
client, so it must be told to trust that hop and read the forwarded header:

```json
"trusted_proxies": ["10.42.0.0/16"]
```

Set this to the **ingress controller's pod CIDR**. Listing all of RFC1918 (which
earlier versions of this manifest did) breaks the design in two separate ways:

1. `/authz` and `/admin/*` refuse peers outside the list — and every pod in the
   cluster sits inside `10.0.0.0/8` by default, so a broad list makes that check
   a no-op and any workload in the cluster can drive the gate.
2. Resolving the client IP **skips** every candidate inside the list. On an
   on-prem or VPN cluster where users are on `10.x`, a broad list means every
   client is skipped, everyone falls back to the controller's own address, and
   they all **share one grant** — one person knocks and everybody is admitted.
   The `externalTrafficPolicy` warning above does not catch this, because it
   only affects external clients.

Find yours with `kubectl -n ingress-nginx get pods -o wide`.

## Reaching the Authorizer

The Service is `ClusterIP` with no Ingress of its own: `/authz` and `/admin/*`
must never be reachable from outside the cluster.

A ClusterIP is still reachable from **every pod in the cluster**, so
`authorizer.yaml` also ships a `NetworkPolicy` restricting `:8998` to the
ingress-controller namespace. Adjust its `namespaceSelector` to match your
controller. Without it, any compromised or hostile workload can call `/authz`
with headers of its choosing.

## admin_token

The shipped config deliberately has **no** `admin_token`, so `/admin/*` refuses
every request out of the box. A placeholder value would be a cluster-wide
backdoor for every operator who never changed it — and the admin API mints
grants that skip the registry re-check, i.e. access with no token at all.

To enable it, generate a value and add it to the Secret:

```bash
openssl rand -base64 32
```

Keep the NetworkPolicy in place regardless: the token is the second line, not
the first.

## Forgeable headers on the auth subrequest

ingress-nginx forwards the **client's own headers** on the auth subrequest, and
the controller pod is inside `trusted_proxies`. The controller describes the
original request with `X-Original-URL`; a client that also sends
`X-Forwarded-Host` or `X-Forwarded-Uri` is describing it a second, different way.

The Authorizer does **not** pick a winner — no fixed precedence is safe, because
which header is authoritative depends on the proxy. It reads every convention
present and **denies when two disagree**. So a forged header makes the attacker's
own request fail; it cannot select someone else's service or open the protocol
carve-out.

Blanking the unused ones with an `auth-snippet` is still worth doing — it turns a
confusing denial into a clean one — but it is defence in depth now, not the thing
standing between a client and someone else's grant:

```yaml
nginx.ingress.kubernetes.io/auth-snippet: |
  proxy_set_header X-Forwarded-Host "";
  proxy_set_header X-Original-Host "";
  proxy_set_header X-Forwarded-Uri "";
  proxy_set_header X-Original-Uri "";
```

## Known difference: no `X-JIT-Access` marker on denials

Every other engine answers a denied request with the interstitial **and** an
`X-JIT-Access: challenge; v=1` header, which the extension can detect to trigger
a knock. `ingress-nginx` answers a failed `auth_request` with **its own** error
page and does not proxy the auth service's response headers, so that marker does
not reach the browser.

This does not stop enrolled devices working: the extension knocks *proactively*
on navigation to an enrolled origin, which is the normal path. What you lose is
the marker-driven **recovery** path (notice a deny → knock → reload). If you want
it, forward the Authorizer's response with `custom-http-errors` plus a default
backend — most deployments do not need to.

Verified in [`test/harness/adapters`](../../test/harness/adapters): the
Kubernetes gate passes dark-before-knock, knock-accepted, service-opens and
replay-rejected, and reports this marker difference explicitly rather than
silently.

## Annotations reference

| Annotation | Purpose |
|---|---|
| `nginx.ingress.kubernetes.io/auth-url` | the Authorizer's `/authz` — this is the gate |
| `nginx.ingress.kubernetes.io/auth-response-headers: X-JIT-Kid` | optional; passes the admitting kid to the backend for logging. `Set-Cookie` is **not** needed: `/authz` never sets one — the grant cookie comes from the knock, which reaches the browser through the ungated protocol Ingress |
| `nginx.ingress.kubernetes.io/auth-snippet` | recommended; blanks the forwarding conventions the controller does not set, so a client cannot make its own request ambiguous |

## Rotating tokens

The token registry lives in a Secret. After editing it:

```bash
kubectl rollout restart -n jit-system deploy/jit-authorizer
```

Grants are in-process, so a restart clears them and enrolled clients silently
re-knock. To revoke one device without a restart, call the admin API instead:

```bash
kubectl exec -n jit-system deploy/jit-authorizer -- wget -qO- \
  --header "Authorization: Bearer $ADMIN_TOKEN" \
  --post-data '{"kid":"kid_x"}' http://localhost:8998/admin/revoke-token
```
