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

## trusted_proxies

The Authorizer sees the **ingress controller pod** as its TCP peer, not the
client, so it must be told to trust that hop and read the forwarded header:

```json
"trusted_proxies": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

Narrow this to your actual pod CIDR if you know it. Everything outside the list
is treated as a direct client whose forwarded headers are ignored — which is why
the Authorizer stays safe even if something else reaches it.

The Service is deliberately `ClusterIP` with no Ingress of its own: `/authz` and
`/admin/*` must never be reachable from outside the cluster. The Authorizer also
refuses those paths from any peer outside `trusted_proxies`, but not being
routable is the real control.

## Annotations reference

| Annotation | Purpose |
|---|---|
| `nginx.ingress.kubernetes.io/auth-url` | the Authorizer's `/authz` — this is the gate |
| `nginx.ingress.kubernetes.io/auth-response-headers: Set-Cookie` | **required for `ip+cookie`** — without it the grant cookie never reaches the browser |
| `nginx.ingress.kubernetes.io/auth-snippet` | optional; forward extra headers to the Authorizer |

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
