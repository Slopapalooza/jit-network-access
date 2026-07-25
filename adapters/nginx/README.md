# JIT Network Access — plain NGINX recipe

NGINX has no plugin here: it delegates to the [standalone
Authorizer](../../authorizer) over `auth_request`. Copy
[`jitaccess.conf`](jitaccess.conf) into your server block.

```
browser ──HTTPS──> nginx ──auth_request──> authorizer (127.0.0.1:8998)
                     │
                     └──> your upstream (only when the Authorizer says 204)
```

## Setup

1. Run the Authorizer on loopback (see [its README](../../authorizer/README.md)).
   `trusted_proxies` must contain the address NGINX connects **from** — with both
   on one host, the default `127.0.0.0/8` is correct.
2. Include `jitaccess.conf` in the `server { }` block you want gated.
3. Reload NGINX.

## The two things that matter

**Strip inbound `X-Forwarded-*`.** The Authorizer trusts the header NGINX sends,
so the client must not be able to pre-set it. The config below always *assigns*
`X-Forwarded-For` from `$remote_addr` rather than appending, which overwrites
anything the client sent.

**Keep the Authorizer off the internet.** It must be bound to loopback or an
internal interface. It refuses `/authz` and `/admin/*` from peers outside
`trusted_proxies` as a second line of defence, but the listener is the first.

If NGINX itself is behind a CDN/load balancer, set `$remote_addr` correctly with
`real_ip_module` (`set_real_ip_from` = the exact front-door hops, never a broad
RFC1918 range) *before* this config uses it — the same rule the BunkerWeb plugin
follows (SECURITY-REVIEW C2/R2).
