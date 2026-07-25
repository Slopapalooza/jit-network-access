# How JIT Network Access works

A visual tour of the protocol, from "the service is invisible" to "the page just
opens." Every diagram below reflects the implementation as built — the wire
format is pinned by [`PROTOCOL.md`](PROTOCOL.md) and the shared conformance
vectors.

---

## 1. The idea in one picture

A protected service answers **nothing useful** to an unknown visitor. A browser
with an enrolled device key silently proves itself and gets a short-lived pass.
No login screen, no VPN client, no user interaction.

```mermaid
flowchart LR
    A["Anyone on the internet"] -->|"GET /"| G{{"JIT gate"}}
    B["You, with the<br/>extension installed"] -->|"GET / + silent knock"| G
    G -->|"no valid knock"| D["403 device-authorization page<br/>or a bare 404 in stealth mode"]
    G -->|"valid knock"| S["Your service<br/>(Guacamole, Grafana, wiki…)"]

    classDef deny fill:#b04444,stroke:#8a3434,color:#ffffff
    classDef allow fill:#2eac68,stroke:#26935a,color:#ffffff
    class D deny
    class S allow
```

It is [Single Packet
Authorization](https://en.wikipedia.org/wiki/Single_Packet_Authorization)
(fwknop-style port knocking) reimagined for HTTPS and the browser: the "knock"
is an HTTP handshake instead of a crafted UDP packet, so it survives NAT, works
over 443, and needs no client software beyond a browser extension.

---

## 2. The knock handshake

This is the core protocol. It runs in about two round trips, entirely in the
background, on the protected origin's own hostname.

```mermaid
sequenceDiagram
    autonumber
    participant Tab as Browser tab
    participant Ext as Extension<br/>(service worker)
    participant Gate as JIT gate
    participant App as Your service

    Tab->>Gate: GET / (no grant yet)
    Gate-->>Tab: 403 + X-JIT-Access marker
    Note over Ext: the marker — or a navigation to<br/>an enrolled origin — triggers a knock

    Ext->>Gate: GET /.well-known/jit-access/challenge
    Note over Gate: mint nonce = ts ‖ random ‖ HMAC<br/>stateless, bound to this service + client IP
    Gate-->>Ext: 204 + X-JIT-Nonce

    Note over Ext: proof = HMAC-SHA256(device secret,<br/>PAE["jitaccess-v1", service, kid, nonce])<br/>key is non-extractable — the worker<br/>signs, it never sees the bytes

    Ext->>Gate: POST /respond {kid, nonce, proof}
    Note over Gate: 1. verify nonce MAC + freshness<br/>2. verify proof (same work for unknown kid)<br/>3. only now burn the nonce — single use
    Gate-->>Ext: 204 (grant created)

    Ext->>Tab: reload
    Tab->>Gate: GET /
    Gate->>App: proxied — the gate steps aside
    App-->>Tab: 200 your app
```

Three details carry most of the security weight:

**The nonce is stateless.** It carries its own HMAC and is bound to the service
and the client IP, so `/challenge` stores nothing. A flood of challenges costs
the server no memory — only *successful* knocks consume a spent-nonce slot.

**Verify, then burn.** The nonce is marked used only after the proof fully
verifies. A wrong proof therefore can't consume someone else's nonce.

**Unknown key IDs cost the same as wrong proofs.** The gate always computes
exactly one HMAC — with a dummy key when the `kid` is unknown — so response
timing never reveals which device IDs exist.

---

## 3. What the gate decides on every request

The grant isn't checked once at login; it's re-evaluated on **every** request.
That's what makes revocation instant rather than eventual.

```mermaid
flowchart TD
    R["Incoming request"] --> P{"path under<br/>/.well-known/jit-access/ ?"}
    P -->|yes| PE["Serve challenge / respond / enroll<br/>(reachable even while dark —<br/>otherwise you could never knock in)"]
    P -->|no| G{"live grant for<br/>this service + client IP?"}

    G -->|no| FM{"failure_mode"}
    G -->|yes| K{"is the grant's kid still<br/>registered and unexpired?"}

    K -->|"no — token deleted,<br/>revoked or expired"| FM
    K -->|yes| BND{"binding"}

    BND -->|"ip"| OK["Pass through to your service"]
    BND -->|"ip+cookie"| CK{"does the presented cookie<br/>hash match the stored one?"}
    CK -->|no| FM
    CK -->|yes| OK

    FM -->|interstitial| I["403 + X-JIT-Access marker<br/>(clear page, extension can detect it)"]
    FM -->|stealth| ST["404 — indistinguishable<br/>from a service that isn't there"]

    classDef deny fill:#b04444,stroke:#8a3434,color:#ffffff
    classDef allow fill:#2eac68,stroke:#26935a,color:#ffffff
    class I,ST deny
    class OK allow
```

Notice the re-check in the middle: deleting a device token evicts every grant it
issued on those clients' **next request**, not when the grant would have expired.

Everything on this chart fails closed. Any error, unparseable address, missing
config, or store failure lands on the deny path — the gate never opens a service
because something went wrong.

---

## 4. Enrolling a device

The device secret never travels in a link, a QR code, or an email. The admin
hands out a **single-use code**; the extension trades it for the secret over TLS.

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant UI as Admin UI
    participant Gate as JIT gate
    participant User as User's browser
    participant Ext as Extension

    Admin->>UI: create device token, pick its sites
    UI->>Gate: mint a one-time code
    Gate-->>UI: registration link (valid ~24 h, single use)
    Admin->>User: send the link (chat, email, ticket)

    User->>Gate: opens the link
    Note over Ext: the extension intercepts<br/>/.well-known/jit-access/register<br/>and shows a confirm page
    User->>Ext: clicks "Enroll this device"
    Ext->>Gate: POST /enroll {code}
    Note over Gate: consume the code — delete after read
    Gate-->>Ext: 204 + device secret (headers, over TLS)
    Note over Ext: import as a NON-EXTRACTABLE key<br/>in IndexedDB — the raw bytes are discarded
    Ext->>Gate: silent knock
    Gate-->>User: the site opens
```

What this buys: a link that leaks (forwarded email, shoulder-surfed screen) is
worth nothing after first use or after its window closes, and it never contained
the long-term secret in the first place. Once imported, the key cannot be
exported from the browser — not by the page, not by the extension, not by
another extension.

---

## 5. Grant binding: why `ip` isn't always enough

A grant admits **an address**. Behind a shared egress — an office NAT, CGNAT, a
VPN concentrator — that address isn't one person.

```mermaid
flowchart TB
    subgraph SHARED["Office / VPN — everyone shares one public IP"]
        You["Your laptop<br/>(enrolled)"]
        Them["A colleague's laptop<br/>(not enrolled)"]
        Guest["Someone on the guest wifi"]
    end

    You -->|knock| NAT["203.0.113.5"]
    Them --> NAT
    Guest --> NAT

    NAT --> IP{{"binding = ip"}}
    NAT --> IPC{{"binding = ip+cookie"}}

    IP --> IPR["Grant is keyed on the IP alone<br/>➜ everyone behind the NAT is admitted"]
    IPC --> IPCR["Grant also requires the opaque cookie<br/>the knock returned<br/>➜ only the browser that knocked is admitted"]

    classDef deny fill:#b04444,stroke:#8a3434,color:#ffffff
    classDef allow fill:#2eac68,stroke:#26935a,color:#ffffff
    class IPR deny
    class IPCR allow
```

With `ip+cookie`, a successful knock also returns a random, opaque grant id:

```
__Host-jit-grant=<32 random bytes>; Path=/; Secure; HttpOnly; SameSite=Strict
```

Only its SHA-256 is stored, and the comparison is constant-time — a dump of the
grant store yields nothing you could replay. Every attribute is load-bearing:

| Attribute | What breaks without it |
| --- | --- |
| `__Host-` prefix | a sibling subdomain could set or overwrite the grant cookie |
| `SameSite=Strict` | a malicious page could drive a victim's browser through the gate via a cross-site link |
| `HttpOnly` | script on the origin could read the grant id |
| stored as a hash | the grant store would hold a working credential |

---

## 6. One protocol, four engines

The gate is not tied to any single web server. The extension speaks only the
wire protocol and never knows what's enforcing it.

```mermaid
flowchart TB
    Ext["One extension,<br/>one enrolled token"]

    Ext --> BW["BunkerWeb plugin<br/>Lua, in-process"]
    Ext --> CD["Caddy module<br/>Go, in-process"]
    Ext --> AZ["Standalone Authorizer<br/>Go, single binary"]

    AZ -.->|forward-auth| NG["NGINX<br/>auth_request"]
    AZ -.->|forward-auth| TR["Traefik<br/>forwardAuth"]
    AZ -.->|ext_authz| EV["Envoy"]

    BW --> CORE["Same protocol, same canonical grant keys,<br/>same crypto — pinned by shared test vectors"]
    CD --> CORE
    AZ --> CORE

    classDef core fill:#2eac68,stroke:#26935a,color:#ffffff
    class CORE core
```

Two implementations of the core exist — Lua and Go — and both are held to the
same byte-level conformance vectors, so a proof minted by the extension verifies
identically no matter which engine answers. That claim is tested, not asserted:
the same knock client and the same device token unlock a service behind each
engine.

**In-process vs. forward-auth** is the one architectural difference worth
knowing. The BunkerWeb and Caddy gates run inside the web server, so they read
the client's real TCP address directly. The Authorizer sits *behind* a proxy, so
its peer is the proxy — it has to trust one specific header from specific hops,
which is why its config has a `trusted_proxies` list and why it refuses requests
from anywhere else.

---

## 7. The lifetime of a grant

```mermaid
stateDiagram-v2
    [*] --> Dark: service enabled
    Dark --> Granted: valid knock
    Granted --> Dark: TTL expires (default 1 h)
    Granted --> Dark: admin revokes the grant
    Granted --> Dark: device token deleted or regenerated
    Granted --> Dark: token reaches its expiry
    Granted --> Granted: silent re-knock before expiry
    Dark --> [*]: service disabled
```

Grants are deliberately short-lived and self-expiring. There's no session to
clean up and no revocation list to propagate: the worst case for a stolen laptop
is that its access dies at the TTL, and the best case is that you delete the
token and it dies on the next request.

---

## Where to go next

- **[BunkerWeb plugin guide](bunkerweb-plugin-guide.md)** — enable the gate,
  issue tokens, hand out enrollment links
- **[Chrome extension guide](chrome-extension-guide.md)** — install, enroll,
  day-to-day use
- **[PROTOCOL.md](PROTOCOL.md)** — the normative wire format
- **[core/SPEC.md](../core/SPEC.md)** — the portable core contract every engine
  implements
