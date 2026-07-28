# Conformance suites

Black-box tests that drive a **deployed** JIT-gated stack over the real wire
protocol, using the shared Python crypto (`core/py/jitcrypto.py`) — so a green
run proves genuine cross-implementation interop (Python client ↔ Lua server),
not just vector matching.

## `differential.py` — cross-language canonicalizer fuzzing

Needs no deployment: it runs offline against the four references directly.

```bash
python3 test/conformance/differential.py
```

`canon_server_name` and `canon_ip` decide the grant key and the MAC input, and
they are implemented four times — Go, Python, JavaScript and Lua. A one-byte
disagreement between any two means a knock minted on one engine does not verify
on another; a *collision* inside one means two services share a key.

`vectors.json` pins the answers for inputs somebody thought of. This throws
generated input at all four at once and diffs the answers, so the ones nobody
thought of surface as a disagreement rather than as a production bypass. It also
asserts idempotency per reference: canonicalization runs at more than one layer
(config keys at load, `Host` at request), so a result that moves on a second pass
means two layers can hold two different names for one service.

Probes: `core/go/canonprobe` (Go), `canonprobe.mjs` (the extension's real
`jitcrypto.js` under Node), direct import for Python, and
`core/lua/canon_port_check.py` — a byte-level transliteration of `canon.lua`,
because there is no Lua runtime on the dev host. Failures are reproducible from
the printed `--seed`.

### What this harness caught

Three bugs in `canon_server_name`, all of which the pinned vectors missed:

- An unbracketed IPv6 `Host` had its last group eaten as a `:port`, so
  `2001:db8::1` and `2001:db8::2` both canonicalized to `2001:db8:` — one grant
  key and one MAC input for two different services.
- Trailing dots and whitespace were each stripped once, so `..` → `.` → `` and
  `example.com:443.` → `example.com:443` → `example.com`: the answer depended on
  how many times a value had been canonicalized.
- Python counted Unicode digits as a port number (`str.isdigit()`), and Python,
  Go and JS all did Unicode-aware trimming and lowercasing where Lua's `%s` and
  `:lower()` are ASCII-only. All four are now pinned to ASCII, which is what a
  hostname is under IDNA anyway.

## `knock_client.py` — the handshake driver (functional)

One full challenge → HMAC-proof → respond handshake, with optional service check
and replay.

```bash
python3 knock_client.py --url https://app-a.local --kid <kid> --secret <b64url> \
    --resolve app-a.local:443:127.0.0.1 --check-service --replay
```

Prints `KNOCK <code>` (204 = accepted), and optionally `SERVICE <code>` /
`REPLAY <code>`. `run.sh` drives it against the docker harness for the
"unlock A not B + replay rejected" matrix.

## `security_suite.py` — adversarial probes (M2.5)

An adapter is "supported" only when it passes these, not just the functional
knock. **12/12 validated on real BunkerWeb.** The suite needs two JIT-enabled
services, so run it against the two-service harness in `../harness/` (pinned to
1.6.13).

| Probe | Property |
|---|---|
| malformed `/respond` × many | never returns 204; the gate still works after (fail-closed, not crash-open) |
| tampered proof / tampered nonce | rejected |
| unknown kid | rejected, and **indistinguishable** from a bad-proof rejection (no timing/`status` oracle) |
| cross-service proof reuse | a valid `(nonce, proof)` for A is rejected at B (PAE `server_name` binding) |
| replay | second use of a nonce rejected (single-use) |
| forged `X-Forwarded-For` / `X-Real-IP` | **cannot inherit another IP's grant** (Simple keys on the TCP peer) |
| well-known path traversal | never reaches the upstream |

```bash
python3 security_suite.py \
  --a-url https://jit-a.local --a-resolve jit-a.local:443:127.0.0.1 --a-kid <kid> --a-secret <b64url> --a-name jit-a.local \
  --b-url https://jit-b.local --b-resolve jit-b.local:443:127.0.0.1 --b-name jit-b.local \
  --api http://127.0.0.1:5000 --api-token <instance API_TOKEN>
```

`--api` / `--api-token` point at the instance internal API (for setup grants,
e.g. granting a distinct victim IP for the XFF probe).

### What this suite caught

On the first real-server run it found a genuine vulnerability: the plugin keyed
grants on `ngx.var.remote_addr`, which BunkerWeb's `realip` rewrites from
`X-Forwarded-For` when `USE_REAL_IP=yes`. On an instance with broad
`REAL_IP_FROM` trust, a forged `X-Forwarded-For` let a client inherit another
IP's grant (SECURITY-REVIEW C2/R2). Fixed by keying on `$realip_remote_addr`
(the un-forgeable TCP peer) by default, with `JIT_ACCESS_TRUST_REALIP=yes` as the
Hardened opt-in for deployments genuinely behind a trusted proxy with a correctly
narrowed `REAL_IP_FROM`.
