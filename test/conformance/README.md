# Conformance suites

Black-box tests that drive a **deployed** JIT-gated stack over the real wire
protocol, using the shared Python crypto (`core/py/jitcrypto.py`) — so a green
run proves genuine cross-implementation interop (Python client ↔ Lua server),
not just vector matching.

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
knock. **12/12 validated on real BunkerWeb 1.6.10.**

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
