# JIT Network Access — Chromium extension (MV3)

The browser client. When you navigate to an enrolled protected origin, the
service worker silently performs the challenge/respond **knock**, so the site
opens transparently — no visible login, no manual step.

Published at
**[JIT Network Access on the Chrome Web Store](https://chromewebstore.google.com/detail/jit-network-access/chkllfmckdloagomooelboobmoednkai)**
(extension ID `chkllfmckdloagomooelboobmoednkai`). This directory is the source
it is built from; a locally-built or self-signed copy gets a different ID,
because the store re-signs with its own key.

## Load it

1. Install from the store link above — or, for development, `chrome://extensions`
   → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
2. **Enroll** — one of three ways (all import the secret as a **non-extractable** WebCrypto key and ask for permission only to the named origins):

   - **Registration URL (easiest — nothing to copy).** Your admin hands you a link like
     `https://app.example.com/.well-known/jit-access/register?code=<code>&origins=…`.
     Just browse to it: the extension recognizes the pattern, opens its own confirm
     page listing the site(s), and one **Enroll** click grants permission and pulls
     the secret via a one-time-code exchange. The secret is never in the link.
   - **Setup string via options.** Open the extension's **options** page and paste a
     string from your admin. Either a code exchange (secret fetched from the server):
     ```
     jitaccess://enroll?v=1&server=https://app.example.com&code=<code>&origins=https://app.example.com&label=<name>
     ```
     or a direct import (testing only — carries the secret):
     ```
     jitaccess://enroll?v=1&kid=<kid>&secret=<b64url-secret>&origins=https://app.example.com&label=<name>
     ```
3. Visit the protected origin. The first hit may briefly show the "device authorization" interstitial; the worker knocks and reloads, and thereafter it opens transparently until the grant expires (then it re-knocks).

The toolbar **popup** shows the current tab's status (Not protected / Locked / Unlocked) and a **Knock now** button.

## Try it against the docker harness

Bring up `test/harness` (`run.sh`), add `127.0.0.1 app-a.local` to your hosts file, then enroll:
```
jitaccess://enroll?v=1&kid=kid_a_test&secret=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&origins=https://app-a.local:8443&label=harness-a
```
Visit `https://app-a.local:8443` — it should open after a silent knock.

## What's validated vs. what needs a browser

- **Validated here:** `src/jitcrypto.js` (WebCrypto) reproduces `core/testdata/vectors.json` byte-for-byte (`npm test` / `node src/jitcrypto.test.mjs`) — so the proof the extension computes is identical to the Python client and the Lua server. The knock logic mirrors the `knock_client.py` flow already validated end-to-end on real BunkerWeb.
- **Needs a browser (manual):** the MV3 plumbing itself — navigation detection, service-worker lifecycle, permissions, popup — is exercised by loading the extension as above.

## Security properties (DESIGN §7 / §11 R6)

- Auto-knock only on **top-level, main-frame** navigations (`frameId === 0`), never subframes / `window.open` — a hidden `<iframe>` on a hostile page cannot make the extension knock (confused-deputy fix).
- **No external messaging surface:** the manifest omits `externally_connectable` (web pages can't connect) and the worker registers **zero** `onMessageExternal`/`onConnectExternal` listeners, so a co-installed extension has nothing to invoke. Internal messages are `sender`-validated, the worker derives the origin from the **authenticated tab URL** (never the message), and a **proof is never returned across a message boundary** (signing-oracle fix). *Do not add any `*External` listener.*
- **Exact-origin** matching (scheme+host+port); **HTTPS-only**.
- Per-tab attempt cap + single-flight (no knock/reload storms). The cap is what
  bounds retries — there is no time-based backoff.
- A tab opened by another page (`window.open`, `target=_blank`) does not
  auto-knock at its first destination, so a hostile page cannot make the browser
  create a grant the user never asked for.
- The `webRequest` recovery listener is registered **only for origins you've granted** (never `https://*/*`) and re-registered when you enroll/remove a token — so the extension never asks for all-sites access.
- Secret is a **non-extractable** key in IndexedDB; config in `storage.local`; grant cache in `storage.session`; **never** `storage.sync`.

## Note on enrollment

The **one-time-code exchange** (`DESIGN.md` §6.1 shipping baseline — secret never
in the link) is implemented, both via a pasted setup string and via the
registration-URL confirm page (`enroll.html`), which is why the confirm page must
request host permission on a user click before it can call the server. Shared
enrollment logic lives in `src/enroll_core.js`. Direct import (secret in the
string) remains for testing. The target is still v3 asymmetric keys (server stores
only a public key); the non-extractable-key handling here is unchanged by how the
secret arrives.

The registration URL is intercepted in `src/sw.js` via `webNavigation` (which
needs no host permission to *observe* a navigation); the worker then redirects the
tab to the extension's own `enroll.html`, because MV3 requires a **user gesture**
to call `chrome.permissions.request` — so the grant + code exchange happen on the
confirm page's button click, not silently.

## Building a release bundle

```bash
cd extension && ./build.sh
```

Produces in `extension/dist/` (git-ignored — release artifacts are attached to a
GitHub release, not committed):

| Artifact | For |
|---|---|
| `jit-access-<version>.zip` | Chrome Web Store upload, and the **Load unpacked** route |
| `jit-access-<version>.crx` | signed; managed/policy force-install |
| `SHA256SUMS` | verify what you downloaded |

`build.sh` validates before it packs — manifest shape, that every file the
manifest references exists, that `externally_connectable` is still absent and the
CSP still pins `script-src 'self'`, and that the crypto still reproduces the
shared vectors. A bundle that installs and then silently fails to knock is worse
than no bundle.

Packing is done by `crx3.py`, which builds the CRX3 container directly and needs
only `openssl` — no browser, so the same command works locally and in CI. It
verifies its own output before declaring success (`crx3.py --verify <file>`).

### Signing

The `.crx` is signed with a PEM that is **not in this repo and must never be**:
that key *is* the extension's identity, and anyone holding it can publish an
update every installed browser will accept. Point `JIT_EXT_KEY` at it, or omit it
and get the `.zip` only:

```bash
JIT_EXT_KEY=/path/to/JIT-Access.pem ./build.sh
```

Reusing the same key keeps the extension ID stable across releases, which is what
lets an installed browser take an update and what a force-install policy pins to.
Print it with `python3 crx3.py --id /path/to/key.pem`.

### Publishing

Tag and push; `.github/workflows/extension-release.yml` builds and creates the
release. The job refuses to publish when the tag and `manifest.version` disagree.

```bash
git tag ext-v$(python3 -c "import json;print(json.load(open('extension/manifest.json'))['version'])")
git push origin --tags
```

CI signs with the `EXT_SIGNING_KEY` repo secret (`gh secret set EXT_SIGNING_KEY <
JIT-Access.pem`); without it the release carries the `.zip` alone and says so.

### Users who do not have it yet

A registration link points at `<host>/.well-known/jit-access/register?code=...`.
With the extension installed, the service worker intercepts that navigation
before it leaves the browser. Without it, the request reaches the server — which
serves an install page pointing at the releases above. So the person who most
needs the download link is exactly the one who gets it, and an enrolled user
never sees the page.
