# JIT Network Access — Chromium extension (MV3)

The browser client. When you navigate to an enrolled protected origin, the
service worker silently performs the challenge/respond **knock**, so the site
opens transparently — no visible login, no manual step.

## Load it

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
2. Open the extension's **options** page and paste a setup string from your admin:
   ```
   jitaccess://enroll?v=1&kid=<kid>&secret=<b64url-secret>&origins=https://app.example.com&label=<name>
   ```
   Enrolling asks for permission to those origins (so the worker may knock there) and imports the secret as a **non-extractable** WebCrypto key.
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
- Per-tab attempt cap + single-flight + backoff (no knock/reload storms).
- The `webRequest` recovery listener is registered **only for origins you've granted** (never `https://*/*`) and re-registered when you enroll/remove a token — so the extension never asks for all-sites access.
- Secret is a **non-extractable** key in IndexedDB; config in `storage.local`; grant cache in `storage.session`; **never** `storage.sync`.

## Note on enrollment

This MVP uses **direct token import** (the setup string carries the secret). Per
`DESIGN.md` §6.1 the shipping baseline is a **one-time-code exchange** at
`<prefix>/enroll` (secret never in the QR/URL), and the target is v3 asymmetric
keys (server stores only a public key). Those depend on a server `/enroll`
endpoint that is the next protocol increment; the non-extractable-key handling
here is unchanged by how the secret arrives.
