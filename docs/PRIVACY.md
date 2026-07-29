# Privacy Policy — JIT Network Access (browser extension)

**Effective 28 July 2026.** Applies to the JIT Network Access extension for
Chrome and other Chromium browsers, published from
<https://github.com/Slopapalooza/jit-network-access>.

## Summary

The extension collects nothing. There is no analytics, no telemetry, no
crash reporting, no advertising identifier, and no third-party service of any
kind. Nothing is sent to the publisher. The only servers it ever contacts are
the ones **you** enrolled it against — servers your own organisation runs.

## What the extension stores, and where

Everything below is stored **locally in your browser** and never transmitted
anywhere by the extension.

| Data | Where | Why |
|---|---|---|
| Device key (the enrollment secret) | IndexedDB, as a **non-extractable** WebCrypto key | Computes the proof that opens a protected site |
| Key id, label, and the origins you enrolled for | `chrome.storage.local` | Identifies which key to use for which site |
| Which enrolled origins are currently unlocked, and when that expires | `chrome.storage.session` | Avoids re-running the handshake on every navigation |
| Per-tab attempt counters | Service-worker memory only | Stops retry loops |

Two properties are deliberate and worth stating plainly:

- The device key is imported as a **non-extractable** key. Neither the
  extension, nor a web page, nor anyone with access to the browser profile UI
  can read the key material back out. The extension can only ask the browser to
  compute with it.
- Nothing is written to `chrome.storage.sync`. Your device key does **not**
  replicate to your other machines through your Google account. Each browser you
  want to use must be enrolled separately, on purpose.

`chrome.storage.session` is cleared when the browser closes. Service-worker
memory is cleared whenever the worker is suspended.

## What the extension sends, and to whom

Only to origins you have explicitly enrolled, and only these requests:

- A **challenge** request and a **respond** request under that origin's
  `/.well-known/jit-access/` path — the knock. The respond request carries your
  key id and a computed proof. **It does not carry your secret**, which never
  leaves the browser.
- During enrollment, a **one-time code exchange** with the server address your
  administrator gave you, to fetch the device key. The enrollment link contains
  a single-use code, not the secret.

The extension does not contact the publisher, does not contact any analytics or
CDN endpoint, and does not read or transmit page content, browsing history, form
data, or cookies. It observes navigation events to know when to knock; it does
not record them.

## Permissions

| Permission | What it is used for |
|---|---|
| `storage` | The local storage described above |
| `webNavigation` | Notice that you are navigating to an enrolled origin so the knock can run, and recognise an enrollment link so it can be confirmed inside the extension |
| `webRequest` | Notice a response from an enrolled origin that indicates a grant has expired, so the next visit re-knocks. Registered **only** for origins you have granted — never for all sites |
| `tabs` | Read the active tab's URL so the toolbar popup can show whether that site is protected, locked or unlocked, and reload the tab after a successful knock |
| Host access (`https://…`) | Declared as an **optional** permission and requested one origin at a time, on your click, during enrollment. Internal hostnames differ per organisation and cannot be listed when the extension is published, which is why the declaration is broad; the grant you actually give is not |

The extension executes no remotely-hosted code. All scripts ship inside the
package and its Content Security Policy pins `script-src 'self'`.

## Removing your data

- **One enrollment:** open the extension's Options page and choose **Remove** on
  that entry. Its key, configuration and host permission are dropped.
- **Everything:** uninstall the extension. Chrome deletes its IndexedDB, local
  storage and session storage with it.

Removing an enrollment in the browser does not tell the server anything. If a
device should no longer have access, ask your administrator to revoke its key id
server-side as well — that is what actually withdraws access.

## Children

The extension is a tool for administering access to private infrastructure. It
is not directed at children and collects no personal information from anyone.

## Changes

Material changes to this policy will be committed to the repository above, so
the file history is the change log. The effective date at the top will be
updated.

## Contact

Questions, or a security report:
<https://github.com/Slopapalooza/jit-network-access/issues>

For security issues specifically, please see the repository's reporting
guidance rather than opening a public issue.

## Source

The extension is free software under **AGPL-3.0**. Every claim on this page can
be checked against the source, which is public:
<https://github.com/Slopapalooza/jit-network-access/tree/main/extension>
