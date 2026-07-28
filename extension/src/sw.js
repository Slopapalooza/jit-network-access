// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

// JIT Network Access — MV3 service worker.
//
// Silently performs the knock so an enrolled protected origin opens without the
// user seeing the challenge. Security rules (DESIGN §7 / §11 R6) enforced here:
//   - auto-knock ONLY on top-level, main-frame navigations (frameId === 0), and
//     never on the first destination of a tab another page opened
//     (window.open / target=_blank — confused-deputy fix, SECURITY-REVIEW C5).
//     Suppression persists until the tab makes a navigation whose transition
//     says the USER drove it (typed / bookmark / reload / generated, and not a
//     client_redirect), so an opener cannot shake it off with one extra hop.
//     Residual, stated plainly: a same-tab script navigation in a tab the user
//     already owned (location.href = ...) is indistinguishable from a click at
//     the API level and IS still knocked. Use binding: ip+cookie where that
//     matters — it stops a co-located client inheriting a grant even if one is
//     created.
//   - NO external messaging surface: the manifest omits externally_connectable
//     (so web pages can't connect) and this worker registers ZERO onMessageExternal
//     / onConnectExternal listeners — so a co-installed extension has nothing to
//     invoke. Internal messages are sender-validated, the worker derives the
//     origin from the authenticated tab (never from message payload), and a proof
//     is NEVER returned across a message boundary (signing-oracle fix, C6).
//     (Do not add any *External listener — that is what keeps the key locked.)
//   - exact-origin matching; HTTPS-only
//   - per-tab attempt cap + single-flight (no knock storms, H12). There is no
//     time-based backoff; the cap is what bounds retries.

import { getKey, tokenForOrigin, getGrant, setGrant } from "./store.js";
import { b64uDecode, buildProof } from "./jitcrypto.js";

const PREFIX = "/.well-known/jit-access";
const MAX_ATTEMPTS = 2;          // per tab per origin, then surface the interstitial
const LOCAL_GRANT_MS = 60_000;   // conservative client cache; server TTL is authoritative

const inflight = new Map();      // origin -> Promise  (single-flight)
const attempts = new Map();      // tabId  -> { origin, n }

const originOf = (url) => { try { return new URL(url).origin; } catch { return null; } };
const isHttps = (url) => { try { return new URL(url).protocol === "https:"; } catch { return false; } };

// The whole handshake for one origin. Returns true iff a grant was created.
async function knock(origin) {
  if (inflight.has(origin)) return inflight.get(origin);
  const p = (async () => {
    const token = await tokenForOrigin(origin);
    if (!token) return false;
    const key = await getKey(token.kid);
    if (!key) return false;

    // 1. challenge — read the server nonce (host permission lets us read headers)
    const cr = await fetch(origin + PREFIX + "/challenge", { cache: "no-store", credentials: "omit" });
    const nonceB64 = cr.headers.get("X-JIT-Nonce");
    if (!nonceB64) return false;

    // 2. proof over the canonical (server_name = origin host)
    const host = new URL(origin).hostname;
    const proof = await buildProof(key, host, token.kid, b64uDecode(nonceB64));

    // 3. respond
    //
    // credentials MUST be "include" here, unlike the challenge above: with
    // ip+cookie binding the server answers a successful knock with a Set-Cookie
    // carrying the opaque grant id, and the browser only stores it when the
    // request was credentialed. With "omit" the cookie is silently dropped, the
    // grant can never be satisfied, and the page re-knocks forever.
    const rr = await fetch(origin + PREFIX + "/respond", {
      method: "POST", cache: "no-store", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ v: 1, kid: token.kid, nonce: nonceB64, proof }),
    });
    if (rr.status === 204) {
      await setGrant(origin, Date.now() + LOCAL_GRANT_MS);
      return true;
    }
    return false;
  })().finally(() => inflight.delete(origin));
  inflight.set(origin, p);
  return p;
}

// Tabs another page opened (window.open / target=_blank). PROTOCOL §7 excludes
// these by name: a hostile page that can open a tab at an enrolled origin could
// otherwise make us knock, creating an IP-keyed grant the user never intended —
// which on shared egress (office NAT, CGNAT, VPN) opens the service to everyone
// behind that address (confused-deputy, SECURITY-REVIEW C5).
//
// Cleared on a navigation that carries a user-gesture transition, NOT simply on
// the first commit: clearing at first commit meant one extra hop defeated the
// whole control (open a blank page, then navigate it to the enrolled origin).
// Entries also expire on their own, so a tab whose first navigation never
// commits — a cancelled or failed load — cannot silently suppress that tab's
// knocks forever.
const pageOpened = new Map(); // tabId -> timestamp
const PAGE_OPENED_TTL_MS = 5 * 60_000;
const USER_TRANSITIONS = new Set(["typed", "auto_bookmark", "generated", "keyword", "reload"]);

function openedByPage(tabId) {
  const t = pageOpened.get(tabId);
  if (t === undefined) return false;
  if (Date.now() - t > PAGE_OPENED_TTL_MS) { pageOpened.delete(tabId); return false; }
  return true;
}

chrome.webNavigation.onCreatedNavigationTarget.addListener((d) => pageOpened.set(d.tabId, Date.now()));
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  // Only a navigation the USER drove releases the tab. A script-driven hop
  // (transitionType "link" with a client_redirect qualifier, or any transition
  // the page itself caused) leaves the suppression in place.
  const quals = d.transitionQualifiers || [];
  const userDriven = USER_TRANSITIONS.has(d.transitionType) && !quals.includes("client_redirect");
  if (userDriven) pageOpened.delete(d.tabId);
});
chrome.webNavigation.onErrorOccurred.addListener((d) => {
  if (d.frameId === 0) pageOpened.delete(d.tabId);
});

// Proactive: a genuine top-level navigation to an enrolled origin -> best-effort
// knock in parallel with the load. If the grant lands first the page just opens;
// otherwise the recovery path below catches the interstitial.
chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || d.parentFrameId !== -1) return;   // top-level main frame ONLY
  if (!isHttps(d.url)) return;

  // Registration URL: <host><PREFIX>/register?code=... — hand the token off to
  // our confirm page. webNavigation fires for all URLs (no host permission
  // needed to observe), and we navigate the tab to our own page; the confirm
  // page then requests permission + exchanges the code on a user click.
  //
  // The path is matched EXACTLY, not with endsWith: any site could otherwise
  // serve /anything/.well-known/jit-access/register and steer the tab into our
  // consent UI. Exact matching does not make an untrusted origin trustworthy —
  // the consent page names the issuing server and the user still has to
  // approve — but it removes the "buried under an unrelated path" variant.
  //
  // `origins` IS forwarded, because the consent page has to show what the link
  // claims it is for. It is attacker-controlled, so it is treated as display
  // text only: enrollToken() enrols exactly the set the user approved and
  // refuses a server that tries to widen it.
  let u;
  try { u = new URL(d.url); } catch { return; }
  if (u.pathname === PREFIX + "/register" && u.searchParams.get("code")) {
    const dest = chrome.runtime.getURL("enroll.html") + "?" + new URLSearchParams({
      server: u.origin,
      code: u.searchParams.get("code") || "",
      origins: u.searchParams.get("origins") || u.origin,
      label: u.searchParams.get("label") || "",
    }).toString();
    // The one-time code is NOT logged: it is a bearer credential for a device
    // secret, and the service-worker console is readable from devtools.
    console.log("[JIT] registration URL detected on", u.origin, "→ opening enroll page in tab", d.tabId);
    chrome.tabs.update(d.tabId, { url: dest }).then(
      () => console.log("[JIT] redirect to enroll page OK"),
      (e) => console.error("[JIT] tabs.update to enroll page FAILED:", e && e.message),
    );
    return;
  }

  if (openedByPage(d.tabId)) return;                      // opened by another page
  const origin = originOf(d.url);
  if (!origin) return;
  if (!(await tokenForOrigin(origin))) return;
  if (await getGrant(origin)) return;                       // already have a fresh grant
  knock(origin).catch(() => {});
});

// Recovery: a main-frame response carrying the deny marker -> knock, then reload.
// Capped per tab so a persistent marker can't cause a reload storm.
function onHeaders(d) {
  if (d.type !== "main_frame") return;
  const marked = (d.responseHeaders || []).some((h) => h.name.toLowerCase() === "x-jit-access");
  if (!marked) {
    // The gate let this through: the knock worked. THIS is the success signal
    // that clears the per-tab budget, not a 204 from /respond.
    attempts.delete(d.tabId);
    return;
  }
  // Same exclusion as the proactive path: a page-opened tab must not be able to
  // drive a knock, and this fires before onCommitted clears the flag.
  if (openedByPage(d.tabId)) return;
  const origin = originOf(d.url);
  if (!origin) return;
  tokenForOrigin(origin).then(async (token) => {
    if (!token) return;                                     // marker on a non-enrolled origin: ignore
    const rec = attempts.get(d.tabId) || { origin, n: 0 };
    if (rec.origin !== origin) { rec.origin = origin; rec.n = 0; }
    if (rec.n >= MAX_ATTEMPTS) return;                      // give up; user sees the interstitial
    rec.n += 1;
    attempts.set(d.tabId, rec);
    const ok = await knock(origin).catch(() => false);
    // Do NOT clear the counter on knock success. A 204 means the verifier
    // accepted the proof, not that the reload will be admitted — with ip+cookie
    // on a browser that drops the cookie, or a grant keyed on an address the
    // reload arrives from differently, the reloaded page carries the marker
    // again and we knock again, forever. The counter is what bounds that, so it
    // must survive a "successful" knock; it is reset only when a response for
    // this tab arrives WITHOUT the marker, i.e. the grant demonstrably worked.
    if (ok) chrome.tabs.reload(d.tabId);
  });
}

// webRequest needs HOST PERMISSION for the URLs it observes. We only hold
// per-origin (optional) permissions granted at enrollment, so register the
// listener for exactly those origins — never https://*/* — and re-register when
// permissions change (enroll / remove token).
async function refreshWebRequest() {
  if (chrome.webRequest.onHeadersReceived.hasListener(onHeaders)) {
    chrome.webRequest.onHeadersReceived.removeListener(onHeaders);
  }
  const perms = await chrome.permissions.getAll();
  const urls = (perms.origins || []).filter((o) => o.startsWith("https://"));
  if (urls.length) {
    chrome.webRequest.onHeadersReceived.addListener(onHeaders, { urls, types: ["main_frame"] }, ["responseHeaders"]);
  }
}
refreshWebRequest();
chrome.permissions.onAdded.addListener(refreshWebRequest);
chrome.permissions.onRemoved.addListener(refreshWebRequest);

chrome.tabs.onRemoved.addListener((tabId) => { attempts.delete(tabId); pageOpened.delete(tabId); });

// Popup messaging only. Sender is validated; the origin is derived from the
// authenticated tab (never from the message); a proof is never returned.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;              // not us -> ignore
  if (!msg || typeof msg.tabId !== "number") return;

  if (msg.type === "status") {
    (async () => {
      const tab = await chrome.tabs.get(msg.tabId).catch(() => null);
      const origin = tab && originOf(tab.url);
      const token = origin ? await tokenForOrigin(origin) : null;
      const grant = origin ? await getGrant(origin) : null;
      sendResponse({ origin, enrolled: !!token, granted: !!grant, https: tab ? isHttps(tab.url) : false });
    })();
    return true;
  }
  if (msg.type === "knock") {
    (async () => {
      const tab = await chrome.tabs.get(msg.tabId).catch(() => null);
      const origin = tab && originOf(tab.url);
      const ok = origin ? await knock(origin).catch(() => false) : false;
      if (ok) chrome.tabs.reload(msg.tabId);
      sendResponse({ ok });                                 // boolean only — never the proof
    })();
    return true;
  }
});
