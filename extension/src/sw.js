// JIT Network Access — MV3 service worker.
//
// Silently performs the knock so an enrolled protected origin opens without the
// user seeing the challenge. Security rules (DESIGN §7 / §11 R6) enforced here:
//   - auto-knock ONLY on top-level, main-frame navigations (frameId === 0),
//     never subframes / window.open (confused-deputy fix, SECURITY-REVIEW C5)
//   - NO external messaging surface: the manifest omits externally_connectable
//     (so web pages can't connect) and this worker registers ZERO onMessageExternal
//     / onConnectExternal listeners — so a co-installed extension has nothing to
//     invoke. Internal messages are sender-validated, the worker derives the
//     origin from the authenticated tab (never from message payload), and a proof
//     is NEVER returned across a message boundary (signing-oracle fix, C6).
//     (Do not add any *External listener — that is what keeps the key locked.)
//   - exact-origin matching; HTTPS-only
//   - per-tab attempt cap + single-flight + backoff (no knock storms, H12)

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
    const rr = await fetch(origin + PREFIX + "/respond", {
      method: "POST", cache: "no-store", credentials: "omit",
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
  let u;
  try { u = new URL(d.url); } catch { return; }
  if (u.pathname.endsWith(PREFIX + "/register") && u.searchParams.get("code")) {
    const dest = chrome.runtime.getURL("enroll.html") + "?" + new URLSearchParams({
      server: u.origin,
      code: u.searchParams.get("code") || "",
      origins: u.searchParams.get("origins") || u.origin,
      label: u.searchParams.get("label") || "",
    }).toString();
    console.log("[JIT] registration URL detected:", u.href, "→ redirecting tab", d.tabId, "to enroll page");
    chrome.tabs.update(d.tabId, { url: dest }).then(
      () => console.log("[JIT] redirect to enroll page OK"),
      (e) => console.error("[JIT] tabs.update to enroll page FAILED:", e && e.message),
    );
    return;
  }

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
  const hasMarker = (d.responseHeaders || []).some((h) => h.name.toLowerCase() === "x-jit-access");
  if (!hasMarker) return;
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
    if (ok) { attempts.delete(d.tabId); chrome.tabs.reload(d.tabId); }
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

chrome.tabs.onRemoved.addListener((tabId) => attempts.delete(tabId));

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
