// Enrollment + grant state for the extension.
//
//  - the token SECRET is imported as a NON-EXTRACTABLE HMAC CryptoKey and stored
//    in IndexedDB (structured-clone keeps the handle, not the bytes). Raw bytes
//    are discarded after import.
//  - non-secret config (kid, origins, label) lives in chrome.storage.local.
//  - the short grant cache lives in chrome.storage.session (cleared on browser
//    exit; the server is always the authoritative gate).
//  - NEVER chrome.storage.sync (would upload to the account).

import { importSecret } from "./jitcrypto.js";

const DB = "jitaccess";
const KEYS = "keys";

function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(KEYS);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
function tx(db, mode, fn) {
  return new Promise((res, rej) => {
    const t = db.transaction(KEYS, mode);
    const store = t.objectStore(KEYS);
    const req = fn(store);
    t.oncomplete = () => res(req && req.result);
    t.onerror = () => rej(t.error);
  });
}
const idbPut = async (kid, key) => tx(await idb(), "readwrite", (s) => s.put(key, kid));
const idbGet = async (kid) => tx(await idb(), "readonly", (s) => s.get(kid));
const idbDel = async (kid) => tx(await idb(), "readwrite", (s) => s.delete(kid));

// ---- tokens ----------------------------------------------------------------

export async function listTokens() {
  const { tokens = [] } = await chrome.storage.local.get("tokens");
  return tokens;
}

export async function enroll({ kid, secretBytes, origins, label }) {
  const key = await importSecret(secretBytes);   // non-extractable
  await idbPut(kid, key);                          // only the key handle persists
  const tokens = (await listTokens()).filter((t) => t.kid !== kid);
  if (!label && origins && origins.length) {
    try { label = new URL(origins[0]).hostname; } catch { label = ""; }   // registration-URL flow has no label
  }
  tokens.push({ kid, origins, label: label || "" });
  await chrome.storage.local.set({ tokens });
}

export async function removeToken(kid) {
  await idbDel(kid);
  const tokens = (await listTokens()).filter((t) => t.kid !== kid);
  await chrome.storage.local.set({ tokens });
}

export async function getKey(kid) {
  return idbGet(kid);
}

// Exact-origin match (scheme+host+port). No substring / implicit-subdomain.
export async function tokenForOrigin(origin) {
  return (await listTokens()).find((t) => t.origins.includes(origin));
}

// ---- grant cache (session) -------------------------------------------------

export async function getGrant(origin) {
  const { grants = {} } = await chrome.storage.session.get("grants");
  const exp = grants[origin];
  return exp && exp > Date.now() ? exp : null;
}
export async function setGrant(origin, expiresAt) {
  const { grants = {} } = await chrome.storage.session.get("grants");
  grants[origin] = expiresAt;
  await chrome.storage.session.set({ grants });
}
export async function clearGrant(origin) {
  const { grants = {} } = await chrome.storage.session.get("grants");
  delete grants[origin];
  await chrome.storage.session.set({ grants });
}
