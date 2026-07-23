// JIT Network Access — browser crypto (L2/L3).
//
// The same byte-level constructions as core/py/jitcrypto.py and
// core/lua/jitaccess/core, in WebCrypto. Pinned by core/testdata/vectors.json.
// Runs in an MV3 service worker and in Node 24 (both expose crypto.subtle).

const enc = new TextEncoder();

// ---- base64url (no padding) ----------------------------------------------

export function b64uEncode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (str.length % 4)) % 4;
  const bin = atob(str + "=".repeat(pad));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- PAE (PASETO-compatible) ----------------------------------------------

function le64(n) {
  const b = new Uint8Array(8);
  let x = n;
  for (let i = 0; i < 8; i++) { b[i] = x & 0xff; x = Math.floor(x / 256); }
  b[7] &= 0x7f;
  return b;
}

function concatBytes(chunks) {
  let len = 0;
  for (const c of chunks) len += c.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

// pieces: array of Uint8Array
export function pae(pieces) {
  const chunks = [le64(pieces.length)];
  for (const p of pieces) { chunks.push(le64(p.length)); chunks.push(p); }
  return concatBytes(chunks);
}

// ---- canonicalization ------------------------------------------------------

export function canonServerName(host) {
  let h = String(host).trim();
  const m = h.match(/^\[([^\]]+)\]/);
  if (m) return m[1].trim().toLowerCase();
  const hp = h.match(/^(.*?):\d+$/);
  if (hp) h = hp[1];
  return h.replace(/\.$/, "").toLowerCase();
}

// ---- proof -----------------------------------------------------------------

// Import a 32-byte token secret as a NON-EXTRACTABLE HMAC key. After this the
// raw bytes can be discarded; no code (even a compromised extension) can read
// them back — only request signatures. Runtime protection against misuse comes
// from the service-worker messaging lockdown, not from non-extractability alone.
export async function importSecret(secretBytes) {
  return crypto.subtle.importKey(
    "raw", secretBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

export function proofCanonical(serverName, kid, nonceRaw) {
  return pae([enc.encode("jitaccess-v1"), enc.encode(canonServerName(serverName)),
              enc.encode(kid), nonceRaw]);
}

// key: a CryptoKey from importSecret. nonceRaw: Uint8Array (decoded X-JIT-Nonce).
// Returns the proof as base64url.
export async function buildProof(key, serverName, kid, nonceRaw) {
  const sig = await crypto.subtle.sign("HMAC", key, proofCanonical(serverName, kid, nonceRaw));
  return b64uEncode(new Uint8Array(sig));
}
