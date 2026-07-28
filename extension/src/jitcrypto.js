// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

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

// Lua's "%s" class. String.trim()/toLowerCase() are Unicode-aware and Lua's are
// not, so a Host carrying U+00A0 or a non-ASCII letter canonicalized one way here
// and another on the Lua engines. Hostnames are ASCII by IDNA, so pinning both to
// ASCII costs nothing real and makes all four references byte-identical.
const ASCII_TRIM = /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g;
const asciiTrim = (s) => s.replace(ASCII_TRIM, "");
const asciiLower = (s) => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

// Trim whitespace and trailing dots to a fixpoint BEFORE the port strip as
// well as after. Doing it only after meant removing a trailing dot could
// expose a port that then survived to the next pass: "[:0." became "[:0"
// became "[", and "example.com:443." became "example.com:443" became
// "example.com". Two layers canonicalizing the same Host a different number
// of times would hold two different names for one service.
function trimDotsAndSpace(s) {
  for (;;) {
    const t = asciiTrim(s).replace(/\.$/, "");
    if (t === s) return s;
    s = t;
  }
}

export function canonServerName(host) {
  let h = trimDotsAndSpace(String(host));

  // A bracketed literal delimits its own host. The port strip below is guarded
  // by colon count alone rather than by "was it bracketed": no valid IPv6
  // address has exactly one colon, so the guard only ever protected malformed
  // input like "[a:80]" - which then canonicalized to "a:80" and, on a second
  // pass, to "a".
  // [^\]]* not [^\]]+ : Go and Python both treat [] as an empty bracketed host.
  const m = h.match(/^\[([^\]]*)\]/);
  if (m) h = trimDotsAndSpace(m[1]);

  // Strip a trailing :port - but ONLY when the host has exactly one colon.
  //
  // An unbracketed host with several colons is an IPv6 literal: RFC 3986
  // requires brackets to carry a port, so there is no port to strip. Stripping
  // anyway truncated "2001:db8::1" to "2001:db8:" - and "2001:db8::2" to the
  // SAME value, which is a cross-service collision in both the grant key and
  // the MAC input, the exact class PAE framing exists to prevent. It also made
  // the bracketed and unbracketed spellings of one host canonicalize
  // differently, so a grant made via one would not match a request via the
  // other.
  if ((h.match(/:/g) || []).length === 1) {
    const hp = h.match(/^(.*?):[0-9]+$/);
    if (hp) h = hp[1];
  }
  return asciiLower(trimDotsAndSpace(h));
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
