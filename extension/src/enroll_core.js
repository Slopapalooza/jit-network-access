// Shared enrollment logic used by the options page (paste a setup string) and
// the confirm page (arrive via a registration URL). Both end at enrollToken().

import { enroll } from "./store.js";
import { b64uDecode } from "./jitcrypto.js";

const PREFIX = "/.well-known/jit-access";

export function normalizeOrigins(origins) {
  return origins.map((o) => {
    const u = new URL(o);
    if (u.protocol !== "https:") throw new Error("origins must be https (" + o + ")");
    return u.origin;
  });
}

// Exchange a one-time code at <server>/enroll for the token secret (via headers).
export async function exchangeCode(server, code) {
  const origin = new URL(server).origin;
  const res = await fetch(origin + PREFIX + "/enroll", {
    method: "POST", cache: "no-store", credentials: "omit",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }),
  });
  const secret = res.headers.get("X-JIT-Secret");
  if (!secret) throw new Error("code rejected (invalid or already used)");
  return {
    kid: res.headers.get("X-JIT-Kid"),
    secretB64: secret,
    origins: (res.headers.get("X-JIT-Origins") || "").split(",").map((s) => s.trim()).filter(Boolean),
  };
}

// Parse a jitaccess://enroll?... setup string or registration query into fields.
export function parseParams(str) {
  str = str.trim();
  const q = str.includes("?") ? str.slice(str.indexOf("?") + 1) : str;
  const p = new URLSearchParams(q);
  return {
    kid: p.get("kid"), secret: p.get("secret"),
    code: p.get("code"), server: p.get("server"),
    origins: (p.get("origins") || "").split(",").map((s) => s.trim()).filter(Boolean),
    label: p.get("label") || "",
  };
}

// The full enrollment. MUST be called from a user gesture (it requests host
// permissions). Returns { kid, origins }.
export async function enrollToken(f) {
  const usingCode = !!(f.code && f.server);
  if (!usingCode && !f.secret) throw new Error("need a code + server (recommended) or a secret");

  let origins = normalizeOrigins(f.origins || []);
  const permOrigins = origins.map((o) => o + "/*");
  if (usingCode) permOrigins.push(new URL(f.server).origin + "/*");
  if (!(await chrome.permissions.request({ origins: permOrigins }))) {
    throw new Error("permission to the origins was declined");
  }

  let kid = f.kid, secretB64 = f.secret;
  if (usingCode) {
    const r = await exchangeCode(f.server, f.code);
    kid = r.kid || kid;
    secretB64 = r.secretB64;
    if (r.origins.length) origins = normalizeOrigins(r.origins);   // server is authoritative
  }
  if (!kid || !origins.length) throw new Error("enrollment did not yield a kid/origins");

  const secretBytes = b64uDecode(secretB64);
  if (secretBytes.length < 16) throw new Error("secret too short");

  // ensure permission for any server-provided origins too
  await chrome.permissions.request({ origins: origins.map((o) => o + "/*") });

  await enroll({ kid, secretBytes, origins, label: f.label });
  return { kid, origins };
}
