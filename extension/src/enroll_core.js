// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

// Shared enrollment logic used by the options page (paste a setup string) and
// the confirm page (arrive via a registration URL). Both end at enrollToken().

import { enroll } from "./store.js";
import { b64uDecode } from "./jitcrypto.js";

const PREFIX = "/.well-known/jit-access";

export function normalizeOrigins(origins) {
  return origins.map((o) => {
    let u;
    try {
      // PROTOCOL §2.1 shows X-JIT-Origins as bare hostnames, and admins hand-write
      // them that way; accept both rather than dying with a bare "Invalid URL"
      // that names neither the offending entry nor the expected form.
      u = new URL(String(o).includes("://") ? o : "https://" + o);
    } catch {
      throw new Error("not a valid origin: " + JSON.stringify(o) +
        " (expected https://host or host)");
    }
    if (u.protocol !== "https:") throw new Error("origins must be https (" + o + ")");
    return u.origin;
  });
}

// Exchange a one-time code at <server>/enroll for the token secret (via headers).
export async function exchangeCode(server, code) {
  const origin = new URL(server).origin;
  if (new URL(origin).protocol !== "https:") throw new Error("enrollment server must be https");
  const res = await fetch(origin + PREFIX + "/enroll", {
    method: "POST", cache: "no-store", credentials: "omit",
    // A redirect would replay the single-use code at a host the user never
    // approved, and the response would still be read for X-JIT-Secret. Refuse
    // to follow it rather than hand the code to somewhere else.
    redirect: "error",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify({ v: 1, code }),
  });
  if (!res.ok && res.status !== 204) throw new Error("code rejected (HTTP " + res.status + ")");
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

  // The set the user is shown and asked to approve. This is the ONLY set that
  // can end up enrolled — see the filter after the exchange.
  const consented = normalizeOrigins(f.origins || []);
  const permOrigins = consented.map((o) => o + "/*");
  if (usingCode) permOrigins.push(new URL(f.server).origin + "/*");
  if (!(await chrome.permissions.request({ origins: permOrigins }))) {
    throw new Error("permission to the origins was declined");
  }

  // Anything that throws from here on must not leave host permissions granted for
  // an enrollment that never completed — the user would be left holding access
  // they cannot see in the extension and did not ultimately agree to.
  try {
    return await finishEnroll(f, consented, usingCode);
  } catch (e) {
    await chrome.permissions.remove({ origins: permOrigins }).catch(() => {});
    throw e;
  }
}

async function finishEnroll(f, consented, usingCode) {
  let kid = f.kid, secretB64 = f.secret;
  let origins = consented;
  if (usingCode) {
    const r = await exchangeCode(f.server, f.code);
    kid = r.kid || kid;
    secretB64 = r.secretB64;

    // PROTOCOL §2.1: policy.origins is ADVISORY. The server may narrow what the
    // user approved, never widen it — otherwise a hostile enrollment server
    // names origins the consent dialog never showed and the extension knocks at
    // them afterwards. Previously the server's list simply replaced `consented`
    // and the follow-up permission request's result was discarded, so a decline
    // (or an expired user gesture) did not stop the enrollment.
    if (r.origins.length) {
      const offered = normalizeOrigins(r.origins);
      const accepted = offered.filter((o) => consented.includes(o));
      const widened = offered.filter((o) => !consented.includes(o));
      if (widened.length) {
        // Not a silent drop: the user consented to something different from what
        // the server tried to hand back, and should be told which.
        throw new Error(
          "the server tried to enrol origins you were not asked about (" +
            widened.join(", ") + ") — enrollment aborted",
        );
      }
      origins = accepted;
    }
  }
  if (!kid || !origins.length) throw new Error("enrollment did not yield a kid/origins");

  const secretBytes = b64uDecode(secretB64);
  // Matches the floor every verifier enforces on its own registry (>= 16 bytes).
  // PROTOCOL §1 describes the secret as 32 bytes; raising this to 32 is a
  // coordinated protocol + all-verifiers change, not a client-side one.
  if (secretBytes.length < 16) throw new Error("secret too short");

  // Belt and braces: only enrol origins we actually hold host permission for, so
  // a permission the user revoked mid-flow cannot leave a token behind.
  const held = await chrome.permissions.contains({ origins: origins.map((o) => o + "/*") });
  if (!held) throw new Error("host permission for the enrolled origins is missing");

  await enroll({ kid, secretBytes, origins, label: f.label });
  return { kid, origins };
}
