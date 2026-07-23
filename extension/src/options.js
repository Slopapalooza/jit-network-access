import { enroll, listTokens, removeToken } from "./store.js";
import { b64uDecode } from "./jitcrypto.js";

const $ = (id) => document.getElementById(id);
const PREFIX = "/.well-known/jit-access";

function parseSetup(str) {
  str = str.trim();
  const q = str.includes("?") ? str.slice(str.indexOf("?") + 1) : str;
  const p = new URLSearchParams(q);
  const origins = (p.get("origins") || "").split(",").map((s) => s.trim()).filter(Boolean);
  return {
    kid: p.get("kid"), secret: p.get("secret"),
    code: p.get("code"), server: p.get("server"),
    origins, label: p.get("label") || "",
  };
}

function msg(text, cls) { const el = $("msg"); el.textContent = text; el.className = cls || "muted"; }

function normalizeOrigins(origins) {
  return origins.map((o) => {
    const u = new URL(o);
    if (u.protocol !== "https:") throw new Error("origins must be https (" + o + ")");
    return u.origin;
  });
}

async function render() {
  const tokens = await listTokens();
  const box = $("tokens");
  box.innerHTML = "";
  if (!tokens.length) { box.innerHTML = '<p class="muted">No tokens enrolled yet.</p>'; return; }
  for (const t of tokens) {
    const div = document.createElement("div");
    div.className = "tok";
    const meta = document.createElement("div");
    meta.innerHTML = `<b>${t.label || "(unnamed)"}</b> — <code>${t.kid}</code><br>` +
      `<span class="muted">${t.origins.join(", ")}</span>`;
    const btn = document.createElement("button");
    btn.textContent = "Remove";
    btn.onclick = async () => { await removeToken(t.kid); render(); };
    div.append(meta, btn);
    box.appendChild(div);
  }
}

// Exchange a one-time code at the server's /enroll for the token secret.
async function exchangeCode(server, code) {
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

async function onEnroll() {
  const s = parseSetup($("setup").value);
  const usingCode = !!(s.code && s.server);
  if (!usingCode && !s.secret) return msg("Setup string needs a code + server (recommended) or a secret.", "err");
  if (!s.origins.length && !usingCode) return msg("Setup string needs at least one origin.", "err");

  // Permissions: the token origins, plus the enroll server for a code exchange.
  let normalized;
  try {
    normalized = normalizeOrigins(s.origins);
    if (usingCode) new URL(s.server);   // validate
  } catch (e) { return msg("Invalid origin: " + e.message, "err"); }

  const permOrigins = normalized.map((o) => o + "/*");
  if (usingCode) permOrigins.push(new URL(s.server).origin + "/*");
  const granted = await chrome.permissions.request({ origins: permOrigins });
  if (!granted) return msg("Permission to the origins was declined; cannot knock/enroll there.", "err");

  let kid = s.kid, secretB64 = s.secret, origins = normalized;
  if (usingCode) {
    try {
      const r = await exchangeCode(s.server, s.code);
      kid = r.kid || kid;
      secretB64 = r.secretB64;
      if (r.origins.length) { origins = normalizeOrigins(r.origins); }   // server is authoritative
    } catch (e) { return msg("Enrollment failed: " + e.message, "err"); }
  }
  if (!kid || !origins.length) return msg("Enrollment did not yield a kid/origins.", "err");

  let secretBytes;
  try {
    secretBytes = b64uDecode(secretB64);
    if (secretBytes.length < 16) throw new Error("secret too short");
  } catch (e) { return msg("Invalid secret: " + e.message, "err"); }

  // Make sure we hold permission for any server-provided origins too.
  await chrome.permissions.request({ origins: origins.map((o) => o + "/*") });

  await enroll({ kid, secretBytes, origins, label: s.label });
  $("setup").value = "";
  msg("Enrolled " + kid + ". Clear the setup string from wherever you copied it.", "ok");
  render();
}

$("enroll").addEventListener("click", onEnroll);
render();
