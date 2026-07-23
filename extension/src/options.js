import { enroll, listTokens, removeToken } from "./store.js";
import { b64uDecode } from "./jitcrypto.js";

const $ = (id) => document.getElementById(id);

function parseSetup(str) {
  str = str.trim();
  const q = str.includes("?") ? str.slice(str.indexOf("?") + 1) : str;
  const p = new URLSearchParams(q);
  const origins = (p.get("origins") || "").split(",").map((s) => s.trim()).filter(Boolean);
  return { kid: p.get("kid"), secret: p.get("secret"), origins, label: p.get("label") || "" };
}

function msg(text, cls) {
  const el = $("msg");
  el.textContent = text;
  el.className = cls || "muted";
}

async function render() {
  const tokens = await listTokens();
  const box = $("tokens");
  box.innerHTML = "";
  if (!tokens.length) {
    box.innerHTML = '<p class="muted">No tokens enrolled yet.</p>';
    return;
  }
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

async function onEnroll() {
  const { kid, secret, origins, label } = parseSetup($("setup").value);
  if (!kid || !secret || !origins.length) {
    return msg("Setup string needs kid, secret, and at least one origin.", "err");
  }
  let normalized;
  try {
    normalized = origins.map((o) => {
      const u = new URL(o);
      if (u.protocol !== "https:") throw new Error("origins must be https");
      return u.origin;
    });
  } catch (e) {
    return msg("Invalid origin: " + e.message, "err");
  }
  let secretBytes;
  try {
    secretBytes = b64uDecode(secret);
    if (secretBytes.length < 16) throw new Error("secret too short");
  } catch (e) {
    return msg("Invalid secret: " + e.message, "err");
  }

  const granted = await chrome.permissions.request({ origins: normalized.map((o) => o + "/*") });
  if (!granted) return msg("Permission to the origins was declined; cannot knock there.", "err");

  await enroll({ kid, secretBytes, origins: normalized, label });
  $("setup").value = "";
  msg("Enrolled " + kid + ". Clear the setup string from wherever you copied it.", "ok");
  render();
}

$("enroll").addEventListener("click", onEnroll);
render();
