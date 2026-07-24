import { listTokens, removeToken } from "./store.js";
import { parseParams, enrollToken } from "./enroll_core.js";

const $ = (id) => document.getElementById(id);
const msg = (text, cls) => { const el = $("msg"); el.textContent = text || ""; el.className = cls || "muted"; };

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function hostOf(origin) {
  try { return new URL(origin).hostname; } catch { return origin; }
}

function tokenName(t) {
  return t.label || (t.origins && t.origins.length ? hostOf(t.origins[0]) : "(unnamed)");
}

async function render() {
  const box = $("tokens");
  box.textContent = "";
  let tokens = [];
  try { tokens = await listTokens(); } catch { /* not running as an extension page */ }
  if (!tokens.length) {
    box.appendChild(el("p", "muted",
      "No devices enrolled yet. Open a registration link from your admin, or paste a setup string above."));
    return;
  }
  for (const t of tokens) {
    const row = el("div", "tok");
    const meta = el("div");
    const line = el("div");
    line.appendChild(el("span", "name", tokenName(t)));
    line.appendChild(el("code", "kid", t.kid));
    meta.appendChild(line);
    const badges = el("div", "badges");
    for (const o of t.origins || []) badges.appendChild(el("span", "badge", hostOf(o)));
    meta.appendChild(badges);
    const btn = el("button", "btn-danger", "Remove");
    btn.addEventListener("click", async () => {
      if (!confirm(`Remove “${tokenName(t)}”? This browser loses access to its sites until it is re-enrolled.`)) return;
      await removeToken(t.kid);
      render();
    });
    row.append(meta, btn);
    box.appendChild(row);
  }
}

async function onEnroll() {
  const btn = $("enroll");
  btn.disabled = true;
  msg("Enrolling…");
  try {
    const { kid } = await enrollToken(parseParams($("setup").value));
    $("setup").value = "";
    msg("Enrolled " + kid + ". Clear the setup string from wherever you copied it.", "ok");
    render();
  } catch (e) {
    msg(e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

$("enroll").addEventListener("click", onEnroll);
$("setup").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); onEnroll(); }
});

try {
  $("version").textContent = "v" + chrome.runtime.getManifest().version;
  $("version").style.display = "inline-block";
} catch { /* non-extension preview */ }

render();
