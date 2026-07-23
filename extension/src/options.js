import { listTokens, removeToken } from "./store.js";
import { parseParams, enrollToken } from "./enroll_core.js";

const $ = (id) => document.getElementById(id);
function msg(text, cls) { const el = $("msg"); el.textContent = text; el.className = cls || "muted"; }

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

async function onEnroll() {
  try {
    const { kid } = await enrollToken(parseParams($("setup").value));
    $("setup").value = "";
    msg("Enrolled " + kid + ". Clear the setup string from wherever you copied it.", "ok");
    render();
  } catch (e) {
    msg(e.message, "err");
  }
}

$("enroll").addEventListener("click", onEnroll);
render();
