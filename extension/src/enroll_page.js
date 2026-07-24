// Confirm page reached via a registration URL (the service worker redirects here
// when the user lands on <host>/.well-known/jit-access/register?code=...).
// One click grants permission for the site(s) and pulls the token.

// Clickjacking guard: refuse to run framed. (MV3 CSP blocks inline scripts in
// extension pages, so this must live here, not in a <script> tag; the manifest's
// frame-ancestors 'none' is the hard stop, this is the belt.)
if (window.top !== window.self) {
  document.documentElement.textContent = "This page cannot be embedded.";
  throw new Error("framed");
}

import { enrollToken } from "./enroll_core.js";

const $ = (id) => document.getElementById(id);
const msg = (t, c) => { $("msg").textContent = t; $("msg").className = c || "muted"; };
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

const p = new URLSearchParams(location.search);
const f = {
  server: p.get("server"),
  code: p.get("code"),
  origins: (p.get("origins") || "").split(",").map((s) => s.trim()).filter(Boolean),
  label: p.get("label") || "",
};
if (!f.origins.length && f.server) f.origins = [new URL(f.server).origin];

const shown = f.origins.length ? f.origins : (f.server ? [f.server] : []);
for (const o of shown) {
  const li = document.createElement("li");
  li.appendChild(el("code", null, o));
  $("origins").appendChild(li);
}

if (!f.code || !f.server) {
  $("box").textContent = "";
  $("box").appendChild(el("p", "err", "This registration link is missing a code or server."));
} else {
  $("enroll").addEventListener("click", async () => {
    $("enroll").disabled = true;
    msg("Enrolling…");
    try {
      const { kid, origins } = await enrollToken(f);
      $("box").textContent = "";
      $("box").appendChild(el("p", "ok", "✓ Enrolled (" + kid + "). This browser can now open:"));
      const ul = document.createElement("ul");
      for (const o of origins) {
        const li = document.createElement("li");
        const a = el("a", null, o);
        a.href = o;                       // origins are https-validated by enrollToken
        li.appendChild(a);
        ul.appendChild(li);
      }
      $("box").appendChild(ul);
    } catch (e) {
      msg("Enrollment failed: " + e.message, "err");
      $("enroll").disabled = false;
    }
  });
  $("cancel").addEventListener("click", (e) => { e.preventDefault(); window.close(); });
}
