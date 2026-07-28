// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// Every field here comes from the query string of a link that ANY website may
// have served, so nothing is assumed well-formed.
const serverOrigin = (() => {
  try { return new URL(f.server).origin; } catch { return null; }
})();
if (!f.origins.length && serverOrigin) f.origins = [serverOrigin];

// Display the NORMALIZED origin, which is what enrollToken actually requests
// permission for and enrols. Showing the raw query-string value meant the
// consent list and the enrolled set could differ — "https://app.example.com:443"
// and "https://app.example.com/anything" both normalize to the same origin, and
// the user was asked about a string that was not the thing being granted.
// Anything that will not normalize is surfaced as invalid rather than silently
// dropped or rendered as-is.
const shownRaw = f.origins.length ? f.origins : (serverOrigin ? [serverOrigin] : []);
const shown = [];
let invalid = 0;
for (const o of shownRaw) {
  try {
    const u = new URL(o.includes("://") ? o : "https://" + o);
    if (u.protocol !== "https:") throw new Error("not https");
    shown.push(u.origin);
  } catch {
    invalid++;
  }
}
f.origins = shown;
for (const o of shown) {
  const li = document.createElement("li");
  li.appendChild(el("code", null, o));
  $("origins").appendChild(li);
}
if (invalid) {
  const li = document.createElement("li");
  li.appendChild(el("span", "err", invalid + " entry/entries in this link are not valid https origins and were ignored"));
  $("origins").appendChild(li);
}

// Name the server the one-time code will be exchanged with. The service worker
// only steers the tab here; it does not vouch for the site. Which host is about
// to hand this browser a device key is the decision the user is actually being
// asked to make, so it has to be on screen. textContent, never innerHTML.
$("server").textContent = serverOrigin || "(missing or malformed)";

if (!f.code || !serverOrigin) {
  $("box").textContent = "";
  $("box").appendChild(el("p", "err", "This registration link is missing a code or a valid server."));
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
