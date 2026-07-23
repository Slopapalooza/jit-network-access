// Confirm page reached via a registration URL (the service worker redirects here
// when the user lands on <host>/.well-known/jit-access/register?code=...).
// One click grants permission for the site(s) and pulls the token.
import { enrollToken } from "./enroll_core.js";

const $ = (id) => document.getElementById(id);
const msg = (t, c) => { $("msg").textContent = t; $("msg").className = c || "muted"; };

const p = new URLSearchParams(location.search);
const f = {
  server: p.get("server"),
  code: p.get("code"),
  origins: (p.get("origins") || "").split(",").map((s) => s.trim()).filter(Boolean),
  label: p.get("label") || "",
};
if (!f.origins.length && f.server) f.origins = [new URL(f.server).origin];

const shown = f.origins.length ? f.origins : (f.server ? [f.server] : []);
$("origins").innerHTML = shown.map((o) => `<li><code>${o}</code></li>`).join("");

if (!f.code || !f.server) {
  $("box").innerHTML = "<p class='err'>This registration link is missing a code or server.</p>";
} else {
  $("enroll").addEventListener("click", async () => {
    $("enroll").disabled = true;
    msg("Enrolling…");
    try {
      const { kid, origins } = await enrollToken(f);
      $("box").innerHTML =
        `<p class="ok">&#10003; Enrolled (${kid}). This browser can now open:</p>` +
        `<ul>${origins.map((o) => `<li><a href="${o}">${o}</a></li>`).join("")}</ul>`;
    } catch (e) {
      msg("Enrollment failed: " + e.message, "err");
      $("enroll").disabled = false;
    }
  });
  $("cancel").addEventListener("click", (e) => { e.preventDefault(); window.close(); });
}
