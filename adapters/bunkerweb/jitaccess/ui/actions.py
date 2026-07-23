# BunkerWeb UI integration for jitaccess.
#
#   pre_render()  -> metric cards the UI renders on the plugin's page (the
#                    framework-native pattern; the plugin emits these counters).
#   jitaccess()   -> POST handler for the "create token" form on template.html.
#                    Generates a token and returns a standalone result page with
#                    the config line + enrollment options. It does NOT write the
#                    config (that stays an explicit admin step via Global Config)
#                    and needs no server round-trip, so it can't break anything.
#
# Grant/enroll-code management lives on the instance internal API
# (/jitaccess/grants|revoke|revoke-token|enroll-code) and `bwcli jitaccess token`
# — see ../../README.md.

import base64
import os
from html import escape
from logging import getLogger
from traceback import format_exc

# (metric_name, title, subtitle, subtitle_color, svg_color)
_CARDS = [
    ("jit_knock_ok",   "JIT ACCESS", "Knocks accepted",   "success", "emerald"),
    ("jit_knock_fail", "JIT ACCESS", "Knocks rejected",   "error",   "red"),
    ("jit_granted",    "JIT ACCESS", "Requests admitted", "success", "emerald"),
    ("jit_denied",     "JIT ACCESS", "Requests denied",   "warning", "amber"),
    ("jit_enroll_ok",  "JIT ACCESS", "Enrollments",       "info",    "blue"),
]


def pre_render(**kwargs):
    logger = getLogger("UI")
    ret = {}
    metrics = {}
    try:
        metrics = kwargs["bw_instances_utils"].get_metrics("jitaccess") or {}
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to get jitaccess metrics: {e}")
        ret["error"] = str(e)
    for name, title, subtitle, color, svg in _CARDS:
        ret[f"counter_{name}"] = {
            "value": metrics.get(f"counter_{name}", 0),
            "title": title,
            "subtitle": subtitle,
            "subtitle_color": color,
            "svg_color": svg,
        }
    return ret


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _result_page(kid, secret, label, origins):
    config_line = f"JIT_ACCESS_TOKEN={kid}:{secret}:{label}"
    first = origins[0] if origins else "https://YOUR-SERVICE"
    origins_csv = ",".join(origins) if origins else first
    tokens_setting = " ".join(o for o in [kid])  # single kid for the allow-list
    direct = f"jitaccess://enroll?v=1&kid={kid}&secret={secret}&origins={origins_csv}&label={label}"
    register_note = (
        f"# after adding the token above and reloading, mint a one-time code:\n"
        f'#   curl -s -H "Host: bwapi" -H "Authorization: Bearer $API_TOKEN" \\\n'
        f"#     -X POST http://127.0.0.1:5000/jitaccess/enroll-code \\\n"
        f'#     -d \'{{"kid":"{kid}","origins":{_origins_json(origins, first)},"server":"{first}"}}\'\n'
        f"# the response includes register_url — hand that to the user."
    )
    e = escape
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>JIT Access — token created</title>
<style>body{{font:14px system-ui;margin:2rem;max-width:760px}}code,pre{{background:#f4f4f4;border-radius:4px}}
pre{{padding:.8rem;overflow:auto;white-space:pre-wrap;word-break:break-all}}h2{{margin-top:1.4rem}}a{{font-size:13px}}</style>
</head><body>
<h1>Token created</h1>
<p>Label: <b>{e(label)}</b> &nbsp; kid: <code>{e(kid)}</code></p>
<h2>1) Add to your <b>global</b> config</h2>
<pre>{e(config_line)}</pre>
<h2>2) Allow it on the service(s)</h2>
<pre>{e(first.split('//')[-1])}_USE_JIT_ACCESS=yes
{e(first.split('//')[-1])}_JIT_ACCESS_TOKENS={e(kid)}</pre>
<h2>3) Enrollment</h2>
<p><b>Recommended</b> — registration URL (secret never in the link):</p>
<pre>{e(register_note)}</pre>
<p>Or a direct setup string (testing only — carries the secret):</p>
<pre>{e(direct)}</pre>
<p class="muted">This secret is shown once. Store the config line securely; treat the setup string as sensitive.</p>
<p><a href="javascript:history.back()">&larr; Back</a></p>
</body></html>"""
    return html


def _origins_json(origins, first):
    items = origins or [first]
    return "[" + ",".join('"' + o.replace('"', "") + '"' for o in items) + "]"


def jitaccess(**kwargs):
    from flask import request, Response

    label = (request.form.get("label") or "device").strip()[:64]
    if ":" in label:
        label = label.replace(":", "-")
    origins = [o.strip() for o in (request.form.get("origins") or "").split(",") if o.strip()]
    # keep only well-formed https origins
    clean = []
    for o in origins:
        if o.startswith("https://") and " " not in o:
            clean.append(o.rstrip("/"))

    kid = "kid_" + _b64u(os.urandom(9))
    secret = _b64u(os.urandom(32))
    return Response(_result_page(kid, secret, label, clean), mimetype="text/html")
