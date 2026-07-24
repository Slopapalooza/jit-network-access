# BunkerWeb UI integration for jitaccess: token lifecycle + site picker.
#
#   pre_render()  -> metric cards + the token list + the JIT-enabled service list
#                    that template.html renders.
#   jitaccess()   -> POST handler for the create / delete / regenerate / enroll
#                    actions on that page.
#
# Tokens are BunkerWeb GLOBAL config settings (JIT_ACCESS_TOKEN, _1, _2, ...) —
# the same registry the scheduler job reads. We manage them through the Database
# the UI itself uses (get_config / save_config, method "ui"), mirroring the Global
# Config page, so every change is a normal, reload-triggering config edit — no
# separate datastore. Per-service allow-lists (which kids may open a service) are
# the multisite JIT_ACCESS_TOKENS setting. Both writes were validated against a
# hot copy of the production DB to be surgical: only the token rows and the
# selected services' JIT_ACCESS_TOKENS change; services and every other setting
# are left untouched (save_config's own data-loss guards back this up).
#
# Immediate grant eviction (so a deleted/rotated device loses access now, not at
# TTL) is done via the instance internal API (POST /jitaccess/revoke-token).

import base64
import json
import os
import re
from html import escape
from logging import getLogger
from traceback import format_exc

_TOKEN_KEY_RE = re.compile(r"^JIT_ACCESS_TOKEN(_\d+)?$")
_LABEL_OK = re.compile(r"[^A-Za-z0-9 _.\-]")

# (metric_name, title, subtitle, subtitle_color, svg_color)
_CARDS = [
    ("jit_knock_ok",   "JIT ACCESS", "Knocks accepted",   "success", "emerald"),
    ("jit_knock_fail", "JIT ACCESS", "Knocks rejected",   "error",   "red"),
    ("jit_granted",    "JIT ACCESS", "Requests admitted", "success", "emerald"),
    ("jit_denied",     "JIT ACCESS", "Requests denied",   "warning", "amber"),
    ("jit_enroll_ok",  "JIT ACCESS", "Enrollments",       "info",    "blue"),
]


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _clean_label(s):
    return _LABEL_OK.sub("-", (s or "device").strip())[:64] or "device"


# ---- config reads ----------------------------------------------------------

def _token_entries(cfg):
    """[(config_key, 'kid:secret:label[:exp]')] for the non-empty token slots."""
    return [(k, v) for k, v in cfg.items() if _TOKEN_KEY_RE.match(k) and v]


def _parse_entry(entry):
    parts = entry.split(":")
    if len(parts) < 3:
        return None
    return {"kid": parts[0], "secret": parts[1], "label": parts[2],
            "expiry": parts[3] if len(parts) >= 4 and parts[3] else ""}


def _read_state(db):
    """(tokens, jit_services). tokens carry NO secret; each lists the sites it opens."""
    cfg = db.get_config(methods=False, filtered_settings=["USE_JIT_ACCESS", "JIT_ACCESS_TOKENS", "JIT_ACCESS_TOKEN"])
    names = (cfg.get("SERVER_NAME") or "").split()
    g_use = cfg.get("USE_JIT_ACCESS", "no")
    g_tok = cfg.get("JIT_ACCESS_TOKENS", "")
    jit_services, allow = [], {}
    for s in names:
        if cfg.get(f"{s}_USE_JIT_ACCESS", g_use) == "yes":
            jit_services.append(s)
        allow[s] = set((cfg.get(f"{s}_JIT_ACCESS_TOKENS", g_tok) or "").split())
    tokens = []
    for _k, entry in _token_entries(cfg):
        t = _parse_entry(entry)
        if not t:
            continue
        sites = [s for s in names if t["kid"] in allow.get(s, ()) or "*" in allow.get(s, ())]
        tokens.append({"kid": t["kid"], "label": t["label"], "expiry": t["expiry"], "sites": sites})
    return tokens, jit_services


def pre_render(**kwargs):
    logger = getLogger("UI")
    ret = {}
    metrics = {}
    try:
        metrics = kwargs["bw_instances_utils"].get_metrics("jitaccess") or {}
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"jitaccess metrics: {e}")
    for name, title, subtitle, color, svg in _CARDS:
        ret[f"counter_{name}"] = {
            "value": metrics.get(f"counter_{name}", 0),
            "title": title, "subtitle": subtitle,
            "subtitle_color": color, "svg_color": svg,
        }
    try:
        tokens, services = _read_state(kwargs["db"])
        ret["tokens"], ret["services"] = tokens, services
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"jitaccess read state: {e}")
        ret["tokens"], ret["services"], ret["load_error"] = [], [], str(e)
    return ret


# ---- config writes (validated surgical against a hot DB copy) --------------

def _write_tokens(db, entries, service_updates=None):
    """Rewrite the token slots to exactly `entries` (['kid:secret:label', ...]),
    renumbering base/_1/_2 contiguously so stale rows are removed. Optionally set
    per-service JIT_ACCESS_TOKENS via service_updates {service: 'kid1 kid2'}.
    """
    if service_updates:
        cfg = db.get_config(methods=False)                       # FULL config: services preserved
    else:
        cfg = db.get_config(global_only=True, methods=False)     # globals only: services untouched
    for k in [k for k in cfg if _TOKEN_KEY_RE.match(k)]:
        cfg.pop(k)
    keys = ["JIT_ACCESS_TOKEN"] + [f"JIT_ACCESS_TOKEN_{i}" for i in range(1, len(entries))]
    for k, e in zip(keys, entries):
        cfg[k] = e
    if service_updates:
        for svc, val in service_updates.items():
            cfg[f"{svc}_JIT_ACCESS_TOKENS"] = val
        db.save_config(cfg, "ui")
    else:
        db.save_config(cfg, "ui", skip_service_management=True)


def _instance_post(kwargs, path, data):
    """POST to the plugin's instance internal API on all up instances; merge JSON responses."""
    merged, ok_any = {}, False
    try:
        for inst in kwargs["bw_instances_utils"].get_instances():
            try:
                ok, resp = inst.apiCaller.send_to_apis("POST", path, data=data, response=True)
                ok_any = ok_any or ok
                for _host, r in (resp or {}).items():
                    if isinstance(r, dict):
                        merged.update(r)
            except BaseException:
                continue
    except BaseException:
        pass
    return ok_any, merged


def _dig(d, key):
    """Pull `key` out of a possibly-wrapped instance-API response ({data|msg: {...}})."""
    if not isinstance(d, dict):
        return None
    if key in d:
        return d[key]
    for sub in ("data", "msg"):
        v = d.get(sub)
        if isinstance(v, dict) and key in v:
            return v[key]
        if isinstance(v, str):
            try:
                jv = json.loads(v)
                if isinstance(jv, dict) and key in jv:
                    return jv[key]
            except Exception:
                pass
    return None


# ---- action handlers -------------------------------------------------------

def jitaccess(**kwargs):
    from flask import request, Response

    db = kwargs["db"]
    action = (request.form.get("action") or "create").strip()
    try:
        if action == "create":
            return _create(kwargs, db, request, Response)
        if action == "delete":
            return _delete(kwargs, db, request, Response)
        if action == "regenerate":
            return _regenerate(kwargs, db, request, Response)
        if action == "enroll":
            return _enroll(kwargs, db, request, Response)
    except BaseException as e:
        getLogger("UI").error(format_exc())
        return Response(_page(request, "Error", f'<p class="err">The operation failed: {escape(str(e))}</p>'),
                        mimetype="text/html", status=500)
    return Response(_page(request, "Unknown action", "<p>Unknown action.</p>"), mimetype="text/html", status=400)


def _create(kwargs, db, request, Response):
    label = _clean_label(request.form.get("label"))
    services = [s.strip() for s in request.form.getlist("services") if s.strip()]
    kid = "kid_" + _b64u(os.urandom(9))
    secret = _b64u(os.urandom(32))

    gcfg = db.get_config(global_only=True, methods=False)
    entries = [e for _k, e in _token_entries(gcfg)]
    entries.append(f"{kid}:{secret}:{label}")

    service_updates = None
    if services:
        fcfg = db.get_config(methods=False, filtered_settings=["JIT_ACCESS_TOKENS"])
        g_tok = fcfg.get("JIT_ACCESS_TOKENS", "")
        service_updates = {}
        for s in services:
            cur = (fcfg.get(f"{s}_JIT_ACCESS_TOKENS", g_tok) or "").split()
            if "*" not in cur and kid not in cur:
                cur.append(kid)
            service_updates[s] = " ".join(cur)

    _write_tokens(db, entries, service_updates)

    sites = "".join(f"<li><code>{escape(s)}</code></li>" for s in services) or \
        '<li class="muted">none selected — the token opens nothing until you add a site</li>'
    body = (
        f'<p class="ok">&#10003; Token <b>{escape(label)}</b> created.</p>'
        f'<p>kid: <code>{escape(kid)}</code></p><p>Allowed sites:</p><ul>{sites}</ul>'
        f'<p class="muted">The token activates on the next config reload (usually under a minute). '
        f'Then use <b>Enroll device</b> in the token list to get the registration link to hand to the user.</p>'
    )
    return Response(_page(request, "Token created", body), mimetype="text/html")


def _delete(kwargs, db, request, Response):
    kid = (request.form.get("kid") or "").strip()
    if not kid:
        return Response(_page(request, "Delete", '<p class="err">Missing kid.</p>'), mimetype="text/html", status=400)

    gcfg = db.get_config(global_only=True, methods=False)
    entries = [e for _k, e in _token_entries(gcfg) if (_parse_entry(e) or {}).get("kid") != kid]

    fcfg = db.get_config(methods=False, filtered_settings=["JIT_ACCESS_TOKENS"])
    g_tok = fcfg.get("JIT_ACCESS_TOKENS", "")
    service_updates = {}
    for s in (fcfg.get("SERVER_NAME") or "").split():
        cur = (fcfg.get(f"{s}_JIT_ACCESS_TOKENS", g_tok) or "").split()
        if kid in cur:
            service_updates[s] = " ".join(x for x in cur if x != kid)

    _write_tokens(db, entries, service_updates or None)
    _instance_post(kwargs, "/jitaccess/revoke-token", {"kid": kid})   # evict live grants now
    return _redirect_back(request, Response)


def _regenerate(kwargs, db, request, Response):
    kid = (request.form.get("kid") or "").strip()
    gcfg = db.get_config(global_only=True, methods=False)
    label, entries = None, []
    for _k, e in _token_entries(gcfg):
        t = _parse_entry(e)
        if t and t["kid"] == kid:
            label = t["label"]
            entries.append(f"{kid}:{_b64u(os.urandom(32))}:{label}")   # new secret, same kid
        else:
            entries.append(e)
    if label is None:
        return Response(_page(request, "Regenerate", '<p class="err">Token not found.</p>'), mimetype="text/html", status=404)

    _write_tokens(db, entries)                                          # kid unchanged -> allow-lists untouched
    _instance_post(kwargs, "/jitaccess/revoke-token", {"kid": kid})     # old device out now
    body = (
        f'<p class="ok">&#10003; Token <b>{escape(label)}</b> (<code>{escape(kid)}</code>) regenerated '
        f'with a new secret.</p><p class="muted">The previous device has been revoked and its old secret '
        f'no longer works. After the next reload, use <b>Enroll device</b> to enroll the replacement.</p>'
    )
    return Response(_page(request, "Token regenerated", body), mimetype="text/html")


def _enroll(kwargs, db, request, Response):
    kid = (request.form.get("kid") or "").strip()
    tokens, _services = _read_state(db)
    tok = next((t for t in tokens if t["kid"] == kid), None)
    if not tok:
        return Response(_page(request, "Enroll", '<p class="err">Token not found.</p>'), mimetype="text/html", status=404)

    origins = [f"https://{s}" for s in tok["sites"]]
    data = {"kid": kid, "origins": origins}
    if origins:
        data["server"] = origins[0]
    ok, resp = _instance_post(kwargs, "/jitaccess/enroll-code", data)
    register_url = _dig(resp, "register_url")

    if register_url:
        e = escape
        body = (
            f'<p class="ok">&#10003; Registration link for <b>{e(tok["label"])}</b> '
            f'(<code>{e(kid)}</code>) — valid ~15&nbsp;min, single use, no secret in the link:</p>'
            f'<pre>{e(register_url)}</pre>'
            f'<p>Hand it to the user. With the extension installed, they browse to it and click '
            f'<b>Enroll</b>; the browser then opens {e(", ".join(tok["sites"]) or "the site")} after a silent knock.</p>'
        )
        return Response(_page(request, "Enrollment link", body), mimetype="text/html")

    if not origins:
        hint = "This token has no sites yet — add it to a service's allow-list first (create it against a site, or set JIT_ACCESS_TOKENS)."
    else:
        hint = ("The instance couldn't mint a link. The most common cause is the token isn't loaded yet — "
                "wait for the config reload (under a minute after creating it) and try again.")
    msg = _dig(resp, "msg") or _dig(resp, "error") or ""
    extra = f'<p class="muted">Instance said: {escape(str(msg))}</p>' if msg else ""
    return Response(_page(request, "Enrollment link", f'<p class="err">{escape(hint)}</p>{extra}'),
                    mimetype="text/html", status=502)


# ---- result-page helpers ---------------------------------------------------

def _page(request, title, body_html):
    back = escape(request.base_url)   # 303-equivalent: fresh GET of the plugin page refreshes the list
    e = escape
    return (
        f'<!doctype html><html><head><meta charset="utf-8"><title>JIT Access — {e(title)}</title>'
        '<style>body{font:14px system-ui;margin:2rem;max-width:860px}code,pre{background:#f4f4f4;border-radius:4px}'
        'pre{padding:.8rem;overflow:auto;white-space:pre-wrap;word-break:break-all}'
        '.ok{color:#0a7d33}.err{color:#b00020}.muted{color:#666}ul{margin:.3rem 0}'
        'a.btn{display:inline-block;margin-top:1.2rem;text-decoration:none}</style></head><body>'
        f'<h1>{e(title)}</h1>{body_html}'
        f'<p><a class="btn" href="{back}">&larr; Back to JIT Access</a></p></body></html>'
    )


def _redirect_back(request, Response):
    return Response(status=303, headers={"Location": request.base_url})
