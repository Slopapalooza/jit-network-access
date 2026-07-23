# BunkerWeb UI integration for jitaccess.
#
# Follows the framework-native pattern every core plugin uses: pre_render()
# returns "counter_*" metric cards the UI renders on the plugin's page. The
# plugin emits these counters via self:metric("counters", ...) in the access
# phase. Token/grant management lives in `bwcli jitaccess token` and the instance
# internal API (/jitaccess/grants|revoke|revoke-token|enroll-code) — see
# ../../README.md — rather than a custom template (no core plugin ships one, so
# that contract isn't something we can build against safely).

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
    except BaseException as e:  # never break the UI over a metrics hiccup
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


def jitaccess(**kwargs):  # POST handler (no interactive actions on the page yet)
    pass
