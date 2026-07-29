#!/usr/bin/env bash
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Bundle the Chromium extension for distribution.
#
#   ./build.sh                 # build dist/ artifacts
#   ./build.sh --check         # validate only, write nothing
#
# Produces, in extension/dist/:
#   jit-access-<version>.zip   upload target for the Chrome Web Store
#   jit-access-<version>.crx   signed, for self-hosting / GitHub release install
#   SHA256SUMS                 checksums for both
#
# The .crx needs the signing key. It is NOT in the repo and must never be:
# the key IS the extension's identity, and anyone holding it can publish an
# update that every installed browser will accept. Point JIT_EXT_KEY at it, or
# leave it out and get the .zip only.
#
#   JIT_EXT_KEY=/path/to/JIT-Access.pem ./build.sh
#
# The extension ID is derived from that key, so reusing it keeps the ID stable
# across releases — which is what lets an installed browser take an update, and
# what an enterprise force-install policy pins to.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
dist="$here/dist"

CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

KEY="${JIT_EXT_KEY:-$repo/JIT-Access.pem}"

# python3 here is the Windows interpreter under MSYS, which does not understand
# /c/... paths - always hand it a native path, or a relative one from a cd'd shell.
win() { cygpath -w "$1" 2>/dev/null || echo "$1"; }
VERSION="$(cd "$here" && python3 -c "import json;print(json.load(open('manifest.json'))['version'])")"
echo "JIT Network Access extension v$VERSION"

# ---- 1. validate before packaging ------------------------------------------
# A broken bundle is worse than no bundle: it installs, then silently fails to
# knock. Everything cheap that can be checked here, is.
echo "== validating =="
(cd "$here" && python3 - <<'PY'
import json, pathlib, sys, re
ext = pathlib.Path(".")
m = json.loads((ext / "manifest.json").read_text(encoding="utf-8"))

problems = []
if m.get("manifest_version") != 3:
    problems.append("manifest_version must be 3")
if not re.fullmatch(r"\d+(\.\d+){0,3}", m.get("version", "")):
    problems.append(f"version {m.get('version')!r} is not a valid Chrome version string")

# Every file the manifest points at must exist, or the bundle installs broken.
refs = []
bg = m.get("background", {})
if bg.get("service_worker"):
    refs.append(bg["service_worker"])
for k in ("options_page",):
    if m.get(k):
        refs.append(m[k])
if m.get("action", {}).get("default_popup"):
    refs.append(m["action"]["default_popup"])
for war in m.get("web_accessible_resources", []):
    refs.extend(war.get("resources", []))
for r in refs:
    if not (ext / r).exists():
        problems.append(f"manifest references missing file: {r}")

# The security posture the reviews established, asserted at package time so a
# regression cannot ship quietly.
if "externally_connectable" in m:
    problems.append("externally_connectable must stay ABSENT (MV3 default is closed)")
if "https://*/*" in (m.get("host_permissions") or []):
    problems.append("host_permissions must not include https://*/* (origins are granted per-enrollment)")
csp = (m.get("content_security_policy") or {}).get("extension_pages", "")
if "script-src 'self'" not in csp:
    problems.append("extension_pages CSP must pin script-src 'self'")

for p in problems:
    print("  FAIL:", p)
sys.exit(1 if problems else 0)
PY
)
echo "  manifest OK"

# The crypto must still match the shared vectors, or the extension ships unable
# to produce a proof any verifier accepts.
( cd "$here" && node src/jitcrypto.test.mjs >/dev/null && node src/enroll_core.test.mjs >/dev/null )
echo "  tests OK (vectors + enrollment trust boundary)"

for f in "$here"/src/*.js; do node --check "$f"; done
echo "  syntax OK"

if [ "$CHECK_ONLY" = "1" ]; then
  echo "check-only: nothing written"
  exit 0
fi

# ---- 2. stage exactly what ships -------------------------------------------
# Allow-list, not deny-list: a new stray file in extension/ must not silently
# end up in a signed artifact.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
pkg="$stage/jit-access"
mkdir -p "$pkg/src"

cp "$here/manifest.json" "$pkg/"
for f in enroll.html options.html popup.html; do cp "$here/$f" "$pkg/"; done
for f in enroll_core.js enroll_page.js jitcrypto.js options.js popup.js store.js sw.js; do
  cp "$here/src/$f" "$pkg/src/"
done

# Tests and packaging metadata are not part of the product.
if find "$pkg" -name '*.test.mjs' -o -name 'package.json' -o -name 'README.md' | grep -q .; then
  echo "  FAIL: non-product files staged" >&2
  exit 1
fi
echo "== staged $(find "$pkg" -type f | wc -l) files =="

mkdir -p "$dist"
rm -f "$dist"/jit-access-*.zip "$dist"/jit-access-*.crx "$dist/SHA256SUMS"

# ---- 3. pack -----------------------------------------------------------------
# crx3.py builds BOTH artifacts and needs only openssl — no browser. Driving
# `chrome --pack-extension` worked on a desktop but is a poor fit for CI: it
# needs a real browser, writes output next to its input, and signals failure by
# producing nothing.
if [ -f "$KEY" ]; then
  EXT_ID="$(python3 "$(win "$here/crx3.py")" "$(win "$pkg")" "$(win "$dist/jit-access-$VERSION.crx")" "$(win "$KEY")")"
  echo "  wrote jit-access-$VERSION.crx (signed)"
  echo "  extension id: $EXT_ID"

  # Verify what we just signed rather than assuming it. A malformed CRX installs
  # nowhere, and finding that out from a user is expensive.
  python3 "$(win "$here/crx3.py")" --verify "$(win "$dist/jit-access-$VERSION.crx")"     || { echo "  FAIL: produced .crx does not verify" >&2; exit 1; }
else
  echo "  note: no signing key at $KEY - zip-only build (set JIT_EXT_KEY to sign)"
fi

# The .zip is the Chrome Web Store upload format: same tree, unsigned.
python3 - "$(win "$pkg")" "$(win "$dist/jit-access-$VERSION.zip")" <<'PYZIP'
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
PYZIP
python3 -c "
import sys, pathlib
sys.path.insert(0, r'$(win "$here")')
import crx3
out = pathlib.Path(r'$(win "$dist/jit-access-$VERSION.zip")')
out.write_bytes(crx3.zip_dir(pathlib.Path(r'$(win "$pkg")')))
print(f'  wrote {out.name} ({out.stat().st_size} bytes)')
"

( cd "$dist" && sha256sum jit-access-* > SHA256SUMS && cat SHA256SUMS | sed 's/^/  /' )
echo "done -> extension/dist/"
