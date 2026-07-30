#!/usr/bin/env bash
# Vendor the portable Lua core (core/lua/jitaccess/core) into the BunkerWeb
# plugin, then package the plugin as a tar.gz suitable for EXTERNAL_PLUGIN_URLS
# (file://) or for dropping into the scheduler's /data/plugins volume.
#
# BunkerWeb plugins are self-contained, so the core is copied in (not symlinked).
# The vendored copy is git-ignored (canonical source stays in core/lua).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
plugin="$here/jitaccess"
src="$repo/core/lua/jitaccess/core"

echo "vendoring core -> plugin/core"
rm -rf "$plugin/core"
mkdir -p "$plugin/core"
cp "$src"/*.lua "$plugin/core/"

# sanity: required modules present
for m in pae canon crypto registry store pages; do
  test -f "$plugin/core/$m.lua" || { echo "missing core module: $m"; exit 1; }
done

out="$repo/adapters/bunkerweb/jitaccess.tar.gz"
echo "packaging -> $out"
# Exclude __pycache__: running any of the plugin's Python locally (bwcli, the
# registry job, the UI actions) leaves .pyc files beside it, and tarring the
# directory shipped this developer's bytecode — compiled by whatever CPython
# happened to be installed — into the plugin BunkerWeb unpacks and runs. Caught
# when the release tarball turned out to contain token.cpython-314.pyc.
tar -C "$here" --exclude='__pycache__' --exclude='*.pyc' -czf "$out" jitaccess
echo "done. install by mounting into /data/plugins or via EXTERNAL_PLUGIN_URLS=file://$out"
