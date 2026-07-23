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
for m in pae canon crypto registry store; do
  test -f "$plugin/core/$m.lua" || { echo "missing core module: $m"; exit 1; }
done

out="$repo/adapters/bunkerweb/jitaccess.tar.gz"
echo "packaging -> $out"
tar -C "$here" -czf "$out" jitaccess
echo "done. install by mounting into /data/plugins or via EXTERNAL_PLUGIN_URLS=file://$out"
