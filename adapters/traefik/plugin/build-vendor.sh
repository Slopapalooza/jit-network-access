#!/usr/bin/env bash
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Vendor the portable Go core into the Traefik plugin.
#
# Traefik plugins are interpreted by Yaegi at runtime and must carry every
# dependency with them — there is no module download at plugin load. Vendoring
# the core here keeps the plugin a self-contained module with ZERO external
# dependencies, which is also the safest shape for Yaegi.
#
# The vendored copy IS committed — a Traefik plugin is fetched as source, so what
# is in git is what runs. core/go stays the single source of truth; run this after
# touching it. TestVendoredCoreIsInSyncWithCoreGo fails if you forget, which is
# how a stale copy of the canonicalizers was caught shipping to this engine alone.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
src="$repo/core/go"
dst="$here/internal/jitcore"

echo "vendoring core/go -> internal/jitcore"
rm -rf "$dst"
mkdir -p "$dst"
# tests stay behind: they read ../testdata, which does not exist under the plugin
for f in "$src"/*.go; do
  case "$(basename "$f")" in
    *_test.go) continue ;;
  esac
  cp "$f" "$dst/"
done

for m in pae canon crypto registry store pages; do
  test -f "$dst/$m.go" || { echo "missing core module: $m"; exit 1; }
done

echo "done: $(ls -1 "$dst" | tr '\n' ' ')"
