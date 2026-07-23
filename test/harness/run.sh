#!/usr/bin/env bash
# Bring up the M1 harness: vendor the plugin, stage it, start the stack, wait
# until BunkerWeb serves. Requires Docker + docker compose on a Linux host.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

echo "[1/4] vendoring plugin core (core/lua -> plugin/core)..."
bash "$repo/adapters/bunkerweb/build-vendor.sh" >/dev/null

echo "[2/4] staging plugin into harness (./plugins/jitaccess)..."
rm -rf "$here/plugins/jitaccess"
mkdir -p "$here/plugins"
cp -r "$repo/adapters/bunkerweb/jitaccess" "$here/plugins/jitaccess"

echo "[3/4] docker compose up -d ..."
cd "$here"
docker compose up -d

echo "[4/4] waiting for BunkerWeb to serve app-a.local (up to ~5 min)..."
for _ in $(seq 1 60); do
  code=$(docker compose exec -T tester sh -c \
    "curl -s -o /dev/null -w '%{http_code}' -H 'Host: app-a.local' http://bunkerweb:8080/ || true" \
    2>/dev/null | tr -dc '0-9' || true)
  if [ -n "${code:-}" ] && [ "$code" != "000" ]; then
    echo "  ready (app-a returns HTTP $code)"
    echo
    echo "now run:  ./test.sh"
    exit 0
  fi
  sleep 5
done
echo "  BunkerWeb did not become ready in time; check 'docker compose logs bw-scheduler'." >&2
exit 1
