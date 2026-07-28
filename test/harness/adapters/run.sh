#!/usr/bin/env bash
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Drive every engine in the lab with the SAME device token and the SAME knock
# client. A green run is the portability claim proven, not asserted: one
# enrolled token opens a service behind Caddy, NGINX+Authorizer, Traefik and
# OpenResty, each of which implements the gate completely differently.
#
#   docker compose up -d --build
#   ./run.sh
#
# Asserts per engine:
#   1. the service is DARK before knocking          (not 200)
#   2. the deny carries the X-JIT-Access marker     (interstitial mode)
#   3. the knock is accepted                        (204)
#   4. the service then OPENS                       (200)
#   5. replaying the same nonce is rejected         (not 204)
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
KC="python3 $repo/test/conformance/knock_client.py"

KID="kid_lab"
SECRET="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"   # b64u(0x01 * 32)
HOSTNAME_="app.example.com"
STEALTH_HOST="stealth.example.com"

# engine:port
ENGINES=(
  "Caddy (native module):8081"
  "NGINX + Authorizer:8082"
  "Traefik (native plugin):8083"
  "OpenResty (core/lua):8084"
)

# Kubernetes/ingress-nginx runs in its own kind cluster (see kind/setup.sh).
# Include it automatically when that cluster is up.
if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:8085/" 2>/dev/null; then
  ENGINES+=("Kubernetes (ingress-nginx):8085")
else
  # Say so. Silently shrinking the engine list makes a partial run look like a
  # full one, and "5/5 engines green" is the claim this script exists to support.
  echo "NOTE: Kubernetes engine NOT tested (nothing answering on :8085 — run kind/setup.sh first)"
fi

pass=0; fail=0
ok()   { echo "    PASS  $1"; pass=$((pass+1)); }
bad()  { echo "    FAIL  $1${2:+ — $2}"; fail=$((fail+1)); }
note() { echo "    NOTE  $1"; }

# Every gate keeps grants in-process with a 1 h TTL, so a previous run would
# leave this client already admitted and the "dark before knock" assertion
# would fail against a working gate. Restart the gates for a clean slate.
# Pass --no-reset to test against already-running state.
if [ "${1:-}" != "--no-reset" ] && command -v docker >/dev/null 2>&1; then
  echo "resetting gates (clearing grants from any previous run)..."
  (cd "$here" && ${SUDO:-sudo} docker compose restart caddy nginx traefik openresty authorizer >/dev/null 2>&1)
  for port in 8081 8082 8083 8084; do
    for _ in $(seq 1 30); do
      curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/" && break
      sleep 1
    done
  done
  sleep 2
fi

# The kind-hosted Authorizer is not part of the compose project, so clear its
# grants separately (a rollout restart is the simplest reliable reset).
if command -v kubectl >/dev/null 2>&1 && ${SUDO:-sudo} kubectl get ns jit-system >/dev/null 2>&1; then
  echo "resetting the Kubernetes gate..."
  ${SUDO:-sudo} kubectl -n jit-system rollout restart deploy/jit-authorizer >/dev/null 2>&1
  ${SUDO:-sudo} kubectl -n jit-system rollout status deploy/jit-authorizer --timeout=120s >/dev/null 2>&1
  sleep 3
fi

for spec in "${ENGINES[@]}"; do
  name="${spec%:*}"; port="${spec##*:}"
  base="http://$HOSTNAME_:$port"
  resolve="$HOSTNAME_:$port:127.0.0.1"

  echo
  echo "== $name (port $port) =="

  # 1 + 2. dark, with the detection marker
  hdrs=$(curl -s -D- -o /dev/null --max-time 10 --resolve "$resolve" "$base/" 2>/dev/null)
  code=$(sed -n 's|^HTTP/[0-9.]* \([0-9]*\).*|\1|p' <<<"$hdrs" | tail -1)
  if [ "$code" = "200" ]; then bad "dark before knock" "got 200 — the gate is not engaged"; else ok "dark before knock (HTTP ${code:-none})"; fi
  if grep -qi '^x-jit-access:' <<<"$hdrs"; then
    ok "deny carries X-JIT-Access marker"
  elif [ "$port" = "8085" ]; then
    # ingress-nginx answers a failed auth_request with ITS OWN error page and
    # does not proxy the auth service's headers, so the marker cannot survive.
    # Enrolled devices are unaffected (the extension knocks proactively on
    # navigation); only marker-based recovery is unavailable. See
    # adapters/kubernetes/README.md.
    note "no X-JIT-Access marker — expected on ingress-nginx (serves its own error page)"
  else
    bad "deny carries X-JIT-Access marker"
  fi

  # 3 + 4 + 5. knock, service opens, replay rejected
  out=$($KC --url "$base" --resolve "$resolve" --kid "$KID" --secret "$SECRET" --check-service --replay 2>&1)
  knock=$(sed -n 's/^KNOCK //p'   <<<"$out")
  svc=$(sed -n   's/^SERVICE //p' <<<"$out")
  replay=$(sed -n 's/^REPLAY //p' <<<"$out")

  [ "$knock" = "204" ]  && ok "knock accepted (204)"            || bad "knock accepted" "got ${knock:-$out}"
  [ "$svc"   = "200" ]  && ok "service opens after knock (200)" || bad "service opens after knock" "got ${svc:-none}"
  [ "$replay" != "204" ] && ok "replayed nonce rejected (${replay:-none})" || bad "replayed nonce rejected" "got 204 — replay accepted!"
done

# ---- security probes, per engine ------------------------------------------
# PROTOCOL §9 is explicit that a functional pass is NOT sufficient for
# conformance. This lab used to assert only the five functional properties
# above, which is how a traversal bypass in the forward-auth adapters survived:
# it was never exercised here, and the BunkerWeb-only security suite could not
# reach these engines. These are the engine-agnostic probes that need no
# instance API.
echo
echo "== security probes (all engines) =="
# These MUST run against a DARK gate. Previously they ran after the functional
# loop above, which leaves this client holding a grant — so the traversal probe
# was asking an already-open gate whether it was open, and could not detect the
# bypass it exists for. Restart the gates to drop every grant first.
if [ "${1:-}" != "--no-reset" ] && command -v docker >/dev/null 2>&1; then
  echo "  (restarting gates so probes run against a dark service)"
  (cd "$here" && ${SUDO:-sudo} docker compose restart caddy nginx traefik openresty authorizer >/dev/null 2>&1)
  for port in 8081 8082 8083 8084; do
    for _ in $(seq 1 30); do
      curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/" && break
      sleep 1
    done
  done
  sleep 2
fi
if command -v kubectl >/dev/null 2>&1 && ${SUDO:-sudo} kubectl get ns jit-system >/dev/null 2>&1; then
  ${SUDO:-sudo} kubectl -n jit-system rollout restart deploy/jit-authorizer >/dev/null 2>&1
  ${SUDO:-sudo} kubectl -n jit-system rollout status deploy/jit-authorizer --timeout=120s >/dev/null 2>&1
  sleep 3
fi

for spec in "${ENGINES[@]}"; do
  name="${spec%:*}"; port="${spec##*:}"
  base="http://$HOSTNAME_:$port"
  resolve="$HOSTNAME_:$port:127.0.0.1"

  # Sanity: the gate must actually be dark, or nothing below proves anything.
  dark=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --resolve "$resolve" "$base/" 2>/dev/null)
  if [ "$dark" = "200" ]; then
    bad "$name: probes need a dark gate" "still open (HTTP 200) — probes below are meaningless"
    continue
  fi

  # 1. Protocol-prefix traversal must not reach the upstream. The prefix is the
  #    one path answered WITHOUT a grant, so if the gate's view of the path can
  #    differ from the proxy's, that carve-out opens every path. Payloads must
  #    normalize onto something the upstream actually serves.
  trav_bad=""
  for t in "/.well-known/jit-access/../../"            "/.well-known/jit-access/../../index.html"            "/.well-known/jit-access/..%2f..%2f"            "/.well-known/jit-access/%2e%2e/%2e%2e/"; do
    c=$(curl -s -o /dev/null -w "%{http_code}" --path-as-is --max-time 10           --resolve "$resolve" "$base$t" 2>/dev/null)
    [ "$c" = "200" ] && trav_bad="$trav_bad $t->$c"
  done
  if [ -z "$trav_bad" ]; then ok "$name: traversal never reaches upstream"
  else bad "$name: traversal reached upstream" "$trav_bad"; fi

  # 2. Stealth mode must be INDISTINGUISHABLE from an unrouted path.
  #
  # Every engine in this lab used to pin failure_mode: interstitial, so the
  # generic-reply path was exercised by no live-stack test — and OpenResty had no
  # stealth coverage of any kind, not even a unit test. Each engine now also
  # serves stealth.example.com in stealth mode.
  sresolve="$STEALTH_HOST:$port:127.0.0.1"
  sbase="http://$STEALTH_HOST:$port"
  shape() { # status|content-type|body  for one request
    curl -s -o /tmp/jit_body.$$ -w "%{http_code}|%{content_type}" --max-time 10          --resolve "$sresolve" "$@" 2>/dev/null
    printf '|%s' "$(cat /tmp/jit_body.$$ 2>/dev/null)"; rm -f /tmp/jit_body.$$
  }
  unrouted=$(shape "$sbase/definitely-not-a-route-$$")
  s_bad=""
  for probe in "no-grant request:$sbase/"                "unknown path under the prefix:$sbase/.well-known/jit-access/nope"                "wrong method on challenge:-XPOST|$sbase/.well-known/jit-access/challenge"; do
    label="${probe%%:*}"; rest="${probe#*:}"
    if [ "${rest#*|}" != "$rest" ]; then got=$(shape "${rest%%|*}" "${rest#*|}"); else got=$(shape "$rest"); fi
    [ "$got" != "$unrouted" ] && s_bad="$s_bad [$label: $got vs $unrouted]"
  done
  if [ -z "$s_bad" ]; then ok "$name: stealth replies are indistinguishable from an unrouted path"
  else bad "$name: stealth is distinguishable" "$s_bad"; fi

  # ...and stealth must never carry the interstitial's detection marker.
  if curl -s -D- -o /dev/null --max-time 10 --resolve "$sresolve" "$sbase/" 2>/dev/null | grep -qi '^x-jit-access:'; then
    bad "$name: stealth deny carries X-JIT-Access" "the marker advertises a gate the operator hid"
  else
    ok "$name: stealth deny carries no marker"
  fi

  # 3. A malformed /respond must deny deliberately, never 5xx and never open.
  mal_bad=""
  for b in '' 'not json' '{}' '{"v":1,"kid":"x","nonce":"@@@","proof":"@@@"}'; do
    c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --resolve "$resolve"           -X POST -H "Content-Type: application/json" --data "$b"           "$base/.well-known/jit-access/respond" 2>/dev/null)
    case "$c" in 403|404) ;; *) mal_bad="$mal_bad [$c]";; esac
  done
  if [ -z "$mal_bad" ]; then ok "$name: malformed /respond denies deliberately"
  else bad "$name: malformed /respond" "non-deny codes:$mal_bad"; fi
done

echo
echo "=================================================="
echo "  $pass passed, $fail failed"
[ $fail -eq 0 ] && echo "  one token opened every engine" || echo "  SOME ENGINES FAILED"
echo "=================================================="
exit $([ $fail -eq 0 ] && echo 0 || echo 1)
