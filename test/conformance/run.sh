#!/usr/bin/env bash
# M2 conformance: drive the knock client against the docker harness (start it
# first with ../harness/run.sh). Requires python3 + curl on the host; the
# harness publishes :8443. Uses the harness's fixed test tokens.
#
# Asserts: kid_a unlocks app-a but NOT app-b (per-service allow-list), replay
# of a used nonce is rejected, and kid_b unlocks app-b.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KC="python3 $here/knock_client.py"
PORT="${PORT:-8443}"
SEC_A="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"   # base64url(0x01*32)
SEC_B="AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"   # base64url(0x02*32)

pass=0; fail=0
expect() { # desc  "KEY VAL"  actual-multiline
  if grep -q "^$2\$" <<<"$3"; then echo "  PASS: $1"; pass=$((pass+1)); else echo "  FAIL: $1 (got: $(tr '\n' ' ' <<<"$3"))"; fail=$((fail+1)); fi
}

echo "== kid_a on app-a (allowed): expect KNOCK 204, SERVICE 200, REPLAY 403 =="
o=$($KC --url "https://app-a.local:$PORT" --kid kid_a_test --secret "$SEC_A" --resolve "app-a.local:$PORT:127.0.0.1" --check-service --replay)
echo "$o" | sed 's/^/    /'
expect "app-a knock accepted" "KNOCK 204" "$o"
expect "app-a service unlocked" "SERVICE 200" "$o"
expect "replay rejected" "REPLAY 403" "$o"

echo "== kid_a on app-b (NOT allowed): expect KNOCK 404 (stealth) =="
o=$($KC --url "https://app-b.local:$PORT" --kid kid_a_test --secret "$SEC_A" --resolve "app-b.local:$PORT:127.0.0.1")
echo "$o" | sed 's/^/    /'
expect "app-b rejects kid_a" "KNOCK 404" "$o"

echo "== kid_b on app-b (allowed): expect KNOCK 204, SERVICE 200 =="
o=$($KC --url "https://app-b.local:$PORT" --kid kid_b_test --secret "$SEC_B" --resolve "app-b.local:$PORT:127.0.0.1" --check-service)
echo "$o" | sed 's/^/    /'
expect "app-b knock accepted" "KNOCK 204" "$o"
expect "app-b service unlocked" "SERVICE 200" "$o"

# ---- security conformance (M2.5) ------------------------------------------
# PROTOCOL §9: an implementation is conformant only when it passes the SECURITY
# profile too — "functional pass alone is not sufficient". Both suites below
# existed but were wired into no runner, so in practice only the functional
# knock above ever ran, and the security probes were executed by hand if at all.
#
# --api/--api-token are optional but STRONGLY recommended: without them the
# probes that need to set up a victim grant report themselves as SETUP FAILED
# rather than passing vacuously.
API_ARGS=""
if [ -n "${API_URL:-}" ] && [ -n "${API_TOKEN:-}" ]; then
  API_ARGS="--api $API_URL --api-token $API_TOKEN"
else
  echo
  echo "NOTE: set API_URL and API_TOKEN to enable the probes that need the instance API."
fi

echo
echo "== security conformance suite =="
if python3 "$here/security_suite.py"      --a-url "https://app-a.local:$PORT" --a-resolve "app-a.local:$PORT:127.0.0.1"      --a-kid kid_a_test --a-secret "$SEC_A" --a-name app-a.local      --b-url "https://app-b.local:$PORT" --b-resolve "app-b.local:$PORT:127.0.0.1"      --b-name app-b.local --b-kid kid_b_test --b-secret "$SEC_B"      ${PEER_IP:+--peer-ip "$PEER_IP"} $API_ARGS; then
  pass=$((pass+1)); echo "  PASS: security suite"
else
  fail=$((fail+1)); echo "  FAIL: security suite"
fi

# ---- ip+cookie binding ----------------------------------------------------
# cookie_binding.py asserts the six properties of the device-bound grant
# (__Host- prefix, Secure, HttpOnly, SameSite=Strict, opacity, entropy). It was
# wired into no runner at all, so those properties were only ever checked by
# hand. It needs a service configured with binding: ip+cookie over HTTPS —
# app-a in the harness qualifies once JIT_ACCESS_BINDING is set for it.
if [ "${COOKIE_BINDING:-1}" = "1" ]; then
  echo
  echo "== ip+cookie binding =="
  if python3 "$here/cookie_binding.py" --url "https://app-c.local:$PORT"        --resolve "app-c.local:$PORT:127.0.0.1"        --kid kid_a_test --secret "$SEC_A" --host app-c.local; then
    pass=$((pass+1)); echo "  PASS: ip+cookie binding (app-c)"
  else
    fail=$((fail+1)); echo "  FAIL: ip+cookie binding (is app-c.local up with JIT_ACCESS_BINDING=ip+cookie?)"
  fi
fi

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "M2 conformance GREEN" || { echo "M2 conformance RED"; exit 1; }
