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

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "M2 conformance GREEN" || { echo "M2 conformance RED"; exit 1; }
