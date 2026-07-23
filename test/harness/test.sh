#!/usr/bin/env bash
# M1 exit test: the curl matrix from DESIGN §9 M1.
# Runs every request from the `tester` container so the source IP (the grant key
# in Simple mode) is stable. Run ./run.sh first.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

T() { docker compose exec -T tester sh -c "$1"; }

pass=0; fail=0
check() { # desc expected actual
  if [ "$2" = "$3" ]; then echo "  PASS: $1 ($3)"; pass=$((pass+1))
  else echo "  FAIL: $1 (expected $2, got $3)"; fail=$((fail+1)); fi
}

# tester's IP as BunkerWeb sees it (Simple mode = TCP peer, no real-IP)
IP=$(T "hostname -i" | tr -d '\r' | awk '{print $1}')
echo "tester source IP (grant key): $IP"
echo

svc()  { T "curl -s -o /dev/null -w '%{http_code}' -H 'Host: $1' http://bunkerweb:8080/"; }
path() { T "curl -s -o /dev/null -w '%{http_code}' -H 'Host: $1' http://bunkerweb:8080$2"; }
hdrs() { T "curl -s -D - -o /dev/null -H 'Host: $1' http://bunkerweb:8080/ | tr -d '\r'"; }
api()  { T "curl -s -o /dev/null -w '%{http_code}' -X POST http://bunkerweb:5000$1 -H 'Host: bwapi' -H 'Content-Type: application/json' -d '$2'"; }

echo "== dark by default =="
check "app-a (interstitial) no grant -> 403" 403 "$(svc app-a.local)"
check "app-b (stealth) no grant -> 404"      404 "$(svc app-b.local)"

echo "== detection marker (interstitial only) =="
if hdrs app-a.local | grep -qi '^X-JIT-Access:'; then
  echo "  PASS: app-a sets X-JIT-Access marker"; pass=$((pass+1))
else echo "  FAIL: app-a missing X-JIT-Access marker"; fail=$((fail+1)); fi
if hdrs app-b.local | grep -qi '^X-JIT-Access:'; then
  echo "  FAIL: app-b (stealth) leaked X-JIT-Access marker"; fail=$((fail+1))
else echo "  PASS: app-b stealth exposes no marker"; pass=$((pass+1)); fi

echo "== manual grant (break-glass) admits, per-service =="
check "POST /jitaccess/grant -> 200" 200 "$(api /jitaccess/grant "{\"service\":\"app-a.local\",\"ip\":\"$IP\",\"ttl\":120}")"
check "app-a after grant -> 200 (upstream)" 200 "$(svc app-a.local)"
check "app-b still dark -> 404 (grant is scoped to app-a)" 404 "$(svc app-b.local)"

echo "== protocol endpoints never pass through (M2 stub denies) =="
check "granted app-a, /.well-known/jit-access/challenge -> 403" 403 "$(path app-a.local /.well-known/jit-access/challenge)"

echo "== revoke re-darkens =="
check "POST /jitaccess/revoke -> 200" 200 "$(api /jitaccess/revoke "{\"service\":\"app-a.local\",\"ip\":\"$IP\"}")"
check "app-a after revoke -> 403" 403 "$(svc app-a.local)"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "M1 exit test GREEN" || { echo "M1 exit test RED"; exit 1; }
