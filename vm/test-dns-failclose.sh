#!/bin/bash
# MACFlow long-run check: DNS fault injection + fail-close auto recovery
set -euo pipefail

API="http://127.0.0.1:18080"
PASS=0
FAIL=0

ok() {
  echo "[OK]   $1"
  PASS=$((PASS+1))
}

fail() {
  echo "[FAIL] $1"
  FAIL=$((FAIL+1))
}

status_fields() {
  curl -s "$API/api/status" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('fail_close_active', False)).lower(), d.get('overall_health','unknown'), d.get('last_probe_at',0))"
}

health_fields() {
  curl -s "$API/api/health" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('checks',{}).get('dns_guard',{}); det=c.get('details',{}); print(d.get('overall_status','unknown'), c.get('status','unknown'), str(det.get('udp_listener', False)).lower(), str(det.get('tcp_listener', False)).lower())"
}

echo "========================================="
echo "  MACFlow DNS Fail-Close Long Test"
echo "========================================="

echo ""
echo "== Setup whitelist + fail-close =="
curl -s -X PUT "$API/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"default_policy":"whitelist","failure_policy":"fail-close"}' >/dev/null
curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}' >/dev/null
curl -s -X POST "$API/api/apply" >/dev/null

echo "== Wait baseline to become healthy and guard-inactive =="
READY=0
for i in $(seq 1 12); do
  read FC OH LP < <(status_fields)
  read BASE_OVERALL BASE_DNS BASE_UDP BASE_TCP < <(health_fields)
  echo "  warmup[$i] fail_close_active=$FC overall=$OH dns=$BASE_DNS udp_listener=$BASE_UDP tcp_listener=$BASE_TCP"
  if [ "$FC" = "false" ] && [ "$OH" = "ok" ] && [ "$BASE_DNS" = "ok" ] && [ "$BASE_UDP" = "true" ] && [ "$BASE_TCP" = "true" ]; then
    READY=1
    break
  fi
  sleep 5
done

if [ "$READY" -eq 1 ]; then
  ok "baseline health is ok and fail-close guard is inactive"
else
  fail "baseline not ready before fault injection"
fi

echo ""
echo "== Inject fault: delete nft table =="
nft delete table inet macflow >/dev/null 2>&1 || true

ACTIVATED=0
for i in $(seq 1 12); do
  sleep 10
  read FC OH LP < <(status_fields)
  echo "  poll[$i] fail_close_active=$FC overall=$OH last_probe=$LP"
  if [ "$FC" = "true" ]; then
    ACTIVATED=1
    break
  fi
done

if [ "$ACTIVATED" -eq 1 ]; then
  ok "fail-close guard activated automatically"
else
  fail "fail-close guard did not activate after injected fault"
fi

LOG_ACTIVE=$(curl -s "$API/api/logs?lines=200" | python3 -c "import sys,json; arr=json.load(sys.stdin); print('yes' if any(isinstance(x,dict) and x.get('event')=='fail_close_guard' and 'active=True' in x.get('message','') for x in arr) else 'no')")
if [ "$LOG_ACTIVE" = "yes" ]; then
  ok "audit log recorded fail_close_guard activation"
else
  fail "audit log missing fail_close_guard activation record"
fi

echo ""
echo "== Wait for self-heal (auto reapply + release) =="
RECOVERED=0
for i in $(seq 1 18); do
  sleep 10
  read FC OH LP < <(status_fields)
  read HOVER HDNS HUDP HTCP < <(health_fields)
  echo "  recover[$i] fail_close_active=$FC overall=$OH dns=$HDNS udp=$HUDP tcp=$HTCP"
  if [ "$FC" = "false" ] && [ "$OH" = "ok" ] && [ "$HDNS" = "ok" ] && [ "$HUDP" = "true" ] && [ "$HTCP" = "true" ]; then
    RECOVERED=1
    break
  fi
done

if [ "$RECOVERED" -eq 1 ]; then
  ok "system recovered to healthy state and released fail-close"
else
  fail "system did not recover to healthy state in expected window"
fi

LOG_RELEASE=$(curl -s "$API/api/logs?lines=200" | python3 -c "import sys,json; arr=json.load(sys.stdin); print('yes' if any(isinstance(x,dict) and ((x.get('event')=='fail_close_released') or (x.get('event')=='fail_close_guard' and 'active=False' in x.get('message',''))) for x in arr) else 'no')")
if [ "$LOG_RELEASE" = "yes" ]; then
  ok "audit log recorded fail-close release"
else
  fail "audit log missing fail-close release record"
fi

echo ""
echo "========================================="
echo "  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "  STATUS: DNS FAIL-CLOSE LONG TEST PASSED" || echo "  STATUS: DNS FAIL-CLOSE LONG TEST FAILED"
exit "$FAIL"
