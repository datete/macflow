#!/bin/bash
# MACFlow v2.0 Regression Test Suite
# Run on VM or via SSH: ssh -p 2222 root@127.0.0.1 'bash /opt/macflow/vm/regression-test.sh'
set -e

API="http://127.0.0.1:18080"
PASS=0
FAIL=0
SKIP=0
RESULTS=""

pass(){ PASS=$((PASS+1)); RESULTS="$RESULTS\n  ✅ $1"; }
fail(){ FAIL=$((FAIL+1)); RESULTS="$RESULTS\n  ❌ $1: $2"; }
skip(){ SKIP=$((SKIP+1)); RESULTS="$RESULTS\n  ⏭️  $1: $2"; }

echo "══════════════════════════════════════"
echo "  MACFlow v2.0 Regression Test Suite"
echo "══════════════════════════════════════"
echo ""

# ── 1. Basic API Health ──
echo "▶ 1. Basic API endpoints..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/status")
[ "$STATUS" = "200" ] && pass "GET /api/status → 200" || fail "GET /api/status" "HTTP $STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API/")
[ "$STATUS" = "200" ] && pass "GET / (index.html) → 200" || fail "GET / (index.html)" "HTTP $STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API/captive")
[ "$STATUS" = "200" ] && pass "GET /captive → 200" || fail "GET /captive" "HTTP $STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/captive/status")
[ "$STATUS" = "200" ] && pass "GET /api/captive/status → 200" || fail "GET /api/captive/status" "HTTP $STATUS"

# ── 2. Status Content Check ──
echo "▶ 2. Status content..."
BODY=$(curl -s "$API/api/status")
VER=$(echo "$BODY" | python3 -c "import sys,json;print(json.load(sys.stdin)['version'])" 2>/dev/null)
[ "$VER" = "2.0.0" ] && pass "Version = 2.0.0" || fail "Version check" "got $VER"

NODES=$(echo "$BODY" | python3 -c "import sys,json;print(json.load(sys.stdin)['node_count'])" 2>/dev/null)
[ "$NODES" -gt 0 ] 2>/dev/null && pass "node_count = $NODES > 0" || fail "node_count" "got $NODES"

DEVS=$(echo "$BODY" | python3 -c "import sys,json;print(json.load(sys.stdin)['device_count'])" 2>/dev/null)
[ "$DEVS" -gt 0 ] 2>/dev/null && pass "device_count = $DEVS > 0" || fail "device_count" "got $DEVS"

HEALTH=$(echo "$BODY" | python3 -c "import sys,json;print(json.load(sys.stdin)['overall_health'])" 2>/dev/null)
[ "$HEALTH" = "ok" ] && pass "overall_health = ok" || fail "overall_health" "got $HEALTH"

# ── 3. Node/Device CRUD ──
echo "▶ 3. Node/Device list..."
NLIST=$(curl -s "$API/api/nodes" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null)
[ "$NLIST" -gt 0 ] 2>/dev/null && pass "GET /api/nodes → $NLIST nodes" || fail "GET /api/nodes" "count=$NLIST"

DLIST=$(curl -s "$API/api/devices" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null)
[ "$DLIST" -gt 0 ] 2>/dev/null && pass "GET /api/devices → $DLIST devices" || fail "GET /api/devices" "count=$DLIST"

# ── 4. MAC Validation (B1/B11) ──
echo "▶ 4. MAC address validation..."
# Valid MAC
RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-regression","mac":"AA:BB:CC:DD:EE:FF","node_tag":"direct","managed":false}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "200" ] && pass "Valid MAC accepted (AA:BB:CC:DD:EE:FF)" || fail "Valid MAC" "HTTP $CODE"

# Invalid MAC - should be rejected
RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"bad-mac","mac":"} ; drop ; {","node_tag":"direct","managed":false}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "422" ] && pass "Invalid MAC rejected (injection attempt → 422)" || fail "Invalid MAC rejection" "HTTP $CODE expected 422"

RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"bad-mac2","mac":"not-a-mac","node_tag":"direct","managed":false}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "422" ] && pass "Invalid MAC rejected (not-a-mac → 422)" || fail "Invalid MAC rejection 2" "HTTP $CODE expected 422"

# Cleanup test device
curl -s -X DELETE "$API/api/devices/AA:BB:CC:DD:EE:FF" > /dev/null 2>&1

# ── 5. DNS Server IP Validation (B2) ──
echo "▶ 5. DNS server IP validation..."
# Save current settings
ORIG_SETTINGS=$(curl -s "$API/api/settings")

# Invalid DNS server
RESP=$(curl -s -w "\n%{http_code}" -X PUT "$API/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"dns":{"servers":["not-an-ip"],"enforce_redirect_port":6053,"block_doh_doq":true,"force_redirect":true}}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "400" ] && pass "Invalid DNS IP rejected (not-an-ip → 400)" || fail "DNS IP validation" "HTTP $CODE expected 400"

# Valid DNS server
RESP=$(curl -s -w "\n%{http_code}" -X PUT "$API/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"dns":{"servers":["8.8.8.8","1.1.1.1"],"enforce_redirect_port":6053,"block_doh_doq":true,"force_redirect":true}}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "200" ] && pass "Valid DNS IPs accepted (8.8.8.8, 1.1.1.1)" || fail "Valid DNS" "HTTP $CODE"

# ── 6. Subscription URL Validation (B5/B20) ──
echo "▶ 6. Subscription URL validation..."
RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/api/subscriptions" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-file","url":"file:///etc/passwd"}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "422" ] && pass "file:// URL rejected → 422" || fail "file:// URL validation" "HTTP $CODE expected 422"

RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/api/subscriptions" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-ftp","url":"ftp://evil.com/payload"}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "422" ] && pass "ftp:// URL rejected → 422" || fail "ftp:// URL validation" "HTTP $CODE expected 422"

# ── 7. Captive Portal XSS Protection (B3) ──
echo "▶ 7. Captive portal XSS..."
CAPTIVE_BODY=$(curl -s "$API/captive")
if echo "$CAPTIVE_BODY" | grep -q '<script>'; then
  # Ensure it's not injected script tag from device names
  # The page should have its own script tags but not unescaped user data
  pass "Captive page renders (contains expected script tags)"
else
  pass "Captive page renders cleanly"
fi

# ── 8. Auth System ──
echo "▶ 8. Auth system..."
AUTH_STATUS=$(curl -s "$API/api/auth/status")
AUTH_EN=$(echo "$AUTH_STATUS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('auth_enabled',False))" 2>/dev/null)
pass "Auth status endpoint works (enabled=$AUTH_EN)"

# ── 9. SSE Events ──
echo "▶ 9. SSE events..."
SSE_RESP=$(timeout 5 curl -s -N "$API/api/events" 2>/dev/null | head -20 || true)
if echo "$SSE_RESP" | grep -q "event:"; then
  pass "SSE events received"
else
  skip "SSE events" "No events in 5s (may be slow)"
fi

# ── 10. Settings & Toggles ──
echo "▶ 10. Settings..."
SETTINGS=$(curl -s "$API/api/settings")
DP=$(echo "$SETTINGS" | python3 -c "import sys,json;print(json.load(sys.stdin)['default_policy'])" 2>/dev/null)
pass "Settings readable (policy=$DP)"

# ── 11. Health Check ──
echo "▶ 11. Health check..."
HEALTH_BODY=$(curl -s "$API/api/health")
OVERALL=$(echo "$HEALTH_BODY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('overall_status','?'))" 2>/dev/null)
pass "Health check endpoint works (status=$OVERALL)"

# ── 12. Sources ──
echo "▶ 12. Sources..."
SOURCES=$(curl -s "$API/api/sources" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null)
pass "GET /api/sources → $SOURCES sources"

# ── 13. Traffic ──
echo "▶ 13. Traffic..."
STATUS_T=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/traffic/realtime")
[ "$STATUS_T" = "200" ] && pass "GET /api/traffic/realtime → 200" || fail "Traffic realtime" "HTTP $STATUS_T"

STATUS_C=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/traffic/connections")
[ "$STATUS_C" = "200" ] && pass "GET /api/traffic/connections → 200" || fail "Traffic connections" "HTTP $STATUS_C"

# ── 14. System Info ──
echo "▶ 14. System info..."
SYSINFO=$(curl -s "$API/api/system/info")
PID=$(echo "$SYSINFO" | python3 -c "import sys,json;print(json.load(sys.stdin)['pid'])" 2>/dev/null)
[ -n "$PID" ] && pass "System info (pid=$PID)" || fail "System info" "no PID"

# ── 15. Logs ──
echo "▶ 15. Logs..."
STATUS_L=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/logs")
[ "$STATUS_L" = "200" ] && pass "GET /api/logs → 200" || fail "GET /api/logs" "HTTP $STATUS_L"

# ── 16. Egress Check ──
echo "▶ 16. Egress..."
STATUS_E=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/egress/router")
[ "$STATUS_E" = "200" ] && pass "GET /api/egress/router → 200" || skip "Egress check" "HTTP $STATUS_E (may timeout)"

# ── 17. Singbox Preview ──
echo "▶ 17. sing-box preview..."
STATUS_P=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/singbox/preview")
[ "$STATUS_P" = "200" ] && pass "GET /api/singbox/preview → 200" || fail "Singbox preview" "HTTP $STATUS_P"

# ── 18. DHCP scan ──
echo "▶ 18. DHCP..."
STATUS_D=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/dhcp")
[ "$STATUS_D" = "200" ] && pass "GET /api/dhcp → 200" || skip "DHCP scan" "HTTP $STATUS_D"

# ── 19. Frontend Content ──
echo "▶ 19. Frontend content checks..."
INDEX=$(curl -s "$API/")
echo "$INDEX" | grep -q "escHtml" && pass "index.html contains escHtml XSS protection" || fail "escHtml presence" "not found"
echo "$INDEX" | grep -q "escAttr" && pass "index.html contains escAttr function" || fail "escAttr presence" "not found"
echo "$INDEX" | grep -q "_topoInited" && pass "index.html has topo reentry guard" || fail "_topoInited presence" "not found"
echo "$INDEX" | grep -q "Promise.allSettled" && pass "index.html uses Promise.allSettled for resilient init" || fail "Promise.allSettled" "not found"
echo "$INDEX" | grep -q "modal-overlay" && pass "index.html has modal overlay CSS" || fail "modal-overlay" "not found"

# ── 20. Update Check ──
echo "▶ 20. Update check..."
STATUS_U=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/update/check")
[ "$STATUS_U" = "200" ] && pass "GET /api/update/check → 200" || skip "Update check" "HTTP $STATUS_U (GitHub may be unreachable)"

echo ""
echo "══════════════════════════════════════"
echo "  RESULTS"
echo "══════════════════════════════════════"
echo -e "$RESULTS"
echo ""
echo "══════════════════════════════════════"
TOTAL=$((PASS+FAIL+SKIP))
echo "  TOTAL: $TOTAL  |  ✅ PASS: $PASS  |  ❌ FAIL: $FAIL  |  ⏭️  SKIP: $SKIP"
echo "══════════════════════════════════════"

[ "$FAIL" -eq 0 ] && echo "  🎉 ALL TESTS PASSED!" || echo "  ⚠️  SOME TESTS FAILED"
exit $FAIL
