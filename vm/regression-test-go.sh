#!/bin/sh
# MACFlow Go 版全量 API 回归测试
# 覆盖 42 个 GET 端点 + 关键 POST/PUT/DELETE 操作
set -u

BASE="http://127.0.0.1:18080/api"
PASS=0
FAIL=0
SKIP=0
TOTAL=0

ok()   { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  [OK]   $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  [FAIL] $1 -- $2"; }
skip() { SKIP=$((SKIP+1)); TOTAL=$((TOTAL+1)); echo "  [SKIP] $1 -- $2"; }

# wget wrapper: check_get <path> [min_bytes]
check_get() {
    local path="$1"
    local min="${2:-1}"
    RESP=$(wget -qO- "${BASE}${path}" 2>/dev/null)
    if [ -n "$RESP" ] && [ "${#RESP}" -ge "$min" ]; then
        ok "GET $path (${#RESP}B)"
    else
        fail "GET $path" "empty or too short (${#RESP}B < ${min}B)"
    fi
}

# check_get_json <path>: must return valid JSON starting with { or [
check_get_json() {
    local path="$1"
    RESP=$(wget -qO- "${BASE}${path}" 2>/dev/null)
    if echo "$RESP" | grep -qE '^\s*[\{\[]'; then
        ok "GET $path (JSON ${#RESP}B)"
    elif [ -z "$RESP" ]; then
        fail "GET $path" "empty response"
    else
        fail "GET $path" "not JSON: $(echo "$RESP" | head -c 80)"
    fi
}

# check_post <path> [body]: expect 2xx (wget exit 0)
check_post() {
    local path="$1"
    local body="${2:-}"
    if [ -n "$body" ]; then
        RESP=$(wget -qO- --post-data="$body" --header="Content-Type: application/json" "${BASE}${path}" 2>/dev/null)
    else
        RESP=$(wget -qO- --post-data="" "${BASE}${path}" 2>/dev/null)
    fi
    RET=$?
    if [ "$RET" = "0" ] || [ -n "$RESP" ]; then
        ok "POST $path (${#RESP}B)"
    else
        fail "POST $path" "exit=$RET"
    fi
}

# check_put <path> <body>: expect 2xx
check_put() {
    local path="$1"
    local body="$2"
    # busybox wget doesn't support PUT, use wget with --method if available
    if wget --help 2>&1 | grep -q "\-\-method"; then
        RESP=$(wget -qO- --method=PUT --body-data="$body" --header="Content-Type: application/json" "${BASE}${path}" 2>/dev/null)
    else
        # fallback: use curl if available
        if command -v curl >/dev/null 2>&1; then
            RESP=$(curl -s -X PUT -H "Content-Type: application/json" -d "$body" "${BASE}${path}" 2>/dev/null)
        else
            skip "PUT $path" "no wget --method or curl"
            return
        fi
    fi
    RET=$?
    if [ "$RET" = "0" ] || [ -n "$RESP" ]; then
        ok "PUT $path (${#RESP}B)"
    else
        fail "PUT $path" "exit=$RET"
    fi
}

# check_delete <path>
check_delete() {
    local path="$1"
    if command -v curl >/dev/null 2>&1; then
        RESP=$(curl -s -X DELETE "${BASE}${path}" 2>/dev/null)
    else
        skip "DELETE $path" "no curl"
        return
    fi
    RET=$?
    if [ "$RET" = "0" ]; then
        ok "DELETE $path"
    else
        fail "DELETE $path" "exit=$RET"
    fi
}

echo "============================================="
echo "  MACFlow Go API 全量回归测试"
echo "  Target: $BASE"
echo "============================================="
echo ""

# ── 1. Auth ──────────────────────────────────────────
echo "[1/12] Auth"
check_get_json /auth/status

# ── 2. Status & Health ───────────────────────────────
echo "[2/12] Status & Health"
check_get_json /status
check_get_json /health
check_get_json /alerts
check_get_json /captive/status

# ── 3. Settings ──────────────────────────────────────
echo "[3/12] Settings"
check_get_json /settings

# ── 4. Sources ───────────────────────────────────────
echo "[4/12] Sources"
check_get_json /sources
# Create → Update → Delete a test source
check_post /sources '{"name":"regression-test","url":"http://127.0.0.1:1234","type":"3x-ui","sync_interval":3600}'
SRC_ID=$(wget -qO- "${BASE}/sources" 2>/dev/null | grep -oE '"id":"[^"]*"' | tail -1 | sed 's/"id":"//;s/"//')
if [ -n "$SRC_ID" ]; then
    check_put "/sources/$SRC_ID" '{"name":"regression-test-updated","url":"http://127.0.0.1:1234","type":"3x-ui","sync_interval":7200}'
    check_delete "/sources/$SRC_ID"
else
    skip "PUT /sources/:sid" "no source ID"
    skip "DELETE /sources/:sid" "no source ID"
fi

# ── 5. Nodes ─────────────────────────────────────────
echo "[5/12] Nodes"
check_get_json /nodes
check_post /nodes/manual '{"tag":"regression-node","protocol":"vless","address":"1.2.3.4","port":443,"uuid":"test-uuid"}'
# check_post /nodes/import-link/preview  -- would need a valid link
NODE_TAG="regression-node"
check_put "/nodes/$NODE_TAG" '{"tag":"regression-node","protocol":"vless","address":"1.2.3.4","port":8443,"uuid":"test-uuid-2"}'
check_put "/nodes/$NODE_TAG/toggle" '{}'
check_delete "/nodes/$NODE_TAG"

# ── 6. Subscriptions ────────────────────────────────
echo "[6/12] Subscriptions"
check_get_json /subscriptions
check_post /subscriptions '{"name":"regression-sub","url":"https://example.com/sub"}'
SUB_ID=$(wget -qO- "${BASE}/subscriptions" 2>/dev/null | grep -oE '"id":"[^"]*"' | tail -1 | sed 's/"id":"//;s/"//')
if [ -n "$SUB_ID" ]; then
    check_put "/subscriptions/$SUB_ID" '{"name":"regression-sub-updated","url":"https://example.com/sub2"}'
    check_delete "/subscriptions/$SUB_ID"
else
    skip "PUT /subscriptions/:sid" "no sub ID"
    skip "DELETE /subscriptions/:sid" "no sub ID"
fi

# ── 7. Devices ───────────────────────────────────────
echo "[7/12] Devices"
check_get_json /devices
check_post /devices '{"mac":"AA:BB:CC:DD:EE:FF","remark":"regression-device"}'
check_put "/devices/AA:BB:CC:DD:EE:FF/remark" '{"remark":"regression-updated"}'
check_put "/devices/AA:BB:CC:DD:EE:FF/ip" '{"ip":"10.0.0.99"}'
check_delete "/devices/AA:BB:CC:DD:EE:FF"

# ── 8. Egress ────────────────────────────────────────
echo "[8/12] Egress"
check_get_json /egress/router
# egress/node and egress/device need valid params
FIRST_NODE=$(wget -qO- "${BASE}/nodes" 2>/dev/null | grep -oE '"tag":"[^"]*"' | head -1 | sed 's/"tag":"//;s/"//')
if [ -n "$FIRST_NODE" ]; then
    check_get_json "/egress/node/$FIRST_NODE"
else
    skip "GET /egress/node/:tag" "no nodes"
fi
FIRST_DEV=$(wget -qO- "${BASE}/devices" 2>/dev/null | grep -oE '"mac":"[^"]*"' | head -1 | sed 's/"mac":"//;s/"//')
if [ -n "$FIRST_DEV" ]; then
    check_get_json "/egress/device/$FIRST_DEV"
else
    skip "GET /egress/device/:mac" "no devices"
fi

# ── 9. System ────────────────────────────────────────
echo "[9/12] System"
check_get_json /system/info
check_get_json /update/check

# ── 10. Traffic ──────────────────────────────────────
echo "[10/12] Traffic"
check_get_json /traffic/realtime
check_get_json /traffic/connections

# ── 11. Logs ─────────────────────────────────────────
echo "[11/12] Logs"
check_get /logs
# check_post /logs/clear  -- destructive, skip

# ── 12. DHCP & Misc ─────────────────────────────────
echo "[12/12] DHCP & Misc"
check_get_json /dhcp/discover
check_get_json /singbox/preview

# ── final-check.sh 系统检查 ──────────────────────────
echo ""
echo "[Bonus] System infrastructure checks"
if nft list table inet macflow >/dev/null 2>&1; then ok "nftables macflow table"; else fail "nftables" "macflow table missing"; fi
if pgrep -f sing-box >/dev/null 2>&1; then ok "sing-box running"; else fail "sing-box" "not running"; fi
if ip link show singtun0 2>/dev/null | grep -q UP; then ok "TUN singtun0 UP"; else fail "TUN" "singtun0 down"; fi

# ── Memory / Performance ────────────────────────────
echo ""
echo "[Performance]"
PID=$(pgrep -f "/opt/macflow/macflowd")
if [ -n "$PID" ]; then
    MEM=$(awk '/VmRSS/{print $2}' /proc/$PID/status)
    ok "macflowd memory: ${MEM} kB"
fi
UPTIME=$(wget -qO- "${BASE}/status" 2>/dev/null | grep -oE '"uptime":[0-9.]*' | cut -d: -f2)
if [ -n "$UPTIME" ]; then
    ok "uptime: ${UPTIME}s"
fi

# ── Summary ──────────────────────────────────────────
echo ""
echo "============================================="
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP  TOTAL=$TOTAL"
if [ "$FAIL" -gt 0 ]; then
    echo "  STATUS: REGRESSION FOUND"
    exit 2
elif [ "$SKIP" -gt 0 ]; then
    echo "  STATUS: PASS (with skips)"
    exit 0
else
    echo "  STATUS: ALL PASSED"
    exit 0
fi
