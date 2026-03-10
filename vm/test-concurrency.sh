#!/bin/bash
# MACFlow concurrency + multi-agent tests
set -euo pipefail
API="http://127.0.0.1:18080"
PASS=0; FAIL=0
ok()   { echo "[OK]   $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() {
  echo "== Cleanup =="
  for i in $(seq 1 50); do
    MAC=$(printf "CC:CC:CC:%02X:%02X:%02X" $((i/256/256%256)) $((i/256%256)) $((i%256)))
    curl -s -X DELETE "$API/api/devices/$MAC" >/dev/null 2>&1 || true
  done
  for tag in conc-node-a conc-node-b conc-agent-a conc-agent-b; do
    curl -s -X DELETE "$API/api/nodes/$tag" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "========================================="
echo "  MACFlow Concurrency & Multi-Agent Test"
echo "========================================="

echo ""
echo "== Setup nodes =="
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"conc-node-a","server":"10.0.2.1","server_port":8388,"method":"aes-256-gcm","password":"ca"}'
echo ""
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"conc-node-b","server":"10.0.2.2","server_port":8389,"method":"aes-256-gcm","password":"cb"}'
echo ""
curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" -d '{"enabled":true}'
echo ""

# ─────────────────────────────────────────────
echo ""
echo "== TEST 1: Concurrent device add (20 devices) =="
for i in $(seq 1 20); do
  MAC=$(printf "CC:CC:CC:%02X:%02X:%02X" $((i/256/256%256)) $((i/256%256)) $((i%256)))
  NODE="conc-node-a"
  [ $((i % 2)) -eq 0 ] && NODE="conc-node-b"
  curl -s -X POST "$API/api/devices" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"conc-dev-$i\",\"mac\":\"$MAC\",\"node_tag\":\"$NODE\",\"managed\":true}" &
done
wait
echo "  20 concurrent device adds completed"

DEVS=$(curl -s "$API/api/devices" 2>/dev/null)
DEV_COUNT=$(echo "$DEVS" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len([x for x in d if x.get('mac','').startswith('CC:CC:CC')]))" 2>/dev/null || echo "0")
echo "  devices with CC:CC:CC prefix: $DEV_COUNT"
if [ "$DEV_COUNT" -eq 20 ]; then
  ok "concurrent add: all 20 devices created"
else
  fail "concurrent add: expected 20 devices, got $DEV_COUNT"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 2: Verify all marks unique =="
MARKS=$(echo "$DEVS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
marks=[x.get('mark',0) for x in d if x.get('mac','').startswith('CC:CC:CC') and x.get('mark',0)>0]
print(f'total={len(marks)} unique={len(set(marks))}')" 2>/dev/null || echo "error")
MARK_UNIQUE=$(echo "$DEVS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
marks=[x.get('mark',0) for x in d if x.get('mac','').startswith('CC:CC:CC') and x.get('mark',0)>0]
print('yes' if len(marks)>0 and len(marks)==len(set(marks)) else 'no')" 2>/dev/null || echo "no")
echo "  marks: $MARKS"
if [ "$MARK_UNIQUE" = "yes" ]; then
  ok "mark uniqueness: all marks unique"
else
  fail "mark uniqueness: duplicate marks detected"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 3: Concurrent node set (10 devices switch) =="
for i in $(seq 1 10); do
  MAC=$(printf "CC:CC:CC:%02X:%02X:%02X" $((i/256/256%256)) $((i/256%256)) $((i%256)))
  NODE="conc-node-b"
  [ $((i % 2)) -eq 0 ] && NODE="conc-node-a"
  curl -s -X PUT "$API/api/devices/$MAC/node" \
    -H "Content-Type: application/json" \
    -d "{\"node_tag\":\"$NODE\"}" &
done
wait
echo "  10 concurrent set_node completed"

STATE_JSON=$(cat /opt/macflow/data/state.json 2>/dev/null || echo "{}")
STATE_OK=$(echo "$STATE_JSON" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    devs=d.get('devices',[])
    print(f'devices={len(devs)} ok=true')
except:
    print('ok=false')" 2>/dev/null || echo "ok=false")
echo "  state check: $STATE_OK"
echo "$STATE_OK" | grep -q "ok=true" && ok "concurrent set_node: state.json valid" || fail "concurrent set_node: state.json corrupted"

# ─────────────────────────────────────────────
echo ""
echo "== TEST 4: Concurrent apply + set_node =="
curl -s -X POST "$API/api/apply" &
PID_APPLY=$!

for i in 11 12 13; do
  MAC=$(printf "CC:CC:CC:%02X:%02X:%02X" $((i/256/256%256)) $((i/256%256)) $((i%256)))
  curl -s -X PUT "$API/api/devices/$MAC/node" \
    -H "Content-Type: application/json" \
    -d '{"node_tag":"conc-node-a"}' &
done
wait "$PID_APPLY" 2>/dev/null || true
wait

STATE_JSON2=$(cat /opt/macflow/data/state.json 2>/dev/null || echo "{}")
STATE_OK2=$(echo "$STATE_JSON2" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('valid')
except:
    print('corrupted')" 2>/dev/null || echo "corrupted")
[ "$STATE_OK2" = "valid" ] && ok "apply+set_node race: state.json valid" || fail "apply+set_node race: state.json corrupted"

NFT_VALID=$(nft list table inet macflow >/dev/null 2>&1 && echo "yes" || echo "no")
[ "$NFT_VALID" = "yes" ] && ok "apply+set_node race: nftables consistent" || fail "apply+set_node race: nftables broken"

# ─────────────────────────────────────────────
echo ""
echo "== TEST 5: Multi-agent - simultaneous node add =="
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"conc-agent-a","server":"10.0.3.1","server_port":8391,"method":"aes-256-gcm","password":"aa"}' &
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"conc-agent-b","server":"10.0.3.2","server_port":8392,"method":"aes-256-gcm","password":"bb"}' &
wait
echo ""

NODES=$(curl -s "$API/api/nodes" 2>/dev/null)
echo "$NODES" | grep -q "conc-agent-a" && ok "multi-agent: node conc-agent-a exists" || fail "multi-agent: node conc-agent-a missing"
echo "$NODES" | grep -q "conc-agent-b" && ok "multi-agent: node conc-agent-b exists" || fail "multi-agent: node conc-agent-b missing"

# ─────────────────────────────────────────────
echo ""
echo "== TEST 6: Multi-agent - simultaneous apply =="
curl -s -X POST "$API/api/apply" &
curl -s -X POST "$API/api/apply" &
wait
echo ""

NFT_OK=$(nft list table inet macflow >/dev/null 2>&1 && echo "yes" || echo "no")
[ "$NFT_OK" = "yes" ] && ok "dual apply: nftables consistent" || fail "dual apply: nftables broken"

STATE_OK3=$(python3 -c "
import json
with open('/opt/macflow/data/state.json') as f:
    d=json.load(f)
    print('valid' if 'nodes' in d and 'devices' in d else 'invalid')" 2>/dev/null || echo "invalid")
[ "$STATE_OK3" = "valid" ] && ok "dual apply: state.json valid" || fail "dual apply: state.json corrupted"

# ─────────────────────────────────────────────
echo ""
echo "== TEST 7: Add device + delete same device race =="
TEST_MAC="CC:CC:CC:FF:FF:01"
curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"race-dev\",\"mac\":\"$TEST_MAC\",\"node_tag\":\"conc-node-a\",\"managed\":true}" >/dev/null 2>&1

curl -s -X DELETE "$API/api/devices/$TEST_MAC" &
curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"race-dev-2\",\"mac\":\"$TEST_MAC\",\"node_tag\":\"conc-node-b\",\"managed\":true}" &
wait

STATE_OK4=$(python3 -c "
import json
with open('/opt/macflow/data/state.json') as f:
    d=json.load(f)
    macs=[x['mac'] for x in d.get('devices',[])]
    dupes=len(macs)!=len(set(macs))
    print('valid' if not dupes else 'duplicates')" 2>/dev/null || echo "error")
[ "$STATE_OK4" = "valid" ] && ok "add+delete race: no duplicate MACs" || fail "add+delete race: $STATE_OK4"

curl -s -X DELETE "$API/api/devices/$TEST_MAC" >/dev/null 2>&1 || true

echo ""
echo "========================================="
echo "  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "  STATUS: ALL CONCURRENCY TESTS PASSED" || echo "  STATUS: SOME TESTS FAILED"
exit "$FAIL"
