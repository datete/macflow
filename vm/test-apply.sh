#!/bin/bash
API="http://127.0.0.1:18080"

echo "== 1. Add test node =="
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"test-ss-node","server":"1.2.3.4","server_port":8388,"method":"aes-256-gcm","password":"testpass"}'
echo ""

echo "== 2. Add test device =="
curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-phone","mac":"AA:BB:CC:00:11:22","node_tag":"test-ss-node","managed":true}'
echo ""

echo "== 3. Enable service =="
curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}'
echo ""

echo "== 4. Apply =="
curl -s -X POST "$API/api/apply" \
  -H "Content-Type: application/json"
echo ""

echo "== 5. Check nftables =="
nft list table inet macflow 2>/dev/null | head -20
echo ""

echo "== 6. Check ip rules =="
ip -4 rule show | head -10
echo ""

echo "== 7. Check sing-box config =="
cat /etc/sing-box/config.json | python3 -c "import sys,json;d=json.load(sys.stdin);print('outbounds:',len(d.get('outbounds',[])),'tags:',[o['tag'] for o in d.get('outbounds',[])])" 2>/dev/null
echo ""

echo "== 8. Check sing-box running =="
pgrep -la sing-box
echo ""

echo "== DONE =="
