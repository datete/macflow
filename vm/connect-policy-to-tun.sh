#!/usr/bin/env bash
set -euo pipefail

echo "=== connect policy routing to sing-box TUN ==="

TUN_IF="singtun0"
ip link show "$TUN_IF" >/dev/null 2>&1 || { echo "ERROR: $TUN_IF not found"; exit 1; }

# Clean old macflow rules
while ip -4 rule show | grep -q '# macflow'; do
    rid=$(ip -4 rule show | awk '/# macflow/ {print $1; exit}' | tr -d ':')
    ip -4 rule del pref "$rid" 2>/dev/null || true
done

# fwmark 0x100 (proxy_hk) -> table 100 -> via singtun0
ip -4 rule add pref 20000 fwmark 0x100 lookup 100 # macflow
ip -4 route replace table 100 default dev "$TUN_IF"

# fwmark 0x200 (proxy_us) -> table 200 -> via singtun0
ip -4 rule add pref 20010 fwmark 0x200 lookup 200 # macflow
ip -4 route replace table 200 default dev "$TUN_IF"

echo "=== verify ==="
echo "--- ip rules ---"
ip -4 rule show | grep -E 'macflow|fwmark'

echo "--- route tables ---"
echo "table 100:"
ip -4 route show table 100
echo "table 200:"
ip -4 route show table 200

echo "--- TUN status ---"
ip addr show "$TUN_IF"

echo "=== policy routing connected to sing-box TUN ==="
