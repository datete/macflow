#!/usr/bin/env bash
set -euo pipefail

CONF_DIR="/etc/sing-box"
CONF_FILE="${CONF_DIR}/config.json"
mkdir -p "$CONF_DIR"

cat > "$CONF_FILE" <<'SINGBOX_EOF'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "proxy-dns",
        "type": "https",
        "server": "1.1.1.1",
        "server_port": 443
      },
      {
        "tag": "local-dns",
        "type": "local",
        "detour": "direct-out"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "local-dns"
      }
    ]
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "singtun0",
      "address": ["172.19.0.1/30"],
      "auto_route": false,
      "stack": "gvisor",
      "sniff": true,
      "sniff_override_destination": true
    },
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "::",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy-select",
      "outbounds": [
        "direct-out"
      ],
      "default": "direct-out",
      "interrupt_exist_connections": false
    },
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      }
    ],
    "default_mark": 255
  },
  "experimental": {
    "clash_api": {
      "external_controller": "0.0.0.0:9090",
      "external_ui": "",
      "secret": ""
    }
  }
}
SINGBOX_EOF

echo "[config] validating..."
sing-box check -c "$CONF_FILE"
echo "[config] valid"

echo "[config] setting up procd service..."
cat > /etc/init.d/sing-box-macflow <<'INITEOF'
#!/bin/sh /etc/rc.common

START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/sing-box run -c /etc/sing-box/config.json
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/sing-box-macflow

/etc/init.d/sing-box-macflow stop 2>/dev/null || true
/etc/init.d/sing-box-macflow start
/etc/init.d/sing-box-macflow enable

sleep 3
echo "[config] checking sing-box process..."
pgrep -a sing-box || echo "sing-box not running"

echo "[config] checking TUN interface..."
ip link show singtun0 2>/dev/null || echo "TUN not yet up"

echo "[config] checking clash API..."
wget -qO- http://127.0.0.1:9090/ 2>/dev/null || echo "clash API not ready yet"

echo ""
echo "=== sing-box setup complete ==="
