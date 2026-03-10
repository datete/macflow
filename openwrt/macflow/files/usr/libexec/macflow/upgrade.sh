#!/bin/sh
set -eu

APP_ROOT="$(uci -q get macflow.main.app_root || echo /opt/macflow)"
DATA_DIR="$(uci -q get macflow.main.data_dir || echo "${APP_ROOT}/data")"
BAK_DIR="/tmp/macflow-upgrade"

backup_state() {
    mkdir -p "$BAK_DIR"
    [ -f "${DATA_DIR}/state.json" ] && cp -f "${DATA_DIR}/state.json" "${BAK_DIR}/state.json"
    [ -f "${DATA_DIR}/audit.log" ] && cp -f "${DATA_DIR}/audit.log" "${BAK_DIR}/audit.log"
    [ -f "${DATA_DIR}/auth.json" ] && cp -f "${DATA_DIR}/auth.json" "${BAK_DIR}/auth.json"
}

restore_state() {
    mkdir -p "$DATA_DIR"
    if [ -f "${BAK_DIR}/state.json" ] && [ ! -f "${DATA_DIR}/state.json" ]; then
        cp -f "${BAK_DIR}/state.json" "${DATA_DIR}/state.json"
    fi
    if [ -f "${BAK_DIR}/audit.log" ] && [ ! -f "${DATA_DIR}/audit.log" ]; then
        cp -f "${BAK_DIR}/audit.log" "${DATA_DIR}/audit.log"
    fi
    if [ -f "${BAK_DIR}/auth.json" ] && [ ! -f "${DATA_DIR}/auth.json" ]; then
        cp -f "${BAK_DIR}/auth.json" "${DATA_DIR}/auth.json"
        chmod 600 "${DATA_DIR}/auth.json" 2>/dev/null || true
    fi
    if [ ! -f "${DATA_DIR}/state.json" ]; then
        cat > "${DATA_DIR}/state.json" <<'EOF'
{
  "enabled": false,
  "default_policy": "whitelist",
  "failure_policy": "fail-close",
  "dns": {
    "enforce_redirect_port": 6053,
    "block_doh_doq": true,
    "servers": [
      "8.8.8.8",
      "1.1.1.1"
    ],
    "force_redirect": true
  },
  "xui_sources": [],
  "subscriptions": [],
  "nodes": [],
  "devices": [],
  "last_sync": 0,
  "last_apply": 0,
  "policy_version": null,
  "rollback_version": null
}
EOF
    fi
}

case "${1:-}" in
    preinst)
        backup_state
        ;;
    postinst)
        restore_state
        ;;
    *)
        echo "usage: $0 preinst|postinst" >&2
        exit 1
        ;;
esac

exit 0
