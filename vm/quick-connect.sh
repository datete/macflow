#!/usr/bin/env bash
set -euo pipefail

TIMEOUT="${MACFLOW_DISCOVER_TIMEOUT:-2}"
OPEN_BROWSER=0
CONNECT_SSH=0
JSON_OUT=0
CONNECT_FILE="${MACFLOW_CONNECT_FILE:-$HOME/.config/macflow/connect.env}"
TLS_INSECURE="${MACFLOW_INSECURE_TLS:-0}"

PANEL_CANDIDATES=()
LUCI_CANDIDATES=()
SSH_CANDIDATES=()

usage() {
  echo "Usage: $0 [--open] [--ssh] [--json]"
  echo "  --open   Open detected MACFlow panel URL"
  echo "  --ssh    Directly SSH into detected iStoreOS"
  echo "  --json   Output machine-readable JSON"
  echo ""
  echo "Environment:"
  echo "  ISTORE_HOST=host1,host2   Extra host candidates"
  echo "  ISTORE_PANEL_URLS=url1,url2"
  echo "  ISTORE_LUCI_URLS=url1,url2"
  echo "  ISTORE_SSH_TARGETS=user@host:port,..."
  echo "  MACFLOW_CONNECT_FILE=~/.config/macflow/connect.env"
  echo "  MACFLOW_DISCOVER_TIMEOUT=2 HTTP timeout seconds"
  echo "  MACFLOW_INSECURE_TLS=1    Allow self-signed HTTPS"
}

for arg in "$@"; do
  case "$arg" in
    --open) OPEN_BROWSER=1 ;;
    --ssh) CONNECT_SSH=1 ;;
    --json) JSON_OUT=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown arg: $arg"
      usage
      exit 1
      ;;
  esac
done

if [[ -f "$CONNECT_FILE" ]]; then
  # shellcheck disable=SC1090
  . "$CONNECT_FILE"
fi

normalize_url() {
  local u="$1"
  u="${u#${u%%[![:space:]]*}}"
  u="${u%${u##*[![:space:]]}}"
  [[ -z "$u" ]] && return
  if [[ "$u" != http://* && "$u" != https://* ]]; then
    u="http://$u"
  fi
  u="${u%/}"
  printf '%s\n' "$u"
}

add_url_candidate() {
  local raw="$1"
  local n
  n="$(normalize_url "$raw")"
  [[ -n "$n" ]] && printf '%s\n' "$n"
}

split_csv_to_urls() {
  local csv="$1"
  local item
  for item in ${csv//,/ }; do
    add_url_candidate "$item"
  done
}

split_csv_to_items() {
  local csv="$1"
  local item
  for item in ${csv//,/ }; do
    item="${item#${item%%[![:space:]]*}}"
    item="${item%${item##*[![:space:]]}}"
    [[ -n "$item" ]] && printf '%s\n' "$item"
  done
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/ }"
  printf '%s' "$s"
}

curl_check() {
  local url="$1"
  if [[ "$TLS_INSECURE" = "1" ]]; then
    curl -k -fsS --max-time "$TIMEOUT" "$url" >/dev/null 2>&1
  else
    curl -fsS --max-time "$TIMEOUT" "$url" >/dev/null 2>&1
  fi
}

panel_url_ok() {
  local base="$1"
  curl_check "${base}/api/status"
}

luci_url_ok() {
  local base="$1"
  curl_check "${base}/"
}

if [[ -n "${ISTORE_PANEL_URLS:-}" ]]; then
  while IFS= read -r u; do PANEL_CANDIDATES+=("$u"); done < <(split_csv_to_urls "$ISTORE_PANEL_URLS")
fi

if [[ -n "${ISTORE_LUCI_URLS:-}" ]]; then
  while IFS= read -r u; do LUCI_CANDIDATES+=("$u"); done < <(split_csv_to_urls "$ISTORE_LUCI_URLS")
fi

if [[ -n "${ISTORE_SSH_TARGETS:-}" ]]; then
  while IFS= read -r s; do SSH_CANDIDATES+=("$s"); done < <(split_csv_to_items "$ISTORE_SSH_TARGETS")
fi

declare -A _seen=()
HOSTS=()

add_host() {
  local h="$1"
  [[ -z "$h" ]] && return
  h="${h#http://}"
  h="${h#https://}"
  h="${h%%/*}"
  h="${h%%:*}"
  [[ -z "$h" ]] && return
  if [[ -z "${_seen[$h]:-}" ]]; then
    HOSTS+=("$h")
    _seen[$h]=1
  fi
}

http_ok() {
  local url="$1"
  curl_check "$url"
}

tcp_open() {
  local host="$1"
  local port="$2"
  if command -v timeout >/dev/null 2>&1; then
    timeout "${TIMEOUT}s" bash -c "echo >/dev/tcp/$host/$port" >/dev/null 2>&1
  else
    (echo >"/dev/tcp/$host/$port") >/dev/null 2>&1
  fi
}

parse_ssh_target() {
  local target="$1"
  local user="root"
  local hostport="$target"
  local host=""
  local port="22"

  if [[ "$target" == *@* ]]; then
    user="${target%@*}"
    hostport="${target#*@}"
  fi

  if [[ "$hostport" == *:* ]]; then
    host="${hostport%:*}"
    port="${hostport##*:}"
  else
    host="$hostport"
  fi

  printf '%s\n%s\n%s\n' "$user" "$host" "$port"
}

if [[ -n "${ISTORE_HOST:-}" ]]; then
  for h in ${ISTORE_HOST//,/ }; do
    add_host "$h"
  done
fi

add_host "127.0.0.1"
add_host "localhost"

if command -v ip >/dev/null 2>&1; then
  gw="$(ip route show default 2>/dev/null | sed -n 's/^default via \([^ ]*\).*/\1/p' | head -n1 || true)"
  add_host "$gw"
fi

if grep -qi microsoft /proc/version 2>/dev/null; then
  wsl_win_host="$(sed -n 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*/\1/p' /etc/resolv.conf | head -n1 || true)"
  add_host "$wsl_win_host"
fi

for h in 192.168.1.1 192.168.50.1 192.168.31.1 192.168.0.1 10.0.0.1 10.0.1.1 10.1.1.1 172.16.1.1; do
  add_host "$h"
done

API_HOST=""
API_PORT=""
PANEL_URL=""

for u in "${PANEL_CANDIDATES[@]}"; do
  if panel_url_ok "$u"; then
    PANEL_URL="$u"
    break
  fi
done

if [[ -z "$PANEL_URL" ]]; then
  for h in "${HOSTS[@]}"; do
    for p in 18080 8080 80; do
      if http_ok "http://$h:$p/api/status"; then
        API_HOST="$h"
        API_PORT="$p"
        PANEL_URL="http://$h:$p"
        break 2
      fi
    done
  done
fi

if [[ -n "$PANEL_URL" ]]; then
  raw="${PANEL_URL#*://}"
  hp="${raw%%/*}"
  API_HOST="${hp%%:*}"
  if [[ "$hp" == *:* ]]; then
    API_PORT="${hp##*:}"
  elif [[ "$PANEL_URL" == https://* ]]; then
    API_PORT="443"
  else
    API_PORT="80"
  fi
fi

LUCI_URL=""
for u in "${LUCI_CANDIDATES[@]}"; do
  if luci_url_ok "$u"; then
    LUCI_URL="$u"
    break
  fi
done

if [[ -z "$LUCI_URL" ]]; then
  for h in "${HOSTS[@]}"; do
    for p in 8080 80; do
      if http_ok "http://$h:$p/"; then
        LUCI_URL="http://$h:$p"
        break 2
      fi
    done
  done
fi

SSH_HOST=""
SSH_PORT=""
SSH_USER="root"
SSH_VIA_WSL=0

for t in "${SSH_CANDIDATES[@]}"; do
  mapfile -t parsed < <(parse_ssh_target "$t")
  p_user="${parsed[0]:-root}"
  p_host="${parsed[1]:-}"
  p_port="${parsed[2]:-22}"
  if [[ -n "$p_host" ]] && tcp_open "$p_host" "$p_port"; then
    SSH_USER="$p_user"
    SSH_HOST="$p_host"
    SSH_PORT="$p_port"
    break
  fi
done

if [[ -z "$SSH_HOST" ]]; then
  for h in "${HOSTS[@]}"; do
    for p in 2222 22; do
      if tcp_open "$h" "$p"; then
        SSH_HOST="$h"
        SSH_PORT="$p"
        SSH_USER="root"
        break 2
      fi
    done
  done
fi

if [[ -z "$SSH_HOST" ]] && command -v wsl.exe >/dev/null 2>&1; then
  if wsl.exe -e bash -lc "timeout ${TIMEOUT}s bash -c 'echo >/dev/tcp/127.0.0.1/2222'" >/dev/null 2>&1; then
    SSH_HOST="127.0.0.1"
    SSH_PORT="2222"
    SSH_USER="root"
    SSH_VIA_WSL=1
  fi
fi

SSH_CMD=""
if [[ -n "$SSH_HOST" ]]; then
  if [[ "$SSH_VIA_WSL" -eq 1 ]]; then
    SSH_CMD="wsl.exe -e ssh -o StrictHostKeyChecking=no -p ${SSH_PORT} ${SSH_USER}@${SSH_HOST}"
  else
    SSH_CMD="ssh -o StrictHostKeyChecking=no -p ${SSH_PORT} ${SSH_USER}@${SSH_HOST}"
  fi
fi

if [[ "$JSON_OUT" -eq 1 ]]; then
  printf '{"panel_url":"%s","api_host":"%s","api_port":"%s","luci_url":"%s","ssh_host":"%s","ssh_port":"%s","ssh_user":"%s","ssh_via_wsl":%s,"ssh_cmd":"%s","candidates":"%s"}\n' \
    "$(json_escape "$PANEL_URL")" \
    "$(json_escape "$API_HOST")" \
    "$(json_escape "$API_PORT")" \
    "$(json_escape "$LUCI_URL")" \
    "$(json_escape "$SSH_HOST")" \
    "$(json_escape "$SSH_PORT")" \
    "$(json_escape "$SSH_USER")" \
    "$([[ "$SSH_VIA_WSL" -eq 1 ]] && echo true || echo false)" \
    "$(json_escape "$SSH_CMD")" \
    "$(json_escape "${HOSTS[*]}")"
else
  echo "=== iStoreOS Quick Connect ==="
  echo "Candidates: ${HOSTS[*]}"
  if [[ -n "$PANEL_URL" ]]; then
    echo "[OK] MACFlow panel: ${PANEL_URL}"
    echo "[OK] API status: ${PANEL_URL}/api/status"
  else
    echo "[WARN] MACFlow panel not found"
  fi

  if [[ -n "$LUCI_URL" ]]; then
    echo "[OK] LuCI: ${LUCI_URL}"
  else
    echo "[WARN] LuCI not found"
  fi

  if [[ -n "$SSH_CMD" ]]; then
    if [[ "$SSH_VIA_WSL" -eq 1 ]]; then
      echo "[OK] SSH (via WSL): ${SSH_CMD}"
    else
      echo "[OK] SSH: ${SSH_CMD}"
    fi
  else
    echo "[WARN] SSH endpoint not found"
  fi
fi

if [[ "$OPEN_BROWSER" -eq 1 ]]; then
  if [[ -z "$PANEL_URL" ]]; then
    echo "[ERR] cannot open browser: panel not found"
    exit 2
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$PANEL_URL" >/dev/null 2>&1 &
    echo "[OK] opened ${PANEL_URL}"
  else
    echo "[WARN] xdg-open not available"
  fi
fi

if [[ "$CONNECT_SSH" -eq 1 ]]; then
  if [[ -z "$SSH_HOST" ]]; then
    echo "[ERR] cannot SSH: no endpoint detected"
    exit 3
  fi
  if [[ "$SSH_VIA_WSL" -eq 1 ]]; then
    exec wsl.exe -e ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}"
  else
    exec ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}"
  fi
fi
