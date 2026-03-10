#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  atomic_apply.sh --nft <file> --iprules <file> [--namespace <ns>] [--health-target <ip>] [--policy-version <id>]

Notes:
  - Applies nftables and ip rules transactionally.
  - On failure, rolls back to the previous nft snapshot.
EOF
}

NS=""
NFT_FILE=""
IPRULE_FILE=""
HEALTH_TARGET="1.1.1.1"
STATE_DIR="/tmp/macflow-state"
POLICY_VERSION=""
LOCK_DIR="${STATE_DIR}/.apply.lock"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)
      NS="$2"
      shift 2
      ;;
    --nft)
      NFT_FILE="$2"
      shift 2
      ;;
    --iprules)
      IPRULE_FILE="$2"
      shift 2
      ;;
    --health-target)
      HEALTH_TARGET="$2"
      shift 2
      ;;
    --policy-version)
      POLICY_VERSION="$2"
      shift 2
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${NFT_FILE}" || -z "${IPRULE_FILE}" ]]; then
  usage
  exit 1
fi

if [[ ! -f "${NFT_FILE}" ]]; then
  echo "[atomic_apply] nft file not found: ${NFT_FILE}" >&2
  exit 1
fi

if [[ ! -f "${IPRULE_FILE}" ]]; then
  echo "[atomic_apply] iprules file not found: ${IPRULE_FILE}" >&2
  exit 1
fi

mkdir -p "${STATE_DIR}"
PREV_NFT="${STATE_DIR}/previous.nft"
CURRENT_NFT="${STATE_DIR}/current.nft"
VERSIONS_DIR="${STATE_DIR}/versions"
CURRENT_VERSION_FILE="${STATE_DIR}/current_version"
ROLLBACK_VERSION_FILE="${STATE_DIR}/rollback_version"

if [[ -z "${POLICY_VERSION}" ]]; then
  POLICY_VERSION="$(date +%Y%m%d%H%M%S)"
fi

run_cmd() {
  if [[ -n "${NS}" ]]; then
    ip netns exec "${NS}" "$@"
  else
    "$@"
  fi
}

rollback() {
  echo "[atomic_apply] rollback start"
  if [[ -f "${PREV_NFT}" ]]; then
    run_cmd nft -f "${PREV_NFT}" || true
  fi
  if [[ -f "${ROLLBACK_VERSION_FILE}" ]]; then
    cp "${ROLLBACK_VERSION_FILE}" "${CURRENT_VERSION_FILE}" || true
  fi
  echo "[atomic_apply] rollback done"
}

acquire_lock() {
  if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
    # Check if the PID holding the lock is still alive
    if [ -f "${LOCK_DIR}/pid" ]; then
      local old_pid
      old_pid=$(cat "${LOCK_DIR}/pid" 2>/dev/null || echo "")
      if [ -n "${old_pid}" ] && ! kill -0 "${old_pid}" 2>/dev/null; then
        echo "[atomic_apply] stale lock from dead PID ${old_pid}, removing"
        rm -rf "${LOCK_DIR}"
        mkdir "${LOCK_DIR}" 2>/dev/null || { echo "[atomic_apply] cannot acquire lock" >&2; exit 3; }
      else
        echo "[atomic_apply] another apply process is running (PID ${old_pid})" >&2
        exit 3
      fi
    else
      echo "[atomic_apply] another apply process is running" >&2
      exit 3
    fi
  fi
  echo $$ > "${LOCK_DIR}/pid"
}

release_lock() {
  rmdir "${LOCK_DIR}" 2>/dev/null || true
}

snapshot_version() {
  local version_dir="${VERSIONS_DIR}/${POLICY_VERSION}"
  mkdir -p "${version_dir}"
  cp "${NFT_FILE}" "${version_dir}/macflow.nft"
  cp "${IPRULE_FILE}" "${version_dir}/iprules.sh"
  cat > "${version_dir}/meta.env" <<EOF
POLICY_VERSION=${POLICY_VERSION}
APPLIED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HEALTH_TARGET=${HEALTH_TARGET}
NAMESPACE=${NS}
EOF
}

trap release_lock EXIT
acquire_lock

echo "[atomic_apply] snapshot current nftables"
if ! run_cmd nft list ruleset > "${CURRENT_NFT}" 2>/dev/null; then
  : > "${CURRENT_NFT}"
fi
cp "${CURRENT_NFT}" "${PREV_NFT}"

echo "[atomic_apply] validate nft file"
run_cmd nft -c -f "${NFT_FILE}"

echo "[atomic_apply] validate iprule script syntax"
bash -n "${IPRULE_FILE}"

echo "[atomic_apply] apply nft (atomic)"
run_cmd nft -f "${NFT_FILE}"

echo "[atomic_apply] apply ip rules"
if [[ -n "${NS}" ]]; then
  ip netns exec "${NS}" bash "${IPRULE_FILE}"
else
  bash "${IPRULE_FILE}"
fi

echo "[atomic_apply] health probe ${HEALTH_TARGET}"
if ! run_cmd ping -c 1 -W 1 "${HEALTH_TARGET}" >/dev/null 2>&1; then
  echo "[atomic_apply] health probe failed" >&2
  rollback
  exit 2
fi

mkdir -p "${VERSIONS_DIR}"
if [[ -f "${CURRENT_VERSION_FILE}" ]]; then
  cp "${CURRENT_VERSION_FILE}" "${ROLLBACK_VERSION_FILE}"
fi
snapshot_version
echo "${POLICY_VERSION}" > "${CURRENT_VERSION_FILE}"

echo "[atomic_apply] success"
echo "[atomic_apply] current_version=${POLICY_VERSION}"
