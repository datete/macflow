#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RELEASE="${OPENWRT_RELEASE:-24.10.0}"
TARGET="${OPENWRT_TARGET:-rockchip}"
SUBTARGET="${OPENWRT_SUBTARGET:-armv8}"
PROFILE="${OPENWRT_PROFILE:-friendlyarm_nanopi-r2s}"
EXTRA_PACKAGES="${OPENWRT_EXTRA_PACKAGES:-}"
PACKAGE_ADJUSTMENTS="${OPENWRT_PACKAGE_ADJUSTMENTS:--nftables-nojson nftables-json}"
FILES_DIR="${OPENWRT_FILES_DIR:-}"
ROOTFS_PARTSIZE="${OPENWRT_ROOTFS_PARTSIZE:-256}"

BUILD_IPK_IF_MISSING="${MACFLOW_BUILD_IPK_IF_MISSING:-1}"
IPK_GLOB="${MACFLOW_IPK_GLOB:-${REPO_ROOT}/dist/ipk/${TARGET}-${SUBTARGET}/macflow_*.ipk}"
IMAGEBUILDER_WORKDIR="${OPENWRT_IMAGEBUILDER_WORKDIR:-${HOME}/.cache/macflow-openwrt-imagebuilder}"
DOWNLOAD_BASE_URL="${OPENWRT_DOWNLOAD_BASE_URL:-https://downloads.openwrt.org/releases}"

INDEX_URL="${DOWNLOAD_BASE_URL}/${RELEASE}/targets/${TARGET}/${SUBTARGET}/"
PROFILES_URL="${INDEX_URL}profiles.json"

sanitize_path_absolute() {
  local part
  local cleaned=""
  local -a parts=()

  IFS=':' read -r -a parts <<<"${PATH}"
  for part in "${parts[@]}"; do
    [[ -n "${part}" ]] || continue
    [[ "${part}" == /* ]] || continue
    if [[ -z "${cleaned}" ]]; then
      cleaned="${part}"
    else
      cleaned="${cleaned}:${part}"
    fi
  done

  if [[ -n "${cleaned}" ]]; then
    PATH="${cleaned}"
    export PATH
  fi
}

sanitize_path_absolute

is_case_sensitive_fs() {
  local base="$1"
  local probe
  probe="$(mktemp -d "${base}/.macflow-casecheck-XXXXXX")"
  rm -f "${probe}/CaseCheck" "${probe}/casecheck"
  : > "${probe}/CaseCheck"
  if [[ -e "${probe}/casecheck" ]]; then
    rm -rf "${probe}"
    return 1
  fi
  rm -rf "${probe}"
  return 0
}

mkdir -p "${IMAGEBUILDER_WORKDIR}"
if ! is_case_sensitive_fs "${IMAGEBUILDER_WORKDIR}"; then
  if [[ "${OPENWRT_ALLOW_CASE_INSENSITIVE:-0}" == "1" ]]; then
    echo "[macflow] warning: case-insensitive imagebuilder path forced: ${IMAGEBUILDER_WORKDIR}"
  else
    FALLBACK_WORKDIR="${XDG_CACHE_HOME:-/tmp}/macflow-openwrt-imagebuilder"
    echo "[macflow] warning: case-insensitive imagebuilder path: ${IMAGEBUILDER_WORKDIR}"
    echo "[macflow] switching imagebuilder path to: ${FALLBACK_WORKDIR}"
    IMAGEBUILDER_WORKDIR="${FALLBACK_WORKDIR}"
    mkdir -p "${IMAGEBUILDER_WORKDIR}"
    if ! is_case_sensitive_fs "${IMAGEBUILDER_WORKDIR}"; then
      echo "[macflow] case-sensitive workspace not available: ${IMAGEBUILDER_WORKDIR}" >&2
      echo "[macflow] set OPENWRT_IMAGEBUILDER_WORKDIR to a Linux case-sensitive path" >&2
      echo "[macflow] or force with OPENWRT_ALLOW_CASE_INSENSITIVE=1" >&2
      exit 5
    fi
  fi
fi

for c in curl tar zstd gzip sed awk; do
  command -v "${c}" >/dev/null 2>&1 || {
    echo "[macflow] missing required tool: ${c}" >&2
    exit 4
  }
done

echo "[macflow] resolve imagebuilder from: ${INDEX_URL}"
IMAGEBUILDER_NAME="$(
  curl -fsSL "${INDEX_URL}" \
    | grep -oE "openwrt-imagebuilder-${RELEASE}-${TARGET}-${SUBTARGET}[^\"']*Linux-x86_64\.tar\.zst" \
    | head -n1 || true
)"

if [[ -z "${IMAGEBUILDER_NAME}" ]]; then
  echo "[macflow] cannot find imagebuilder archive at ${INDEX_URL}" >&2
  exit 2
fi

IMAGEBUILDER_ARCHIVE="${IMAGEBUILDER_WORKDIR}/${IMAGEBUILDER_NAME}"
IMAGEBUILDER_DIR="${IMAGEBUILDER_WORKDIR}/${IMAGEBUILDER_NAME%.tar.zst}"

if [[ ! -f "${IMAGEBUILDER_ARCHIVE}" ]]; then
  echo "[macflow] downloading ${IMAGEBUILDER_NAME}"
  curl -fL -C - "${INDEX_URL}${IMAGEBUILDER_NAME}" -o "${IMAGEBUILDER_ARCHIVE}"
else
  echo "[macflow] imagebuilder archive already exists"
fi

if [[ ! -d "${IMAGEBUILDER_DIR}" ]]; then
  echo "[macflow] extracting imagebuilder"
  tar --zstd -xf "${IMAGEBUILDER_ARCHIVE}" -C "${IMAGEBUILDER_WORKDIR}"
fi

if ! curl -fsSL "${PROFILES_URL}" | grep -q "\"${PROFILE}\""; then
  echo "[macflow] unknown profile: ${PROFILE}" >&2
  echo "[macflow] check profiles at: ${PROFILES_URL}" >&2
  exit 6
fi

resolve_ipk() {
  local latest
  local matches=()

  shopt -s nullglob
  matches=( ${IPK_GLOB} )
  shopt -u nullglob

  if [[ ${#matches[@]} -gt 0 ]]; then
    latest="$(ls -1t -- "${matches[@]}" | head -n1 || true)"
  else
    latest=""
  fi

  if [[ -n "${latest}" && -f "${latest}" ]]; then
    printf '%s\n' "${latest}"
    return 0
  fi

  if [[ "${BUILD_IPK_IF_MISSING}" != "1" ]]; then
    return 1
  fi

  echo "[macflow] ipk not found, building ipk first"
  OPENWRT_RELEASE="${RELEASE}" OPENWRT_TARGET="${TARGET}" OPENWRT_SUBTARGET="${SUBTARGET}" \
    bash "${SCRIPT_DIR}/build-arm64-ipk.sh"

  shopt -s nullglob
  matches=( ${IPK_GLOB} )
  shopt -u nullglob
  if [[ ${#matches[@]} -gt 0 ]]; then
    latest="$(ls -1t -- "${matches[@]}" | head -n1 || true)"
  else
    latest=""
  fi
  [[ -n "${latest}" && -f "${latest}" ]] || return 1
  printf '%s\n' "${latest}"
}

IPK_PATH="$(resolve_ipk || true)"
if [[ -z "${IPK_PATH}" ]]; then
  echo "[macflow] macflow ipk not found: ${IPK_GLOB}" >&2
  exit 3
fi

echo "[macflow] using ipk: ${IPK_PATH}"

pushd "${IMAGEBUILDER_DIR}" >/dev/null

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

mkdir -p packages
# 清除旧版本 macflow IPK，避免 Image Builder 版本冲突
rm -f packages/macflow_*.ipk
cp -f "${IPK_PATH}" packages/

PKG_LIST="macflow"
if [[ -n "${PACKAGE_ADJUSTMENTS}" ]]; then
  PKG_LIST="${PKG_LIST} ${PACKAGE_ADJUSTMENTS}"
fi
if [[ -n "${EXTRA_PACKAGES}" ]]; then
  PKG_LIST="${PKG_LIST} ${EXTRA_PACKAGES}"
fi

echo "[macflow] profile: ${PROFILE}"
echo "[macflow] packages: ${PKG_LIST}"
echo "[macflow] rootfs partsize: ${ROOTFS_PARTSIZE}MB"

if [[ -n "${FILES_DIR}" ]]; then
  if [[ ! -d "${FILES_DIR}" ]]; then
    echo "[macflow] files dir not found: ${FILES_DIR}" >&2
    exit 7
  fi
  make image PROFILE="${PROFILE}" PACKAGES="${PKG_LIST}" FILES="${FILES_DIR}" ROOTFS_PARTSIZE="${ROOTFS_PARTSIZE}"
else
  make image PROFILE="${PROFILE}" PACKAGES="${PKG_LIST}" ROOTFS_PARTSIZE="${ROOTFS_PARTSIZE}"
fi

TARGET_DIR="bin/targets/${TARGET}/${SUBTARGET}"
if [[ ! -d "${TARGET_DIR}" ]]; then
  echo "[macflow] image output directory missing: ${TARGET_DIR}" >&2
  exit 8
fi

DIST_DIR="${REPO_ROOT}/dist/firmware/${TARGET}-${SUBTARGET}/${PROFILE}"
mkdir -p "${DIST_DIR}"

find "${TARGET_DIR}" -maxdepth 1 -type f \( \
  -name "*${PROFILE}*sysupgrade*.img.gz" -o \
  -name "*${PROFILE}*factory*.img.gz" -o \
  -name "*${PROFILE}*.itb" -o \
  -name "*${PROFILE}*.manifest" -o \
  -name "sha256sums" \
\) -exec cp -f {} "${DIST_DIR}/" \;

echo "[macflow] firmware output: ${DIST_DIR}"
ls -1 "${DIST_DIR}"

popd >/dev/null
