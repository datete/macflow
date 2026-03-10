#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RELEASE="${OPENWRT_RELEASE:-24.10.0}"
TARGET="${OPENWRT_TARGET:-rockchip}"
SUBTARGET="${OPENWRT_SUBTARGET:-armv8}"
SDK_WORKDIR="${OPENWRT_SDK_WORKDIR:-${HOME}/.cache/macflow-openwrt-sdk}"
DOWNLOAD_BASE_URL="${OPENWRT_DOWNLOAD_BASE_URL:-https://downloads.openwrt.org/releases}"

INDEX_URL="${DOWNLOAD_BASE_URL}/${RELEASE}/targets/${TARGET}/${SUBTARGET}/"

is_case_sensitive_fs() {
  local base="$1"
  local probe
  probe="$(mktemp -d "${base}/.macflow-casecheck-XXXXXX")"
  rm -f "$probe/CaseCheck" "$probe/casecheck"
  : > "$probe/CaseCheck"
  if [[ -e "$probe/casecheck" ]]; then
    rm -rf "$probe"
    return 1
  fi
  rm -rf "$probe"
  return 0
}

mkdir -p "${SDK_WORKDIR}"

if ! is_case_sensitive_fs "${SDK_WORKDIR}"; then
  if [[ "${OPENWRT_ALLOW_CASE_INSENSITIVE:-0}" == "1" ]]; then
    echo "[macflow] warning: case-insensitive SDK path forced: ${SDK_WORKDIR}"
  else
    FALLBACK_SDK_WORKDIR="${HOME}/.cache/macflow-openwrt-sdk"
    echo "[macflow] warning: case-insensitive SDK path: ${SDK_WORKDIR}"
    echo "[macflow] switching SDK path to: ${FALLBACK_SDK_WORKDIR}"
    SDK_WORKDIR="${FALLBACK_SDK_WORKDIR}"
    mkdir -p "${SDK_WORKDIR}"
    if ! is_case_sensitive_fs "${SDK_WORKDIR}"; then
      echo "[macflow] case-sensitive workspace not available: ${SDK_WORKDIR}" >&2
      echo "[macflow] set OPENWRT_SDK_WORKDIR to a Linux case-sensitive path" >&2
      exit 5
    fi
  fi
fi

MISSING=()
for c in curl tar zstd unzip gawk; do
  command -v "$c" >/dev/null 2>&1 || MISSING+=("$c")
done
command -v swig >/dev/null 2>&1 || MISSING+=("swig")
if ! command -v make >/dev/null 2>&1; then MISSING+=("make"); fi
if ! command -v gcc >/dev/null 2>&1; then MISSING+=("gcc"); fi
python3 -c "import elftools" >/dev/null 2>&1 || MISSING+=("python3-pyelftools")

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "[macflow] missing tools: ${MISSING[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    echo "[macflow] installing build deps via apt-get"
    sudo apt-get update
    sudo apt-get install -y build-essential gawk unzip zstd libncurses-dev swig python3-pyelftools
  else
    echo "[macflow] install dependencies manually and retry" >&2
    exit 4
  fi
fi

echo "[macflow] resolve SDK from: ${INDEX_URL}"
SDK_NAME="$(curl -fsSL "${INDEX_URL}" | grep -oE "openwrt-sdk-${RELEASE}-${TARGET}-${SUBTARGET}[^\"']*Linux-x86_64\.tar\.zst" | head -n1 || true)"
if [[ -z "${SDK_NAME}" ]]; then
  echo "[macflow] cannot find SDK archive at ${INDEX_URL}" >&2
  exit 2
fi

SDK_ARCHIVE="${SDK_WORKDIR}/${SDK_NAME}"
SDK_DIR="${SDK_WORKDIR}/${SDK_NAME%.tar.zst}"

if [[ ! -f "${SDK_ARCHIVE}" ]]; then
  echo "[macflow] downloading ${SDK_NAME}"
  curl -fL "${INDEX_URL}${SDK_NAME}" -o "${SDK_ARCHIVE}"
fi

if [[ ! -d "${SDK_DIR}" ]]; then
  echo "[macflow] extracting SDK"
  tar --zstd -xf "${SDK_ARCHIVE}" -C "${SDK_WORKDIR}"
fi

echo "[macflow] sync package sources"
mkdir -p "${SDK_DIR}/package/macflow"
rm -rf "${SDK_DIR}/package/macflow"/*
cp -rf "${REPO_ROOT}/openwrt/macflow/." "${SDK_DIR}/package/macflow/"
mkdir -p "${SDK_DIR}/package/macflow/src"

# ── Go 交叉编译 ──────────────────────────────────────────
GO_BIN="${REPO_ROOT}/backend-go/macflowd-arm64"
GO_SRC="${REPO_ROOT}/backend-go"

if [[ -d "${GO_SRC}" ]]; then
  echo "[macflow] cross-compiling Go binary (linux/arm64)..."
  if command -v go >/dev/null 2>&1; then
    GIT_TAG=$(git -C "${REPO_ROOT}" describe --tags --always --dirty 2>/dev/null || echo "dev")
    PKG_VER="${GIT_TAG#v}"
    echo "[macflow] version: ${GIT_TAG}"
    pushd "${GO_SRC}" >/dev/null
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.Version=${GIT_TAG}" -o macflowd-arm64 ./cmd/macflowd/
    popd >/dev/null
    echo "[macflow] Go binary built: $(du -h "${GO_BIN}" | cut -f1)"
  elif [[ -f "${GO_BIN}" ]]; then
    echo "[macflow] go not in PATH, using existing binary: ${GO_BIN}"
  else
    echo "[macflow] ERROR: go not found and no prebuilt binary at ${GO_BIN}" >&2
    exit 4
  fi
else
  echo "[macflow] ERROR: backend-go/ not found at ${GO_SRC}" >&2
  exit 4
fi

# ── 拷贝工程文件到 SDK ──────────────────────────────────
cp -rf "${REPO_ROOT}/backend-go" "${SDK_DIR}/package/macflow/src/backend-go"
for d in web core config scripts; do
  rm -rf "${SDK_DIR}/package/macflow/src/${d}"
  cp -rf "${REPO_ROOT}/${d}" "${SDK_DIR}/package/macflow/src/${d}"
done
mkdir -p "${SDK_DIR}/package/macflow/src/vm"
cp -f "${REPO_ROOT}/vm/run-all-tests.sh" "${SDK_DIR}/package/macflow/src/vm/" 2>/dev/null || true
cp -f "${REPO_ROOT}/vm/final-check.sh" "${SDK_DIR}/package/macflow/src/vm/" 2>/dev/null || true
for tf in "${REPO_ROOT}"/vm/test-*.sh; do
  [ -f "$tf" ] && cp -f "$tf" "${SDK_DIR}/package/macflow/src/vm/"
done

pushd "${SDK_DIR}" >/dev/null

echo "[macflow] update feeds"
./scripts/feeds update -a
./scripts/feeds install -a

echo "[macflow] build package"
make defconfig
make package/macflow/compile V=s MACFLOW_SRC_DIR="${SDK_DIR}/package/macflow/src" -j"$(nproc)"

IPK_PATH="$(find bin/packages -type f -name 'macflow_*.ipk' | head -n1 || true)"
if [[ -z "${IPK_PATH}" ]]; then
  echo "[macflow] build done but ipk not found" >&2
  exit 3
fi

DIST_DIR="${REPO_ROOT}/dist/ipk/${TARGET}-${SUBTARGET}"
mkdir -p "${DIST_DIR}"
cp -f "${IPK_PATH}" "${DIST_DIR}/"

echo "[macflow] ipk: ${IPK_PATH}"
echo "[macflow] copied to: ${DIST_DIR}/$(basename "${IPK_PATH}")"

popd >/dev/null
