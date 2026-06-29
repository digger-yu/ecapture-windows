#!/usr/bin/env bash
#
# eCapture development environment initialization (Ubuntu).
#
# Usage:
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"
#
# Or from a local checkout:
#   bash builder/init_env.sh
#
set -euo pipefail

echo "Welcome to eCapture project development environment initialization script."
echo "Home page: https://ecapture.cc"
echo "Github: https://github.com/gojue/ecapture"

# ---------------------------------------------------------------------------
# Detect Ubuntu release
# ---------------------------------------------------------------------------
if ! command -v lsb_release >/dev/null 2>&1; then
  echo "ERROR: lsb_release not found; this script supports Ubuntu only."
  exit 1
fi

release_num=$(lsb_release -r --short)
echo "Ubuntu release: ${release_num}"

# Map Ubuntu release → clang package suffix. Keep in sync with CI images.
# Unknown / rolling releases: pick the newest installed-capable default (-18).
CLANG_NUM=-18
case "${release_num}" in
  20.04|20.10) CLANG_NUM=-10 ;;
  21.04)       CLANG_NUM=-11 ;;
  21.10|22.04|22.10) CLANG_NUM=-12 ;;
  23.04|23.10) CLANG_NUM=-15 ;;
  24.04|24.10) CLANG_NUM=-18 ;;
  25.04|25.10) CLANG_NUM=-20 ;;
  *)
    echo "WARNING: unlisted Ubuntu ${release_num}; using clang${CLANG_NUM} by default."
    ;;
esac
echo "CLANG_NUM=${CLANG_NUM}"

# ---------------------------------------------------------------------------
# Arch / cross toolchain for Linux kernel headers prepare
# ---------------------------------------------------------------------------
UNAME_M=$(uname -m)
ARCH="amd64"
CROSS_ARCH_PATH="arm64"
CROSS_COMPILE=aarch64-linux-gnu-
CROSS_COMPILE_DEB=gcc-aarch64-linux-gnu
if [[ ${UNAME_M} =~ x86_64 ]]; then
  ARCH="amd64"
  CROSS_ARCH_PATH="arm64"
  CROSS_COMPILE=aarch64-linux-gnu-
  CROSS_COMPILE_DEB=gcc-aarch64-linux-gnu
elif [[ ${UNAME_M} =~ aarch64 ]]; then
  ARCH="arm64"
  CROSS_ARCH_PATH="x86"
  CROSS_COMPILE=x86_64-linux-gnu-
  # Ubuntu 24.04+: package name is gcc-x86-64-linux-gnu
  CROSS_COMPILE_DEB=gcc-x86-64-linux-gnu
else
  echo "ERROR: unsupported arch ${UNAME_M}"
  exit 1
fi

GOBIN_ZIP="go1.25.12.linux-${ARCH}.tar.gz"
echo "GOBIN_ZIP=${GOBIN_ZIP}"

cd ~ || exit 1
uname -a

sudo apt-get update || { echo "apt-get update failed"; exit 1; }

# Core build deps + Linux cross GCC + Windows MinGW headers/libs (make windows / schannel_hook.dll)
sudo apt-get -y install \
  build-essential pkgconf libelf-dev \
  "llvm${CLANG_NUM}" "clang${CLANG_NUM}" \
  linux-tools-common linux-tools-generic \
  "${CROSS_COMPILE_DEB}" \
  mingw-w64-x86-64-dev gcc-mingw-w64-aarch64-linux-gnu \
  libssl-dev flex bison bc linux-source unzip wget git \
  || { echo "apt-get install failed"; exit 1; }

# Safe clang/llc/llvm-strip symlinks (never clang -> clang).
for tool in clang llc llvm-strip; do
  target="/usr/bin/${tool}${CLANG_NUM}"
  if [ ! -x "${target}" ]; then
    # Fallback: package may ship without version suffix on some releases.
    if [ -x "/usr/bin/${tool}" ] && [ ! -L "/usr/bin/${tool}" ]; then
      echo "WARNING: ${target} missing; keeping existing /usr/bin/${tool}"
      continue
    fi
    echo "ERROR: ${target} not found after apt install."
    exit 1
  fi
  # Remove broken self-loops from older init_env.sh runs.
  if [ -L "/usr/bin/${tool}" ]; then
    sudo rm -f "/usr/bin/${tool}"
  fi
  sudo ln -sfn "${target}" "/usr/bin/${tool}"
done

# ---------------------------------------------------------------------------
# Kernel source prepare (for non-CO-RE / header builds)
# ---------------------------------------------------------------------------
cd /usr/src || exit 1
source_file=$(find . -maxdepth 1 -name 'linux-source-*.tar.bz2' | head -n1)
if [ -z "${source_file}" ]; then
  echo "ERROR: linux-source tarball not found under /usr/src"
  exit 1
fi
source_dir=$(basename "${source_file}" .tar.bz2)
if [ ! -d "${source_dir}" ]; then
  sudo tar -xf "${source_file}"
fi
cd "${source_dir}" || exit 1
test -f .config || yes "" | sudo make oldconfig
yes "" | sudo make ARCH="${CROSS_ARCH_PATH}" CROSS_COMPILE="${CROSS_COMPILE}" prepare V=0 >/dev/null || true
yes "" | sudo make prepare V=0 >/dev/null || true
echo "Kernel source prepared: /usr/src/${source_dir}"

clang --version
cd ~ || exit 1

# ---------------------------------------------------------------------------
# Install Go
# ---------------------------------------------------------------------------
# GOPROXY is left to the user; do not force a mirror here.
GO_MIRROR_URL="https://golang.google.cn/dl/${GOBIN_ZIP}"
GO_OFFICIAL_URL="https://go.dev/dl/${GOBIN_ZIP}"

download_go() {
  local url="$1"
  local desc="$2"
  echo "Downloading Go: ${desc} (${url})"
  # Avoid PIPESTATUS + set -o pipefail surprises: write wget status explicitly.
  set +e
  wget --timeout=60 --tries=2 --server-response "${url}" -O "${GOBIN_ZIP}" 2>&1 | tee /tmp/wget_go.log
  local wget_status=${PIPESTATUS[0]}
  set -e
  if [ "${wget_status}" -ne 0 ]; then
    echo "WARNING: wget failed with exit code ${wget_status}"
    return 1
  fi
  local file_size
  file_size=$(stat -c%s "${GOBIN_ZIP}" 2>/dev/null || echo 0)
  if [ "${file_size}" -lt 52428800 ]; then
    echo "WARNING: Downloaded file too small (${file_size} bytes), likely a failed download."
    return 1
  fi
  if file "${GOBIN_ZIP}" | grep -qE 'HTML|ASCII text'; then
    echo "WARNING: Downloaded file is HTML/text, not a valid archive."
    return 1
  fi
  return 0
}

if ! download_go "${GO_MIRROR_URL}" "China mirror"; then
  echo "Mirror download failed, trying official site..."
  if ! download_go "${GO_OFFICIAL_URL}" "Official site"; then
    echo "ERROR: Failed to download Go from both mirror and official site."
    echo "Please download manually: https://go.dev/dl/"
    exit 1
  fi
fi

sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "${GOBIN_ZIP}"
if [ ! -x /usr/local/go/bin/go ]; then
  echo "ERROR: Go installation failed, /usr/local/go/bin/go not found."
  exit 1
fi

# Immediate + durable PATH so `go` works in this shell and future shells.
export PATH=/usr/local/go/bin:${PATH}

# Symlink into /usr/bin so non-login shells / scripts find `go` without sourcing.
sudo ln -sfn /usr/local/go/bin/go /usr/bin/go
sudo ln -sfn /usr/local/go/bin/gofmt /usr/bin/gofmt

ECAPTURE_ENV="/etc/profile.d/ecapture.sh"
sudo tee "${ECAPTURE_ENV}" >/dev/null <<'EOF'
# eCapture development environment
export PATH=/usr/local/go/bin:$PATH
EOF
sudo chmod 644 "${ECAPTURE_ENV}"

# Ubuntu interactive bash is often a non-login shell → reads ~/.bashrc, not ~/.profile.
PROFILE_FILE="${HOME}/.profile"
BASHRC_FILE="${HOME}/.bashrc"
NEED_RELOGIN=false

ensure_path_line() {
  local file="$1"
  local line='export PATH=/usr/local/go/bin:$PATH'
  touch "${file}"
  if ! grep -qF '/usr/local/go/bin' "${file}" 2>/dev/null; then
    echo "${line}" >> "${file}"
    NEED_RELOGIN=true
  fi
}

ensure_path_line "${PROFILE_FILE}"
ensure_path_line "${BASHRC_FILE}"

# Load for the remainder of this script (and remind the user to source).
# shellcheck disable=SC1090
source "${ECAPTURE_ENV}" || true
hash -r 2>/dev/null || true

echo ""
echo "============================================================"
echo " Optional: Go module proxy (GOPROXY)"
echo "============================================================"
echo " Default : https://proxy.golang.org,direct   (official, recommended outside China)"
echo " China   : https://goproxy.cn,direct         (faster for users in mainland China)"
echo ""
echo " This script does NOT force any GOPROXY value. Press 'y' to enable goproxy.cn,"
echo " or just press Enter to keep the default."
echo ""
read -r -p " Enable China mirror (goproxy.cn)? [y/N] " enable_proxy
if [[ "${enable_proxy}" =~ ^[Yy]$ ]]; then
  /usr/local/go/bin/go env -w GOPROXY=https://goproxy.cn,direct
  echo "GOPROXY set to: $(/usr/local/go/bin/go env GOPROXY)"
  if ! grep -q 'GOPROXY' "${ECAPTURE_ENV}" 2>/dev/null; then
    echo "export GOPROXY=https://goproxy.cn,direct" | sudo tee -a "${ECAPTURE_ENV}" >/dev/null
    NEED_RELOGIN=true
  fi
else
  echo "GOPROXY left at default: $(/usr/local/go/bin/go env GOPROXY)"
fi

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: 'go' still not on PATH after install. Run: source ${ECAPTURE_ENV}"
  exit 1
fi

echo "Go $(go version | awk '{print $3}') installed successfully."
echo "GOPROXY: $(go env GOPROXY)"
echo "Environment file: ${ECAPTURE_ENV}"
echo "MinGW (Windows): clang --target=x86_64-w64-windows-gnu ($(command -v clang || echo 'clang missing'))"

# ---------------------------------------------------------------------------
# Optional: Npcap SDK (pcap mode for make windows)
# MinGW is already installed above for schannel_hook.dll / basic windows builds.
# ---------------------------------------------------------------------------
echo ""
echo "MinGW-w64 dev libs installed (mingw-w64-x86-64-dev; arm64 sysroot via gcc-mingw-w64-aarch64-linux-gnu)."
echo "  make windows                    # → bin/ecapture.exe + bin/schannel_hook.dll"
echo "  CROSS_ARCH=arm64 make windows # Windows arm64"
echo ""
echo "Npcap SDK is only needed if you want Windows -m pcap builds."
echo ""
read -r -p "Download Npcap SDK to /opt/npcap-sdk (optional, for Windows pcap)? [y/N] " install_npcap
if [[ "${install_npcap}" =~ ^[Yy]$ ]]; then
  NPCAP_SDK_URL="https://npcap.com/dist/npcap-sdk-1.13.zip"
  echo "Downloading Npcap SDK..."
  if wget -q --timeout=60 --tries=2 "${NPCAP_SDK_URL}" -O /tmp/npcap-sdk.zip; then
    sudo mkdir -p /opt/npcap-sdk
    sudo unzip -o /tmp/npcap-sdk.zip -d /opt/npcap-sdk
    export NPCAP_SDK=/opt/npcap-sdk
    if ! grep -q 'NPCAP_SDK' "${ECAPTURE_ENV}" 2>/dev/null; then
      echo 'export NPCAP_SDK=/opt/npcap-sdk' | sudo tee -a "${ECAPTURE_ENV}" >/dev/null
    fi
    if ! grep -q 'NPCAP_SDK' "${PROFILE_FILE}" 2>/dev/null; then
      echo 'export NPCAP_SDK=/opt/npcap-sdk' >> "${PROFILE_FILE}"
    fi
    if ! grep -q 'NPCAP_SDK' "${BASHRC_FILE}" 2>/dev/null; then
      echo 'export NPCAP_SDK=/opt/npcap-sdk' >> "${BASHRC_FILE}"
    fi
    NEED_RELOGIN=true
    echo "Npcap SDK installed to /opt/npcap-sdk"
  else
    echo "WARNING: Npcap SDK download failed. You can install it later:"
    echo "  wget ${NPCAP_SDK_URL} -O /tmp/npcap-sdk.zip"
    echo "  sudo unzip -o /tmp/npcap-sdk.zip -d /opt/npcap-sdk"
    echo "  export NPCAP_SDK=/opt/npcap-sdk"
  fi
fi

# ---------------------------------------------------------------------------
# Optional: clone eCapture source
# ---------------------------------------------------------------------------
CLONE_DIR="${HOME}/ecapture"
echo ""
if [ -d "${CLONE_DIR}/.git" ]; then
  echo "Existing checkout found: ${CLONE_DIR}"
  read -r -p "Update it with git pull? [y/N] " do_pull
  if [[ "${do_pull}" =~ ^[Yy]$ ]]; then
    git -C "${CLONE_DIR}" pull --ff-only || echo "WARNING: git pull failed; leaving tree as-is."
  fi
else
  read -r -p "Clone https://github.com/gojue/ecapture.git into ${CLONE_DIR}? [y/N] " do_clone
  if [[ "${do_clone}" =~ ^[Yy]$ ]]; then
    git clone https://github.com/gojue/ecapture.git "${CLONE_DIR}"
  else
    echo "Skipping clone. Use your own checkout when building."
  fi
fi

echo ""
echo "============================================================"
echo " eCapture development environment initialized successfully!"
echo "============================================================"
echo ""
if [ -d "${CLONE_DIR}" ]; then
  echo " Project path: ${CLONE_DIR}"
else
  echo " Project path: (not cloned; cd to your existing checkout)"
fi
echo ""
echo " IMPORTANT: Environment files updated:"
echo "   ${ECAPTURE_ENV}   (system-wide)"
echo "   ${PROFILE_FILE}   (login shells)"
echo "   ${BASHRC_FILE}    (interactive bash)"
echo "   /usr/bin/go       (symlink → /usr/local/go/bin/go)"
echo ""
echo " If 'go' / 'make windows' is not found in THIS terminal, run:"
echo "   source /etc/profile.d/ecapture.sh"
echo "   # 或"
echo "   export PATH=/usr/local/go/bin:\$PATH"
echo "   go version"
echo ""
echo " New terminals should pick PATH up automatically via .bashrc / profile.d."
echo ""
echo " Quick start:"
echo "   source /etc/profile.d/ecapture.sh"
if [ -d "${CLONE_DIR}" ]; then
  echo "   cd ${CLONE_DIR}"
fi
echo "   make                 # Linux full build"
echo "   make windows         # Windows (HOST_ARCH; use CROSS_ARCH=arm64 for arm64)"
echo ""
echo " See README.md / docs/compilation.md for more information."
echo " Enjoy it!"
