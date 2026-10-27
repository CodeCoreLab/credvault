#!/usr/bin/env bash
# build.sh — 产出可交付件：单目录可执行包 / wheel 集 / docker 镜像
#
#   ./build.sh                # 三种都打（缺 docker 时跳过镜像）
#   ./build.sh binary         # PyInstaller onedir → dist/credvault/
#   ./build.sh wheel          # 离线 wheel 集 → dist/wheels/（可 air-gap 安装）
#   ./build.sh docker         # 镜像 credvault:1.0.0
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
VERSION="$(python3 -c 'import credvault;print(credvault.__version__)' 2>/dev/null || echo 1.0.0)"
WHAT="${1:-all}"

build_wheel() {
  echo "== wheel 集（离线安装用）=="
  python3 -m pip install --quiet --upgrade build wheel
  rm -rf dist/wheels && mkdir -p dist/wheels
  python3 -m pip wheel --no-deps -w dist/wheels . >/dev/null
  python3 -m pip download --quiet -d dist/wheels cryptography pyyaml
  ls -1 dist/wheels
  echo "  离线安装： ./install.sh --offline $PWD/dist/wheels"
}

build_binary() {
  echo "== PyInstaller onedir =="
  python3 -m pip install --quiet pyinstaller
  rm -rf build dist/credvault
  python3 -m PyInstaller --noconfirm --clean credvault.spec >/dev/null
  du -sh dist/credvault 2>/dev/null || true
  echo "  产物： dist/credvault/credvault"
}

build_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "== 跳过 docker（未安装）=="; return
  fi
  echo "== docker 镜像 =="
  docker build -t "credvault:${VERSION}" -t credvault:latest .
  docker image ls credvault
}

case "$WHAT" in
  wheel) build_wheel ;;
  binary) build_binary ;;
  docker) build_docker ;;
  all) build_wheel; build_binary; build_docker ;;
  *) echo "未知目标: $WHAT"; exit 2 ;;
esac
echo "✅ 完成（版本 ${VERSION}）"
