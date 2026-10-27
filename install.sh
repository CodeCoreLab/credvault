#!/usr/bin/env bash
# install.sh — 幂等安装（重复执行不覆盖已有数据）
#
#   ./install.sh                      # 装到当前用户，默认 HOME=~/.credvault
#   CREDVAULT_HOME=/opt/credvault ./install.sh
#   ./install.sh --systemd            # 额外安装 systemd 单元（需 root）
#   ./install.sh --offline wheels/    # 离线安装（从本地 wheel 目录）
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="${CREDVAULT_HOME:-$HOME/.credvault}"
MODE="user"
WHEELS=""
PY="${PYTHON:-python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --systemd) MODE="systemd"; shift ;;
    --offline) WHEELS="${2:-}"; shift 2 ;;
    --home) HOME_DIR="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
done

echo "== CredVault 安装 =="
echo "  源码: $HERE"
echo "  数据: $HOME_DIR"
echo "  Python: $("$PY" -V 2>&1)"

"$PY" - <<'PYCHK'
import sys
if sys.version_info < (3, 11):
    sys.exit("需要 Python 3.11+")
PYCHK

# 1) 依赖（幂等：已装则秒过）
if [[ -n "$WHEELS" ]]; then
  "$PY" -m pip install --no-index --find-links "$WHEELS" cryptography pyyaml
else
  "$PY" -m pip install --quiet cryptography pyyaml
fi

# 2) 装包（editable 便于升级；--force-reinstall 会重建脚本但不碰数据）
"$PY" -m pip install --quiet --upgrade "$HERE"

# 3) 初始化数据目录（保留已有 KEK / 库 / 策略）
export CREDVAULT_HOME="$HOME_DIR"
mkdir -p "$HOME_DIR"
chmod 700 "$HOME_DIR" 2>/dev/null || true
"$PY" -m credvault init --home "$HOME_DIR"

# 4) systemd（可选）
if [[ "$MODE" == "systemd" ]]; then
  if [[ "$(id -u)" != "0" ]]; then
    echo "⚠️  --systemd 需要 root；已跳过（先 sudo）"; exit 0
  fi
  install -m 0644 "$HERE/deploy/credvault.service" /etc/systemd/system/credvault.service
  install -d -m 0700 /etc/credvault
  if [[ ! -f /etc/credvault/env ]]; then
    echo "CREDVAULT_HOME=$HOME_DIR" > /etc/credvault/env
    chmod 600 /etc/credvault/env
  fi
  systemctl daemon-reload
  systemctl enable --now credvault
  sleep 1
  systemctl --no-pager --lines=0 status credvault || true
  curl -fsS "http://127.0.0.1:${CREDVAULT_PORT:-8443}/healthz" && echo
fi

echo
echo "✅ 完成。下一步："
echo "  credvault user add admin          # 建审批账号（Web）"
echo "  credvault token add workbuddy     # 签 AI 令牌"
echo "  credvault doctor                  # 自检"
