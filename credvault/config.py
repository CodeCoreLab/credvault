"""config.py — 配置外置 + 路径锚定（零硬编码）

设计约束（对应 I12 / P4 / P5）：
  - 所有路径来自 CREDVAULT_HOME，不再探测 /opt/workbuddy 之类的历史路径
  - 配置优先级：显式 --config 文件 > $CREDVAULT_CONFIG > $CREDVAULT_HOME/config.yaml > 内置默认
  - 环境变量可覆盖单个叶子项：CREDVAULT_LISTEN_PORT 等（见 _ENV_MAP）
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise SystemExit("缺依赖 pyyaml：pip install pyyaml") from e


DEFAULTS: dict[str, Any] = {
    "home": None,
    "listen": {"host": "127.0.0.1", "port": 8443},
    "kek": {"source": "file", "path": "keys/kek.bin", "env": "CREDVAULT_KEK"},
    "store": {"db": "state/credvault.db", "secrets": "state/secrets.db"},
    "policy": "policy.yaml",
    "capabilities": ["capabilities"],  # 目录或文件，可多个
    "audit": {
        "path": "state/audit.jsonl",
        "strict": False,
        "sink": {"type": "none", "url": "", "timeout_sec": 5},
    },
    "redact": {"max_hits": 200, "patterns": []},
    "limits": {
        "response_bytes": 32768,
        "timeout_sec": 20,
        # 配额：0 = 未设置，跟随 policy（见 service._limits）；非 0 则以 config 为准
        "quota_per_min": 0,
        "quota_per_day": 0,
        "burst_count": 10,
        "burst_window_sec": 60,
        # 软限流（litellm 模式）：默认关闭=超配额硬停；开启后按 pct 概率放行、其余降速拒绝
        "throttle_enabled": False,
        "throttle_pct": 0.5,
        "max_body_bytes": 262144,
    },
    "approval": {
        "ttl_min": 30,
        "session_ttl_min": 120,
        "notifier": {"type": "none", "url": ""},
    },
    "exec": {"enabled": False, "argv_allowlist": [], "timeout_sec": 30},
    "kill_switch": False,
    "web": {"enabled": True, "session_ttl_min": 480, "csrf": True, "cookie_secure": True},
    "timezone": "Asia/Shanghai",
}

_ENV_MAP = {
    "CREDVAULT_LISTEN_HOST": "listen.host",
    "CREDVAULT_LISTEN_PORT": "listen.port",
    "CREDVAULT_KEK_SOURCE": "kek.source",
    "CREDVAULT_KEK_PATH": "kek.path",
    "CREDVAULT_DB": "store.db",
    "CREDVAULT_SECRETS": "store.secrets",
    "CREDVAULT_POLICY": "policy",
    "CREDVAULT_AUDIT": "audit.path",
    "CREDVAULT_AUDIT_STRICT": "audit.strict",
    "CREDVAULT_RESPONSE_BYTES": "limits.response_bytes",
    "CREDVAULT_TIMEOUT_SEC": "limits.timeout_sec",
    "CREDVAULT_KILL_SWITCH": "kill_switch",
    "CREDVAULT_EXEC_ENABLED": "exec.enabled",
    "CREDVAULT_THROTTLE_ENABLED": "limits.throttle_enabled",
    "CREDVAULT_THROTTLE_PCT": "limits.throttle_pct",
    "CREDVAULT_COOKIE_SECURE": "web.cookie_secure",
    "CREDVAULT_WEB_ENABLED": "web.enabled",
}

_BOOL = {"1": True, "0": False, "true": True, "false": False, "yes": True, "no": False}


def _merge(base: dict, over: dict) -> dict:
    """深合并：over 覆盖 base，只认 base 里存在的键（未知键报错，防拼错静默生效）。"""
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if k not in out:
            raise ValueError(f"未知配置项: {k}（可用: {sorted(out)}）")
        if isinstance(out[k], dict):
            if not isinstance(v, dict):
                raise ValueError(f"配置项 {k} 应为映射")
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce(spec: Any, raw: str) -> Any:
    if isinstance(spec, bool):
        low = raw.strip().lower()
        if low not in _BOOL:
            raise ValueError(f"布尔值无法解析: {raw!r}")
        return _BOOL[low]
    if isinstance(spec, int):
        return int(raw)
    if isinstance(spec, list):
        return [x.strip() for x in raw.split(",") if x.strip()]
    return raw


class Config:
    """点号取值 + 路径解析。所有相对路径解析到 home 下。"""

    def __init__(self, data: dict[str, Any], source: Path | None):
        self._d = data
        self.source = source
        home = data.get("home") or os.getenv("CREDVAULT_HOME") or str(Path.home() / ".credvault")
        self.home = Path(home).expanduser().resolve()
        self._apply_env()

    # ── 取值 ──
    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self._d
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def path(self, dotted: str) -> Path:
        v = self.get(dotted)
        if v is None:
            raise KeyError(f"配置项缺失: {dotted}")
        p = Path(str(v)).expanduser()
        return p if p.is_absolute() else (self.home / p)

    def as_dict(self) -> dict[str, Any]:
        d = copy.deepcopy(self._d)
        d["home"] = str(self.home)
        return d

    # ── 环境覆盖 ──
    def _apply_env(self) -> None:
        for env_key, dotted in _ENV_MAP.items():
            raw = os.getenv(env_key)
            if raw is None or raw == "":
                continue
            spec = self.get(dotted)
            try:
                val = _coerce(spec, raw)
            except (ValueError, TypeError) as e:
                raise ValueError(f"环境变量 {env_key}={raw!r} 无法解析为 {type(spec).__name__}: {e}") from e
            self.set(dotted, val)

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur = self._d
        for p in parts[:-1]:
            cur = cur[p]
        cur[parts[-1]] = value

    # ── 目录 ──
    def dirs(self) -> list[Path]:
        return [
            self.home,
            self.path("store.db").parent,
            self.path("audit.path").parent,
            self.path("kek.path").parent,
        ]

    def ensure_dirs(self) -> None:
        for d in self.dirs():
            d.mkdir(parents=True, exist_ok=True)
        # home 与 state 目录收紧（POSIX 生效；Windows 由 harden() 处理）
        try:
            os.chmod(self.home, 0o700)
        except OSError:
            pass


def find_config(explicit: str | None = None) -> Path | None:
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_file():
            raise SystemExit(f"配置文件不存在: {p}")
        return p
    env = os.getenv("CREDVAULT_CONFIG")
    if env:
        p = Path(env).expanduser()
        if not p.is_file():
            raise SystemExit(f"$CREDVAULT_CONFIG 指向的文件不存在: {p}")
        return p
    home = os.getenv("CREDVAULT_HOME") or str(Path.home() / ".credvault")
    for cand in (Path(home) / "config.yaml", Path.cwd() / "config.yaml"):
        if cand.is_file():
            return cand.expanduser()
    return None


def load(explicit: str | None = None) -> Config:
    p = find_config(explicit)
    raw: dict[str, Any] = {}
    if p is not None:
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise SystemExit(f"{p} 顶层必须是映射")
        raw = loaded
        # 配置文件里的相对路径按「配置文件所在目录」解析更符合直觉，
        # 但为避免与 CREDVAULT_HOME 语义打架，这里统一按 home 解析，并在文档中说明。
    data = _merge(DEFAULTS, raw)
    return Config(data, p)
