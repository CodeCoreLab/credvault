"""ops.py — 自检 / 健康探针 / Prometheus 指标（I12）

`credvault doctor` 与 `/healthz` 共用同一份判定，避免「CLI 说好、探针说坏」。
"""
from __future__ import annotations

import platform
import time

VERSION = "1.2.0"
STARTED_AT = int(time.time())


def health(svc, deep: bool = True) -> dict:
    checks: list[dict] = []

    def add(name: str, ok: bool, note: str = "", level: str = "block") -> None:
        checks.append({"name": name, "ok": bool(ok), "note": note, "level": level})

    # 策略
    try:
        pol = svc.policy
        add("policy", bool(pol.agents), f"{len(pol.agents)} agents / {len(pol.deny)} deny")
    except Exception as e:  # noqa: BLE001
        add("policy", False, f"{type(e).__name__}: {e}")

    # 能力
    caps = svc.caps
    enabled = [c for c in caps if c.enabled]
    add("capabilities", bool(enabled), f"{len(enabled)}/{len(caps)} enabled")
    for w in getattr(svc, "cap_warn", [])[:5]:
        add("capability-warn", True, w, level="warn")

    # 凭据
    creds = svc.store.list_credentials()
    names = {c["name"] for c in creds}
    missing = [r for c in caps for r in c.secret_refs if r not in names]
    add("credentials", not missing, f"{len(creds)} 条；缺登记 {sorted(set(missing))[:6]}"
        if missing else f"{len(creds)} 条")

    # 密文库
    try:
        stored = set(svc.store.list_secret_names())
        orphan = sorted(names - stored)
        add("secrets", not orphan,
            f"{len(stored)} 条密文" + (f"；元数据有但密文缺 {orphan[:6]}" if orphan else ""))
    except Exception as e:  # noqa: BLE001
        add("secrets", False, f"{type(e).__name__}: {e}")

    # KEK（F2：长度 + 弱熵 + 权限三项）
    try:
        from . import crypto as crypto_mod
        k = svc.kek()
        ok_s, note_s = crypto_mod.kek_strength(k)
        add("kek", ok_s, f"source={svc.cfg.get('kek.source')}｜{note_s}")
    except Exception as e:  # noqa: BLE001
        add("kek", False, f"{type(e).__name__}: {e}")

    # exec 裸开体检：enabled=true 但白名单为空 = 任意命令执行
    if svc.cfg.get("exec.enabled"):
        caps_exec = [c for c in svc.caps if c.kind == "exec" and c.enabled]
        naked = [c.name for c in caps_exec if not (c.exec or {}).get("argv_allowlist")]
        add("exec-safety", not naked,
            f"exec 已开启；无白名单的能力 {naked}" if naked else
            f"exec 已开启，{len(caps_exec)} 个 exec 能力均有 argv 白名单",
            level="warn" if naked else "block")

    # 审计链
    if deep:
        try:
            ok, note, n = svc.audit.verify()
            add("audit-chain", ok, f"{note}")
        except Exception as e:  # noqa: BLE001
            add("audit-chain", False, f"{type(e).__name__}: {e}")
    else:
        add("audit-chain", True, "skipped", level="warn")

    # 状态
    kill = bool(svc.cfg.get("kill_switch")) or svc.store.meta_get("kill_switch") == "1"
    add("kill-switch", True, "开启（只读）" if kill else "关闭", level="warn")
    exp = svc.store.expiring(14)
    add("expiring", True, f"14 天内到期 {len(exp)} 条", level="warn")

    blocking = [c for c in checks if not c["ok"] and c["level"] == "block"]
    return {"ok": not blocking, "version": VERSION, "checks": checks,
            "blocking": len(blocking),
            "warnings": len([c for c in checks if c["level"] == "warn" and c["note"]]),
            "python": platform.python_version(), "platform": platform.system()}


def metrics(svc) -> str:
    """Prometheus 文本格式（无第三方依赖）。"""
    h = health(svc, deep=False)
    creds = svc.store.list_credentials()
    caps = svc.caps
    st = svc.audit.stats()

    def kv(name: str, val: float, typ: str = "gauge", help_: str = "") -> list[str]:
        return [f"# HELP {name} {help_ or name}", f"# TYPE {name} {typ}", f"{name} {val}"]

    out: list[str] = []
    out += kv("credvault_up", 1, "gauge", "服务存活")
    out += kv("credvault_uptime_seconds", int(time.time()) - STARTED_AT, "gauge")
    out += kv("credvault_healthy", 1 if h["ok"] else 0, "gauge", "1=全部探针通过")
    out += kv("credvault_blocking_checks", h["blocking"], "gauge", "阻断级失败项数")
    out += kv("credvault_credentials", len(creds), "gauge", "凭据条数")
    out += kv("credvault_credentials_expiring_14d", len(svc.store.expiring(14)), "gauge")
    out += kv("credvault_capabilities_enabled", len([c for c in caps if c.enabled]), "gauge")
    out += kv("credvault_agents_active", len([a for a in svc.tokens.list() if not a["revoked"]]),
              "gauge")
    out += kv("credvault_audit_records", st["total"], "gauge")
    out += kv("credvault_audit_failures", st["by_status"]["fail"], "gauge")
    out += kv("credvault_pending_approvals", len(svc.approvals.pending()), "gauge")
    out.append("# HELP credvault_calls_by_capability 按能力计数")
    out.append("# TYPE credvault_calls_by_capability gauge")
    for cap, n in st["by_capability"].items():
        out.append(f'credvault_calls_by_capability{{capability="{cap}"}} {n}')
    return "\n".join(out) + "\n"
