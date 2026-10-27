"""cli/health.py — 自检 / 策略校验 / 能力查看 / 运行时自省 / 迁移

特点：全部只读或只写元数据，不改凭据值、不触发上游调用。
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import config as config_mod
from .. import kinds as kinds_mod, ops, policy as policy_mod
from ..service import Service
from ._common import _agent_from, _import_env, _print, _svc


def cmd_doctor(args) -> int:
    svc = _svc(args)
    h = ops.health(svc)
    print(f"CredVault {h['version']}  doctor（{h['platform']} / py{h['python']}）")
    print("-" * 66)
    for c in h["checks"]:
        mark = "✅" if c["ok"] else ("❌" if c["level"] == "block" else "⚠️")
        print(f"{mark} {c['name']:16} {c['note']}")
    print("-" * 66)
    print(f"阻断 {h['blocking']} / 告警 {h['warnings']} / 检查 {len(h['checks'])}")
    svc.close()
    return 0 if h["ok"] else 1


def cmd_policy_check(args) -> int:
    cfg = config_mod.load(args.config)
    try:
        warns = policy_mod.check(cfg.path("policy"))
    except policy_mod.PolicyError as e:
        print(f"❌ 策略不合法：{e}")
        return 1
    pol = policy_mod.load(cfg.path("policy"))
    for aid in pol.agents:
        d = pol.describe(aid)
        print(f"agent {aid}  allow_exec={d['allow_exec']}  "
              f"visible={d['visible_credentials']}  rules={len(d['rules'])}")
        for r in d["rules"]:
            print(f"   {'ALLOW' if r['allow'] else 'DENY ':5} {r['name']:32} "
                  f"approval={r['require_approval']}")
    if warns:
        print("\n告警：")
        for w in warns:
            print(f" ⚠️ {w}")
    else:
        print("\n✅ 无告警")
    return 0


def cmd_cap(args) -> int:
    svc = _svc(args)
    try:
        if args.action == "list":
            for c in svc.caps:
                flag = "RO " if c.read_only else "WR "
                appr = "APPROVAL " if c.require_confirm else ""
                print(f"{c.name:32} {c.kind:5} {flag}{appr}{'enabled' if c.enabled else 'DISABLED'}  "
                      f"{c.description.splitlines()[0][:70]}")
            return 0
        if args.action == "show":
            c = svc._caps_by_name.get(args.name)
            if not c:
                print("❌ 不存在")
                return 1
            _print(c.to_spec())
            return 0
        if args.action == "disable":
            svc.store.disable_capability(args.name)
            print("✅ 已在库内禁用（YAML 里的 enabled 仍为 true，需同时改 YAML）")
            return 0
        if args.action == "reload":
            svc.reload()
            svc._sync_capabilities()
            print(f"✅ 重载 {len(svc.caps)} 个能力")
            return 0
    finally:
        svc.close()
    return 2


def cmd_whoami(args) -> int:
    svc = _svc(args)
    try:
        _print(svc.whoami(_agent_from(svc, args)))
        return 0
    finally:
        svc.close()


def cmd_migrate(args) -> int:
    """从旧凭据体系迁移：只导元数据 + 可读的明文值，绝不动源文件。"""
    svc = _svc(args)
    try:
        n_idx = 0
        if args.index:
            import yaml
            raw = yaml.safe_load(Path(args.index).read_text(encoding="utf-8")) or {}
            for section in ("server_credentials", "local_credentials", "channel_credentials"):
                for item in raw.get(section) or []:
                    name = item.get("name")
                    if not name:
                        continue
                    svc.store.upsert_credential(
                        name, kind=str(item.get("type") or "generic"),
                        remark=f"{section}: {item.get('server_ref') or item.get('local_ref') or ''}",
                        tags=[str(t) for t in (item.get("consumers") or [])][:5])
                    n_idx += 1
        n_env = 0
        if args.env:
            _import_env(svc, Path(args.env))
        print(f"✅ 元数据导入 {n_idx} 条" + ("；env 值导入见上" if args.env else ""))
        print("  注意：旧密文（ENC_）与 KEK 不同源，需重录；建议先备份再切换")
        return 0
    finally:
        svc.close()


