"""cli/creds.py — 凭据值 / 轮换 / 备份 / KEK

风险最高的一组命令：都会触碰密文库或密钥。改这里的任何一行都要跑
`cred set`+`invoke`+`backup` 三条最小路径。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .. import backup as backup_mod
from .. import config as config_mod
from .. import crypto, kinds as kinds_mod, rotate as rotate_mod
from ..service import Service
from ._common import _import_env, _print, _read_value, _svc


def cmd_cred(args) -> int:
    svc = _svc(args)
    try:
        if args.action == "list":
            rows = svc.store.list_credentials()
            if not rows:
                print("（空）")
            for r in rows:
                exp = r.get("expires_at")
                print(f"{r['name']:34} {r['kind']:14} fp={r.get('secret_fp',''):12} "
                      f"used={r.get('use_count',0):<4} exp={exp or '永不'} "
                      f"tags={','.join(r.get('tags') or [])}")
            return 0
        if args.action == "set":
            val = _read_value(args)
            if not val:
                print("❌ 值为空")
                return 1
            err = kinds_mod.validate(args.kind, val, args.account or "", args.remark or "")
            if err:
                print(f"❌ {err}")
                print("   可用类型：credvault cred kinds")
                return 1
            fp = svc.store.put_secret(args.name, val.encode(), svc.kek(),
                                      keep_history=True, reason="cred set")
            exp = None
            if args.expires_days:
                import time
                exp = int(time.time()) + int(args.expires_days) * 86400
            rec = svc.store.upsert_credential(
                args.name, kind=args.kind, account=args.account or "",
                remark=args.remark or "", tags=(args.tags or "").split(",") if args.tags else [],
                expires_at=exp, secret_fp=fp)
            svc.audit.append("human:cli", "cred.set", True, 0, credential=args.name)
            print(f"✅ {args.name} 已写入（fp={fp}，kind={rec['kind']}）")
            return 0
        if args.action == "show":
            c = svc.store.get_credential(args.name)
            if not c:
                print("❌ 未登记")
                return 1
            print(json.dumps({k: c[k] for k in ("name", "kind", "account", "remark", "tags",
                                                "expires_at", "last_used_at", "use_count",
                                                "secret_fp", "status")},
                             ensure_ascii=False, indent=2))
            print(f"密文存在: {svc.store.has_secret(args.name)}")
            return 0
        if args.action == "rm":
            if not args.yes:
                print("需加 --yes 确认（软删除，密文保留）")
                return 1
            svc.store.delete_credential(args.name)
            svc.audit.append("human:cli", "cred.rm", True, 0, credential=args.name)
            print(f"✅ {args.name} 已软删除")
            return 0
        if args.action == "kinds":
            for k in kinds_mod.describe_all():
                req = ",".join(k["required"]) or "-"
                print(f"{k['name']:14} {k['label']:12} 必填元数据={req:10} "
                      f"最短={k['value_min_len']:<4} {k['hint']}")
            return 0
        if args.action == "import-env":
            return _import_env(svc, Path(args.file))
    finally:
        svc.close()
    return 2


def cmd_rotate(args) -> int:
    svc = _svc(args)
    try:
        res = rotate_mod.rotate(
            svc, args.credential, actor=args.by or "human:cli", adapter=args.adapter,
            new_value=args.value or "", length=args.length,
            probe_capability=args.probe or "", probe_args=json.loads(args.probe_args or "{}"),
            dry_run=args.dry_run)
        _print(res)
        return 0 if res.get("ok") else 1
    finally:
        svc.close()


def cmd_keys(args) -> int:
    cfg = config_mod.load(args.config)
    svc = _svc(args)
    try:
        if args.action == "rewrap":
            newp = Path(args.new_kek)
            if not newp.is_file():
                print("❌ 新 KEK 文件不存在（先 credvault keys new --out <path>）")
                return 1
            new = newp.read_bytes()
            if len(new) != 32:
                print("❌ 新 KEK 必须是 32 字节")
                return 1
            old = svc.kek()
            n = svc.store.rewrap_all(old, new)
            print(f"✅ 已重包 {n} 条 DEK；把新 KEK 换到 {cfg.path('kek.path')} 后重启即可")
            return 0
        if args.action == "new":
            out = Path(args.out)
            if out.exists():
                print("❌ 目标已存在")
                return 1
            crypto.write_private(out, os.urandom(32))
            print(f"✅ 新 KEK 已写入 {out}")
            return 0
    finally:
        svc.close()
    return 2


def cmd_backup(args) -> int:
    svc = _svc(args)
    try:
        if args.action == "export":
            pwd = args.password or getpass.getpass("设置备份主密码（≥8 位）: ")
            _print(backup_mod.export(svc, Path(args.file), pwd))
            return 0
        if args.action == "restore":
            pwd = args.password or getpass.getpass("备份主密码: ")
            _print(backup_mod.restore(svc, Path(args.file), pwd, overwrite=args.overwrite))
            return 0
        if args.action == "peek":
            _print(backup_mod.peek(Path(args.file)))
            return 0
    finally:
        svc.close()
    return 2


