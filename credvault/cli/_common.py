"""cli/_common.py — CLI 共用工具（服务句柄/输出/参数解析助手）

从 cli.py 拆出的原因：802 行的单文件里混了「怎么连服务」「怎么打印」「条命令实现」三件事，
改一条命令要翻 800 行。此处只放跨命令复用的纯工具，无命令实现。
"""
from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path

from .. import config as config_mod
from .. import crypto
from ..service import Service


def _svc(args) -> Service:
    cfg = config_mod.load(getattr(args, "config", None))
    if getattr(args, "home", None):
        cfg.home = Path(args.home).expanduser().resolve()
        cfg.ensure_dirs()
    return Service(cfg)


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _prog() -> str:
    """打印下一步命令时用的程序名（python -m 运行时 argv[0] 是 __main__.py）。"""
    a = os.path.basename(sys.argv[0] or "")
    return "credvault" if a in ("__main__.py", "-c", "") else (a or "credvault")


def _split(v: str | None) -> list[str] | None:
    if not v:
        return None
    items = [x.strip() for x in v.replace("\n", ",").split(",") if x.strip()]
    return items or None


def _read_value(args) -> str:
    if args.value_stdin:
        return sys.stdin.read().strip()
    if args.value:
        return args.value
    return getpass.getpass("输入凭据值（不回显）: ").strip()


def _agent_from(svc, args) -> dict:
    if getattr(args, "token", ""):
        # 当前行为：绑定 IP 白名单的令牌在 CLI/stdio（无来源 IP）会因 fail-closed
        # 被拒，但报错笼统。提前探明并给出可操作提示（改签无白名单令牌）。
        ag = svc.authenticate(args.token, check_ip=False)
        if ag.get("ip_allowlist"):
            raise SystemExit("该令牌绑定了 IP 白名单，CLI/stdio 入口无法声明来源 IP，拒绝使用；"
                             "请改签不带 --ips 的令牌")
        return ag
    if getattr(args, "agent", ""):
        a = svc.tokens.get(args.agent)
        if not a or a["revoked"]:
            raise SystemExit(f"agent {args.agent} 不存在或已吊销")
        return a
    raise SystemExit("需要 --token 或 --agent（CLI 不提供「隐身上帝模式」）")


def _import_env(svc, path: Path) -> int:
    """从 env 文件批量导入（迁移主用）。ENC_ 开头的值无法在此解密，跳过并提示。"""
    import re
    if not path.is_file():
        print(f"❌ 文件不存在: {path}")
        return 1
    n = skip = enc = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
        if not v or v.startswith("#"):
            skip += 1
            continue
        if k.startswith("ENC_"):
            enc += 1
            continue
        svc.store.put_secret(k, v.encode(), svc.kek(), keep_history=False, reason="import-env")
        svc.store.upsert_credential(k, kind="generic", secret_fp=crypto.fingerprint(v.encode()))
        n += 1
    print(f"导入 {n} 条，跳过空值 {skip} 条，跳过 ENC_ 密文 {enc} 条")
    if enc:
        print("  提示：ENC_ 值需在主密码/KEK 可用时用 `cred set` 逐条重录，或先解密再导入")
    return 0


