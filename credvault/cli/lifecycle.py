"""cli/lifecycle.py — 初始化 / 服务进程 / 应急开关 / 人工账号

这些命令都改「平台自身状态」（建目录、起进程、Kill Switch、账号），
与业务命令（凭据/令牌/审批）分开，便于按风险面审阅。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .. import config as config_mod
from .. import crypto, ops
from ..service import Service
from ._common import _prog, _svc


def cmd_init(args) -> int:
    cfg = config_mod.load(args.config)
    if args.home:
        cfg.home = Path(args.home).expanduser().resolve()
    cfg.ensure_dirs()
    kek = crypto.load_kek(cfg.get("kek.source"), cfg.path("kek.path"),
                          cfg.get("kek.env"), create=True)
    # 首次落一份可用的配置/策略/能力骨架，做到「解压即跑」
    tpl = Path(__file__).resolve().parent.parent
    for src, dst in ((tpl / "config.example.yaml", cfg.home / "config.yaml"),):
        if dst.exists():
            continue
        if src.is_file():
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    pol = cfg.path("policy")
    if not pol.exists() and (tpl / "policy.yaml").is_file():
        pol.write_text((tpl / "policy.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    capdir = cfg.home / "capabilities"
    capdir.mkdir(parents=True, exist_ok=True)
    if not list(capdir.glob("*.yaml")) and (tpl / "capabilities").is_dir():
        for f in (tpl / "capabilities").glob("*.yaml"):
            (capdir / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    svc = Service(cfg)
    svc.kek()
    print(f"✅ 初始化完成：{cfg.home}")
    print(f"   KEK: {cfg.path('kek.path')}（{len(kek)} 字节）")
    print(f"   配置: {cfg.home / 'config.yaml'}")
    print(f"   策略: {cfg.path('policy')}")
    print(f"   能力: {capdir}（{len(svc.caps)} 个）")
    print("\n下一步：")
    print(f"  1) {_prog()} user add admin          # 建审批账号（Web 用）")
    print(f"  2) {_prog()} token add workbuddy     # 签 AI 令牌")
    print(f"  3) {_prog()} doctor                  # 自检")
    svc.close()
    return 0


def cmd_serve(args) -> int:
    svc = _svc(args)
    mode = args.mode
    if mode == "mcp":
        token = args.token or os.getenv("CREDVAULT_TOKEN", "")
        if not token:
            print("❌ 需要 CREDVAULT_TOKEN 或 --token", file=sys.stderr)
            return 2
        try:
            svc.authenticate(token)
        except Exception as e:  # noqa: BLE001
            print(f"❌ {e}", file=sys.stderr)
            return 2
        from ..mcp import serve_stdio
        return serve_stdio(svc, token)
    from ..web import make_server
    host = args.host or svc.cfg.get("listen.host")
    port = int(args.port or svc.cfg.get("listen.port"))
    httpd = make_server(svc, host, port)
    print(f"CredVault {ops.VERSION} 监听 http://{host}:{port}  "
          f"（/healthz /metrics /approvals /audit /tokens /mcp）", file=sys.stderr)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("⚠️ 非回环监听：请确保已用防火墙/反代收敛，且已改默认口令", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        svc.close()
    return 0


def cmd_killswitch(args) -> int:
    svc = _svc(args)
    try:
        if args.action == "on":
            svc.store.meta_set("kill_switch", "1")
            svc.audit.append("human:cli", "killswitch.on", True, 0)
            print("✅ Kill Switch 已开启：只读能力放行，写能力一律拒绝")
        elif args.action == "off":
            svc.store.meta_set("kill_switch", "0")
            svc.audit.append("human:cli", "killswitch.off", True, 0)
            print("✅ Kill Switch 已关闭")
        else:
            on = svc.store.meta_get("kill_switch") == "1" or bool(svc.cfg.get("kill_switch"))
            print(f"Kill Switch: {'ON（只读）' if on else 'OFF'}")
        return 0
    finally:
        svc.close()


def cmd_user(args) -> int:
    from ..web import ensure_user, set_password
    svc = _svc(args)
    try:
        if args.action == "add":
            pwd = args.password or getpass.getpass("口令（≥8 位）: ")
            if len(pwd) < 8:
                print("❌ 口令至少 8 位")
                return 1
            ok = ensure_user(svc.store, args.name, pwd, args.role)
            print("✅ 已创建" if ok else "❌ 用户已存在")
            return 0 if ok else 1
        if args.action == "passwd":
            pwd = args.password or getpass.getpass("新口令: ")
            ok = set_password(svc.store, args.name, pwd)
            print("✅ 已更新" if ok else "❌ 不存在")
            return 0 if ok else 1
        if args.action == "list":
            for r in svc.store._meta.execute("SELECT name,role,created_at FROM users"):
                print(f"{r['name']:20} {r['role']:10} {r['created_at']}")
            return 0
    finally:
        svc.close()
    return 2


