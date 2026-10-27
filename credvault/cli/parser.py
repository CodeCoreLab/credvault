"""cli/parser.py — argparse 定义（纯声明，无业务逻辑）

单独成文件的原因：参数表是 CLI 的对外契约，与实现分离后改参数不影响实现审阅。
公共参数挂到每个子命令上——顶层与子命令同名 dest 会互相覆盖。
"""
from __future__ import annotations

import argparse
import sys

from .. import ops, rotate as rotate_mod
from .access import (cmd_approval, cmd_audit, cmd_invoke, cmd_lease, cmd_token)
from .creds import cmd_backup, cmd_cred, cmd_keys, cmd_rotate
from .health import cmd_cap, cmd_doctor, cmd_policy_check, cmd_whoami, cmd_migrate
from .lifecycle import cmd_init, cmd_killswitch, cmd_serve, cmd_user


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="credvault",
                                description="CredVault — AI 主用的凭据平台")
    # 公共参数挂到每个子命令上（子命令与全局同名 dest 会互相覆盖，故不放顶层）
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=None,
                        help="配置文件路径（默认 $CREDVAULT_HOME/config.yaml）")
    common.add_argument("--home", default=None, help="覆盖 CREDVAULT_HOME")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, **kw) -> argparse.ArgumentParser:
        return sub.add_parser(name, parents=[common], **kw)

    add("version", help="版本").set_defaults(func=lambda a: (
        print(f"credvault {ops.VERSION}"), 0)[1])

    add("init", help="初始化目录/KEK/配置/策略/能力骨架").set_defaults(func=cmd_init)

    add("doctor", help="自检").set_defaults(func=cmd_doctor)

    add("policy-check", help="校验策略并列出授权").set_defaults(func=cmd_policy_check)

    s = add("cred", help="凭据管理")
    s.add_argument("action", choices=["list", "set", "show", "rm", "import-env", "kinds"])
    s.add_argument("name", nargs="?", default="")
    s.add_argument("--kind", default="generic")
    s.add_argument("--account", default="")
    s.add_argument("--remark", default="")
    s.add_argument("--tags", default="")
    s.add_argument("--expires-days", type=int, default=0)
    s.add_argument("--value", default="")
    s.add_argument("--value-stdin", action="store_true")
    s.add_argument("--file", default="", help="import-env 的文件")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(func=cmd_cred)

    s = add("token", help="机器身份")
    s.add_argument("action", choices=["add", "list", "rotate", "revoke", "scopes"])
    s.add_argument("name", nargs="?", default="")
    s.add_argument("--ttl-days", type=int, default=0)
    s.add_argument("--creds", help="可见凭据（逗号分隔）")
    s.add_argument("--caps", help="允许能力（逗号分隔）")
    s.add_argument("--ips", help="IP 白名单")
    s.add_argument("--scope", default="mcp", choices=["mcp", "api", "both"],
                   help="令牌可用的入口：mcp（默认）/ api（REST）/ both")
    s.set_defaults(func=cmd_token)

    s = add("approval", help="审批")
    s.add_argument("action", choices=["list", "pending", "approve", "reject", "status",
                                      "exemptions", "cleanup"])
    s.add_argument("id", nargs="?", default="")
    s.add_argument("--by", default="")
    s.add_argument("--reason", default="")
    s.add_argument("--session", action="store_true", help="批准并开本会话豁免")
    s.set_defaults(func=cmd_approval)

    s = add("audit", help="审计")
    s.add_argument("action", choices=["verify", "tail", "search", "stats", "export"])
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--hours", type=int, default=24)
    s.add_argument("--actor", default="")
    s.add_argument("--capability", default="")
    s.add_argument("--keyword", default="")
    s.add_argument("--ok", dest="ok", action="store_true", default=None)
    s.add_argument("--format", default="jsonl", choices=["jsonl", "csv", "md"])
    s.add_argument("--out", default="")
    s.set_defaults(func=cmd_audit)

    s = add("cap", help="能力注册表")
    s.add_argument("action", choices=["list", "show", "disable", "reload"])
    s.add_argument("name", nargs="?", default="")
    s.set_defaults(func=cmd_cap)

    s = add("invoke", help="调用能力（需 --token 或 --agent）")
    s.add_argument("capability")
    s.add_argument("--args", default="{}")
    s.add_argument("--token", default="")
    s.add_argument("--agent", default="")
    s.add_argument("--approval", default="")
    s.add_argument("--explain", action="store_true")
    s.set_defaults(func=cmd_invoke)

    s = add("whoami", help="运行时自省：可用能力/约束/额度")
    s.add_argument("--token", default="")
    s.add_argument("--agent", default="")
    s.set_defaults(func=cmd_whoami)

    s = add("rotate", help="轮换凭据（探针失败自动回滚）")
    s.add_argument("credential")
    s.add_argument("--adapter", default="generic", choices=list(rotate_mod.KINDS))
    s.add_argument("--length", type=int, default=32)
    s.add_argument("--value", default="")
    s.add_argument("--probe", default="", help="探针能力名")
    s.add_argument("--probe-args", default="{}")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--by", default="")
    s.set_defaults(func=cmd_rotate)

    s = add("lease", help="凭据分发租约（短时凭证）")
    s.add_argument("action", choices=["issue", "list", "revoke", "renew", "pull", "cleanup"])
    s.add_argument("credential", nargs="?", default="")
    s.add_argument("lease_id", nargs="?", default="")
    s.add_argument("--consumer", default="")
    s.add_argument("--ttl", type=int, default=300)
    s.add_argument("--no-renew", action="store_true")
    s.add_argument("--ips", help="IP 白名单（逗号分隔）")
    s.add_argument("--note", default="")
    s.add_argument("--all", action="store_true", help="含已撤销/过期")
    s.add_argument("--ip", default="", help="pull 时声明的来源 IP（用于白名单校验）")
    s.set_defaults(func=cmd_lease)

    s = add("backup", help="备份/恢复")
    s.add_argument("action", choices=["export", "restore", "peek"])
    s.add_argument("file")
    s.add_argument("--password", default="")
    s.add_argument("--overwrite", action="store_true")
    s.set_defaults(func=cmd_backup)

    s = add("keys", help="KEK 管理")
    s.add_argument("action", choices=["rewrap", "new"])
    s.add_argument("--new-kek", default="")
    s.add_argument("--out", default="")
    s.set_defaults(func=cmd_keys)

    s = add("serve", help="起服务（web / mcp）")
    s.add_argument("--mode", default="web", choices=["web", "mcp"])
    s.add_argument("--host", default="")
    s.add_argument("--port", type=int, default=0)
    s.add_argument("--token", default="")
    s.set_defaults(func=cmd_serve)

    s = add("mcp", help="MCP stdio（等价 serve --mode mcp）")
    s.add_argument("--token", default="")
    s.set_defaults(func=lambda a: cmd_serve(argparse.Namespace(**{**vars(a), "mode": "mcp"})))

    s = add("killswitch", help="全局只读开关")
    s.add_argument("action", choices=["on", "off", "status"])
    s.set_defaults(func=cmd_killswitch)

    s = add("user", help="人工账号（Web 审批用）")
    s.add_argument("action", choices=["add", "passwd", "list"])
    s.add_argument("name", nargs="?", default="")
    s.add_argument("--password", default="")
    s.add_argument("--role", default="admin", choices=["admin", "approver", "viewer"])
    s.set_defaults(func=cmd_user)

    s = add("migrate", help="从旧凭据体系迁移元数据")
    s.add_argument("--index", default="", help="CREDENTIALS_INDEX.yaml 路径")
    s.add_argument("--env", default="", help="env 文件路径（导入明文项）")
    s.set_defaults(func=cmd_migrate)
    return p


