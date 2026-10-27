"""cli — 命令行入口（按风险面拆分）

  _common.py   共用工具（服务句柄/输出/解析助手）
  lifecycle.py 平台自身状态：init / serve / killswitch / user
  health.py    只读面：doctor / policy-check / cap / whoami / migrate
  creds.py     触碰密文库与密钥：cred / rotate / keys / backup
  access.py    授权与追溯：token / approval / audit / invoke / lease
  parser.py    argparse 契约（纯声明）

main() 保留在此，统一做异常分流——错误码语义单点定义。
"""
from __future__ import annotations

import os
import sys

from .. import policy as policy_mod, registry


def main(argv: list[str] | None = None) -> int:
    from .parser import build_parser

    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except ValueError as e:
        print(f"❌ 配置错误：{e}", file=sys.stderr)
        return 2
    except (registry.RegistryError, policy_mod.PolicyError) as e:
        print(f"❌ {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        if os.getenv("CREDVAULT_DEBUG"):
            raise
        print(f"❌ {type(e).__name__}: {e}", file=sys.stderr)
        return 1


__all__ = ["main"]
