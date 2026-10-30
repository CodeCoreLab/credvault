"""cli/access.py — 令牌 / 审批 / 审计 / 能力调用 / 租约

共同点：都围绕「谁能在什么条件下用什么」——授权面与追溯面。
"""
from __future__ import annotations

import json
import sys

from .. import crypto, policy as policy_mod
from ..service import LABELS, Service
from ._common import _agent_from, _print, _prog, _split, _svc


def cmd_token(args) -> int:
    svc = _svc(args)
    try:
        if args.action == "add":
            token, rec = svc.tokens.create(
                args.name, ttl_days=args.ttl_days,
                visible_credentials=_split(args.creds),
                allowed_capabilities=_split(args.caps),
                ip_allowlist=_split(args.ips),
                scope=getattr(args, "scope", "mcp"))
            scope = rec.get("scope", "mcp")
            if getattr(args, "json", False):
                # --json：结构化输出，令牌**不落 stdout**。
                # 理由：stdout 常被 CI 日志、终端录屏、管道缓存收集，
                # 令牌明文一旦进入日志就等于长期有效凭据外泄。
                # 这里只把令牌写到 stderr（人眼可见、管道不收），
                # stdout 保持纯 JSON，便于 `| jq` 直接消费。
                payload = {
                    "ok": True,
                    "action": "add",
                    "name": rec["name"],
                    "scope": scope,
                    "ttl_days": rec["ttl_days"],
                    "token_redacted": True,
                    "hint": "令牌只显示一次，已写入 stderr；请立刻配置到客户端",
                    "client_config": {},
                }
                if scope in ("mcp", "both"):
                    payload["client_config"]["mcp"] = {
                        "mcpServers": {"credvault": {
                            "command": _prog(), "args": ["mcp"],
                            "env": {"CREDVAULT_TOKEN": "<TOKEN>"}}},
                    }
                if scope in ("api", "both"):
                    payload["client_config"]["api"] = {
                        "header": "Authorization: Bearer <TOKEN>",
                        "example": 'curl -H "Authorization: Bearer <TOKEN>" '
                                   'http://127.0.0.1:8443/api/v1/whoami',
                    }
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                print(f"\n令牌（只显示这一次，请立刻配置到客户端）：\n{token}\n",
                      file=sys.stderr)
                if scope in ("api", "both"):
                    print(f'  curl -H "Authorization: Bearer {token}" \\\n'
                          f'       http://127.0.0.1:8443/api/v1/whoami',
                          file=sys.stderr)
                return 0
            print(f"✅ agent {rec['name']} 已创建（ttl={rec['ttl_days'] or '永不'} 天，scope={scope}）")
            print(f"\n令牌（只显示这一次，请立刻配置到客户端）：\n{token}\n")
            if scope in ("mcp", "both"):
                print("MCP 客户端配置（stdio）：")
                print(json.dumps({"mcpServers": {"credvault": {
                    "command": _prog(), "args": ["mcp"],
                    "env": {"CREDVAULT_TOKEN": token}}}}, ensure_ascii=False, indent=2))
            if scope in ("api", "both"):
                print("\nREST API 调用示例：")
                print(f'  curl -H "Authorization: Bearer {token}" \\\n'
                      f'       http://127.0.0.1:8443/api/v1/whoami')
            return 0
        if args.action == "list":
            for a in svc.tokens.list():
                st = "已吊销" if a["revoked"] else "有效"
                print(f"{a['name']:24} {st:6} scope={a.get('scope', 'mcp'):5} "
                      f"exp={a['expires_at'] or '永不'} "
                      f"caps={a['allowed_capabilities'] or '全部'} creds={a['visible_credentials'] or '全部'}")
            return 0
        if args.action == "rotate":
            print(svc.tokens.rotate(args.name))
            return 0
        if args.action == "revoke":
            print("✅ 已吊销" if svc.tokens.revoke(args.name) else "❌ 不存在或已吊销")
            return 0
        if args.action == "scopes":
            # 当前行为：直接透传列表，`--creds "a,,b"`（连续逗号）会把空串写进
            # 授权轴；scope 拼错值只在 DB 层报错。先做白名单/空项校验再更新。
            if getattr(args, "set_scope", None) is not None and args.set_scope not in ("mcp", "api", "both"):
                print(f"❌ scope 必须是 mcp/api/both 之一，收到 {args.set_scope!r}")
                return 1
            lists = {"--creds": _split(args.creds), "--caps": _split(args.caps),
                     "--ips": _split(args.ips)}
            for flag, items in lists.items():
                if items is not None and any(not x.strip() for x in items):
                    print(f"❌ {flag} 含空项（连续逗号？），拒绝整批更新")
                    return 1
            ok = svc.tokens.update_scopes(args.name, lists["--creds"], lists["--caps"],
                                          lists["--ips"],
                                          scope=getattr(args, "set_scope", None))
            print("✅ 已更新" if ok else "❌ 未更新（agent 不存在或没有任何变更项）")
            return 0
    finally:
        svc.close()
    return 2


def cmd_approval(args) -> int:
    svc = _svc(args)
    try:
        if args.action in ("list", "pending"):
            rows = svc.approvals.pending() if args.action == "pending" else svc.approvals.recent(50)
            if not rows:
                print("（无）")
            for r in rows:
                print(f"{r['id']}  {r['state']:9} {r['capability']:28} "
                      f"by={r['requested_by']:16} {r.get('remaining_sec','')}  "
                      f"{r['args_preview'][:70]}")
            return 0
        if args.action in ("approve", "reject"):
            ok, msg = svc.approvals.decide(args.id, args.action == "approve",
                                           args.by or "human:cli", args.reason or "",
                                           session=bool(args.session))
            print(("✅ " if ok else "❌ ") + msg)
            return 0 if ok else 1
        if args.action == "status":
            _print(svc.approvals.status(args.id))
            return 0
        if args.action == "exemptions":
            for e in svc.approvals.exemptions():
                print(f"{e['id']}  {e['capability']:28} agent={e['agent_id']:16} "
                      f"剩余 {max(0, e['expires_at'] - __import__('time').time())//60:.0f} 分钟")
            return 0
        if args.action == "cleanup":
            print(f"清理 {svc.approvals.cleanup()} 条历史审批")
            return 0
    finally:
        svc.close()
    return 2


def cmd_audit(args) -> int:
    svc = _svc(args)
    try:
        if args.action == "verify":
            ok, note, n = svc.audit.verify()
            print(("✅ " if ok else "❌ ") + note)
            return 0 if ok else 1
        if args.action == "tail":
            for r in svc.audit.search(limit=args.limit):
                print(f"{r.get('ts','')[11:19]} {r.get('actor',''):18} "
                      f"{(r.get('capability') or r.get('tool','')):28} "
                      f"{'OK ' if r.get('ok') else 'FAIL'} {r.get('dur_ms',0):>5}ms "
                      f"{(r.get('note') or '')[:70]}")
            return 0
        if args.action == "search":
            import time
            rows = svc.audit.search(limit=args.limit, actor=args.actor or "",
                                    capability=args.capability or "",
                                    ok=(None if args.ok is None else args.ok),
                                    since_epoch=int(time.time()) - args.hours * 3600,
                                    keyword=args.keyword or "")
            _print(rows)
            return 0
        if args.action == "stats":
            import time
            _print(svc.audit.stats(int(time.time()) - args.hours * 3600))
            return 0
        if args.action == "export":
            import time
            out = svc.audit.export(args.format, int(time.time()) - args.hours * 3600,
                                   args.limit)
            if args.out:
                Path(args.out).write_text(out, encoding="utf-8")
                print(f"✅ 已写入 {args.out}")
            else:
                print(out)
            return 0
    finally:
        svc.close()
    return 2


def cmd_invoke(args) -> int:
    svc = _svc(args)
    try:
        agent = _agent_from(svc, args)
        payload = json.loads(args.args) if args.args else {}
        if args.explain:
            _print(svc.explain(agent, args.capability, payload))
            return 0
        res = svc.invoke(agent, args.capability, payload, approval_id=args.approval or "")
        # 控制台只打印可读部分，保持与 MCP 一致的 code 语义
        out = {k: res.get(k) for k in ("ok", "code", "capability", "reason", "status",
                                       "dur_ms", "truncated", "audit_lost", "needs_approval",
                                       "approval_id", "next_action") if k in res}
        _print(out)
        if res.get("text"):
            print("─" * 66)
            print(res["text"])
        return 0 if res.get("ok") else (1 if res.get("code") else 0)
    finally:
        svc.close()


def cmd_lease(args) -> int:
    svc = _svc(args)
    try:
        if args.action == "issue":
            if not args.credential:
                print("❌ 需要 --credential")
                return 1
            _print(svc.lease_issue(args.consumer or "cli", args.credential,
                                   ttl=args.ttl, renewable=not args.no_renew,
                                   ip_allowlist=_split(args.ips), note=args.note or "",
                                   actor="human:cli"))
            return 0
        if args.action == "list":
            rows = svc.leases.list(include_revoked=bool(args.all))
            if not rows:
                print("（无活跃租约）")
            for r in rows:
                print(f"{r['id']}  {r['consumer']:20} {r['credential']:24} "
                      f"剩余 {r['remaining_sec']:>5}s renew={r['renewals']} "
                      f"{'已撤销' if r['revoked'] else ''}")
            return 0
        if args.action == "revoke":
            print("✅ 已撤销" if svc.lease_revoke(args.lease_id, "human:cli") else "❌ 不存在或已撤销")
            return 0
        if args.action == "renew":
            _print(svc.leases.renew(args.lease_id, args.ttl))
            return 0
        if args.action == "pull":
            # 值只打印到 stdout，供管道使用（不进审计、不落文件）
            print(svc.lease_pull(args.lease_id, args.ip or "")["value"])
            return 0
        if args.action == "cleanup":
            print(f"清理 {svc.leases.cleanup()} 条历史租约")
            return 0
    finally:
        svc.close()
    return 2


