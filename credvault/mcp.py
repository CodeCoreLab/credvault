"""mcp.py — MCP 服务（手写 JSON-RPC，不依赖 mcp SDK）

为什么手写：旧实现同时要兼容 mcp 1.x(FastMCP) 与 2.x(MCPServer)，host/port 走两套
参数，部署时反复踩版本坑。协议本身只有 initialize / tools/list / tools/call / prompts，
手写 ~200 行换取「零版本依赖」，符合「环境依赖最小化」。

三个 AI 面关键设计（I2/I3/I4）：
  1. `initialize.instructions` 随部署动态生成的中文引导块
  2. `tools/list` 按 agent 双轴授权**渐进披露**（没授权的工具根本不出现在列表里）
  3. `tools/call` 返回 content + structuredContent，失败置 isError=true
"""
from __future__ import annotations

import json
import sys
from typing import Any

PROTOCOL = "2025-06-18"
SERVER_INFO = {"name": "credvault", "version": __import__("credvault").__version__}


def build_instructions(svc, agent: dict) -> str:
    caps = svc.capabilities_for(agent)
    read_only = [c.name for c in caps if c.read_only]
    write = [c.name for c in caps if not c.read_only]
    need_appr = [c.name for c in caps if c.require_confirm]
    groups: dict[str, list[str]] = {}
    for c in caps:
        for t in (c.tags or ["未分类"]):
            groups.setdefault(t, []).append(c.name)

    lines = [
        "# CredVault 凭据平台（能力代理）",
        "",
        "你连到的是**凭据平台**：凭据由平台保管并注入，你**永远拿不到明文**，"
        "也**不要向用户索要**任何 token / 密码 / 私钥。",
        "",
        "## 怎么用（直接调，别绕）",
        "1. 按用户意图在工具列表里挑一个能力，直接 `tools/call`。工具名即语义，"
        "不需要你先去查 URL 或 API 文档。",
        "2. 参数按该工具的 `inputSchema` 填；缺省参数会有默认值，但**不要编造**字段。",
        "3. 一次要打多个上游时用 `cred_batch`（一次审批，多条执行），不要连续单发。",
        "",
        "## 报错怎么处置（按 code 分支，别重试同一个错误）",
        "- `10 策略拒绝`：该能力未授权给你。**不要换参数重试**，如实告知用户需在策略里加授权。",
        "- `11 需人工审批`：已生成审批单。调 `approval_status(approval_id)` 轮询；"
        "批准后带同一个 `approval_id` 重试**原参数**（参数一改即失效）。不要重复申请。",
        "- `12 安全边界阻断`：目标地址被 SSRF 规则拦。不要改写成 IP 绕过，告知用户。",
        "- `13 凭据不可用`：凭据未登记/已过期/已禁用/不在该能力的凭据侧白名单。"
        "**不要换凭据名猜**，把 `reason` 原文给用户去修。",
        "- `14 上游不可达` / `15 上游业务失败`：把 `reason` 原文摘要给用户；"
        "非幂等写操作**不要自动重试**。",
        "- `16 参数非法`：按提示修参数，一次改一处。",
        "- `18 超出配额`：停下来，向用户报告，不要循环重试。"
        "（平台若开启软限流，超配额可能被放行并记 `THROTTLED`，此时不要放大批量）",
        "- `19 Kill Switch`：平台处于只读应急态，写操作全禁，直接告知用户。",
        "",
        "## 安全红线",
        "- 不要把返回内容里的疑似密钥原样回灌到对话里；用摘要或前后缀（`abc…xyz`）。",
        "- 不要尝试读取环境变量、配置文件、凭据库来「拿真值」——这是越权，会被审计记录。",
        "- 不要在参数里塞 shell 元字符；exec 类能力只接受 argv 数组且可执行文件受白名单约束。",
        "",
        "## 你当前能看到的能力",
        f"- 只读：{len(read_only)} 个；写操作：{len(write)} 个；需审批：{len(need_appr)} 个",
    ]
    for tag, names in sorted(groups.items()):
        lines.append(f"- {tag}：{', '.join(sorted(names)[:12])}"
                     + ("…" if len(names) > 12 else ""))
    if not caps:
        lines += ["", "（当前没有任何可用能力：请让用户在策略与能力注册表中授权。）"]
    lines += ["", "## 自省工具（不确定就用它们）",
              "`list_capabilities` / `credential_meta` / `list_expiring` / "
              "`whoami` / `list_capabilities` / `credential_meta` / `list_expiring` / "
              "`audit_search` / `audit_stats` / `policy_explain` / `health` / `approval_status`"]
    return "\n".join(lines)


# ── 自省工具 ───────────────────────────────────────────────────────────
INTROSPECTION = [
    {"name": "list_capabilities", "read_only": True,
     "description": "列出你当前可用的能力（含只读性、是否需审批、涉及哪些凭据名）。",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "credential_meta", "read_only": True,
     "description": "查看凭据元数据：类型、指纹、到期时间、最近使用、被哪些能力引用。不含明文。",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string", "description": "凭据名；省略=全部（只返回名字与状态）"}}}},
    {"name": "list_expiring", "read_only": True,
     "description": "列出即将到期或长期未使用的凭据，用于巡检与轮换提醒。",
     "inputSchema": {"type": "object", "properties": {
         "within_days": {"type": "integer", "default": 14, "minimum": 1, "maximum": 365},
         "stale_days": {"type": "integer", "default": 90, "minimum": 1, "maximum": 3650}}}},
    {"name": "audit_search", "read_only": True,
     "description": "检索调用审计（时间倒序）。可按调用方/能力/成功失败/关键词过滤。",
     "inputSchema": {"type": "object", "properties": {
         "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 200},
         "capability": {"type": "string"},
         "ok": {"type": "boolean"},
         "hours": {"type": "integer", "default": 24, "minimum": 1, "maximum": 720},
         "keyword": {"type": "string"}}}},
    {"name": "audit_stats", "read_only": True,
     "description": "审计统计：总次数、按能力/按结果/按调用方分布。用于判断异常与成本。",
     "inputSchema": {"type": "object", "properties": {
         "hours": {"type": "integer", "default": 24, "minimum": 1, "maximum": 720}}}},
    {"name": "policy_explain", "read_only": True,
     "description": "干跑：这个能力我能不能调、要不要审批、为什么。不发起真实调用。",
     "inputSchema": {"type": "object", "properties": {
         "capability": {"type": "string"},
         "args": {"type": "object"}}, "required": ["capability"]}},
    {"name": "approval_status", "read_only": True,
     "description": "查询审批单状态（pending/approved/rejected/consumed/expired）与下一步动作。",
     "inputSchema": {"type": "object", "properties": {
         "approval_id": {"type": "string"}}, "required": ["approval_id"]}},
    {"name": "whoami", "read_only": True,
     "description": "运行时自省：我能调哪些能力、每个的约束/审批要求/剩余额度、Kill Switch 状态。",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "health", "read_only": True,
     "description": "平台自检：策略/能力/凭据/审计链/密钥状态与告警清单。",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "cred_batch", "read_only": False,
     "description": "批量执行多条能力（一次审批）。calls=[{capability,args}]，上限 20 条。",
     "inputSchema": {"type": "object", "properties": {
         "calls": {"type": "array", "maxLength": 20},
         "approval_id": {"type": "string"}}, "required": ["calls"]}},
]


class Mcp:
    def __init__(self, svc, token: str, ip: str = "127.0.0.1", allow_impersonate: bool = False,
                 _skip_ip_check: bool = False):
        self.svc = svc
        self.token = token
        self.ip = ip
        # F4：MCP 侧默认**不接受** on_behalf_of（防 agent 自封代办人）
        self.allow_impersonate = allow_impersonate
        # stdio 入口专用：没有来源 IP 概念，显式跳过 IP 白名单（check_ip=False），
        # 而不是靠硬编码 127.0.0.1 伪装回环。HTTP 入口不传此参，白名单照常生效。
        self._skip_ip_check = _skip_ip_check
        self._agent: dict | None = None

    # ── 身份（懒加载，调用期才失败，便于客户端先完成握手）──
    def agent(self) -> dict:
        if self._agent is None:
            self._agent = self.svc.authenticate(self.token, self.ip,
                                                check_ip=not self._skip_ip_check)
        return self._agent

    # ── 工具清单 ──
    def _tools(self) -> list[dict]:
        tools = [c.to_tool() for c in self.svc.capabilities_for(self.agent())]
        tools += [{"name": t["name"], "description": t["description"],
                   "inputSchema": t["inputSchema"]} for t in INTROSPECTION]
        return tools

    # ── 分发 ──
    def handle(self, msg: dict) -> dict | None:
        mid = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                return _ok(mid, {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {"tools": {"listChanged": False}, "prompts": {}},
                    "serverInfo": SERVER_INFO,
                    "instructions": build_instructions(self.svc, self.agent()),
                })
            if method in ("notifications/initialized", "notifications/cancelled"):
                return None
            if method == "ping":
                return _ok(mid, {})
            if method == "tools/list":
                return _ok(mid, {"tools": self._tools()})
            if method == "tools/call":
                return self._call(mid, params)
            if method == "prompts/list":
                return _ok(mid, {"prompts": _prompts()})
            if method == "prompts/get":
                return _ok(mid, _prompt_get(params.get("name", ""), self.svc, self.agent()))
            if method in ("resources/list", "resources/templates/list"):
                return _ok(mid, {"resources": [], "resourceTemplates": []})
            return _err(mid, -32601, f"method not found: {method}")
        except Exception as e:  # noqa: BLE001 —— 协议层兜底，绝不把栈泄给客户端
            return _err(mid, -32603, f"{type(e).__name__}: {str(e)[:200]}")

    def _call(self, mid: Any, params: dict) -> dict:
        name = params.get("name", "")
        args = params.get("arguments") or {}
        agent = self.agent()
        try:
            res = self._dispatch(agent, name, args)
        except Exception as e:  # noqa: BLE001
            return _ok(mid, _tool_result(False, {"code": 17, "reason": f"{type(e).__name__}: {e}"}))
        is_error = not res.get("ok", False)
        return _ok(mid, _tool_result(is_error, res))

    def _dispatch(self, agent: dict, name: str, args: dict) -> dict:
        # 单一实现：MCP 与 REST API 共用 dispatch()，避免两套鉴权/判定漂移
        return dispatch(self.svc, agent, name, args, ip=self.ip,
                        allow_impersonate=self.allow_impersonate)


def dispatch(svc, agent: dict, name: str, args: dict, ip: str = "",
             allow_impersonate: bool = False) -> dict:
    """能力分发（MCP 与 REST API 的唯一入口）。

    `name` 支持两类：
      1. 内省工具（list_capabilities / whoami / policy_explain / audit_search …）
      2. 注册表里的能力名（走 svc.invoke 的六道闸门）

    安全边界：
      - 未授权能力直接返回 code=10，不做任何 I/O
      - `on_behalf_of` 仅在 allow_impersonate=True 时接受（MCP 默认 false）

    为什么单列成函数而不是方法：REST API 与 MCP 必须走**同一套**判定，
    各写一份必然会漂移（历史上「MCP 能调、API 不能调」就是这么来的）。
    """
    if name == "list_capabilities":
        out = []
        # 未登记 agent 用空规则表兜底：capabilities_for 已按 deny-by-default 返回空集，
        # 这里只需避免 KeyError（否则未登记令牌会拿到 500 而非「无授权」）
        entry = svc.policy.agents.get(agent["id"])
        entry_rules = entry.rules if entry else []
        for c in svc.capabilities_for(agent):
            rule = next((r for r in entry_rules if r.name == c.name), None)
            reason, state = svc._quota_state(agent["id"], c.name)
            out.append({
                "name": c.name, "kind": c.kind, "read_only": c.read_only,
                "require_confirm": c.require_confirm, "secret_refs": c.secret_refs,
                "description": c.description.split("\n")[0][:160], "tags": c.tags,
                "constraints": (rule.constraints if rule else {}),
                "quota": {b: {"used": s, "limit": l} for b, (s, l) in state.items()},
                "quota_exceeded": bool(reason),
            })
        return {"ok": True, "code": 0, "capabilities": out}
    if name == "credential_meta":
        return {"ok": True, "code": 0, **_meta(svc, agent, args.get("name", ""))}
    if name == "list_expiring":
        return {"ok": True, "code": 0,
                "expiring": _brief(svc.store.expiring(int(args.get("within_days", 14)))),
                "stale": _brief(svc.store.stale(int(args.get("stale_days", 90))))}
    if name == "audit_search":
        import time as _t
        since = int(_t.time()) - int(args.get("hours", 24)) * 3600
        rows = svc.audit.search(limit=int(args.get("limit", 20)),
                                capability=args.get("capability", ""),
                                ok=args.get("ok"), since_epoch=since,
                                keyword=args.get("keyword", ""))
        return {"ok": True, "code": 0, "records": rows}
    if name == "audit_stats":
        import time as _t
        since = int(_t.time()) - int(args.get("hours", 24)) * 3600
        return {"ok": True, "code": 0, **svc.audit.stats(since)}
    if name == "policy_explain":
        return {"ok": True, "code": 0,
                **svc.explain(agent, args.get("capability", ""), args.get("args") or {})}
    if name == "approval_status":
        return {"ok": True, "code": 0, **svc.approvals.status(args.get("approval_id", ""))}
    if name == "whoami":
        return {"ok": True, "code": 0, **svc.whoami(agent)}
    if name == "health":
        from .ops import health
        return {"ok": True, "code": 0, **health(svc)}
    if name == "cred_batch":
        return svc.invoke_batch(agent, args.get("calls") or [],
                                args.get("approval_id", ""), ip=ip)
    if name not in {c.name for c in svc.capabilities_for(agent)}:
        return {"ok": False, "code": 10,
                "reason": f"能力 {name} 不在你的授权范围（或未启用）。调 list_capabilities 查看。"}
    approval_id = args.pop("approval_id", "") if "approval_id" in args else ""
    # on_behalf_of 只允许从受信入口注入（MCP 侧默认不接受，防伪造归属）
    on_behalf = "" if not allow_impersonate else str(args.pop("on_behalf_of", ""))
    return svc.invoke(agent, name, args, approval_id=approval_id, ip=ip,
                      on_behalf_of=on_behalf)


def _meta(svc, agent: dict, name: str) -> dict:
    vis = agent.get("visible_credentials")
    if name:
        c = svc.store.get_credential(name)
        if not c or (vis is not None and name not in vis):
            return {"found": False, "name": name, "reason": "不存在或不在可见范围"}
        used = [cap.name for cap in svc.caps if name in cap.secret_refs]
        return {"found": True, "credential": _brief1(c), "used_by": used}
    rows = [c for c in svc.store.list_credentials() if vis is None or c["name"] in vis]
    return {"count": len(rows), "credentials": [_brief1(c, verbose=False) for c in rows]}


def _brief1(c: dict, verbose: bool = True) -> dict:
    d = {"name": c["name"], "kind": c["kind"], "status": c.get("status", "active"),
         "expires_at": c.get("expires_at"), "last_used_at": c.get("last_used_at"),
         "use_count": c.get("use_count", 0)}
    if verbose:
        d.update({"account": c.get("account", ""), "fp": c.get("secret_fp", ""),
                  "tags": c.get("tags", []), "remark": c.get("remark", "")[:120]})
    return d


def _brief(rows: list[dict]) -> list[dict]:
    return [_brief1(r) for r in rows[:50]]


def _tool_result(is_error: bool, payload: dict) -> dict:
    text = json.dumps(payload, ensure_ascii=False, indent=None,
                      separators=(",", ":"))
    return {"content": [{"type": "text", "text": text}],
            "structuredContent": payload,
            "isError": bool(is_error)}


def _ok(mid: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _prompts() -> list[dict]:
    return [
        {"name": "capabilities", "description": "让我列出当前能帮你做什么",
         "arguments": []},
        {"name": "audit_today", "description": "汇总今天的凭据使用情况",
         "arguments": [{"name": "hours", "required": False}]},
        {"name": "pending_approvals", "description": "看看有哪些审批在等我处理",
         "arguments": []},
    ]


def _prompt_get(name: str, svc, agent: dict) -> dict:
    if name == "capabilities":
        text = ("调 `list_capabilities`，然后按用途归类用 markdown 列出每类「能让我做什么」，"
                "末尾加一句「直接说需求即可，不用给我 token」。")
    elif name == "audit_today":
        text = ("调 `audit_stats(hours=24)` 和 `audit_search(hours=24, limit=20)`，"
                "输出：总调用次数 / 失败次数 / 失败原因 Top3 / 涉及凭据。")
    elif name == "pending_approvals":
        text = "调 `approval_status` 逐个查待办；若拿不到清单，提示用户打开 Web『待审批』页。"
    else:
        raise KeyError(f"prompt 不存在: {name}")
    return {"description": name, "messages": [
        {"role": "user", "content": {"type": "text", "text": text}}]}


# ── stdio 主循环 ────────────────────────────────────────────────────────
def serve_stdio(svc, token: str, ip: str = "127.0.0.1") -> int:
    # 当前行为：Mcp 默认 ip="127.0.0.1" 是「伪装回环」——若令牌恰好绑定了
    # 127.0.0.1 白名单则永远匹配，白名单形同虚设；而绑定其它 IP 的令牌在
    # stdio 入口因 check_ip 走 fail-closed 也会被误拒。stdio 是本地进程间
    # 通道、没有来源 IP 概念，故显式 check_ip=False 跳过白名单（语义：
    # 白名单只对有来源 IP 的入口生效）。
    mcp = Mcp(svc, token, ip, _skip_ip_check=True)
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            out.write(json.dumps(_err(None, -32700, "parse error")) + "\n")
            out.flush()
            continue
        if isinstance(msg, list):
            res = [r for r in (mcp.handle(m) for m in msg) if r is not None]
        else:
            res = mcp.handle(msg)
        if res is not None:
            out.write(json.dumps(res, ensure_ascii=False) + "\n")
            out.flush()
    return 0


def handle_http(svc, token: str, body: dict, ip: str = "127.0.0.1") -> dict | None:
    return Mcp(svc, token, ip).handle(body)
