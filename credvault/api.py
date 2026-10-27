"""api.py — 面向程序的 REST API（Bearer 令牌鉴权，v1）

## 为什么需要这个模块

v1.1.x 之前，`/api/*` 只有 **Web 会话 Cookie + CSRF** 一条鉴权路径：
人工点后台能用，外部脚本/CI/监控探针用不了。MCP 那条路（stdio + `/mcp`）
对 AI 客户端够用，但对「用 curl 或 Python requests 直接调」的场景不成立。

本模块补的就是这条：**同一套六道闸门、同一个 dispatch、只换入口与鉴权方式。**

## 鉴权（fail-closed）

```
Authorization: Bearer cbk_xxx
```

1. 令牌解析：sha256 比对 → 不存在 / 已吊销 / 已过期 → 401
2. IP 白名单：令牌声明的 pattern 不匹配来源 IP → 401
3. **scope 校验**：令牌 scope 必须是 `api` 或 `both`；`mcp` 令牌调 API → 403
   （这条是刻意加的：否则给 AI 的 MCP 令牌会顺带获得脚本调用权，扩权而不自知）
4. 能力授权：仍由 `gates` 六道闸门判定（与 MCP 完全同源）

## 路由表

| 方法 | 路径 | 作用 |
|---|---|---|
| GET  | `/api/v1/whoami` | 我是谁、能调什么、还剩多少额度 |
| GET  | `/api/v1/capabilities` | 能力清单（含约束与配额） |
| GET  | `/api/v1/credentials` | 凭据元数据（**永不返回值**） |
| POST | `/api/v1/invoke` | 调用能力 `{capability, args, approval_id}` |
| POST | `/api/v1/explain` | 干跑，不发起真实调用 |
| GET  | `/api/v1/approvals` | 我相关的审批单 |
| GET  | `/api/v1/audit` | 审计检索（只读） |
| GET  | `/api/v1/health` | 平台自检 |

## 安全边界

- **不提供**凭据值的读取接口。取明文只有 `lease pull`（带 TTL/撤销/一性）
- 错误码与 MCP 对齐（0/10–20），HTTP 状态只是传输层包装
- 所有调用进哈希链审计（actor=`api:<agent>`）
- 响应体同样过 32KB 预算与 `redact.shrink`
"""
from __future__ import annotations

import json
import os
import traceback

from . import mcp as mcp_mod
from . import ops

API_PREFIX = "/api/v1"

# 错误码 → HTTP 状态。传输层语义与业务语义分离：
# 即使业务失败也返回 200，让调用方读 `code` 做判断（与 MCP 的 isError 一致）
STATUS = {
    0: 200,
    10: 403,   # 策略拒绝
    11: 202,   # 待审批（不是错误，是「已受理待确认」）
    12: 403,   # 安全拦截
    13: 404,   # 凭据不可用
    14: 502,   # 上游网络
    15: 200,   # 业务失败（上游回包但业务码失败）
    16: 400,   # 参数非法
    17: 500,   # 内部错误
    18: 429,   # 配额
    19: 503,   # Kill Switch
    20: 200,   # 软限流放行
}


def _qv(query: dict, key: str, default=None):
    """取 query 参数的第一值。

    `urllib.parse.parse_qs` 返回的是 {key: [value, ...]}，**每个值都是列表**。
    直接 `int(query.get("hours"))` 会抛 TypeError（实测踩到：
    `/api/v1/audit?hours=1` 因此 500，被误解成「0 条记录」）。
    """
    if key not in query:
        return default
    v = query[key]
    if isinstance(v, (list, tuple)):
        return v[0] if v else default
    return v


def _qint(query: dict, key: str, default: int) -> int:
    try:
        return int(_qv(query, key, default))
    except (TypeError, ValueError):
        return default


def _qstr(query: dict, key: str, default: str = "") -> str:
    v = _qv(query, key, default)
    return default if v is None else str(v)


def _unauth(reason: str) -> tuple[int, dict]:
    return 401, {"ok": False, "code": 4010, "reason": reason,
                 "next_action": "检查 Authorization: Bearer <token>；令牌需 scope=api 或 both"}


def _forbidden(reason: str) -> tuple[int, dict]:
    return 403, {"ok": False, "code": 4011, "reason": reason,
                 "next_action": "用 `credvault token add <name> --scope api` 重新签发"}


def authenticate(svc, token: str, ip: str, need_scope: str = "api") -> tuple[dict | None, tuple[int, dict] | None]:
    """令牌鉴权 + scope 校验。返回 (agent, None) 或 (None, (status, body))。"""
    if not token:
        return None, _unauth("缺少 Bearer Token")
    try:
        agent = svc.authenticate(token, ip)
    except Exception as e:  # noqa: BLE001 —— 一律 fail-closed，不区分「不存在」与「已吊销」
        # 默认只回错误类型（不把内部细节泄给外部调用方）；开 CREDVAULT_DEBUG 时
        # 把完整堆栈打到 stderr，否则这类 AttributeError 会被静默吞掉，极难定位。
        if os.environ.get("CREDVAULT_DEBUG"):
            traceback.print_exc()
        return None, _unauth(f"令牌无效：{type(e).__name__}")
    scope = agent.get("scope") or "mcp"
    if scope not in (need_scope, "both"):
        return None, _forbidden(
            f"该令牌 scope={scope}，不能调用 {need_scope} 入口")
    return agent, None


def handle(svc, method: str, path: str, query: dict, body: dict,
           token: str, ip: str = "") -> tuple[int, dict]:
    """REST 入口（唯一分发点）。返回 (http_status, payload)。

    `path` 需已剥掉 `/api/v1` 前缀，例如 `/invoke`。
    """
    agent, err = authenticate(svc, token, ip, "api")
    if err:
        return err

    # 审计：鉴权失败也不留白，但这里只记成功的入口调用
    actor = f"api:{agent['id']}"

    if method == "GET" and path == "/whoami":
        return 200, {"ok": True, "code": 0, **svc.whoami(agent), "via": "api"}
    if method == "GET" and path == "/capabilities":
        r = mcp_mod.dispatch(svc, agent, "list_capabilities", {}, ip=ip)
        return STATUS.get(r.get("code", 0), 200), r
    if method == "GET" and path == "/credentials":
        r = mcp_mod.dispatch(svc, agent, "credential_meta", {}, ip=ip)
        return STATUS.get(r.get("code", 0), 200), r
    if method == "GET" and path == "/approvals":
        # 只返回该 agent 自己相关的单，不泄露别人的待办
        r = mcp_mod.dispatch(svc, agent, "approval_status",
                             {"approval_id": query.get("id", "")}, ip=ip)
        return STATUS.get(r.get("code", 0), 200), r
    if method == "GET" and path == "/audit":
        args = {"hours": _qint(query, "hours", 24),
                "limit": _qint(query, "limit", 50),
                "capability": _qstr(query, "capability"),
                "keyword": _qstr(query, "keyword")}
        r = mcp_mod.dispatch(svc, agent, "audit_search", args, ip=ip)
        return STATUS.get(r.get("code", 0), 200), r
    if method == "GET" and path == "/health":
        return 200, {"ok": True, "code": 0, **ops.health(svc)}

    if method == "POST" and path == "/invoke":
        cap = str(body.get("capability") or "").strip()
        if not cap:
            return 400, {"ok": False, "code": 16, "reason": "缺少 capability",
                         "next_action": "GET /api/v1/capabilities 查看可用能力名"}
        args = body.get("args") or {}
        if not isinstance(args, dict):
            return 400, {"ok": False, "code": 16, "reason": "args 必须是对象"}
        if body.get("approval_id"):
            args = {**args, "approval_id": str(body["approval_id"])}
        r = mcp_mod.dispatch(svc, agent, cap, dict(args), ip=ip)
        st = STATUS.get(r.get("code", 0), 200)
        r = {**r, "via": "api", "actor": actor}
        return st, r

    if method == "POST" and path == "/explain":
        cap = str(body.get("capability") or "").strip()
        if not cap:
            return 400, {"ok": False, "code": 16, "reason": "缺少 capability"}
        r = mcp_mod.dispatch(svc, agent, "policy_explain",
                             {"capability": cap, "args": body.get("args") or {}}, ip=ip)
        return STATUS.get(r.get("code", 0), 200), r

    return 404, {"ok": False, "code": 4040,
                 "reason": f"未知端点 {method} {API_PREFIX}{path}",
                 "next_action": "支持：GET whoami|capabilities|credentials|approvals|audit|health；"
                                "POST invoke|explain"}


def openapi(svc=None) -> dict:
    """机器可读的接口描述（给外部集成方看，不含任何凭据信息）。"""
    return {
        "openapi": "3.1.0",
        "info": {"title": "CredVault API", "version": ops.VERSION,
                 "description": "AI 主用凭据平台的程序化入口。鉴权：Authorization: Bearer <cbk_ token>，"
                                "令牌 scope 必须是 api 或 both。"},
        "servers": [{"url": API_PREFIX}],
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "security": [{"bearer": []}],
        "paths": {
            "/whoami": {"get": {"summary": "我是谁、能调什么、剩余额度",
                                "responses": {"200": {"description": "OK"}}}},
            "/capabilities": {"get": {"summary": "能力清单（含约束与配额）",
                                      "responses": {"200": {"description": "OK"}}}},
            "/credentials": {"get": {"summary": "凭据元数据（永不返回值）",
                                     "responses": {"200": {"description": "OK"}}}},
            "/approvals": {"get": {"summary": "查询审批单",
                                   "parameters": [{"name": "id", "in": "query",
                                                   "schema": {"type": "string"}}],
                                   "responses": {"200": {"description": "OK"}}}},
            "/audit": {"get": {"summary": "审计检索",
                               "parameters": [
                                   {"name": "hours", "in": "query", "schema": {"type": "integer"}},
                                   {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                                   {"name": "capability", "in": "query", "schema": {"type": "string"}},
                                   {"name": "keyword", "in": "query", "schema": {"type": "string"}}],
                               "responses": {"200": {"description": "OK"}}}},
            "/health": {"get": {"summary": "平台自检", "responses": {"200": {"description": "OK"}}}},
            "/invoke": {"post": {"summary": "调用能力",
                                 "requestBody": {"required": True, "content": {"application/json": {
                                     "schema": {"type": "object",
                                                "required": ["capability"],
                                                "properties": {
                                                    "capability": {"type": "string"},
                                                    "args": {"type": "object"},
                                                    "approval_id": {"type": "string"}}}}}},
                                 "responses": {**{str(v): {"description": k}
                                                  for k, v in {**STATUS}.items()},
                                               "202": {"description": "需审批，poll /approvals"}}}},
            "/explain": {"post": {"summary": "干跑：能不能调、要不要审批、为什么",
                                  "responses": {"200": {"description": "OK"}}}},
        },
    }
