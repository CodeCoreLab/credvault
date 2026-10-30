"""tokens.py — 机器身份（双轴授权 + IP 白名单 + TTL/轮换/吊销）

双轴（照抄 Sigil 的 mcp_tokens，并补上吊销/过期）：
  visible_credentials  —— 连「能看见哪些凭据名」都要受限
  allowed_capabilities —— 能调哪些能力（None = 由 policy 决定）
外加 ip_allowlist，防令牌被带走后异地使用。

令牌明文只在创建/轮换时打印一次，落库只存 sha256。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from pathlib import Path

from .store import Store, now

PREFIX = "cbk_"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenError(RuntimeError):
    pass


class Tokens:
    def __init__(self, store: Store):
        self.s = store

    # ── 创建 ──
    SCOPES = ("mcp", "api", "both")

    def create(self, name: str, ttl_days: int = 0,
               visible_credentials: list[str] | None = None,
               allowed_capabilities: list[str] | None = None,
               ip_allowlist: list[str] | None = None,
               scope: str = "mcp") -> tuple[str, dict]:
        """签发令牌。scope 决定这把令牌能走哪条入口：

        - `mcp`（默认）：只走 MCP（stdio / HTTP /mcp）——保持 v1.1.x 行为
        - `api`        ：只走 REST API（/api/v1/*）
        - `both`       ：两条都走

        默认 `mcp` 而非 `both`：升级不扩权，已有令牌不会被顺带放大权限。
        """
        if scope not in self.SCOPES:
            raise TokenError(f"scope 必须是 {self.SCOPES} 之一，收到 {scope!r}")
        if self.s._meta.execute("SELECT 1 FROM agents WHERE name=?", (name,)).fetchone():
            raise TokenError(f"agent {name} 已存在（改名或用 rotate）")
        token = PREFIX + secrets.token_urlsafe(32)
        exp = now() + ttl_days * 86400 if ttl_days else None
        with self.s.tx() as c:
            c.execute(
                "INSERT INTO agents(id,name,token_hash,visible_credentials,allowed_capabilities,"
                "ip_allowlist,ttl_days,expires_at,revoked,created_at,scope)"
                " VALUES(?,?,?,?,?,?,?,?,0,?,?)",
                (uuid.uuid4().hex[:12], name, _hash(token),
                 None if visible_credentials is None else json.dumps(visible_credentials),
                 None if allowed_capabilities is None else json.dumps(allowed_capabilities),
                 None if ip_allowlist is None else json.dumps(ip_allowlist),
                 ttl_days, exp, now(), scope))
        return token, self.get(name) or {}

    # ── 解析（fail-closed）──
    def resolve(self, token: str, ip: str = "", check_ip: bool = True) -> dict | None:
        """解析令牌（成功返回 agent，失败返回 None）。

        `check_ip=False` 表示**显式跳过 IP 白名单校验**，只给「没有来源 IP 概念」
        的本地进程场景用（stdio MCP / 本地 CLI）。这类场景过去靠硬编码
        "127.0.0.1" 伪装成回环 —— 那样白名单形同虚设（配了 127.0.0.1 也永远匹配成功），
        改成显式跳过才符合「白名单只对有来源 IP 的入口生效」的语义。
        """
        agent, _reason, _name = self.resolve_ex(token, ip, check_ip=check_ip)
        return agent

    def resolve_ex(self, token: str, ip: str = "", check_ip: bool = True
                   ) -> tuple[dict | None, str, str]:
        """带失败原因的解析：返回 (agent|None, reason, agent_name)。

        当前行为：`resolve()` 对「令牌不存在 / 已吊销 / 已过期 / IP 不在白名单」
        四条失败路径一律 `return None`，调用方无从区分是哪一种 —— 于是鉴权失败
        既无法落审计，也没法告诉调用方到底是哪一步被拒。

        reason 取值：
          ""          成功
          "missing"   未提供令牌
          "not_found" 令牌不存在（哈希不匹配）
          "revoked"   已吊销
          "expired"   已过期
          "ip_denied" 来源 IP 不在白名单（含「IP 为空」的情形）
          "db_error"  令牌库读取异常
        agent_name：能定位到 agents 行时的令牌名（失败时也可能非空，便于审计定位）。
        """
        if not token:
            return None, "missing", ""
        tok = token.strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        try:
            r = self.s._meta.execute("SELECT * FROM agents WHERE token_hash=?",
                                     (_hash(tok),)).fetchone()
        except Exception:  # noqa: BLE001 —— 令牌库损坏不等于"无令牌"，但对外一律 fail-closed
            return None, "db_error", ""
        if not r:
            return None, "not_found", ""
        row = dict(r)
        name = str(row.get("name") or "")
        if row["revoked"]:
            return None, "revoked", name
        if row["expires_at"] and int(row["expires_at"]) < now():
            return None, "expired", name
        allow = json.loads(row["ip_allowlist"]) if row["ip_allowlist"] else None
        if allow and check_ip:
            import fnmatch
            # 当前行为：条件是 `if allow and ip` —— ip 为空时整段白名单检查被跳过，
            # 于是「没拿到来源 IP」等于「白名单不生效」，fail-closed 变成 fail-open。
            # 改为：只要配了白名单，ip 为空即视为不匹配任何 pattern → 拒绝。
            if not ip or not any(fnmatch.fnmatchcase(ip, p) for p in allow):
                return None, "ip_denied", name
        with self.s.tx() as c:
            c.execute("UPDATE agents SET last_used_at=? WHERE id=?", (now(), row["id"]))
        return self._shape(row), "", name

    def _shape(self, row: dict) -> dict:
        # sqlite3.Row 支持 keys() 但不支持 get()，故统一用 keys() 探测
        r = row
        keys = r.keys() if hasattr(r, "keys") else r
        return {
            "id": r["name"], "name": r["name"],
            "scope": r["scope"] if "scope" in keys else "mcp",
            "visible_credentials": (json.loads(r["visible_credentials"])
                                    if r["visible_credentials"] else None),
            "allowed_capabilities": (json.loads(r["allowed_capabilities"])
                                     if r["allowed_capabilities"] else None),
            "ip_allowlist": json.loads(r["ip_allowlist"]) if r["ip_allowlist"] else None,
            "expires_at": r["expires_at"], "revoked": bool(r["revoked"]),
            "ttl_days": r["ttl_days"], "created_at": r["created_at"],
            "last_used_at": r["last_used_at"],
        }

    def get(self, name: str) -> dict | None:
        r = self.s._meta.execute("SELECT * FROM agents WHERE name=?", (name,)).fetchone()
        return self._shape(dict(r)) if r else None

    def list(self) -> list[dict]:
        return [self._shape(dict(r)) for r in
                self.s._meta.execute("SELECT * FROM agents ORDER BY created_at DESC")]

    # ── 生命周期 ──
    # 可更新字段 → 列名 的**固定白名单**。
    # 当前行为：update_scopes 用 f-string 拼 UPDATE 语句（`,'.join(sets)`）。
    # 今天的 sets 元素来自固定分支字面量，注入不了；但模式本身危险 ——
    # 任何人日后加一个「列名来自入参」的分支就变成真注入。
    # 改为：列名一律从本白名单查表得到，用户可控的值只进参数位。
    FIELD_MAP = {
        "scope": "scope",
        "visible_credentials": "visible_credentials",
        "allowed_capabilities": "allowed_capabilities",
        "ip_allowlist": "ip_allowlist",
    }

    def revoke(self, name: str) -> bool:
        with self.s.tx() as c:
            cur = c.execute("UPDATE agents SET revoked=1 WHERE name=? AND revoked=0", (name,))
        return cur.rowcount > 0

    def rotate(self, name: str, ttl_days: int = -1) -> str:
        r = self.s._meta.execute("SELECT * FROM agents WHERE name=?", (name,)).fetchone()
        if not r:
            raise TokenError(f"agent {name} 不存在")
        token = PREFIX + secrets.token_urlsafe(32)
        days = r["ttl_days"] if ttl_days < 0 else ttl_days
        exp = now() + days * 86400 if days else None
        with self.s.tx() as c:
            c.execute("UPDATE agents SET token_hash=?, revoked=0, ttl_days=?, expires_at=?"
                      " WHERE name=?", (_hash(token), days, exp, name))
        return token

    def update_scopes(self, name: str, visible_credentials: list[str] | None = None,
                      allowed_capabilities: list[str] | None = None,
                      ip_allowlist: list[str] | None = None,
                      scope: str | None = None) -> bool:
        """更新令牌的双轴授权与 scope。

        当前行为：用 f-string 拼 SQL（`f"UPDATE agents SET {','.join(sets)} ..."`）。
        列名来源虽已是固定字面量，但拼接模式本身是注入的温床 ——
        改为：列名一律走 FIELD_MAP 白名单查表，值只进参数位（?占位符）。
        行为保持不变。
        """
        sets, args = [], []
        if scope is not None:
            if scope not in self.SCOPES:
                raise TokenError(f"scope 必须是 {self.SCOPES} 之一，收到 {scope!r}")
            sets.append(f"{self.FIELD_MAP['scope']}=?")
            args.append(scope)
        if visible_credentials is not None:
            sets.append(f"{self.FIELD_MAP['visible_credentials']}=?")
            args.append(json.dumps(visible_credentials))
        if allowed_capabilities is not None:
            sets.append(f"{self.FIELD_MAP['allowed_capabilities']}=?")
            args.append(json.dumps(allowed_capabilities))
        if ip_allowlist is not None:
            sets.append(f"{self.FIELD_MAP['ip_allowlist']}=?")
            args.append(json.dumps(ip_allowlist))
        if not sets:
            return False
        args.append(name)
        with self.s.tx() as c:
            cur = c.execute(f"UPDATE agents SET {','.join(sets)} WHERE name=?", args)
        return cur.rowcount > 0

    # ── 兼容：从旧 cred_broker agents.json 导入 ──
    def import_legacy(self, path: Path) -> tuple[int, int]:
        """旧库只存 token 的 sha256，无明文 —— 只能导入「名字 + 哈希」，
        令牌本身需在客户端继续沿用旧值（哈希一致即可通过校验）。"""
        p = Path(path)
        if not p.is_file():
            return (0, 0)
        raw = json.loads(p.read_text(encoding="utf-8"))
        ok = skip = 0
        for name, rec in (raw.items() if isinstance(raw, dict) else []):
            h = rec.get("hash") or rec.get("sha256") or ""
            if not h:
                skip += 1
                continue
            if self.s._meta.execute("SELECT 1 FROM agents WHERE name=?", (name,)).fetchone():
                skip += 1
                continue
            with self.s.tx() as c:
                c.execute(
                    "INSERT INTO agents(id,name,token_hash,ttl_days,revoked,created_at)"
                    " VALUES(?,?,?,0,0,?)", (uuid.uuid4().hex[:12], name, h, now()))
            ok += 1
        return ok, skip
