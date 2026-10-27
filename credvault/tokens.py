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
    def resolve(self, token: str, ip: str = "") -> dict | None:
        if not token:
            return None
        tok = token.strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        try:
            r = self.s._meta.execute("SELECT * FROM agents WHERE token_hash=?",
                                     (_hash(tok),)).fetchone()
        except Exception:  # noqa: BLE001 —— 令牌库损坏不等于"无令牌"，但对外一律 fail-closed
            return None
        if not r:
            return None
        row = dict(r)
        if row["revoked"]:
            return None
        if row["expires_at"] and int(row["expires_at"]) < now():
            return None
        allow = json.loads(row["ip_allowlist"]) if row["ip_allowlist"] else None
        if allow and ip:
            import fnmatch
            if not any(fnmatch.fnmatchcase(ip, p) for p in allow):
                return None
        with self.s.tx() as c:
            c.execute("UPDATE agents SET last_used_at=? WHERE id=?", (now(), row["id"]))
        return self._shape(row)

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
        sets, args = [], []
        if scope is not None:
            if scope not in self.SCOPES:
                raise TokenError(f"scope 必须是 {self.SCOPES} 之一，收到 {scope!r}")
            sets.append("scope=?"); args.append(scope)
        if visible_credentials is not None:
            sets.append("visible_credentials=?"); args.append(json.dumps(visible_credentials))
        if allowed_capabilities is not None:
            sets.append("allowed_capabilities=?"); args.append(json.dumps(allowed_capabilities))
        if ip_allowlist is not None:
            sets.append("ip_allowlist=?"); args.append(json.dumps(ip_allowlist))
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
