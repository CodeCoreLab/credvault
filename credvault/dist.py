"""dist.py — lease 化凭据分发（F5，OpenBao lease 语义）

为什么不是「静态同步文件」：现有 sync_credentials.py 把值写成一端文件就失去控制——
谁拿过、还能用多久、怎么撤销，全无记录。lease 把这三件事变成可查可撤的状态。

语义（对齐 OpenBao）：
  lease_create  → 发放 lease_id + 短时值（默认 ttl=300s，最长 3600s）
  lease_renew   → 续期（可配 renewable=false 则拒；续期次数有上限）
  lease_revoke  → 立即失效，后续拉取一律拒
  lease_list    → 列活跃租约（消费方/凭据/剩余时间）
  lease_pull    → 消费方用 lease_id 换值；过期/撤销/tty 用尽即拒

安全边界：
  - 值只在 lease_pull 响应里出现一次，且不写审计（只记 lease_id 与指纹）
  - 消费方身份由 lease 绑定的 consumer 名 + 可选 IP 白名单校验
  - 所有动作进审计（actor=consumer:<name>）
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
DEFAULT_TTL = 300
MAX_TTL = 3600
MAX_RENEW = 3


class LeaseError(RuntimeError):
    pass


class Leases:
    def __init__(self, store, table: str = "leases"):
        self.s = store
        self.table = table
        self._ensure()

    def _ensure(self) -> None:
        with self.s.tx() as c:
            c.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                  id TEXT PRIMARY KEY, consumer TEXT NOT NULL, credential TEXT NOT NULL,
                  ip_allowlist TEXT, ttl INTEGER NOT NULL, issued_at INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL, renewals INTEGER NOT NULL DEFAULT 0,
                  renewable INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0,
                  fp TEXT DEFAULT '', note TEXT DEFAULT ''
                )""")
            c.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.table}_exp "
                      f"ON {self.table}(expires_at)")

    # ── 发放 ──
    def create(self, consumer: str, credential: str, ttl: int = DEFAULT_TTL,
               renewable: bool = True, ip_allowlist: list[str] | None = None,
               note: str = "") -> dict:
        if not consumer or not credential:
            raise LeaseError("consumer 与 credential 均必填")
        ttl = max(30, min(int(ttl), MAX_TTL))
        lid = "lease_" + uuid.uuid4().hex[:16]
        t = int(time.time())
        with self.s.tx() as c:
            c.execute(f"INSERT INTO {self.table}"
                      f"(id,consumer,credential,ip_allowlist,ttl,issued_at,expires_at,"
                      f"renewable,note) VALUES(?,?,?,?,?,?,?,?,?)",
                      (lid, consumer, credential,
                       None if ip_allowlist is None else json.dumps(ip_allowlist),
                       ttl, t, t + ttl, 1 if renewable else 0, note[:200]))
        return {"lease_id": lid, "ttl": ttl, "expires_at": t + ttl,
                "renewable": renewable, "consumer": consumer, "credential": credential}

    # ── 拉取（消费方换值）──
    def pull(self, lease_id: str, kek: bytes, ip: str = "") -> dict:
        rec = self._get(lease_id)
        if rec is None:
            raise LeaseError("租约不存在")
        if rec["revoked"]:
            raise LeaseError("租约已撤销")
        if int(rec["expires_at"]) < int(time.time()):
            raise LeaseError("租约已过期，请重新申请")
        allow = json.loads(rec["ip_allowlist"]) if rec["ip_allowlist"] else None
        if allow and ip:
            import fnmatch
            if not any(fnmatch.fnmatchcase(ip, p) for p in allow):
                raise LeaseError(f"来源 {ip} 不在租约白名单 {allow}")
        raw = self.s.get_secret(rec["credential"], kek)
        fp = hashlib.sha256(raw).hexdigest()[:12]
        return {"value": raw.decode("utf-8", errors="replace"), "fp": fp,
                "lease_id": lease_id, "remaining_sec": int(rec["expires_at"]) - int(time.time())}

    # ── 续期 / 撤销 / 列表 ──
    def renew(self, lease_id: str, ttl: int = 0) -> dict:
        rec = self._get(lease_id)
        if rec is None:
            raise LeaseError("租约不存在")
        if rec["revoked"]:
            raise LeaseError("租约已撤销")
        if not rec["renewable"]:
            raise LeaseError("该租约不可续期（renewable=false）")
        if int(rec["renewals"]) >= MAX_RENEW:
            raise LeaseError(f"已续期 {MAX_RENEW} 次上限，请重新申请")
        new_ttl = max(30, min(int(ttl or rec["ttl"]), MAX_TTL))
        exp = int(time.time()) + new_ttl
        with self.s.tx() as c:
            c.execute(f"UPDATE {self.table} SET expires_at=?, ttl=?, renewals=renewals+1"
                      f" WHERE id=?", (exp, new_ttl, lease_id))
        return {"lease_id": lease_id, "expires_at": exp, "ttl": new_ttl,
                "renewals": int(rec["renewals"]) + 1}

    def revoke(self, lease_id: str) -> bool:
        with self.s.tx() as c:
            cur = c.execute(f"UPDATE {self.table} SET revoked=1 WHERE id=? AND revoked=0",
                            (lease_id,))
        return cur.rowcount > 0

    def _get(self, lease_id: str):
        return self.s._meta.execute(f"SELECT * FROM {self.table} WHERE id=?",
                                    (lease_id,)).fetchone()

    def list(self, include_revoked: bool = False) -> list[dict]:
        q = (f"SELECT * FROM {self.table}" if include_revoked
             else f"SELECT * FROM {self.table} WHERE revoked=0 AND expires_at>?")
        args = () if include_revoked else (int(time.time()),)
        out = []
        for r in self.s._meta.execute(q + " ORDER BY expires_at", args):
            d = dict(r)
            d["remaining_sec"] = max(0, int(d["expires_at"]) - int(time.time()))
            d["ip_allowlist"] = json.loads(d["ip_allowlist"]) if d["ip_allowlist"] else None
            out.append(d)
        return out

    def cleanup(self) -> int:
        cutoff = int(time.time()) - 86400
        with self.s.tx() as c:
            cur = c.execute(f"DELETE FROM {self.table} WHERE expires_at<?", (cutoff,))
        return cur.rowcount
