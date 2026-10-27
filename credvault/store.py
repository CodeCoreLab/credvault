"""store.py — 元数据库与密文库**分离**（I8/I9 的落地）

   state/credvault.db   元数据：凭据名/类型/标签/到期/指纹、能力、令牌、审批、配额、用户
   state/secrets.db     密文：wrapped_dek / nonce / ciphertext（只有它能解密出明文）

分离的意义：拖走元数据库拿不到任何密文；拖走密文库没有 KEK 也只能拿到 DEK 包裹体。
（对比 Sigil 2.4：value_encrypted 与元数据同表；对比 cred_broker：密文与元数据同在 env 文件里）
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import crypto

META_DDL = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL DEFAULT 'generic',
  account TEXT DEFAULT '', remark TEXT DEFAULT '', tags TEXT DEFAULT '[]',
  allowed_capabilities TEXT, expires_at INTEGER, created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL, last_used_at INTEGER, use_count INTEGER NOT NULL DEFAULT 0,
  secret_fp TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS capabilities (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '', input_schema TEXT NOT NULL DEFAULT '{}',
  config TEXT NOT NULL DEFAULT '{}', secret_refs TEXT DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1, read_only INTEGER NOT NULL DEFAULT 1,
  require_confirm INTEGER NOT NULL DEFAULT 0, source TEXT DEFAULT '',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
  visible_credentials TEXT, allowed_capabilities TEXT, ip_allowlist TEXT,
  ttl_days INTEGER NOT NULL DEFAULT 0, expires_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, last_used_at INTEGER,
  scope TEXT NOT NULL DEFAULT 'mcp'
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, capability TEXT NOT NULL, args_fp TEXT NOT NULL,
  args_preview TEXT DEFAULT '', reason TEXT DEFAULT '', requested_by TEXT DEFAULT '',
  state TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, decided_by TEXT DEFAULT '', decided_at INTEGER,
  decision_reason TEXT DEFAULT '', consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS exemptions (
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, capability TEXT NOT NULL,
  expires_at INTEGER NOT NULL, created_by TEXT DEFAULT '', created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, pwd_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'approver', created_at INTEGER NOT NULL, last_login INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, csrf TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS quota (
  agent_id TEXT NOT NULL, capability TEXT NOT NULL, bucket TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0, window_start INTEGER NOT NULL,
  PRIMARY KEY (agent_id, capability, bucket)
);
CREATE TABLE IF NOT EXISTS rotations (
  id TEXT PRIMARY KEY, credential TEXT NOT NULL, old_fp TEXT DEFAULT '',
  new_fp TEXT DEFAULT '', state TEXT NOT NULL, note TEXT DEFAULT '',
  actor TEXT DEFAULT '', created_at INTEGER NOT NULL, finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cred_exp ON credentials(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_lookup ON approvals(state, created_at DESC);
"""

SECRETS_DDL = """
CREATE TABLE IF NOT EXISTS vault (
  name TEXT PRIMARY KEY, wrapped_dek BLOB NOT NULL, dek_nonce BLOB NOT NULL,
  data_nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, kek_version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_history (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, wrapped_dek BLOB NOT NULL,
  dek_nonce BLOB NOT NULL, data_nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  kek_version INTEGER NOT NULL, created_at INTEGER NOT NULL, reason TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hist_name ON vault_history(name, created_at DESC);
"""

SCHEMA_VERSION = 1


def now() -> int:
    return int(time.time())


def uid(n: int = 12) -> str:
    return uuid.uuid4().hex[:n]


class _LockedConn:
    """串行化 sqlite 连接：跨线程共享时，execute/commit 必须互斥。

    实测（16 线程抢同一审批单核销）：裸共享连接会抛
    `sqlite3.InterfaceError: bad parameter or other API misuse` —— 一个线程
    在 cursor 迭代时另一线程 commit。sqlite3 的 serialized 模式只保证单次
    调用原子，不保证「execute + commit」这个复合操作的原子。
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock):
        self._c = conn
        self._lock = lock

    def execute(self, *a, **kw):
        with self._lock:
            return self._c.execute(*a, **kw)

    def executescript(self, *a, **kw):
        with self._lock:
            return self._c.executescript(*a, **kw)

    def commit(self):
        with self._lock:
            self._c.commit()

    def rollback(self):
        with self._lock:
            self._c.rollback()

    def close(self):
        with self._lock:
            self._c.close()

    def __setattr__(self, name, value):
        # row_factory / isolation_level 等配置必须落到真连接，
        # 否则会静默存在代理对象上（实测导致 row 退化为 tuple）。
        if name in ("_c", "_lock"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._c, name, value)

    def __getattr__(self, name):
        return getattr(self._c, name)


class Store:
    def __init__(self, meta_path: Path, secrets_path: Path):
        self.meta_path = Path(meta_path)
        self.secrets_path = Path(secrets_path)
        for p in (self.meta_path, self.secrets_path):
            p.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        raw_meta = sqlite3.connect(str(self.meta_path), check_same_thread=False)
        raw_sec = sqlite3.connect(str(self.secrets_path), check_same_thread=False)
        self._meta = _LockedConn(raw_meta, self._lock)
        self._sec = _LockedConn(raw_sec, self._lock)
        for c in (self._meta, self._sec):
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
        self._meta.executescript(META_DDL)
        self._migrate()
        self._sec.executescript(SECRETS_DDL)
        self._meta.commit()
        self._sec.commit()
        self._meta.execute(
            "INSERT OR IGNORE INTO meta(k,v) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
        self._meta.commit()
        for p in (self.meta_path, self.secrets_path):
            crypto.harden(p)

    # ── 通用 ──
    @contextmanager
    def tx(self, secrets: bool = False) -> Iterator[sqlite3.Connection]:
        c = self._sec if secrets else self._meta
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise

    def _migrate(self) -> None:
        """存量库结构升级（幂等）。新增列一律给默认值，保证老库行为不变。

        当前迁移项：
          - agents.scope（v1.2.0 引入）：'mcp' | 'api' | 'both'
            老库补成 'mcp' —— 即「升级不扩权」，原有令牌不会被顺带获得 API 能力。
        """
        cols = {r["name"] for r in self._meta.execute("PRAGMA table_info(agents)")}
        if "scope" not in cols:
            with self.tx() as c:
                c.execute("ALTER TABLE agents ADD COLUMN scope TEXT NOT NULL DEFAULT 'mcp'")

    def close(self) -> None:
        for c in (self._meta, self._sec):
            try:
                c.close()
            except sqlite3.Error:
                pass

    def meta_get(self, k: str, default: str = "") -> str:
        r = self._meta.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default

    def meta_set(self, k: str, v: str) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

    # ── 密文库 ──
    def put_secret(self, name: str, plaintext: bytes, kek: bytes, keep_history: bool = False,
                   reason: str = "") -> str:
        s = crypto.seal(plaintext, kek)
        if keep_history:
            old = self._sec.execute("SELECT * FROM vault WHERE name=?", (name,)).fetchone()
            if old:
                with self.tx(secrets=True) as c:
                    c.execute(
                        "INSERT INTO vault_history(id,name,wrapped_dek,dek_nonce,data_nonce,"
                        "ciphertext,kek_version,created_at,reason) VALUES(?,?,?,?,?,?,?,?,?)",
                        (uid(), name, old["wrapped_dek"], old["dek_nonce"], old["data_nonce"],
                         old["ciphertext"], old["kek_version"], now(), reason))
        with self.tx(secrets=True) as c:
            c.execute(
                "INSERT INTO vault(name,wrapped_dek,dek_nonce,data_nonce,ciphertext,kek_version,updated_at)"
                " VALUES(?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                "wrapped_dek=excluded.wrapped_dek, dek_nonce=excluded.dek_nonce,"
                " data_nonce=excluded.data_nonce, ciphertext=excluded.ciphertext,"
                " kek_version=excluded.kek_version, updated_at=excluded.updated_at",
                (name, s.wrapped_dek, s.dek_nonce, s.data_nonce, s.ciphertext, s.kek_version, now()))
        return crypto.fingerprint(plaintext)

    def _row_to_sealed(self, r: sqlite3.Row) -> crypto.Sealed:
        return crypto.Sealed(r["wrapped_dek"], r["dek_nonce"], r["data_nonce"],
                             r["ciphertext"], r["kek_version"])

    def get_secret(self, name: str, kek: bytes) -> bytes:
        r = self._sec.execute("SELECT * FROM vault WHERE name=?", (name,)).fetchone()
        if not r:
            raise KeyError(name)
        return crypto.unseal(self._row_to_sealed(r), kek)

    def has_secret(self, name: str) -> bool:
        return self._sec.execute("SELECT 1 FROM vault WHERE name=?", (name,)).fetchone() is not None

    def delete_secret(self, name: str) -> bool:
        with self.tx(secrets=True) as c:
            cur = c.execute("DELETE FROM vault WHERE name=?", (name,))
        return cur.rowcount > 0

    def list_secret_names(self) -> list[str]:
        return [r["name"] for r in self._sec.execute("SELECT name FROM vault ORDER BY name")]

    def history_top(self, name: str) -> tuple[bytes, bytes] | None:
        r = self._sec.execute(
            "SELECT * FROM vault_history WHERE name=? ORDER BY created_at DESC LIMIT 1",
            (name,)).fetchone()
        return (self._row_to_sealed(r), r) if r else None

    def rollback_secret(self, name: str, kek: bytes) -> bool:
        """把最近一条历史写回现值（轮换失败回滚）。"""
        top = self.history_top(name)
        if not top:
            return False
        sealed, _ = top
        with self.tx(secrets=True) as c:
            c.execute(
                "UPDATE vault SET wrapped_dek=?,dek_nonce=?,data_nonce=?,ciphertext=?,"
                "kek_version=?,updated_at=? WHERE name=?",
                (sealed.wrapped_dek, sealed.dek_nonce, sealed.data_nonce, sealed.ciphertext,
                 sealed.kek_version, now(), name))
        return True

    def rewrap_all(self, old_kek: bytes, new_kek: bytes) -> int:
        rows = self._sec.execute("SELECT * FROM vault").fetchall()
        n = 0
        for r in rows:
            s = crypto.rewrap(self._row_to_sealed(r), old_kek, new_kek)
            with self.tx(secrets=True) as c:
                c.execute("UPDATE vault SET wrapped_dek=?,dek_nonce=?,kek_version=?,updated_at=?"
                          " WHERE name=?",
                          (s.wrapped_dek, s.dek_nonce, s.kek_version, now(), r["name"]))
            n += 1
        for h in self._sec.execute("SELECT * FROM vault_history").fetchall():
            s = crypto.rewrap(self._row_to_sealed(h), old_kek, new_kek)
            with self.tx(secrets=True) as c:
                c.execute("UPDATE vault_history SET wrapped_dek=?,dek_nonce=?,kek_version=?"
                          " WHERE id=?", (s.wrapped_dek, s.dek_nonce, s.kek_version, h["id"]))
        return n

    # ── 凭据元数据 ──
    def upsert_credential(self, name: str, kind: str = "generic", account: str = "",
                          remark: str = "", tags: list[str] | None = None,
                          expires_at: int | None = None, secret_fp: str = "",
                          allowed_capabilities: list[str] | None = None,
                          status: str = "active") -> dict:
        t = now()
        r = self._meta.execute("SELECT id FROM credentials WHERE name=?", (name,)).fetchone()
        if r:
            with self.tx() as c:
                c.execute(
                    "UPDATE credentials SET kind=?,account=?,remark=?,tags=?,expires_at=?,"
                    "secret_fp=COALESCE(NULLIF(?,''),secret_fp),allowed_capabilities=?,"
                    "status=?,updated_at=? WHERE name=?",
                    (kind, account, remark, json.dumps(tags or []), expires_at, secret_fp,
                     None if allowed_capabilities is None else json.dumps(allowed_capabilities),
                     status, t, name))
            return self.get_credential(name) or {}
        cid = uid()
        with self.tx() as c:
            c.execute(
                "INSERT INTO credentials(id,name,kind,account,remark,tags,allowed_capabilities,"
                "expires_at,created_at,updated_at,secret_fp,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, name, kind, account, remark, json.dumps(tags or []),
                 None if allowed_capabilities is None else json.dumps(allowed_capabilities),
                 expires_at, t, t, secret_fp, status))
        return self.get_credential(name) or {}

    def get_credential(self, name: str) -> dict | None:
        r = self._meta.execute("SELECT * FROM credentials WHERE name=?", (name,)).fetchone()
        return _cred_row(r) if r else None

    def list_credentials(self, include_deleted: bool = False) -> list[dict]:
        q = "SELECT * FROM credentials" + ("" if include_deleted else " WHERE status!='deleted'")
        return [_cred_row(r) for r in self._meta.execute(q + " ORDER BY name")]

    def touch_credential(self, name: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE credentials SET last_used_at=?, use_count=use_count+1 WHERE name=?",
                      (now(), name))

    def expiring(self, within_days: int = 14) -> list[dict]:
        limit = now() + within_days * 86400
        rows = self._meta.execute(
            "SELECT * FROM credentials WHERE expires_at IS NOT NULL AND expires_at<=? "
            "AND status!='deleted' ORDER BY expires_at", (limit,))
        return [_cred_row(r) for r in rows]

    def stale(self, days: int = 90) -> list[dict]:
        limit = now() - days * 86400
        rows = self._meta.execute(
            "SELECT * FROM credentials WHERE (last_used_at IS NULL OR last_used_at<?) "
            "AND status!='deleted' ORDER BY last_used_at", (limit,))
        return [_cred_row(r) for r in rows]

    def delete_credential(self, name: str) -> bool:
        c = self.get_credential(name)
        if not c:
            return False
        with self.tx() as conn:
            conn.execute("UPDATE credentials SET status='deleted',updated_at=? WHERE name=?",
                         (now(), name))
        return True

    # ── 能力 ──
    def upsert_capability(self, spec: dict, source: str = "") -> None:
        t = now()
        with self.tx() as c:
            c.execute(
                "INSERT INTO capabilities(id,name,kind,description,input_schema,config,secret_refs,"
                "enabled,read_only,require_confirm,source,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                "kind=excluded.kind, description=excluded.description,"
                " input_schema=excluded.input_schema, config=excluded.config,"
                " secret_refs=excluded.secret_refs, enabled=excluded.enabled,"
                " read_only=excluded.read_only, require_confirm=excluded.require_confirm,"
                " source=excluded.source, updated_at=excluded.updated_at",
                (uid(), spec["name"], spec.get("kind", "http"), spec.get("description", ""),
                 json.dumps(spec.get("input_schema") or {}, ensure_ascii=False),
                 json.dumps(spec.get("config") or {}, ensure_ascii=False),
                 json.dumps(spec.get("secret_refs") or []),
                 1 if spec.get("enabled", True) else 0,
                 1 if spec.get("read_only", True) else 0,
                 1 if spec.get("require_confirm", False) else 0,
                 source, t, t))

    def list_capabilities(self, enabled_only: bool = True) -> list[dict]:
        q = "SELECT * FROM capabilities" + (" WHERE enabled=1" if enabled_only else "")
        return [_cap_row(r) for r in self._meta.execute(q + " ORDER BY name")]

    def get_capability(self, name: str) -> dict | None:
        r = self._meta.execute("SELECT * FROM capabilities WHERE name=?", (name,)).fetchone()
        return _cap_row(r) if r else None

    def disable_capability(self, name: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE capabilities SET enabled=0,updated_at=? WHERE name=?", (now(), name))


def _cred_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["tags"] = json.loads(d.get("tags") or "[]")
    d["allowed_capabilities"] = (None if d["allowed_capabilities"] is None
                                else json.loads(d["allowed_capabilities"]))
    return d


def _cap_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["input_schema"] = json.loads(d.get("input_schema") or "{}")
    d["config"] = json.loads(d.get("config") or "{}")
    d["secret_refs"] = json.loads(d.get("secret_refs") or "[]")
    d["enabled"] = bool(d["enabled"])
    d["read_only"] = bool(d["read_only"])
    d["require_confirm"] = bool(d["require_confirm"])
    return d
