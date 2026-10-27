"""audit.py — 哈希链审计（追加即定序，改一行即断链）

格式：一行一 JSON，含 prev（上一条 hash）与 hash，自己算自己。
  - 跨进程锁覆盖「读链尾 → 算 hash → 追加」全过程（并发下不断链）
  - 链尾从文件尾部反向按块回读，不整载（千行后不变慢）
  - 审计失败默认不阻断业务，但返回 audit_lost；strict=True 时 fail-closed
  - 外部 sink 默认关，显式开启才外发（避免把审计数据送到第三方）
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

_LOCK = threading.Lock()
GENESIS = "0" * 64


class AuditError(RuntimeError):
    pass


# ── 跨进程文件锁 ────────────────────────────────────────────────────────
class _FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.fh = None

    def __enter__(self) -> "_FileLock":
        self.fh = open(self.path, "a+b")
        if os.name == "nt":
            import msvcrt
            for _ in range(200):
                try:
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
                    return self
                except OSError:
                    time.sleep(0.01)
            raise AuditError("审计文件锁获取超时")
        import fcntl
        fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            if os.name == "nt":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        finally:
            self.fh.close()
            self.fh = None


def _canon(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash_of(rec: dict) -> str:
    return hashlib.sha256(_canon(rec).encode("utf-8")).hexdigest()


def _read_tail(path: Path, block: int = 8192) -> str:
    """从尾部反向按块回读最后一条非空行；找不到返回 GENESIS。"""
    try:
        size = path.stat().st_size
    except OSError:
        return GENESIS
    if size == 0:
        return GENESIS
    with open(path, "rb") as f:
        buf = b""
        pos = size
        while pos > 0:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            lines = [ln for ln in buf.split(b"\n") if ln.strip()]
            if pos == 0 or len(lines) >= 2:
                for ln in reversed(lines):
                    try:
                        return json.loads(ln.decode("utf-8")).get("hash", GENESIS)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
    return GENESIS


def _iter_lines_reverse(path: Path, block: int = 65536) -> Iterator[str]:
    """反向逐行读（大文件不做整载）。"""
    try:
        size = path.stat().st_size
    except OSError:
        return
    with open(path, "rb") as f:
        pos = size
        buf = b""
        while pos > 0:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            parts = buf.split(b"\n")
            buf = parts[0]
            for ln in reversed(parts[1:]):
                if ln.strip():
                    yield ln.decode("utf-8", errors="replace")
        if buf.strip():
            yield buf.decode("utf-8", errors="replace")


class Audit:
    def __init__(self, path: Path, strict: bool = False,
                 sink: dict | None = None, timezone_name: str = "Asia/Shanghai"):
        """ts 统一存 UTC（ISO8601 带 +00:00），查询与展示按 timezone_name 换算。"""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.path.with_suffix(".jsonl.lock")
        self.strict = strict
        self.sink = sink or {"type": "none"}
        self.tz = timezone_name

    # ── 写 ──
    def append(self, actor: str, tool: str, ok: bool, dur_ms: int = 0, *,
               capability: str = "", credential: str = "", note: str = "",
               args_fp: str = "", args_preview: str = "",
               extra: dict | None = None) -> dict:
        rec: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "epoch": int(time.time()),
            "actor": actor,
            "tool": tool,
            "capability": capability,
            "credential": credential,
            "ok": bool(ok),
            "dur_ms": int(dur_ms),
            "note": (note or "")[:400],
            "args_fp": args_fp,
            # 参数摘要：调用方已过 redact；此处只做长度兜底，不做二次脱敏（不重复职责）
            "args_preview": (args_preview or "")[:240],
        }
        if extra:
            rec["extra"] = {k: v for k, v in extra.items() if k not in ("secret", "body")}
        try:
            with _LOCK, _FileLock(self.lock_path):
                rec["prev"] = _read_tail(self.path)
                rec["hash"] = _hash_of(rec)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            self._push_sink(rec)
            return {"written": True, "hash": rec["hash"], "audit_lost": False}
        except (OSError, AuditError) as e:
            if self.strict:
                raise AuditError(f"审计不可用（strict 模式拒绝执行）: {e}") from e
            return {"written": False, "audit_lost": True, "audit_error": str(e)[:200]}

    def _push_sink(self, rec: dict) -> None:
        kind = (self.sink or {}).get("type", "none")
        if kind in ("none", "", None):
            return
        url = (self.sink or {}).get("url", "")
        if not url:
            return
        try:
            data = json.dumps(rec, ensure_ascii=False).encode()
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=float(self.sink.get("timeout_sec", 5))).read()
        except (urllib.error.URLError, OSError, ValueError):
            pass  # 外发失败不影响主链路；链上仍留痕

    # ── 校验 ──
    def verify(self, full: bool = True) -> tuple[bool, str, int]:
        n = 0
        prev = GENESIS
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        return False, f"第 {i} 行不是合法 JSON", n
                    if rec.get("prev") != prev:
                        return False, f"第 {i} 行 prev 断裂（期望 {prev[:12]} 实得 {str(rec.get('prev'))[:12]}）", n
                    if rec.get("hash") != _hash_of(rec):
                        return False, f"第 {i} 行内容被改动（hash 不匹配）", n
                    prev = rec["hash"]
                    n += 1
                    if not full and n >= 1:
                        break
        except FileNotFoundError:
            return True, "无审计文件（空链）", 0
        return True, f"链完整，共 {n} 条", n

    # ── 查 ──
    def search(self, limit: int = 50, actor: str = "", capability: str = "",
               ok: bool | None = None, since_epoch: int = 0, keyword: str = "",
               max_scan: int = 200000) -> list[dict]:
        out: list[dict] = []
        scanned = 0
        for line in _iter_lines_reverse(self.path):
            scanned += 1
            if scanned > max_scan:
                break
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since_epoch and int(r.get("epoch", 0)) < since_epoch:
                break  # 反向扫描，越早越靠后
            if actor and r.get("actor") != actor:
                continue
            if capability and r.get("capability") != capability:
                continue
            if ok is not None and bool(r.get("ok")) != ok:
                continue
            if keyword and keyword.lower() not in (json.dumps(r, ensure_ascii=False).lower()):
                continue
            out.append(r)
            if len(out) >= limit:
                break
        return out

    def stats(self, since_epoch: int = 0) -> dict:
        by_cap: dict[str, int] = {}
        by_status = {"ok": 0, "fail": 0}
        actors: dict[str, int] = {}
        total = 0
        for line in _iter_lines_reverse(self.path):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since_epoch and int(r.get("epoch", 0)) < since_epoch:
                break
            total += 1
            cap = r.get("capability") or r.get("tool") or "-"
            by_cap[cap] = by_cap.get(cap, 0) + 1
            by_status["ok" if r.get("ok") else "fail"] += 1
            actors[r.get("actor", "-")] = actors.get(r.get("actor", "-"), 0) + 1
        return {"total": total, "by_capability": dict(sorted(by_cap.items(), key=lambda x: -x[1])[:20]),
                "by_status": by_status, "by_actor": actors}

    def tail(self, limit: int = 10) -> list[dict]:
        return self.search(limit=limit)

    def export(self, fmt: str = "jsonl", since_epoch: int = 0, limit: int = 10000) -> str:
        rows = list(reversed(self.search(limit=limit, since_epoch=since_epoch)))
        if fmt == "csv":
            import csv
            import io
            buf = io.StringIO()
            cols = ["ts", "actor", "tool", "capability", "credential", "ok", "dur_ms", "note", "args_fp", "hash"]
            w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
            return buf.getvalue()
        if fmt == "md":
            head = "| ts | actor | capability | ok | dur_ms | note |\n|---|---|---|---|---|---|\n"
            body = "\n".join(
                f"| {r.get('ts','')} | {r.get('actor','')} | {r.get('capability','')} | "
                f"{'Y' if r.get('ok') else 'N'} | {r.get('dur_ms',0)} | {(r.get('note') or '')[:60]} |"
                for r in rows)
            return head + body
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
