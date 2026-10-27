"""approvals.py — 异步审批（I5：AI 不用等人开 shell）

与旧实现的差别（R5）：
  旧：AI 收到 E_APPROVAL → 人必须登录服务器跑 `approval approve <id>` → AI 带 id 重放。
      夜间无人值守时 30 分钟过期即废，结果要么阻塞、要么把 require_approval 关掉裸奔。
  新：① 返回 pending + 可轮询的 approval_status
      ② 审批动作通过 Web / 事件通知完成（人只需点一下，不必会命令行）
      ③ 支持会话豁免：批一次，本会话同类不再重复申请（对抗审批疲劳）
      ④ 参数指纹绑定：批准的 A 不能用去执行 B
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
import uuid

from .store import Store, now


def args_fp(capability: str, args: dict) -> str:
    body = json.dumps({"c": capability, "a": args}, sort_keys=True,
                      ensure_ascii=False, default=str, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()[:12]


def _preview(args: dict) -> str:
    parts = []
    for k, v in (args or {}).items():
        s = str(v)
        parts.append(f"{k}={s[:80]}{'…' if len(s) > 80 else ''}")
    return "; ".join(parts)[:400]


class Approvals:
    def __init__(self, store: Store, ttl_min: int = 30, session_ttl_min: int = 120,
                 notifier: dict | None = None):
        self.s = store
        self.ttl = max(1, int(ttl_min)) * 60
        self.session_ttl = max(1, int(session_ttl_min)) * 60
        self.notifier = notifier or {"type": "none"}

    # ── 申请 ──
    def request(self, capability: str, args: dict, agent: str, reason: str = "") -> dict:
        aid = uuid.uuid4().hex[:8]
        fp = args_fp(capability, args)
        with self.s.tx() as c:
            c.execute(
                "INSERT INTO approvals(id,capability,args_fp,args_preview,reason,requested_by,"
                "state,created_at,expires_at) VALUES(?,?,?,?,?,?,'pending',?,?)",
                (aid, capability, fp, _preview(args),
                 (reason or f"{agent} 请求执行 {capability}")[:300], agent, now(),
                 now() + self.ttl))
        self._notify({"event": "approval.requested", "approval_id": aid,
                      "capability": capability, "agent": agent,
                      "args_preview": _preview(args), "expires_in_sec": self.ttl})
        return {"approval_id": aid, "state": "pending", "args_fp": fp,
                "expires_in_sec": self.ttl,
                "next_action": ("告知用户有审批待办（Web 待审批页/企业微信通知），"
                                "然后调 approval_status(approval_id) 轮询；"
                                "批准后带 approval_id 重试本能力。不要重复申请。")}

    # ── 裁决 ──
    def decide(self, aid: str, approve: bool, by: str, reason: str = "",
               session: bool = False) -> tuple[bool, str]:
        r = self.s._meta.execute("SELECT * FROM approvals WHERE id=?", (aid,)).fetchone()
        if not r:
            return False, f"审批单不存在: {aid}"
        rec = dict(r)
        if rec["state"] != "pending":
            return False, f"审批单 {aid} 已是 {rec['state']}"
        if int(rec["expires_at"]) < now():
            with self.s.tx() as c:
                c.execute("UPDATE approvals SET state='expired' WHERE id=?", (aid,))
            return False, f"审批单 {aid} 已过期，需重新申请"
        state = "approved" if approve else "rejected"
        with self.s.tx() as c:
            c.execute("UPDATE approvals SET state=?,decided_by=?,decided_at=?,decision_reason=?"
                      " WHERE id=?", (state, by, now(), (reason or "")[:300], aid))
        extra = ""
        if approve and session:
            with self.s.tx() as c:
                c.execute("INSERT INTO exemptions(id,agent_id,capability,expires_at,created_by,"
                          "created_at) VALUES(?,?,?,?,?,?)",
                          (uuid.uuid4().hex[:8], rec["requested_by"], rec["capability"],
                           now() + self.session_ttl, by, now()))
            extra = f"；已开启会话豁免（{self.session_ttl // 60} 分钟内同类不再申请）"
        self._notify({"event": f"approval.{state}", "approval_id": aid,
                      "capability": rec["capability"], "by": by})
        return True, f"审批单 {aid} 已{'批准' if approve else '拒绝'}（by {by}）{extra}"

    # ── 核销 ──
    def consume(self, aid: str, capability: str, args: dict) -> tuple[bool, str]:
        r = self.s._meta.execute("SELECT * FROM approvals WHERE id=?", (aid,)).fetchone()
        if not r:
            return False, f"审批单不存在: {aid}"
        rec = dict(r)
        if rec["state"] != "approved":
            return False, f"审批单 {aid} 状态={rec['state']}，不可执行" + (
                "（等待批准：调 approval_status 轮询）" if rec["state"] == "pending" else "")
        if int(rec["expires_at"]) < now():
            return False, f"审批单 {aid} 已过期"
        if rec["capability"] != capability:
            return False, f"审批单 {aid} 针对 {rec['capability']}，与本次 {capability} 不符"
        fp = args_fp(capability, args)
        if rec["args_fp"] != fp:
            return False, (f"参数指纹不符（审批 {rec['args_fp']} / 本次 "
                           f"{fp}）—— 防批准 A 执行 B")
        # 原子核销：条件更新 + 受影响行数判定，杜绝并发双核销（TOCTOU）
        with self.s.tx() as c:
            cur = c.execute(
                "UPDATE approvals SET state='consumed',consumed_at=? "
                "WHERE id=? AND state='approved' AND args_fp=?", (now(), aid, fp))
        if cur.rowcount != 1:
            return False, f"审批单 {aid} 已被核销或状态已变更（并发保护），请重新申请"
        return True, "审批已核销"

    # ── 查询 ──
    def status(self, aid: str) -> dict:
        r = self.s._meta.execute("SELECT * FROM approvals WHERE id=?", (aid,)).fetchone()
        if not r:
            return {"found": False, "approval_id": aid}
        rec = dict(r)
        state = rec["state"]
        if state == "pending" and int(rec["expires_at"]) < now():
            with self.s.tx() as c:
                c.execute("UPDATE approvals SET state='expired' WHERE id=?", (aid,))
            state = "expired"
        hint = {"pending": "仍在等待人工审批：不要重复申请，稍后再查",
                "approved": "已批准：带 approval_id 重新调用原能力即可（一次性）",
                "rejected": "已被拒绝：不要重试，向用户说明原因",
                "consumed": "已使用：如需再执行需重新申请",
                "expired": "已过期：重新申请一张新审批单"}[state]
        return {"found": True, "approval_id": aid, "state": state, "hint": hint,
                "capability": rec["capability"], "requested_by": rec["requested_by"],
                "args_preview": rec["args_preview"], "reason": rec["reason"],
                "created_at": rec["created_at"], "expires_at": rec["expires_at"],
                "decided_by": rec["decided_by"], "decision_reason": rec["decision_reason"]}

    def pending(self, limit: int = 100) -> list[dict]:
        rows = self.s._meta.execute(
            "SELECT * FROM approvals WHERE state='pending' ORDER BY created_at DESC LIMIT ?",
            (limit,))
        out = []
        for r in rows:
            rec = dict(r)
            if int(rec["expires_at"]) < now():
                with self.s.tx() as c:
                    c.execute("UPDATE approvals SET state='expired' WHERE id=?", (rec["id"],))
                continue
            rec["remaining_sec"] = int(rec["expires_at"]) - now()
            out.append(rec)
        return out

    def recent(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self.s._meta.execute(
            "SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,))]

    # ── 会话豁免 ──
    def has_exemption(self, agent: str, capability: str) -> bool:
        r = self.s._meta.execute(
            "SELECT 1 FROM exemptions WHERE agent_id=? AND capability=? AND expires_at>?",
            (agent, capability, now())).fetchone()
        return r is not None

    def exemptions(self) -> list[dict]:
        return [dict(r) for r in self.s._meta.execute(
            "SELECT * FROM exemptions WHERE expires_at>? ORDER BY expires_at", (now(),))]

    def clear_exemption(self, eid: str) -> bool:
        with self.s.tx() as c:
            cur = c.execute("DELETE FROM exemptions WHERE id=?", (eid,))
        return cur.rowcount > 0

    def cleanup(self, keep_hours: int = 48) -> int:
        cutoff = now() - keep_hours * 3600
        with self.s.tx() as c:
            cur = c.execute(
                "DELETE FROM approvals WHERE created_at<? AND state!='pending'", (cutoff,))
            c.execute("DELETE FROM exemptions WHERE expires_at<?", (now(),))
        return cur.rowcount

    # ── 通知 ──
    def _notify(self, payload: dict) -> None:
        kind = (self.notifier or {}).get("type", "none")
        url = (self.notifier or {}).get("url", "")
        if kind in ("none", "", None) or not url:
            return
        try:
            if kind == "wecom":
                text = (f"【凭据平台审批】{payload.get('event')}\n"
                        f"能力: {payload.get('capability')}\n"
                        f"申请方: {payload.get('agent')}\n"
                        f"参数: {payload.get('args_preview')}\n"
                        f"审批号: {payload.get('approval_id')}")
                body = {"msgtype": "text", "text": {"content": text}}
            else:
                body = payload
            data = json.dumps(body, ensure_ascii=False).encode()
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).read()
        except (urllib.error.URLError, OSError, ValueError):
            pass  # 通知失败不影响审批单本身
