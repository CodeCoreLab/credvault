"""quota.py — 配额与软限流（纯计算 + 一次计数读写，无上游 I/O）

抽出的原因：Service 曾同时承担「装配 + 闸门 + 执行 + 配额 + 自省」，配额逻辑
散在 6 个方法里，调阈值要跨读 policy/config/service 三处。这里集中为模块函数，
取值优先级一眼可见：**config 非 0 优先 → policy 兜底 → 硬编码默认**。

软限流（litellm 模式）三条约束：opt-in / burst 永不降速 / 每次现算不复利。
"""
from __future__ import annotations

import random
import time

def _limits(svc) -> list[tuple[str, int, int]]:
    pol = svc.policy
    return [
        ("burst", int(svc.cfg.get("limits.burst_window_sec", 60)),
         int(svc.cfg.get("limits.burst_count", 10))),
        ("min", 60, int(svc.cfg.get("limits.quota_per_min") or pol.quota_per_min)),
        ("day", 86400, int(svc.cfg.get("limits.quota_per_day") or pol.quota_per_day)),
    ]


def _effective_limit(svc, cap_name: str, bucket: str, default: int) -> int:
    """per-capability 覆盖：policy Rule.constraints.quota_per_<bucket>。

    安全语义：取该能力所有匹配规则中的**最小值**（最严者胜），与 deny 优先同向。
    """
    vals = [r.constraints.get(f"quota_per_{bucket}")
            for ag in svc.policy.agents.values()
            for r in ag.rules
            if r.name == cap_name and r.constraints]
    nums = [int(v) for v in vals if isinstance(v, int) and v >= 0]
    return min(nums) if nums else default


def _quota_state(svc, agent: str, capability: str) -> tuple[str | None, dict]:
    """返回 (拒绝原因或 None, {bucket: (count, limit)})。"""
    t = int(time.time())
    over: list[str] = []
    state: dict[str, tuple[int, int]] = {}
    for bucket, window, limit in svc._limits():
        eff = svc._effective_limit(capability, bucket, limit)
        if eff <= 0:
            continue
        start = t - (t % window)
        row = svc.store._meta.execute(
            "SELECT count,window_start FROM quota WHERE agent_id=? AND capability=? AND bucket=?",
            (agent, capability, bucket)).fetchone()
        count = row["count"] if row and row["window_start"] == start else 0
        state[bucket] = (count, eff)
        if count >= eff:
            over.append(f"{capability} 超出 {bucket} 配额（{count}/{eff}）")
    return ("；".join(over) if over else None), state


def _quota_hit(svc, agent: str, capability: str) -> str | None:
    reason, _ = svc._quota_state(agent, capability)
    return reason


def _quota_bump(svc, agent: str, capability: str) -> None:
    """计数自增（窗口翻转即重置），与 _limits 的 bucket 同源。"""
    t = int(time.time())
    for bucket, window, _limit in svc._limits():
        start = t - (t % window)
        with svc.store.tx() as c:
            c.execute(
                "INSERT INTO quota(agent_id,capability,bucket,count,window_start)"
                " VALUES(?,?,?,1,?) ON CONFLICT(agent_id,capability,bucket) DO UPDATE SET"
                " count=CASE WHEN window_start=excluded.window_start THEN count+1 ELSE 1 END,"
                " window_start=excluded.window_start",
                (agent, capability, bucket, start))


def _throttled(svc, agent: str, capability: str) -> bool:
    """软限流（litellm 模式）：超配额时按 pct 概率放行、其余降速拒绝。

    三条安全约束（与 litellm 对齐）：
      1. **opt-in**：`limits.throttle_enabled=true` 才生效，否则硬停（安全默认）
      2. **burst 不享受降速**：突发保护必须硬拦，否则防刷群形同虚设
      3. **每次现算**：按当前 count/limit 现算概率，不在上一次结果上复利
    """
    if not svc.cfg.get("limits.throttle_enabled"):
        return False
    pct = float(svc.cfg.get("limits.throttle_pct") or 0.5)
    if not (0 < pct < 1):
        return False
    reason, state = svc._quota_state(agent, capability)
    if not reason:
        return False
    if any("burst" in r for r in reason.split("；")):
        return False
    return random.random() < pct
