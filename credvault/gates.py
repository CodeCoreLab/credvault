"""gates.py — 调用闸门链（纯判定，无副作用、无 I/O 上游）

从 service.py 抽出的原因：Service 类曾 615 行、invoke 95 行，一个方法里串了六道判定，
改任何一道都必须在 600 行上下文里定位。这里把判定收敛为**模块函数**，入参显式
（svc 只读依赖），既便于单独测试，也让「闸门顺序即语义」在文件层面一眼可见。

顺序铁律（调用方 invoke 必须按此序）：
  static → policy → credential → quota → approval → execute
  凭据闸门必须在审批之前（否则白拿审批）；配额必须在执行之前（否则计数被绕过）。

返回约定：拒绝时返回完整失败 dict（已含 code/reason/label），放行返回 None。
"""
from __future__ import annotations

import json
import time

from . import policy as policy_mod
from . import redact
from .approvals import args_fp
from . import registry


def _svc_mod():
    """延迟导入 service 模块：gates 被 service 导入，模块级 import 会成环。

    只取三个纯符号（错误码常量、_cap_from_row、E_* 族），无状态依赖。
    """
    from . import service as service_mod
    return service_mod

def _resolve_cap(svc, capability: str) -> registry.Capability | None:
    """能力解析：注册表优先，库内定义兜底（注册表热加载后以其为准）。"""
    cap = svc._caps_by_name.get(capability)
    if cap is not None:
        return cap
    row = svc.store.get_capability(capability)
    return _svc_mod()._cap_from_row(row) if row else None


def _gate_static(svc, agent: dict, cap: registry.Capability, args: dict,
                 on_behalf_of: str, t0: float) -> dict | None:
    """静态闸门：启用状态 / 参数 schema / 令牌能力轴 / 代办人 / 令牌凭据轴。

    全部与外部状态无关，先跑最便宜的判定，被拒时不产生任何 I/O。
    """
    if not cap.enabled:
        return svc._fail(agent, cap.name, _svc_mod().E_DENIED, "能力已禁用", t0)
    ok_schema, err = cap.validate(args)
    if not ok_schema:
        return svc._fail(agent, cap.name, _svc_mod().E_INPUT, err, t0)

    allowed = agent.get("allowed_capabilities")
    if allowed is not None and cap.name not in allowed and "*" not in allowed:
        return svc._fail(agent, cap.name, _svc_mod().E_DENIED,
                          "令牌未授权该能力（allowed_capabilities）", t0)

    if on_behalf_of:
        if not svc._can_impersonate(agent["id"], cap.name):
            return svc._fail(agent, cap.name, _svc_mod().E_DENIED,
                              "该 agent 未获 impersonate 授权，不得声明 on_behalf_of", t0)
        if not on_behalf_of.startswith("human:"):
            return svc._fail(agent, cap.name, _svc_mod().E_INPUT,
                              "on_behalf_of 必须形如 human:<id>（机器身份无需代办）", t0)

    vis = agent.get("visible_credentials")
    if vis is not None:
        hidden = [r for r in cap.secret_refs if r not in vis]
        if hidden:
            return svc._fail(agent, cap.name, _svc_mod().E_DENIED,
                              f"令牌不可见凭据 {hidden}（双轴授权）", t0)
    return None


def _gate_policy(svc, agent: dict, cap: registry.Capability, args: dict,
                 t0: float) -> tuple[dict | None, policy_mod.Verdict | None]:
    """策略闸门：Kill Switch / exec 开关 / 授权规则 / 参数级约束。

    返回 (早停结果或 None, verdict)。verdict 供后续审批判定复用，
    避免 invoke 再算一遍策略——判定必须与干跑同源。
    """
    kill = bool(svc.cfg.get("kill_switch")) or svc.store.meta_get("kill_switch") == "1"
    if cap.kind == "exec" and not bool(svc.cfg.get("exec.enabled")):
        return svc._fail(agent, cap.name, _svc_mod().E_DENIED,
                          "exec 能力在配置层被关闭（exec.enabled=false）", t0), None
    v = svc.policy.evaluate(agent["id"], cap.name, read_only=cap.read_only,
                             require_confirm=cap.require_confirm,
                             is_exec=(cap.kind == "exec"), kill_switch=kill)
    if not v.allow:
        m = _svc_mod()
        code = m.E_KILL if "Kill Switch" in v.reason else m.E_DENIED
        return svc._fail(agent, cap.name, code, v.reason, t0, rule=v.rule), None
    ok_lim, lim_err = policy_mod.Policy.check_arg_limits(v.constraints, args)
    if not ok_lim:
        return svc._fail(agent, cap.name, _svc_mod().E_INPUT, lim_err, t0), None
    return None, v


def _gate_quota(svc, agent: dict, cap: registry.Capability, t0: float) -> dict | None:
    """配额闸门：超限时先看软限流是否放行，否则硬拒（burst 永不降速）。"""
    q = svc._quota_hit(agent["id"], cap.name)
    if not q:
        return None
    if svc._throttled(agent["id"], cap.name):
        svc.audit.append(agent["id"], "throttle", True, 0, capability=cap.name,
                          note=f"THROTTLED {q}")
        return None
    return svc._fail(agent, cap.name, _svc_mod().E_QUOTA, q, t0)


def _gate_approval(svc, agent: dict, cap: registry.Capability, args: dict,
                   need: bool, approval_id: str, t0: float) -> dict | None:
    """审批闸门：无单则建单并提示轮询；有单则核销（一次性 + 指纹绑定）。"""
    if not need or svc.approvals.has_exemption(agent["id"], cap.name):
        return None
    if not approval_id:
        req = svc.approvals.request(cap.name, args, agent["id"])
        svc.audit.append(agent["id"], "invoke", False,
                          int((time.monotonic() - t0) * 1000), capability=cap.name,
                          note=f"APPROVAL-REQUEST {req['approval_id']}",
                          args_fp=args_fp(cap.name, args))
        return {"ok": False, "code": _svc_mod().E_APPROVAL, "capability": cap.name,
                "needs_approval": True, **req}
    ok_a, msg = svc.approvals.consume(approval_id, cap.name, args)
    if not ok_a:
        return svc._fail(agent, cap.name, _svc_mod().E_APPROVAL, msg, t0)
    return None


def _credential_gate(svc, cap: registry.Capability) -> str:
    """凭据可用性闸门：返回拒绝原因，空串=通过。

    三类判据（任一命中即拒）：
      1. 已过期（expires_at < now）—— 到期即失效，不靠人工记得去禁用
      2. 状态非 active（deleted / disabled）
      3. 凭据侧 allowed_capabilities 白名单不含本能力（双轴的最小权限第二维）
    """
    now = int(time.time())
    for ref in cap.secret_refs:
        meta = svc.store.get_credential(ref)
        if not meta:
            continue  # 未登记由 _execute 的 KeyError 分支负责（E_RESOLVE）
        if meta.get("status") not in (None, "active"):
            return f"凭据 {ref} 状态={meta.get('status')}，拒绝使用"
        exp = meta.get("expires_at")
        if exp and int(exp) < now:
            days = (now - int(exp)) // 86400
            return f"凭据 {ref} 已过期 {days} 天（expires_at={exp}），拒绝使用；请轮换后重试"
        allowed = meta.get("allowed_capabilities")
        if allowed is not None and cap.name not in allowed:
            return (f"凭据 {ref} 不允许被 {cap.name} 使用"
                    f"（凭据侧白名单 {allowed}）")
    return ""


def _can_impersonate(svc, agent_id: str, capability: str) -> bool:
    """该 agent 对该能力是否被授予 impersonate（F4）。"""
    for rule in svc.policy.agents.get(agent_id).rules if svc.policy.agents.get(agent_id) else []:
        if rule.name in (capability, "*") and (rule.constraints or {}).get("impersonate") is True:
            return True
    return False


def _safe_args_preview(svc, args: dict, secrets: list[str]) -> str:
    """审计用参数摘要：先脱敏再截断（M1）。

    顺序不能反：先截断会把密钥切半导致脱敏规则匹配不到 → 明文残片入审计。
    """
    if not args:
        return ""
    raw = json.dumps(args, ensure_ascii=False, default=str)
    clean, _ = redact.scrub(raw, secrets,
                            max_hits=int(svc.cfg.get("redact.max_hits", 200)),
                            extra_patterns=svc.cfg.get("redact.patterns"))
    return clean[:240]
