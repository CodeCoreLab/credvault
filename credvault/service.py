"""service.py — 调用内核：身份 → 配额 → 策略 → 审批 → 注入 → 脱敏 → 审计

这是唯一允许出现「解密后明文」的地方，且明文生命周期限于单次调用（finally 清理）。
所有入口（MCP / CLI / Web）都走这一条路径，保证 `explain` 与真实执行判定同源。
"""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

from . import crypto, executor, policy as policy_mod, redact, registry
from .approvals import Approvals, args_fp
from . import gates, quota, runner
from .audit import Audit
from .dist import Leases
from .store import Store
from .tokens import Tokens

# 统一错误码（与旧 cred_broker 对齐，新增 QUOTA / KILL）
E_OK = 0
E_DENIED = 10
E_APPROVAL = 11
E_SECURITY = 12
E_RESOLVE = 13
E_NETWORK = 14
E_BIZ = 15
E_INPUT = 16
E_INTERNAL = 17
E_QUOTA = 18
E_KILL = 19
E_THROTTLED = 20

LABELS = {
    E_OK: "成功", E_DENIED: "策略拒绝", E_APPROVAL: "需人工审批", E_SECURITY: "安全边界阻断",
    E_RESOLVE: "凭据不可用", E_NETWORK: "上游不可达", E_BIZ: "上游业务失败",
    E_INPUT: "参数非法", E_INTERNAL: "内部错误", E_QUOTA: "超出配额", E_KILL: "Kill Switch 只读",
    E_THROTTLED: "已降速（软限流）",
}

BATCH_CAP = "__batch__"


class ServiceError(RuntimeError):
    pass


class AuthError(ServiceError):
    pass


class CredentialUnavailable(ServiceError):
    """凭据存在但不可用：已过期、已禁用、或不允许被该能力使用。"""


class Service:
    def __init__(self, cfg):
        self.cfg = cfg
        cfg.ensure_dirs()
        self.store = Store(cfg.path("store.db"), cfg.path("store.secrets"))
        self.audit = Audit(cfg.path("audit.path"), strict=bool(cfg.get("audit.strict")),
                           sink=cfg.get("audit.sink"), timezone_name=cfg.get("timezone"))
        self.tokens = Tokens(self.store)
        self.approvals = Approvals(self.store, ttl_min=int(cfg.get("approval.ttl_min", 30)),
                                   session_ttl_min=int(cfg.get("approval.session_ttl_min", 120)),
                                   notifier=cfg.get("approval.notifier"))
        self.leases = Leases(self.store)
        self._kek: bytes | None = None
        self._pol: policy_mod.Policy | None = None
        self._pol_key: tuple = ("", -1, -1)
        self.reload()
        self._sync_capabilities()

    # ── 基础设施 ──
    def kek(self, create: bool = False) -> bytes:
        if self._kek is None:
            src = self.cfg.get("kek.source", "file")
            self._kek = crypto.load_kek(
                src,
                self.cfg.path("kek.path") if src == "file" else None,
                self.cfg.get("kek.env", "CREDVAULT_KEK"), create=create)
        return self._kek

    def reload(self) -> None:
        self.reload_policy(force=True)
        targets = [self._resolve_one(t) for t in (self.cfg.get("capabilities") or [])]
        self.caps, self.cap_warn = registry.load([t for t in targets if t])
        self._caps_by_name = {c.name: c for c in self.caps}

    def _resolve_one(self, t: str) -> Path:
        p = Path(str(t)).expanduser()
        return p if p.is_absolute() else (self.cfg.home / p)

    def reload_policy(self, force: bool = False) -> policy_mod.Policy:
        p = self.cfg.path("policy")
        try:
            st = p.stat()
            key = (str(p), st.st_mtime_ns, st.st_size)
        except OSError:
            key = (str(p), -1, -1)
        if not force and key == self._pol_key and self._pol is not None:
            return self._pol
        self._pol = policy_mod.load(p)
        self._pol_key = key
        return self._pol

    @property
    def policy(self) -> policy_mod.Policy:
        return self.reload_policy()

    def _sync_capabilities(self) -> None:
        for c in self.caps:
            self.store.upsert_capability(c.to_spec(), source=c.source)

    def close(self) -> None:
        executor.close_pool()
        self.store.close()

    # ── 身份 ──
    def authenticate(self, token: str, ip: str = "") -> dict:
        ag = self.tokens.resolve(token, ip)
        if not ag:
            raise AuthError("令牌无效、已吊销、已过期，或来源 IP 不在白名单（fail-closed）")
        return ag

    # ── 渐进披露 ──
    def capabilities_for(self, agent: dict) -> list[registry.Capability]:
        pol = self.policy
        allowed = agent.get("allowed_capabilities")
        vis = agent.get("visible_credentials")
        out = []
        for c in self.caps:
            if not c.enabled:
                continue
            if allowed is not None and c.name not in allowed and "*" not in allowed:
                continue
            v = pol.evaluate(agent["id"], c.name, read_only=c.read_only,
                             require_confirm=c.require_confirm,
                             is_exec=(c.kind == "exec"))
            if not v.allow:
                continue
            if vis is not None and any(r not in vis for r in c.secret_refs):
                continue
            out.append(c)
        return out

    def tools_for(self, agent: dict) -> list[dict]:
        return [c.to_tool() for c in self.capabilities_for(agent)]

    # ── 配额（config 优先、policy 兜底；单一取值源） ──
    # ── 凭据分发（F5）──
    def lease_issue(self, consumer: str, credential: str, ttl: int = 300,
                    renewable: bool = True, ip_allowlist: list[str] | None = None,
                    note: str = "", actor: str = "") -> dict:
        res = self.leases.create(consumer, credential, ttl, renewable, ip_allowlist, note)
        self.audit.append(actor or f"lease:{consumer}", "lease.create", True, 0,
                          credential=credential,
                          note=f"{res['lease_id']} ttl={res['ttl']}")
        return res

    def lease_pull(self, lease_id: str, ip: str = "") -> dict:
        try:
            res = self.leases.pull(lease_id, self.kek(), ip)
        except Exception as e:  # noqa: BLE001
            self.audit.append("lease", "lease.pull", False, 0,
                              note=f"{lease_id}: {type(e).__name__}")
            raise
        self.audit.append("lease", "lease.pull", True, 0,
                          credential="", note=f"{lease_id} fp={res['fp']}")
        return res

    def lease_revoke(self, lease_id: str, actor: str = "") -> bool:
        ok = self.leases.revoke(lease_id)
        self.audit.append(actor or "lease", "lease.revoke", ok, 0, note=lease_id)
        return ok

    def whoami(self, agent: dict) -> dict:
        """运行时自省（F8，warden agent flow）：能调什么、限制是什么、还剩多少额度。

        对**未在策略中登记**的 agent 不抛 KeyError：这类令牌本身合法（能解析），
        但没有任何授权。按 deny-by-default 返回空能力集 + unregistered 标记，
        比抛 500 更准确——调用方需要知道「是没权限」而不是「服务坏了」。
        """
        entry = self.policy.agents.get(agent["id"])
        if entry is None:
            return {"agent": agent["id"], "unregistered": True,
                    "capability_count": 0, "capabilities": [],
                    "visible_credentials": agent.get("visible_credentials"),
                    "reason": "该 agent 未在 policy.yaml 登记，按 deny-by-default 无任何授权",
                    "kill_switch": (bool(self.cfg.get("kill_switch"))
                                    or self.store.meta_get("kill_switch") == "1"),
                    "session_exemptions": len(self.approvals.exemptions())}
        caps = self.capabilities_for(agent)
        rules = {r.name: r for r in entry.rules}
        rows = []
        for c in caps:
            reason, state = self._quota_state(agent["id"], c.name)
            rows.append({
                "capability": c.name, "read_only": c.read_only,
                "require_approval": c.require_confirm,
                "secret_refs": c.secret_refs,
                "constraints": ((rules.get(c.name).constraints if rules.get(c.name) else None) or {}),
                "quota": {b: f"{u}/{l}" for b, (u, l) in state.items()},
                "available": not reason,
            })
        return {"agent": agent["id"],
                "visible_credentials": agent.get("visible_credentials"),
                "capability_count": len(caps), "capabilities": rows,
                "kill_switch": (bool(self.cfg.get("kill_switch"))
                                or self.store.meta_get("kill_switch") == "1"),
                "session_exemptions": len(self.approvals.exemptions())}

    # ── 干跑 ──
    def explain(self, agent: dict, capability: str, args: dict | None = None) -> dict:
        cap = self._caps_by_name.get(capability) or self.store.get_capability(capability)
        if not cap:
            return {"allow": False, "code": E_INPUT, "reason": f"能力不存在: {capability}"}
        c = cap if isinstance(cap, registry.Capability) else _cap_from_row(cap)
        v = self.policy.evaluate(agent["id"], c.name, read_only=c.read_only,
                                 require_confirm=c.require_confirm, is_exec=(c.kind == "exec"))
        reasons = [v.reason]
        if not v.allow:
            return {"allow": False, "code": E_DENIED, "reason": "；".join(reasons),
                    "rule": v.rule}
        ok_schema, err = c.validate(args or {})
        if not ok_schema:
            return {"allow": False, "code": E_INPUT, "reason": err}
        ok_lim, lim_err = policy_mod.Policy.check_arg_limits(v.constraints, args or {})
        if not ok_lim:
            return {"allow": False, "code": E_INPUT, "reason": lim_err}
        bad = self._credential_gate(c)
        if bad:
            return {"allow": False, "code": E_RESOLVE, "reason": bad}
        q = self._quota_hit(agent["id"], c.name)
        if q:
            return {"allow": False, "code": E_QUOTA, "reason": q}
        need = v.needs_approval and not self.approvals.has_exemption(agent["id"], c.name)
        if need:
            reasons.append("需人工审批（或本会话已有豁免）")
        return {"allow": True, "code": E_OK, "reason": "；".join(reasons),
                "needs_approval": need, "read_only": c.read_only,
                "secret_refs": c.secret_refs, "rule": v.rule}

    # ── 执行 ──
    # ── 闸门链（invoke 拆解：每道闸门独立可测，顺序即语义）────────────
    # ── 配额薄封装（实现见 quota.py）──
    def _limits(self):
        return quota._limits(self)

    def _effective_limit(self, cap_name: str, bucket: str, default: int) -> int:
        return quota._effective_limit(self, cap_name, bucket, default)

    def _quota_state(self, agent: str, capability: str):
        return quota._quota_state(self, agent, capability)

    def _quota_hit(self, agent: str, capability: str) -> str | None:
        return quota._quota_hit(self, agent, capability)

    def _quota_bump(self, agent: str, capability: str) -> None:
        return quota._quota_bump(self, agent, capability)

    def _throttled(self, agent: str, capability: str) -> bool:
        return quota._throttled(self, agent, capability)

    # ── 执行薄封装（实现见 runner.py；明文只在那一个文件的 _execute 内出现）──
    def _execute(self, cap: registry.Capability, args: dict, agent: dict,
                 on_behalf_of: str = "") -> dict:
        return runner._execute(self, cap, args, agent, on_behalf_of)

    def _do_http(self, cap, args, secrets, primary):
        return runner._do_http(self, cap, args, secrets, primary)

    def _do_exec(self, cap, args, secrets, primary):
        return runner._do_exec(self, cap, args, secrets, primary)

    def _do_rotate(self, cap, args, agent):
        return runner._do_rotate(self, cap, args, agent)

    # ── 闸门薄封装（实现见 gates.py；此处只保持 Service 公开面稳定）──
    def _credential_gate(self, cap: registry.Capability) -> str:
        return gates._credential_gate(self, cap)

    def _can_impersonate(self, agent_id: str, capability: str) -> bool:
        return gates._can_impersonate(self, agent_id, capability)

    def _safe_args_preview(self, args: dict, secrets: list[str]) -> str:
        return gates._safe_args_preview(self, args, secrets)

    def invoke(self, agent: dict, capability: str, args: dict | None = None,
               approval_id: str = "", ip: str = "", skip_approval: bool = False,
               on_behalf_of: str = "") -> dict:
        """调用能力：静态 → 策略 → 凭据 → 配额 → 审批 → 执行（顺序即语义）。

        闸门顺序不可交换：凭据闸门必须在审批之前（否则白拿审批），
        配额必须在执行之前（否则计数被绕过），审批必须在执行之前（否则越权）。
        """
        schema = (self._caps_by_name[capability].input_schema
                  if capability in self._caps_by_name else {})
        args = registry.apply_defaults(schema, dict(args or {}))
        t0 = time.monotonic()

        cap = gates._resolve_cap(self, capability)
        if cap is None:
            return self._fail(agent, capability, E_INPUT, f"能力不存在: {capability}", t0)

        early = gates._gate_static(self, agent, cap, args, on_behalf_of, t0)
        if early:
            return early
        early, v = gates._gate_policy(self, agent, cap, args, t0)
        if early:
            return early
        if v is None:  # 策略闸门未返回 verdict 即实现异常，按内部错误处理（不裸 assert）
            return self._fail(agent, capability, E_INTERNAL, "策略闸门未产出判定", t0)

        # 凭据可用性与凭据侧授权（C1/C2）：必须在审批之前判，避免白拿审批
        bad = self._credential_gate(cap)
        if bad:
            return self._fail(agent, capability, E_RESOLVE, bad, t0)

        early = gates._gate_quota(self, agent, cap, t0)
        if early:
            return early
        early = gates._gate_approval(self, agent, cap, args,
                                    v.needs_approval and not skip_approval, approval_id, t0)
        if early:
            return early

        self._quota_bump(agent["id"], cap.name)
        try:
            return self._execute(cap, args, agent, on_behalf_of)
        except KeyError as e:
            return self._fail(agent, capability, E_RESOLVE, f"凭据未登记: {e}", t0)
        except crypto.CryptoError as e:
            return self._fail(agent, capability, E_RESOLVE, str(e), t0)
        except executor.ExecError as e:
            msg = str(e)
            code = E_SECURITY if "白名单" in msg else E_NETWORK
            return self._fail(agent, capability, code, msg, t0)

    # ── 批量（一次审批，多能力）───────────────────────────────────────
    def invoke_batch(self, agent: dict, calls: list[dict], approval_id: str = "",
                     ip: str = "") -> dict:
        if not isinstance(calls, list) or not calls:
            return {"ok": False, "code": E_INPUT, "reason": "calls 必须是非空数组"}
        if len(calls) > 20:
            return {"ok": False, "code": E_INPUT, "reason": "单次批量上限 20 条"}
        need_any = False
        for c in calls:
            r = self.explain(agent, c.get("capability", ""), c.get("args") or {})
            if not r.get("allow"):
                return {"ok": False, "code": r.get("code", E_DENIED),
                        "reason": f"{c.get('capability')}: {r.get('reason')}",
                        "failed_index": calls.index(c)}
            need_any = need_any or bool(r.get("needs_approval"))
        batch_args = {"calls": calls}
        if need_any and not approval_id and not self.approvals.has_exemption(agent["id"], BATCH_CAP):
            req = self.approvals.request(BATCH_CAP, batch_args, agent["id"], reason="批量执行")
            return {"ok": False, "code": E_APPROVAL, "needs_approval": True, **req}
        if approval_id:
            ok_a, msg = self.approvals.consume(approval_id, BATCH_CAP, batch_args)
            if not ok_a:
                return {"ok": False, "code": E_APPROVAL, "reason": msg}
        results = []
        for c in calls:
            results.append(self.invoke(agent, c.get("capability", ""), c.get("args") or {},
                                       skip_approval=True, ip=ip))
        return {"ok": all(r.get("ok") for r in results), "code": E_OK,
                "results": results, "count": len(results)}

    # ── 失败封装 ──
    def _fail(self, agent: dict, capability: str, code: int, reason: str,
              t0: float, rule: str = "") -> dict:
        dur = int((time.monotonic() - t0) * 1000)
        self.audit.append(agent["id"], "invoke", False, dur, capability=capability,
                          note=f"{LABELS.get(code, code)}: {reason}"[:300])
        return {"ok": False, "code": code, "capability": capability,
                "reason": reason, "label": LABELS.get(code, ""), "rule": rule,
                "dur_ms": dur}


# ── 辅助 ──
def _business_verdict(text: str) -> tuple[bool, str]:
    """HTTP 200 但业务失败要判失败（企微 errcode!=0 / JSON-RPC error / success=false）。"""
    t = (text or "").strip()
    if not t or t[0] not in "{[":
        return True, ""
    try:
        obj = json.loads(t)
    except json.JSONDecodeError:
        return True, ""
    if isinstance(obj, dict):
        for k in ("errcode", "ret", "code"):
            v = obj.get(k)
            if isinstance(v, int) and k in obj and v not in (0, 200):
                return False, f"业务码 {k}={v}"
        if obj.get("error") and not obj.get("result"):
            return False, "jsonrpc error"
        if obj.get("success") is False or obj.get("ok") is False:
            return False, "success=false"
        if obj.get("state") in ("error", "failed"):
            return False, f"state={obj['state']}"
    return True, ""


def _shape(cap: registry.Capability, text: str) -> Any:
    """按能力声明的 response 段做结构化裁剪（I3：别把整段原文塞进模型上下文）。"""
    spec = cap.response or {}
    if not spec or not spec.get("json"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    pick = spec.get("pick")
    if pick:
        cur = obj
        for part in str(pick).split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        obj = cur
    if isinstance(obj, list):
        lim = int(spec.get("array_limit", 50))
        if len(obj) > lim:
            # W5：截断必须显式告知，否则 AI 会把「只看到 50 条」当成「总共 50 条」
            return {"items": obj[:lim], "total": len(obj), "shown": lim,
                    "truncated": True,
                    "note": f"数组共 {len(obj)} 条，此处仅前 {lim} 条；调小分页或加过滤条件"}
        return obj
    return obj


def _cap_from_row(row: dict) -> registry.Capability:
    cfg = row.get("config") or {}
    return registry.Capability(
        name=row["name"], kind=row["kind"], description=row.get("description", ""),
        read_only=bool(row.get("read_only", True)),
        require_confirm=bool(row.get("require_confirm", False)),
        enabled=bool(row.get("enabled", True)),
        secret_refs=row.get("secret_refs") or [],
        input_schema=row.get("input_schema") or {},
        http=(cfg.get("http") or {}), exec=(cfg.get("exec") or {}),
        rotate=(cfg.get("rotate") or {}), response=(cfg.get("response") or {}),
        tags=row.get("tags") or [], source=row.get("source", ""),
    )
