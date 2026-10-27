"""policy.py — 能力级授权（deny-by-default / deny 优先 / 最具体规则胜出）

与 cred_broker 的差异：授权对象从「URL+method」升级为「能力名 + 只读性」。
  为什么必须换：URL 白名单表达不了语义动作 —— 放行 /api_jsonrpc.php 之后
  AI 仍可发 host.delete；只有把动作固化成能力，最小权限才成立（R6）。

语义铁律（与旧实现一致，防止回退）：
  1. 未显式 allow 一律拒（deny_by_default）
  2. deny 命中永远胜出，即使 allow 也命中
  3. 未知字段直接报错 —— 拼错 deny 成 denny 不会静默放开
  4. 同一能力多条规则时，最具体者胜出（exact > glob > `*`），与书写顺序无关
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise SystemExit("缺依赖 pyyaml") from e

_ALLOWED_DEFAULTS = {"deny_by_default", "allow_private_upstream", "response_bytes",
                     "quota_per_min", "quota_per_day", "timeout_sec"}
_ALLOWED_AGENT = {"id", "label", "visible_credentials", "allow_exec", "capabilities",
                  "ip_allowlist", "token_hint"}
_ALLOWED_RULE = {"name", "allow", "require_approval", "constraints", "note"}
_ALLOWED_DENY = {"capability", "reason"}


class PolicyError(RuntimeError):
    pass


@dataclass
class Rule:
    name: str
    allow: bool
    require_approval: bool | None = None
    constraints: dict = field(default_factory=dict)
    note: str = ""

    @property
    def specificity(self) -> int:
        if self.name == "*":
            return 0
        if "*" in self.name or "?" in self.name:
            return 1
        return 2


@dataclass
class Agent:
    id: str
    label: str = ""
    visible_credentials: list[str] | None = None      # None = 全部可见
    allow_exec: bool = False
    ip_allowlist: list[str] | None = None
    rules: list[Rule] = field(default_factory=list)


@dataclass
class Verdict:
    allow: bool
    reason: str
    needs_approval: bool = False
    rule: str = ""
    constraints: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"allow": self.allow, "reason": self.reason,
                "needs_approval": self.needs_approval, "rule": self.rule}


class Policy:
    def __init__(self, raw: dict, source: Path | None = None):
        self.source = source
        _strict_keys(raw, {"version", "defaults", "agents", "deny"}, "顶层")
        d = raw.get("defaults") or {}
        _strict_keys(d, _ALLOWED_DEFAULTS, "defaults")
        self.deny_by_default = bool(d.get("deny_by_default", True))
        self.allow_private_upstream = bool(d.get("allow_private_upstream", False))
        self.response_bytes = int(d.get("response_bytes", 32768))
        self.timeout_sec = int(d.get("timeout_sec", 20))
        self.quota_per_min = int(d.get("quota_per_min", 60))
        self.quota_per_day = int(d.get("quota_per_day", 2000))

        self.deny: list[tuple[str, str]] = []
        for item in raw.get("deny") or []:
            _strict_keys(item, _ALLOWED_DENY, "deny 条目")
            self.deny.append((item.get("capability", "*"), item.get("reason", "全局禁用")))

        self.agents: dict[str, Agent] = {}
        for a in raw.get("agents") or []:
            _strict_keys(a, _ALLOWED_AGENT, "agent 条目")
            rules = []
            for r in a.get("capabilities") or []:
                _strict_keys(r, _ALLOWED_RULE, f"agent {a.get('id')} 的规则")
                rules.append(Rule(name=r.get("name", "*"), allow=bool(r.get("allow", False)),
                                  require_approval=r.get("require_approval"),
                                  constraints=r.get("constraints") or {},
                                  note=r.get("note", "")))
            vis = a.get("visible_credentials", None)
            self.agents[a["id"]] = Agent(
                id=a["id"], label=a.get("label", ""),
                visible_credentials=None if vis is None else list(vis),
                allow_exec=bool(a.get("allow_exec", False)),
                ip_allowlist=(None if a.get("ip_allowlist") is None
                              else list(a["ip_allowlist"])),
                rules=rules)

    # ── 判定 ──
    def evaluate(self, agent_id: str, capability: str, *, read_only: bool = True,
                 require_confirm: bool = False, is_exec: bool = False,
                 kill_switch: bool = False) -> Verdict:
        ag = self.agents.get(agent_id)
        if ag is None:
            return Verdict(False, f"未知 agent {agent_id}（未在策略登记）")

        for pat, reason in self.deny:
            if fnmatch.fnmatchcase(capability, pat):
                return Verdict(False, f"命中全局 deny [{pat}]：{reason}")

        if is_exec and not ag.allow_exec:
            return Verdict(False, "该 agent 未开启 allow_exec（exec 注入默认关闭）")

        if kill_switch and not read_only:
            return Verdict(False, "Kill Switch 已开启：只读能力放行，写能力一律拒绝")

        matched = [r for r in ag.rules if fnmatch.fnmatchcase(capability, r.name)]
        if not matched:
            if self.deny_by_default:
                return Verdict(False, f"能力 {capability} 未被授权（deny-by-default）")
            return Verdict(True, "默认放行（策略允许）", require_confirm)

        best = max(matched, key=lambda r: r.specificity)
        if not best.allow:
            return Verdict(False, f"规则 [{best.name}] 显式拒绝" + (f"：{best.note}" if best.note else ""))
        need = best.require_approval if best.require_approval is not None else require_confirm
        return Verdict(True, f"规则 [{best.name}] 放行", bool(need),
                       rule=best.name, constraints=best.constraints)

    @staticmethod
    def check_arg_limits(constraints: dict, args: dict) -> tuple[bool, str]:
        """参数级约束（F3，warden 参数级策略）。

        `constraints.arg_limits` 形如：
            arg_limits:
              limit:  {max: 100}                       # 数值上限
              filter: {max_len: 16, pattern: "^[a-z]+$"} # 长度与形态
              method: {enum: ["a", "b"]}               # 枚举
        只对**实际提供的参数**生效（缺省参数由 schema default 管）。
        """
        limits = (constraints or {}).get("arg_limits") or {}
        for name, spec in limits.items():
            if name not in args or args[name] is None:
                continue
            v = args[name]
            if not isinstance(spec, dict):
                return False, f"arg_limits.{name} 配置非法（应为映射）"
            if "max" in spec:
                num = v if isinstance(v, (int, float)) else (
                    int(v) if isinstance(v, str) and v.isdigit() else None)
                if num is None:
                    return False, f"参数 {name} 非数值，无法应用 max={spec['max']}"
                if num > spec["max"]:
                    return False, f"参数 {name}={num} 超过上限 {spec['max']}"
            if "min" in spec and isinstance(v, (int, float)) and v < spec["min"]:
                return False, f"参数 {name}={v} 低于下限 {spec['min']}"
            if isinstance(v, str):
                if "max_len" in spec and len(v) > int(spec["max_len"]):
                    return False, f"参数 {name} 长度 {len(v)} 超过 {spec['max_len']}"
                if spec.get("pattern"):
                    import re as _re
                    try:
                        if not _re.search(spec["pattern"], v):
                            return False, f"参数 {name} 不匹配 pattern {spec['pattern']}"
                    except _re.error:
                        pass
            if spec.get("enum") and v not in spec["enum"]:
                return False, f"参数 {name}={v!r} 不在允许值 {spec['enum']}"
        return True, ""

    def visible_credentials(self, agent_id: str) -> list[str] | None:
        ag = self.agents.get(agent_id)
        return None if ag is None else ag.visible_credentials

    def ip_allowed(self, agent_id: str, ip: str) -> bool:
        ag = self.agents.get(agent_id)
        if ag is None or not ag.ip_allowlist:
            return True
        return any(fnmatch.fnmatchcase(ip, p) for p in ag.ip_allowlist)

    def describe(self, agent_id: str) -> dict:
        ag = self.agents.get(agent_id)
        if ag is None:
            return {}
        return {"id": ag.id, "label": ag.label,
                "visible_credentials": ag.visible_credentials,
                "allow_exec": ag.allow_exec,
                "ip_allowlist": ag.ip_allowlist,
                "rules": [{"name": r.name, "allow": r.allow,
                           "require_approval": r.require_approval} for r in ag.rules]}


def _strict_keys(d: dict, allowed: set[str], where: str) -> None:
    if not isinstance(d, dict):
        raise PolicyError(f"{where} 必须是映射")
    unknown = set(d) - allowed
    if unknown:
        raise PolicyError(f"{where} 含未知字段 {sorted(unknown)}（可用: {sorted(allowed)}）")


def load(path: Path) -> Policy:
    p = Path(path)
    if not p.is_file():
        raise PolicyError(f"策略文件不存在: {p}")
    raw: Any = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise PolicyError("策略文件顶层必须是映射")
    return Policy(raw, p)


def check(path: Path) -> list[str]:
    """策略体检：返回告警清单（不抛异常，供 CLI/policy-check 用）。"""
    warn: list[str] = []
    pol = load(path)
    if not pol.agents:
        warn.append("策略里没有任何 agent —— 所有调用都会被拒")
    for aid, ag in pol.agents.items():
        if not ag.rules:
            warn.append(f"agent {aid} 没有任何能力规则 —— 全部请求都会 deny-by-default")
        for r in ag.rules:
            if r.allow and r.name == "*" and r.require_approval is not True:
                warn.append(f"agent {aid} 用 `*` 全量放行且不需审批，等于无最小权限")
    if not pol.deny:
        warn.append("deny 列表为空 —— 建议至少加一条不可逆动作的通配 deny")
    return warn
