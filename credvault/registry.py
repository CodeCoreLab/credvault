"""registry.py — 能力注册表（I1：加一段 YAML = 多一个 AI 工具，不改代码）

一个能力 = 一条声明式记录，包含五件事：
  1. 语义（name / description）     —— AI 靠它选工具，不靠猜 URL
  2. 契约（input_schema）           —— 调用前校验，错参数当场拒（R8）
  3. 动作（http / exec）            —— 固定 method + path + argv，不可被参数改写（R6）
  4. 凭据（secret_ref）             —— 只写名字，值由内核注入
  5. 门禁（read_only / require_confirm / enabled）

设计取自 Sigil 的 `vault_capabilities`，并补上它缺的策略兜底（schema 严格校验、
未知字段报错、argv 白名单）。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise SystemExit("缺依赖 pyyaml") from e

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,60}$")
KINDS = {"http", "exec", "rotate"}
TOP_KEYS = {"version", "capabilities"}
CAP_KEYS = {"name", "kind", "description", "read_only", "require_confirm", "enabled",
            "secret_ref", "secret_refs", "input_schema", "http", "exec", "rotate",
            "response",
            "tags", "namespace"}
HTTP_KEYS = {"method", "base_url", "path", "inject", "headers", "query", "body_template",
             "allow_private_upstream", "content_type", "timeout_sec",
             "pin_resolved_ip"}
EXEC_KEYS = {"argv", "env_var", "argv_allowlist", "timeout_sec", "cwd"}
ROTATE_KEYS = {"credential", "adapter", "probe", "probe_args", "length"}


class RegistryError(RuntimeError):
    pass


@dataclass
class Capability:
    name: str
    kind: str
    description: str = ""
    read_only: bool = True
    require_confirm: bool = False
    enabled: bool = True
    secret_refs: list[str] = field(default_factory=list)
    input_schema: dict = field(default_factory=lambda: {"type": "object", "properties": {}})
    http: dict = field(default_factory=dict)
    exec: dict = field(default_factory=dict)
    rotate: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    source: str = ""

    # ── 对外形态 ──
    def to_spec(self) -> dict:
        return {"name": self.name, "kind": self.kind, "description": self.description,
                "read_only": self.read_only, "require_confirm": self.require_confirm,
                "enabled": self.enabled, "secret_refs": self.secret_refs,
                "input_schema": self.input_schema,
                "config": {"http": self.http, "exec": self.exec, "rotate": self.rotate,
                           "response": self.response},
                "tags": self.tags}

    def to_tool(self) -> dict:
        """MCP / OpenAI 兼容的工具描述。描述首行必须是「能做什么」，末行写只读性。"""
        desc = (self.description or self.name).strip()
        suffix = "只读" if self.read_only else "写操作"
        if self.require_confirm:
            suffix += " · 需人工审批"
        return {"name": self.name,
                "description": f"{desc}\n（{suffix}）",
                "inputSchema": self.input_schema or {"type": "object", "properties": {}}}

    # ── 参数校验 ──
    def validate(self, args: dict) -> tuple[bool, str]:
        return validate_args(self.input_schema, args)


# ── 加载 ──
def _iter_files(targets: list[str | Path]) -> list[Path]:
    out: list[Path] = []
    for t in targets:
        p = Path(t)
        if p.is_dir():
            out.extend(sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")))
        elif p.is_file():
            out.append(p)
    return out


def load(targets: list[str | Path]) -> tuple[list[Capability], list[str]]:
    """返回 (能力列表, 告警)。同名能力后者覆盖前者，重复会记一条告警。"""
    caps: dict[str, Capability] = {}
    warn: list[str] = []
    files = _iter_files(targets)
    if not files:
        warn.append("未找到任何能力文件（capabilities/*.yaml）")
    for f in files:
        raw = yaml.safe_load(Path(f).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise RegistryError(f"{f} 顶层必须是映射")
        unknown = set(raw) - TOP_KEYS
        if unknown:
            raise RegistryError(f"{f} 含未知顶层字段 {sorted(unknown)}")
        for item in raw.get("capabilities") or []:
            cap = _parse(item, str(f))
            if cap.name in caps:
                warn.append(f"能力 {cap.name} 重复定义，{f} 覆盖先前定义")
            caps[cap.name] = cap
    return list(caps.values()), warn


def _parse(item: dict, where: str) -> Capability:
    if not isinstance(item, dict):
        raise RegistryError(f"{where}: capabilities 条目必须是映射")
    unknown = set(item) - CAP_KEYS
    if unknown:
        raise RegistryError(f"{where}: 能力 {item.get('name')} 含未知字段 {sorted(unknown)}")

    name = str(item.get("name", "")).strip()
    if not NAME_RE.match(name):
        raise RegistryError(f"{where}: 能力名非法 {name!r}（须 ^[a-z][a-z0-9_]{{2,60}}$）")
    kind = str(item.get("kind", "http"))
    if kind not in KINDS:
        raise RegistryError(f"{where}: 能力 {name} 的 kind={kind} 不支持（可选 {sorted(KINDS)}）")

    refs: list[str] = []
    if item.get("secret_ref"):
        refs.append(str(item["secret_ref"]))
    refs.extend(str(x) for x in (item.get("secret_refs") or []))
    refs = list(dict.fromkeys(refs))

    cap = Capability(
        name=name, kind=kind,
        description=str(item.get("description", "")).strip(),
        read_only=bool(item.get("read_only", True)),
        require_confirm=bool(item.get("require_confirm", False)),
        enabled=bool(item.get("enabled", True)),
        secret_refs=refs,
        input_schema=item.get("input_schema") or {"type": "object", "properties": {}},
        http=item.get("http") or {},
        exec=item.get("exec") or {},
        rotate=item.get("rotate") or {},
        response=item.get("response") or {},
        tags=[str(t) for t in (item.get("tags") or [])],
        source=where,
    )

    if not cap.description:
        raise RegistryError(f"{where}: 能力 {name} 缺 description —— AI 靠它选工具，不能空")

    if kind == "http":
        h = cap.http
        bad = set(h) - HTTP_KEYS
        if bad:
            raise RegistryError(f"{where}: 能力 {name} http 段含未知字段 {sorted(bad)}")
        for k in ("method", "base_url", "path"):
            if not h.get(k):
                raise RegistryError(f"{where}: 能力 {name} 缺 http.{k}")
        if str(h["method"]).upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
            raise RegistryError(f"{where}: 能力 {name} 的 http.method 非法")
        if not str(h["path"]).startswith("/"):
            raise RegistryError(f"{where}: 能力 {name} 的 http.path 必须以 / 开头")
        inject = h.get("inject") or {}
        if inject and inject.get("type") not in ("header", "bearer", "basic", "query", "body"):
            raise RegistryError(f"{where}: 能力 {name} 的 http.inject.type 非法")
        if not cap.read_only and str(h["method"]).upper() in ("GET", "HEAD") :
            pass  # 允许 GET 但标为写操作（例如查询会触发副作用的上游），不拦
    elif kind == "rotate":
        r = cap.rotate
        bad = set(r) - ROTATE_KEYS
        if bad:
            raise RegistryError(f"{where}: 能力 {name} rotate 段含未知字段 {sorted(bad)}")
        if not r.get("credential"):
            raise RegistryError(f"{where}: 能力 {name} 缺 rotate.credential")
        if cap.require_confirm is not True:
            raise RegistryError(f"{where}: 能力 {name} 是轮换能力，必须 require_confirm: true")
        if cap.read_only:
            raise RegistryError(f"{where}: 能力 {name} 是轮换能力，必须 read_only: false")
    else:
        e = cap.exec
        bad = set(e) - EXEC_KEYS
        if bad:
            raise RegistryError(f"{where}: 能力 {name} exec 段含未知字段 {sorted(bad)}")
        if not isinstance(e.get("argv"), list) or not e["argv"]:
            raise RegistryError(f"{where}: 能力 {name} 缺 exec.argv（列表，不接受 shell 字符串）")
        if not e.get("env_var"):
            raise RegistryError(f"{where}: 能力 {name} 缺 exec.env_var")
        if not e.get("argv_allowlist"):
            raise RegistryError(f"{where}: 能力 {name} 缺 exec.argv_allowlist "
                                f"—— exec 能力必须显式声明允许执行的可执行文件")
        if not cap.read_only and not cap.require_confirm:
            raise RegistryError(f"{where}: 能力 {name} 是写操作且 exec，必须 require_confirm: true")
    return cap


# ── 模板渲染：{{ var }} / {{ var | default('x') }} / {{ var | json }} ──
_TPL = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*(?:\|\s*([a-zA-Z_]+)(?:\(([^)]*)\))?\s*)?\}\}")


class TemplateError(RuntimeError):
    pass


def _lookup(ctx: dict, dotted: str) -> Any:
    cur: Any = ctx
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(dotted)
    return cur


def _apply_filter(val: Any, filt: str | None, arg: str | None) -> Any:
    if not filt:
        return val
    if filt == "default":
        if val is None:
            return _unquote(arg or "")
        return val
    if filt == "json":
        return json.dumps(val, ensure_ascii=False)
    if filt == "upper":
        return str(val).upper()
    if filt == "lower":
        return str(val).lower()
    if filt == "int":
        try:
            return int(val)
        except (TypeError, ValueError):
            return 0
    if filt == "str":
        return str(val)
    if filt == "quote":
        return json.dumps(str(val), ensure_ascii=False)
    if filt == "raw":
        # 显式「原样嵌入」：配合 {{ var | raw }} 用于把 JSON 片段塞进 body_template
        return val
    raise TemplateError(f"未知过滤器 {filt}")


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def render(node: Any, ctx: dict) -> Any:
    """递归渲染：dict/list/str 都支持；未提供的变量若无 default 则报错（不静默留空）。"""
    if isinstance(node, dict):
        return {k: render(v, ctx) for k, v in node.items()}
    if isinstance(node, list):
        return [render(v, ctx) for v in node]
    if not isinstance(node, str):
        return node

    whole = _TPL.fullmatch(node.strip())
    if whole:
        missing_default = "default" not in (whole.group(2) or "x")
        try:
            val = _lookup(ctx, whole.group(1))
        except KeyError:
            if missing_default:
                raise TemplateError(f"模板变量缺失: {whole.group(1)}") from None
            val = None
        return _apply_filter(val, whole.group(2), whole.group(3))

    def _sub(m: re.Match) -> str:
        try:
            val = _lookup(ctx, m.group(1))
        except KeyError:
            if (m.group(2) or "") != "default":
                raise TemplateError(f"模板变量缺失: {m.group(1)}") from None
            val = None
        v = _apply_filter(val, m.group(2), m.group(3))
        return "" if v is None else str(v)

    return _TPL.sub(_sub, node)


# ── JSON Schema（子集）校验 ──
def validate_args(schema: dict, args: dict) -> tuple[bool, str]:
    if not isinstance(args, dict):
        return False, "参数必须是 JSON 对象"
    if not schema or schema.get("type") not in (None, "object"):
        return True, ""
    props: dict = schema.get("properties") or {}
    required: list = schema.get("required") or []
    extra = set(args) - set(props)
    if schema.get("additionalProperties") is False and extra:
        return False, f"未知参数 {sorted(extra)}（允许: {sorted(props)}）"
    if extra and not schema.get("additionalProperties", True):
        return False, f"未知参数 {sorted(extra)}"
    for k in required:
        if k not in args or args[k] in (None, ""):
            return False, f"缺必填参数 {k}"
    for k, v in args.items():
        spec = props.get(k) or {}
        t = spec.get("type")
        if v is None:
            continue
        if t == "string" and not isinstance(v, str):
            return False, f"参数 {k} 应为 string"
        if t == "integer" and not (isinstance(v, int) and not isinstance(v, bool)):
            return False, f"参数 {k} 应为 integer"
        if t == "number" and not isinstance(v, (int, float)):
            return False, f"参数 {k} 应为 number"
        if t == "boolean" and not isinstance(v, bool):
            return False, f"参数 {k} 应为 boolean"
        if t == "array" and not isinstance(v, list):
            return False, f"参数 {k} 应为 array"
        if t == "object" and not isinstance(v, dict):
            return False, f"参数 {k} 应为 object"
        if isinstance(v, str):
            if "maxLength" in spec and len(v) > int(spec["maxLength"]):
                return False, f"参数 {k} 超过 maxLength={spec['maxLength']}"
            if spec.get("enum") and v not in spec["enum"]:
                return False, f"参数 {k} 必须是 {spec['enum']} 之一"
            if spec.get("pattern"):
                try:
                    if not re.search(spec["pattern"], v):
                        return False, f"参数 {k} 不匹配 pattern"
                except re.error:
                    pass
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            if "minimum" in spec and v < spec["minimum"]:
                return False, f"参数 {k} 小于 minimum"
            if "maximum" in spec and v > spec["maximum"]:
                return False, f"参数 {k} 大于 maximum"
    return True, ""


def apply_defaults(schema: dict, args: dict) -> dict:
    """把 schema 里的 default 填进缺省参数（AI 少写一个字段也能跑）。"""
    out = dict(args)
    for k, spec in ((schema or {}).get("properties") or {}).items():
        if k not in out and "default" in spec:
            out[k] = spec["default"]
    return out
