"""runner.py — 执行器（唯一允许出现解密明文的边界）

抽出的原因：`_execute` 及其三个 `_do_*` 是「拿到明文 → 注入 → 上游调用 → 脱敏」
的唯一场所，与装配/闸门逻辑混在一起时，审阅者很难确认"明文是否只在这里出现"。
独立成文件后，明文边界可由文件边界直接证明。

硬约束：
  1. 明文只在 `svc.kek()` 解出后存在，`finally` 清空 secrets 字典
  2. 所有返回文本必经 `redact.scrub`（含本次用到的全部凭据值）
  3. 响应体经 `redact.shrink` 按预算裁剪
"""
from __future__ import annotations

import json
import time

from . import crypto, executor, redact, registry
from .approvals import args_fp


def _svc_mod():
    """延迟导入：runner 被 service 导入，模块级 import 会成环（同 gates 约定）。"""
    from . import service as service_mod
    return service_mod

def _execute(svc, cap: registry.Capability, args: dict, agent: dict,
             on_behalf_of: str = "") -> dict:
    t0 = time.monotonic()
    kek = svc.kek()
    secrets: dict[str, str] = {}
    for ref in cap.secret_refs:
        raw = svc.store.get_secret(ref, kek)
        secrets[ref] = raw.decode("utf-8", errors="replace")
    primary = secrets.get(cap.secret_refs[0], "") if cap.secret_refs else ""

    try:
        if cap.kind == "http":
            out = svc._do_http(cap, args, secrets, primary)
        elif cap.kind == "exec":
            out = svc._do_exec(cap, args, secrets, primary)
        elif cap.kind == "rotate":
            out = svc._do_rotate(cap, args, agent)
        else:
            raise executor.ExecError(f"未知 kind {cap.kind}")
    finally:
        secrets.clear()

    text, stat = redact.scrub(out["text"], [primary] + list(secrets.values()),
                              max_hits=int(svc.cfg.get("redact.max_hits", 200)),
                              extra_patterns=svc.cfg.get("redact.patterns"))
    budget = int(svc.policy.response_bytes or svc.cfg.get("limits.response_bytes", 32768))
    text, tr = redact.shrink(text, budget)

    ok = out["ok"]
    dur = int((time.monotonic() - t0) * 1000)
    for ref in cap.secret_refs:
        svc.store.touch_credential(ref)
    rec = svc.audit.append(
        agent["id"], "invoke", ok, dur, capability=cap.name,
        credential=",".join(cap.secret_refs),
        note=(f"{out.get('note','')} scrub={stat['hits']}"
              f"{' TRUNC' if tr.get('truncated') else ''}"),
        args_fp=args_fp(cap.name, args),
        args_preview=svc._safe_args_preview(args, [primary] + list(secrets.values())),
        extra={"status": out.get("status"), "on_behalf_of": on_behalf_of})
    return {
        "ok": ok, "code": out["code"], "capability": cap.name,
        "text": text, "structured": out.get("structured"),
        "status": out.get("status"), "dur_ms": dur,
        "scrubbed": stat, "truncated": tr,
        "audit_lost": rec.get("audit_lost", False),
    }


def _do_http(svc, cap: registry.Capability, args: dict, secrets: dict, primary: str) -> dict:
    h = cap.http
    base = str(h["base_url"]).rstrip("/")
    path = str(h["path"])
    ctx = {**args, "secret": primary, "credential": primary}
    path_r = registry.render(path, ctx)
    url = base + path_r if path_r.startswith("/") else f"{base}/{path_r}"
    query = registry.render(h.get("query") or {}, {k: v for k, v in ctx.items() if k != "secret"})
    if query:
        q = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        url += ("&" if "?" in url else "?") + q

    allow_private = bool(h.get("allow_private_upstream"))
    bad, addrs = executor.resolve_and_check(url, allow_private)
    if bad:
        raise executor.ExecError(f"SSRF 拦截：{bad}")
    # pin_resolved_ip 默认 **false**：实测部分自签证书上游用 IP 建连即 TLS 握手失败，
    # 即使显式带 SNI 也不通。仅在能力显式声明 pin_resolved_ip: true 时 pin。
    pinned = ""
    if addrs and h.get("pin_resolved_ip") is True:
        pinned = addrs[0]

    headers = {str(k): str(v) for k, v in (h.get("headers") or {}).items()}
    body_obj = None
    if h.get("body_template") is not None:
        ctx_nosecret = {k: v for k, v in ctx.items() if k != "secret"}
        body_obj = registry.render(h["body_template"], ctx_nosecret)
    if cap.secret_refs:
        headers, url, body_obj = executor.apply_inject(
            headers, [], body_obj, h.get("inject") or {}, primary, url)
    headers.setdefault("Accept", "*/*")

    body = b""
    if body_obj is not None:
        if isinstance(body_obj, (dict, list)):
            body = json.dumps(body_obj, ensure_ascii=False).encode()
            headers.setdefault("Content-Type", h.get("content_type") or "application/json")
        else:
            body = str(body_obj).encode()
            headers.setdefault("Content-Type", h.get("content_type")
                               or "application/x-www-form-urlencoded")
    if len(body) > int(svc.cfg.get("limits.max_body_bytes", 262144)):
        raise executor.ExecError("请求体超过 max_body_bytes")

    method = str(h["method"]).upper()
    timeout = int(h.get("timeout_sec") or svc.policy.timeout_sec)
    status, rh, raw = executor.http_request(
        url, method, headers, body, timeout,
        retry_ok=method in ("GET", "HEAD"), pinned_host=pinned)
    text = raw.decode("utf-8", errors="replace")
    http_ok = 200 <= status < 400
    biz_ok, biz_note = _svc_mod()._business_verdict(text) if http_ok else (False, "")
    structured = _svc_mod()._shape(cap, text)
    return {"ok": http_ok and biz_ok,
            "code": (_svc_mod().E_OK if http_ok and biz_ok
                     else (_svc_mod().E_BIZ if http_ok else _svc_mod().E_NETWORK)),
            "text": text, "structured": structured, "status": status,
            "note": f"HTTP {status}" + (f" {biz_note}" if biz_note else "")}


def _do_exec(svc, cap: registry.Capability, args: dict, secrets: dict, primary: str) -> dict:
    e = cap.exec
    ctx = {**args, "secret": primary}
    argv = [str(a) for a in registry.render(list(e["argv"]), ctx)]
    rc, out, err = executor.run_exec(
        argv, {str(e["env_var"]): primary}, list(e["argv_allowlist"]),
        int(e.get("timeout_sec") or 30), str(e.get("cwd") or ""))
    text = out if rc == 0 else (out + ("\n[stderr]\n" + err if err else ""))
    return {"ok": rc == 0,
            "code": _svc_mod().E_OK if rc == 0 else _svc_mod().E_BIZ, "text": text,
            "structured": {"rc": rc}, "status": rc, "note": f"rc={rc}"}


def _do_rotate(svc, cap: registry.Capability, args: dict, agent: dict) -> dict:
    """轮换作为能力执行：受审批 + 探针 + 失败回滚（I17）。"""
    from . import rotate as rotate_mod
    cfg = cap.rotate or {}
    res = rotate_mod.rotate(
        svc, str(cfg["credential"]), actor=f"ai:{agent['id']}",
        adapter=str(cfg.get("adapter") or "generic"),
        length=int(cfg.get("length") or 32),
        probe_capability=str(cfg.get("probe") or ""),
        probe_args=cfg.get("probe_args") or args.get("probe_args") or {},
        dry_run=bool(args.get("dry_run", False)))
    return {"ok": bool(res.get("ok")),
            "code": _svc_mod().E_OK if res.get("ok") else _svc_mod().E_BIZ,
            "text": json.dumps(res, ensure_ascii=False),
            "structured": res,
            "status": res.get("state"),
            "note": f"rotate {res.get('state')}"}
