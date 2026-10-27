"""redact.py — 脱敏引擎（规则可配 + 值形态穷举 + 预算裁剪）

三条原则：
  1. **值形态穷举**：明文本身、URL 编码、JSON 转义、base64 三种变体都要清
     （只清原值会被 `urlencode` / `json.dumps` 绕过）
  2. **规则可配**：内置 7 条通用规则，配置追加自定义正则，且**只删命中行内容不删全文**
  3. **预算裁剪**：返回体按 max_bytes 硬截断，并附结构化摘要（I3）
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse

DEFAULT_PATTERNS: list[tuple[str, str]] = [
    ("bearer", r"(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("uuid_key", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    ("gh_token", r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}"),
    ("sk_token", r"\b(?:sk|pk|rk)[-_](?:live|test)[-_][A-Za-z0-9]{10,}"),
    ("kv_secret", r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
                  r"\s*[=:]\s*[\"']?([^\s\"'&,;]{6,})"),
    ("pem_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{20,}?-----END [A-Z ]*PRIVATE KEY-----"),
]

MASK = "[REDACTED:%s]"


def value_forms(secret: str) -> list[str]:
    """一条明文的所有常见泄露形态（去重、只留长度 ≥6 的）。"""
    if not secret:
        return []
    forms = {
        secret,
        urllib.parse.quote(secret, safe=""),
        urllib.parse.quote_plus(secret),
        json.dumps(secret)[1:-1],
        base64.b64encode(secret.encode()).decode(),
        base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
    }
    return [f for f in forms if len(f) >= 6]


def scrub(text: str, secrets: list[str] | None = None, max_hits: int = 200,
          extra_patterns: list[dict] | None = None) -> tuple[str, dict]:
    """返回 (清洗后文本, 统计)。stat.hits 为替换总次数。"""
    stat = {"hits": 0, "types": {}, "truncated_hits": False}
    if not text:
        return text, stat
    out = text

    def _bump(kind: str) -> None:
        stat["hits"] += 1
        stat["types"][kind] = stat["types"].get(kind, 0) + 1
        if stat["hits"] >= max_hits:
            stat["truncated_hits"] = True

    # 1) 值形态（本次用到的那条凭据，优先级最高）
    for s in secrets or []:
        for form in value_forms(s):
            if stat["hits"] >= max_hits:
                break
            if form in out:
                n = out.count(form)
                out = out.replace(form, MASK % "value")
                for _ in range(min(n, max_hits - (stat["hits"] - 1))):
                    _bump("value")

    # 2) 规则（内置 + 自定义）
    for name, pat in DEFAULT_PATTERNS:
        if stat["hits"] >= max_hits:
            break
        rx = re.compile(pat)

        def _sub(m: re.Match, _n: str = name) -> str:
            if stat["hits"] >= max_hits:
                return m.group(0)
            _bump(_n)
            return MASK % _n

        out = rx.sub(_sub, out)

    for item in extra_patterns or []:
        if stat["hits"] >= max_hits:
            break
        name = item.get("name") or "custom"
        try:
            rx = re.compile(item.get("pattern") or "")
        except re.error:
            continue
        out = rx.sub(lambda m, _n=name: (_bump(_n), MASK % _n)[1], out)

    return out, stat


def shrink(text: str, max_bytes: int) -> tuple[str, dict]:
    """按字节预算裁剪，附结构化摘要（给模型看的「还有多少」）。"""
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text, {"truncated": False, "bytes": len(raw), "lines": text.count("\n") + 1}
    head_n = max(256, max_bytes - 256)
    head = raw[:head_n].decode("utf-8", errors="ignore")
    dropped = len(raw) - head_n
    note = (f"\n\n... [响应被裁剪：共 {len(raw)} 字节，只返回前 {head_n} 字节，"
            f"省略 {dropped} 字节 / 约 {text.count(chr(10)) + 1} 行中的尾部]")
    return head + note, {"truncated": True, "bytes": len(raw),
                         "kept_bytes": head_n, "dropped_bytes": dropped,
                         "lines": text.count("\n") + 1}


def preview(value: str, keep: int = 4) -> str:
    """给审计/审批用的值预览：只露头尾各 keep 字符。"""
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}…{value[-keep:]}(len={len(value)})"
