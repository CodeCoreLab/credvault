"""kinds.py — 凭据类型注册表（I8：类型决定必填字段与校验规则）

为什么要类型：`kind` 只当标签用时，AI 传错字段要到上游才炸；而类型一旦声明了
必填字段与格式，`cred set` 与导入就能当场拒掉不完整的数据。

8 个内置类型覆盖跳板机常见面；扩展只需往 KINDS 里加一条，不改代码逻辑。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Kind:
    name: str
    label: str
    required: tuple[str, ...] = ()          # 元数据必填（不是值）
    optional: tuple[str, ...] = ()          # 元数据可选
    value_pattern: str = ""                 # 值的形态校验（正则），空=不校验
    value_min_len: int = 8
    hint: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def check_value(self, value: str) -> str:
        if value is None or value == "":
            return "值为空"
        if len(value) < self.value_min_len:
            return f"值过短（<{self.value_min_len}）"
        if self.value_pattern and not re.search(self.value_pattern, value):
            return f"值不符合 {self.name} 的形态（{self.value_pattern}）"
        return ""

    def check_meta(self, account: str = "", remark: str = "") -> str:
        vals = {"account": account, "remark": remark}
        missing = [k for k in self.required if not vals.get(k)]
        if missing:
            return f"{self.name} 需要元数据 {missing}（用 --account/--remark 补）"
        return ""


KINDS: dict[str, Kind] = {
    "api_token": Kind("api_token", "API 令牌", optional=("account",),
                      value_pattern=r"^[\x21-\x7e]+$", value_min_len=12,
                      hint="Bearer/Header 注入的长期令牌", tags=("token",)),
    "webhook": Kind("webhook", "Webhook Key", optional=("remark",),
                    value_pattern=r"^[\x21-\x7e]{8,}$", value_min_len=8,
                    hint="企微/钉钉/Slack 机器人 key", tags=("token",)),
    "ssh_key": Kind("ssh_key", "SSH 私钥", required=("account",),
                    value_pattern=r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
                    value_min_len=100, hint="OpenSSH/PEM 私钥全文", tags=("ssh",)),
    "ssh_password": Kind("ssh_password", "SSH 口令", required=("account",),
                         value_min_len=8, hint="账号口令登录", tags=("ssh",)),
    "db_password": Kind("db_password", "数据库口令", required=("account",),
                        value_min_len=8, hint="MySQL/PG/Redis 口令", tags=("db",)),
    "tls_cert": Kind("tls_cert", "证书/密钥对", required=("account",),
                     value_pattern=r"-----BEGIN", value_min_len=100,
                     hint="PEM 证书或私钥", tags=("tls",)),
    "totp_seed": Kind("totp_seed", "TOTP 种子", optional=("account",),
                      value_pattern=r"^[A-Z2-7=]{16,}$", value_min_len=16,
                      hint="Base32 种子", tags=("mfa",)),
    "generic": Kind("generic", "通用口令", value_min_len=1,
                    hint="未归类（建议补 kind）", tags=("misc",)),
}


def get(name: str) -> Kind | None:
    return KINDS.get(name)


def validate(kind: str, value: str, account: str = "", remark: str = "") -> str:
    """返回错误描述；空串=通过。未知类型直接拒（避免拼错静默通过）。"""
    k = get(kind)
    if k is None:
        return f"未知凭据类型 {kind}（可选 {sorted(KINDS)}）"
    err = k.check_meta(account, remark)
    if err:
        return err
    return k.check_value(value)


def describe_all() -> list[dict]:
    return [{"name": k.name, "label": k.label, "required": list(k.required),
             "value_min_len": k.value_min_len, "hint": k.hint, "tags": list(k.tags)}
            for k in KINDS.values()]
