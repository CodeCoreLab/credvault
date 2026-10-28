#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""打包 credvault 源码压缩包（供产品页下载）。

用法：
    python web/make_dist.py --out <输出目录> [--version 1.2.0] [--name credvault]

产物：
    <输出目录>/credvault-<version>-src.zip

设计约束（与 alert-sift/web/make_dist.py 同构，但独立实现 —— 两个仓互不依赖）：
  * 内容取自 **git 已跟踪文件**（git ls-files），天然排除 __pycache__/.env/.db
    等运行期产物与本地未跟踪文件，不会把本地脏文件打进包。
  * 排除 .github/（CI 配置与分发无关）、CHANGELOG.md、LICENSE
    以及打包工具自身 —— 对齐 v1.2.0 已发布包的 45 文件结构。
  * 包内做一次敏感信息自检，命中即中止 —— 防止把本地临时改动里的
    真实内网地址 / 凭据带进公开可下载的包。
  * zip 内文件统一 LF 换行；顶层单一目录 credvault-<version>/；
    时间戳固定，保证同版本产物可复现。
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 排除的路径前缀 / 精确文件名
EXCLUDE_PREFIXES = (".github/",)
EXCLUDE_NAMES = {"CHANGELOG.md", "LICENSE", "web/make_dist.py"}

# zip 内时间戳固定，保证同版本产物可复现
FIXED_DATE = (2026, 1, 1, 0, 0, 0)

# 示例值白名单：RFC 5737 文档专用网段（192.0.2.0/24、198.51.100.0/24、
# 203.0.113.0/24）—— 业界标准保留段，用作示例天然自证非真实地址。
EXAMPLE_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

# 敏感信息自检规则：命中即打包中止。
# 不使用行首锚定的正则 —— 「注释里出现示例」与「真值」必须能区分开。
#
# 每条规则可选带 skip_dirs：该目录下的命中视为「测试固件里的构造性假值」，
# 不算泄露。豁免是**按规则粒度**的，不是整目录放行 ——
# 例如测试目录里的 IP / 私钥串是构造出来的假值，但测试目录里若出现
# 真实内网域名或带口令的数据库连接串，仍然必须拦下。
SENSITIVE_RULES = [
    ("内网 IP", re.compile(r"\b(?:10|172|192|198|203)\.(?:\d{1,3}\.){2}\d{1,3}\b"),
     ("tests/",)),
    ("内部域名", re.compile(r"\b[a-z0-9.-]*\.gf\.com\.cn\b"), ()),
    ("凭据赋值", re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\"'][^\"']{6,}"),
     ("tests/",)),
    ("webhook 明文 key", re.compile(r"webhook/send\?key=[A-Za-z0-9_\-]{8,}"), ()),
    ("SSH 私钥", re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"), ("tests/",)),
    ("数据库连接串", re.compile(
        r"(?i)\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s'\"]+:[^\s'\"]+@"), ()),
]


def tracked_files(repo: str) -> list[str]:
    """取 git 已跟踪文件（相对仓库根）。"""
    try:
        out = subprocess.run(
            ["git", "-C", repo, "ls-files", "-z"],
            capture_output=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"✗ 无法执行 git ls-files: {exc}")
        return []
    return [p for p in out.decode("utf-8").split("\0") if p]


def is_excluded(rel: str) -> bool:
    if rel in EXCLUDE_NAMES:
        return True
    return any(rel.startswith(p) for p in EXCLUDE_PREFIXES)


def scan_sensitive(files: list[tuple[str, bytes]]) -> list[str]:
    """对将写入 zip 的内容做敏感信息扫描。"""
    hits = []
    for rel, data in files:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue  # 二进制文件跳过
        for rule in SENSITIVE_RULES:
            label, pattern = rule[0], rule[1]
            skip_dirs = rule[2] if len(rule) > 2 else ()
            if any(rel.startswith(d) for d in skip_dirs):
                continue
            for m in pattern.finditer(text):
                value = m.group(0)
                if label == "内网 IP" and value.startswith(EXAMPLE_NETS):
                    continue  # RFC 5737 示例段，跳过
                hits.append(f"{rel}: {label} -> {value[:60]}")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="打包 credvault 源码压缩包")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--version", default="1.2.0", help="版本号（用于文件名与包内目录名）")
    ap.add_argument("--name", default="credvault", help="包名前缀")
    args = ap.parse_args()

    repo = ROOT
    if not os.path.isdir(os.path.join(repo, ".git")):
        print(f"✗ 不是 git 仓库目录: {repo}")
        return 1

    tracked = tracked_files(repo)
    if not tracked:
        print("✗ 未取到任何已跟踪文件")
        return 1

    print("=" * 58)
    print(f"  打包 {args.name} {args.version} 源码包")
    print("=" * 58)

    # ---- 1) 收集文件 ----
    payload: list[tuple[str, bytes]] = []
    for rel in sorted(tracked):
        if is_excluded(rel):
            continue
        src = os.path.join(repo, rel)
        if not os.path.isfile(src):
            print(f"  ! 跳过缺失文件: {rel}")
            continue
        with open(src, "rb") as f:
            data = f.read()
        # 统一 LF：源码不应带 CRLF，避免在 Linux 上产生差异
        data = data.replace(b"\r\n", b"\n")
        payload.append((rel, data))

    print(f"  纳入文件 {len(payload)} 个"
          f"（已排除 .github/、CHANGELOG.md、LICENSE 与打包工具自身）")

    # ---- 2) 敏感信息自检 ----
    hits = scan_sensitive(payload)
    if hits:
        print("\n  ✗ 敏感信息自检未通过，打包中止：")
        for h in hits[:12]:
            print("     ", h)
        print("  请先脱敏再打包")
        return 1
    print("  敏感信息自检：PASS")

    # ---- 3) 写 zip ----
    os.makedirs(args.out, exist_ok=True)
    zip_name = f"{args.name}-{args.version}-src.zip"
    zip_path = os.path.join(args.out, zip_name)
    prefix = f"{args.name}-{args.version}/"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel, data in payload:
            info = zipfile.ZipInfo(prefix + rel, date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 << 16)
            zf.writestr(info, data)

    size = os.path.getsize(zip_path)
    print(f"\n  产物: {zip_path}  ({size:,} 字节)")

    # ---- 4) 校验：可解压 + 文件数一致 + 前缀一致 ----
    with zipfile.ZipFile(zip_path) as zf:
        bad = zf.testzip()
        names = zf.namelist()
    if bad:
        print(f"  ✗ zip 完整性校验失败: {bad}")
        return 1
    if len(names) != len(payload):
        print(f"  ✗ 包内文件数不符: {len(names)} != {len(payload)}")
        return 1
    if not all(n.startswith(prefix) for n in names):
        print("  ✗ 包内路径前缀不一致")
        return 1
    print(f"  完整性校验：PASS（{len(names)} 个条目）")

    # ---- 5) 清单 ----
    print("\n  包内清单（前 12 项）:")
    for n in names[:12]:
        print("    ", n)
    if len(names) > 12:
        print(f"    ... 共 {len(names)} 项")
    print("=" * 58)
    return 0


if __name__ == "__main__":
    sys.exit(main())
