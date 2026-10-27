# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — 单目录可执行包（onedir，跨机器解压即跑）

为什么 onedir 而不是 onefile：onefile 每次启动要解压到临时目录，
凭据类进程不该有可被窥探的临时落盘；onedir 直接映射文件，启动也更快。
"""
import sys
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

datas = [
    ("config.example.yaml", "."),
    ("policy.yaml", "."),
    ("capabilities", "capabilities"),
]

hiddenimports = collect_submodules("cryptography") + ["yaml"] + collect_submodules("credvault.cli")

a = Analysis(
    ["credvault/__main__.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest", "pydoc", "email", "http.server"],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="credvault",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas, strip=False, upx=False,
               name="credvault")
