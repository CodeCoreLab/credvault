"""crypto.py — KEK→DEK 信封加密 + 文件权限收紧

为什么不是「一把 MASTER_KEY 直接包所有值」（v0.1 的现状）：
  - 换密钥要重加密全库，且无法按凭据吊销
  - DEK 泄露只影响一条凭据；KEK 轮换只重包 DEK（O(n) 小数据）

层级：
  KEK（file 0600 / env base64）──包裹──> DEK（每凭据一把）──AES-256-GCM──> 明文
  KEK 永不出现在密文库；wrapped_dek 与密文同库，单独泄露无用。
"""
from __future__ import annotations

import base64
import os
import secrets
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEK_LEN = 32
NONCE_LEN = 12
KEK_VERSION = 1


class CryptoError(RuntimeError):
    pass


# ── 文件权限 ────────────────────────────────────────────────────────────
def harden(path: Path) -> tuple[bool, str]:
    """POSIX: 600；Windows: icacls 移除继承只授当前用户（os.chmod 不生效，实测）。"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            user = os.environ.get("USERNAME") or ""
            if not user:
                return False, "无 USERNAME"
            r = subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                capture_output=True, encoding="gb18030", errors="replace", timeout=15)
            return (r.returncode == 0), (f"icacls rc={r.returncode}" if r.returncode else "ACL 已收紧")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return True, "600"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"{type(e).__name__}: {e}"


def perm_ok(path: Path) -> tuple[bool, str]:
    try:
        if os.name == "nt":
            # 当前行为：恒返回 (True, "windows-acl") —— os.chmod 在 Windows 只动
            # 只读位，权限实际由 ACL 决定，这里等于不设防。改用 icacls 反查真实 ACL：
            # 1) harden() 已 /inheritance:r，若仍见继承型 ACE 说明收紧失败
            # 2) 授权主体只允许当前用户与 SYSTEM/Administrators（内置管理组）
            r = subprocess.run(["icacls", str(path)], capture_output=True,
                               encoding="gb18030", errors="replace", timeout=15)
            if r.returncode != 0:
                return False, f"icacls rc={r.returncode}"
            user = (os.environ.get("USERNAME") or "").upper()
            ok = True
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or line.endswith(str(path)) or ":" not in line:
                    # 首行是文件路径本身；其余形如 "主体:(权限)"
                    continue
                ace = line.split(":", 1)[0].strip()
                # 继承残留形如 "BUILTIN\Administrators" / "NT AUTHORITY\SYSTEM"；
                # harden() 已 /inheritance:r，出现继承型主体即未收紧
                if "\\BUILTIN" in ace.upper() or ace.upper().startswith("NT AUTHORITY"):
                    if "Administrators" in ace or "SYSTEM" in ace.upper():
                        continue
                    ok = False
                    break
                if "\\" in ace:
                    # DOMAIN\user 形式：仅当等于当前用户时放行，其余（继承残留）拒绝
                    if ace.split("\\")[-1].upper() != user:
                        ok = False
                        break
            return (ok, "windows-acl-ok" if ok else "windows-acl-loose")
        mode = path.stat().st_mode & 0o777
        return (mode & 0o077) == 0, oct(mode)
    except OSError as e:
        return False, str(e)


def write_private(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    harden(tmp)
    os.replace(tmp, path)
    harden(path)


# ── KEK ────────────────────────────────────────────────────────────────
def load_kek(source: str, path: Path | None = None, env_name: str = "CREDVAULT_KEK",
             create: bool = False) -> bytes:
    """读取 KEK。create=True 时文件缺失则生成（仅 file 源）。"""
    if source == "env":
        raw = os.getenv(env_name, "").strip()
        if not raw:
            raise CryptoError(f"$%s 为空：env 源的 KEK 必须显式提供" % env_name)
        return _decode_key(raw, env_name)
    if source != "file":
        raise CryptoError(f"不支持的 kek.source: {source}（可选 file / env）")
    if path is None:
        raise CryptoError("file 源必须给 path")
    if not path.exists():
        if not create:
            raise CryptoError(f"KEK 文件不存在: {path}（先跑 credvault init）")
        write_private(path, secrets.token_bytes(KEK_LEN))
        return path.read_bytes()
    key = path.read_bytes()
    if len(key) != KEK_LEN:
        raise CryptoError(f"KEK 长度异常 {len(key)}（应为 32）")
    ok, note = perm_ok(path)
    if not ok:
        raise CryptoError(f"KEK 文件权限过宽（{note}）：{path}")
    return key


def _decode_key(raw: str, where: str) -> bytes:
    for fn in (lambda s: base64.b64decode(s, validate=True),
               lambda s: bytes.fromhex(s)):
        try:
            k = fn(raw)
        except Exception:  # noqa: BLE001
            continue
        if len(k) == KEK_LEN:
            return k
    raise CryptoError(f"{where} 必须是 32 字节的 base64 或 hex")


# ── DEK / 信封 ──────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Sealed:
    wrapped_dek: bytes
    dek_nonce: bytes
    data_nonce: bytes
    ciphertext: bytes
    kek_version: int = KEK_VERSION


def seal(plaintext: bytes, kek: bytes) -> Sealed:
    dek = secrets.token_bytes(KEK_LEN)
    try:
        data_nonce = secrets.token_bytes(NONCE_LEN)
        ct = AESGCM(dek).encrypt(data_nonce, plaintext, b"credvault:secret")
        dek_nonce = secrets.token_bytes(NONCE_LEN)
        wrapped = AESGCM(kek).encrypt(dek_nonce, dek, b"credvault:dek")
        return Sealed(wrapped, dek_nonce, data_nonce, ct)
    finally:
        del dek


def unseal(s: Sealed, kek: bytes) -> bytes:
    try:
        dek = AESGCM(kek).decrypt(s.dek_nonce, s.wrapped_dek, b"credvault:dek")
    except InvalidTag as e:
        raise CryptoError("DEK 解包失败：KEK 不匹配或密文被改") from e
    try:
        return AESGCM(dek).decrypt(s.data_nonce, s.ciphertext, b"credvault:secret")
    except InvalidTag as e:
        raise CryptoError("凭据解密失败：密文被改或 nonce 不符") from e
    finally:
        del dek


def rewrap(s: Sealed, old_kek: bytes, new_kek: bytes) -> Sealed:
    """仅重包 DEK，不碰密文（KEK 轮换用）。"""
    dek = AESGCM(old_kek).decrypt(s.dek_nonce, s.wrapped_dek, b"credvault:dek")
    try:
        nonce = secrets.token_bytes(NONCE_LEN)
        wrapped = AESGCM(new_kek).encrypt(nonce, dek, b"credvault:dek")
        return Sealed(wrapped, nonce, s.data_nonce, s.ciphertext, KEK_VERSION)
    finally:
        del dek


def kek_strength(key: bytes) -> tuple[bool, str]:
    """KEK 弱熵体检（F2，litellm master_key_boot_check 模式）。

    三类拒绝：长度不足 / 单字节重复（全零或全 a）/ 唯一字节数过少。
    真实随机 32 字节的期望唯一字节数约 30，故阈值取 16 足够宽松。
    """
    if len(key) != KEK_LEN:
        return False, f"长度 {len(key)}（应为 {KEK_LEN}）"
    if len(set(key)) == 1:
        return False, f"全部字节相同（0x{key[0]:02x}），疑似占位符"
    if len(set(key)) < 16:
        return False, f"唯一字节数仅 {len(set(key))}，熵过低（疑似手工构造）"
    return True, f"长度 32 / 唯一字节 {len(set(key))}"


def fingerprint(plaintext: bytes) -> str:
    """外部可见指纹：只用于「这是不是同一个值」的核对，不可逆。"""
    import hashlib
    return hashlib.sha256(plaintext).hexdigest()[:12]


def new_secret(n: int = 32, alphabet: str = "") -> str:
    """生成高熵口令（避免 shell/URL 需转义的字符）。"""
    alpha = alphabet or "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alpha) for _ in range(max(8, n)))
