"""backup.py — .cvault 备份包（PBKDF2-HMAC-SHA256 + AES-256-GCM）

与 KEK 解耦：备份包用**用户主密码**加密，可跨机迁移；
导入时用目标机的 KEK 重新封装 DEK，因此换了 KEK 也能恢复。
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = "credvault-backup"
VERSION = 1
ITER = 200_000


class BackupError(RuntimeError):
    pass


def _derive(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iterations)
    return kdf.derive(password.encode())


def _iterations(svc) -> int:
    """S3：迭代数可配（默认 200k）；提供上限保护，防误配成百万级卡死。"""
    try:
        n = int(svc.cfg.get("backup.pbkdf2_iterations") or ITER)
    except (TypeError, ValueError):
        n = ITER
    return max(100_000, min(n, 2_000_000))


def export(svc, out_path: Path, password: str) -> dict:
    if len(password or "") < 8:
        raise BackupError("主密码至少 8 位")
    iterations = _iterations(svc)
    kek = svc.kek()
    secrets = []
    for name in svc.store.list_secret_names():
        raw = svc.store.get_secret(name, kek)
        secrets.append({"name": name,
                        "value": base64.b64encode(raw).decode()})
    payload = {
        "magic": MAGIC, "version": VERSION, "exported_at": int(__import__("time").time()),
        "credentials": [{k: v for k, v in r.items() if k != "id"}
                        for r in svc.store.list_credentials()],
        "capabilities": [{k: v for k, v in r.items() if k != "id"}
                         for r in svc.store.list_capabilities(enabled_only=False)],
        "secrets": secrets,
        "agents": [{k: v for k, v in a.items() if k != "id"} for a in svc.tokens.list()],
        # 当前行为：SELECT * 连 pwd_hash 一起导出 —— PBKDF2 口令哈希随备份包跨机
        # 流转等于把离线爆破面带出门。只导非敏感三列（恢复端用 `credvault user add` 重建）
        "users": [{"name": r["name"], "role": r["role"], "created_at": r["created_at"]}
                  for r in svc.store._meta.execute(
                      "SELECT name,role,created_at FROM users")],
    }
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(password, salt, iterations)
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload, ensure_ascii=False).encode(),
                             b"credvault:backup")
    blob = {"magic": MAGIC, "version": VERSION, "kdf": "pbkdf2-sha256",
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()}
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(blob), encoding="utf-8")
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    return {"ok": True, "path": str(out), "credentials": len(payload["credentials"]),
            "secrets": len(secrets), "capabilities": len(payload["capabilities"])}


def _read(path: Path, password: str) -> dict:
    blob = json.loads(Path(path).read_text(encoding="utf-8"))
    if blob.get("magic") != MAGIC:
        raise BackupError("不是 credvault 备份包")
    if int(blob.get("version", 0)) > VERSION:
        raise BackupError(f"备份包版本 {blob.get('version')} 高于本程序支持的 {VERSION}")
    salt = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    key = _derive(password, salt, int(blob.get("iterations", ITER)))
    try:
        raw = AESGCM(key).decrypt(nonce, base64.b64decode(blob["ciphertext"]),
                                  b"credvault:backup")
    except Exception as e:  # noqa: BLE001
        raise BackupError("主密码错误或备份包被改动") from e
    return json.loads(raw.decode())


def peek(path: Path) -> dict:
    """不解密，只看头部（用于确认是不是本格式、什么版本）。"""
    blob = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: blob.get(k) for k in ("magic", "version", "kdf", "iterations")}


def restore(svc, path: Path, password: str, overwrite: bool = False) -> dict:
    payload = _read(path, password)
    kek = svc.kek()
    added = skipped = 0
    for c in payload.get("credentials") or []:
        name = c.get("name")
        if not name:
            continue
        if svc.store.get_credential(name) and not overwrite:
            skipped += 1
            continue
        svc.store.upsert_credential(
            name, kind=c.get("kind", "generic"), account=c.get("account", ""),
            remark=c.get("remark", ""), tags=c.get("tags") or [],
            expires_at=c.get("expires_at"), secret_fp=c.get("secret_fp", ""),
            allowed_capabilities=c.get("allowed_capabilities"),
            status=c.get("status", "active"))
        added += 1
    sec_ok = 0
    for s in payload.get("secrets") or []:
        name = s.get("name")
        if not name:
            continue
        if svc.store.has_secret(name) and not overwrite:
            continue
        raw = base64.b64decode(s["value"])
        svc.store.put_secret(name, raw, kek, keep_history=False, reason="restore")
        sec_ok += 1
    caps = 0
    for cp in payload.get("capabilities") or []:
        if cp.get("name"):
            svc.store.upsert_capability(cp, source="restore")
            caps += 1
    # users：V1 起备份包已剥离 pwd_hash（只含 name/role/created_at），恢复不建账号；
    # 旧版包若带 pwd_hash 字段一律忽略，不落库
    users_meta = 0
    for u in payload.get("users") or []:
        if isinstance(u, dict) and u.get("name"):
            users_meta += 1
    svc.audit.append("system", "restore", True, 0,
                     note=f"restore from {Path(path).name}: cred={added} sec={sec_ok} cap={caps}")
    svc.reload()
    return {"ok": True, "credentials_added": added, "credentials_skipped": skipped,
            "secrets_restored": sec_ok, "capabilities": caps,
            "users_in_backup": users_meta,
            "note": "token 只恢复元数据（明文哈希不可逆），需在目标机重新签发令牌；"
                    "用户账号需用 `credvault user add` 重建（备份已剥离口令哈希）"}
