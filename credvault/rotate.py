"""rotate.py — 轮换引擎（I17：生成 → 落库 → 探针验证 → 失败自动回滚）

诚实边界（写进文档，不吹）：
  平台不知道每个上游怎么改密码，所以不假装能全自动改所有系统。
  它做三件真正有价值的事：
    ① 生成高熵新值并**带历史**落库（可回滚）
    ② 改完立刻用**声明的探针能力**实测（探测失败即视为轮换失败）
    ③ 失败自动回滚到上一版并留审计；成功则记录 new_fp 供对账
  远端投放（改 DB 密码 / 追加 authorized_keys）由能力完成 —— 能力可审计、可审批，
  比把 SSH 逻辑硬编码进轮换器更安全。

适配器：
  generic       —— 只生成并落库（密码类；上游由脚本/能力自行应用）
  ssh_keygen    —— 生成 ed25519 密钥对，私钥入库，返回公钥供分发（双钥灰度用）
"""
from __future__ import annotations

import time
import uuid

from . import crypto
from .store import now

KINDS = ("generic", "ssh_keygen")


class RotationError(RuntimeError):
    pass


def rotate(svc, credential: str, *, actor: str = "system", adapter: str = "generic",
           new_value: str = "", length: int = 32, probe_capability: str = "",
           probe_args: dict | None = None, dry_run: bool = False) -> dict:
    if adapter not in KINDS:
        raise RotationError(f"未知适配器 {adapter}（可选 {KINDS}）")
    meta = svc.store.get_credential(credential)
    if not meta:
        raise RotationError(f"凭据未登记: {credential}（先凭证录入再接轮换）")

    plan = {"credential": credential, "adapter": adapter, "actor": actor,
            "probe": probe_capability or "(无探针，仅落库)",
            "has_previous": svc.store.has_secret(credential)}
    if dry_run:
        return {"ok": True, "dry_run": True, "plan": plan,
                "hint": "这是演练：未生成新值、未改库、未调探针"}

    rid = uuid.uuid4().hex[:10]
    with svc.store.tx() as c:
        c.execute("INSERT INTO rotations(id,credential,old_fp,state,note,actor,created_at)"
                  " VALUES(?,?,?,?,?,?,?)",
                  (rid, credential, meta.get("secret_fp", ""), "running", "", actor, now()))

    public_note = ""
    if adapter == "ssh_keygen":
        new_value, public_key = _ssh_keypair()
        public_note = public_key
    elif not new_value:
        new_value = crypto.new_secret(max(16, length))
    if len(new_value) < 8:
        raise RotationError("新值过短（<8），拒绝写入")

    kek = svc.kek()
    try:
        new_fp = svc.store.put_secret(credential, new_value.encode(), kek,
                                      keep_history=True, reason=f"rotate:{rid}")
        svc.store.upsert_credential(credential, secret_fp=new_fp,
                                    kind=meta.get("kind", "generic"))
    except Exception as e:  # noqa: BLE001
        _finish(svc, rid, "failed", f"写入失败 {type(e).__name__}: {e}")
        raise RotationError(f"新值落库失败，未做任何修改: {e}") from e

    probe = {"ran": False, "ok": None, "note": ""}
    if probe_capability:
        probe = _probe(svc, probe_capability, probe_args or {})
        if not probe["ok"]:
            svc.store.rollback_secret(credential, kek)
            _finish(svc, rid, "rolled_back", f"探针失败 {probe['note'][:120]}")
            svc.audit.append(actor, "rotate", False, 0, capability=probe_capability,
                             credential=credential,
                             note=f"probe failed → rollback ({probe['note'][:120]})")
            return {"ok": False, "code": 13, "rotation_id": rid, "state": "rolled_back",
                    "reason": f"探针 {probe_capability} 失败，已自动回滚到上一版值",
                    "probe": probe}

    _finish(svc, rid, "done", "")
    svc.audit.append(actor, "rotate", True, 0, credential=credential,
                     note=f"rotated via {adapter} fp={new_fp} probe={probe['note'][:80]}")
    return {"ok": True, "rotation_id": rid, "state": "done", "credential": credential,
            "new_fp": new_fp, "adapter": adapter, "probe": probe,
            "public_key": public_note,
            "next_action": ("上游侧仍需应用新值（由对应能力/脚本执行）；"
                            "应用后跑一次探针确认，再删旧值（双钥灰度）")}


def _probe(svc, capability: str, args: dict) -> dict:
    """内部探针：绕过策略直连执行器（探针本身就是平台动作，不是 agent 请求）。"""
    cap = svc._caps_by_name.get(capability)
    if cap is None:
        return {"ran": False, "ok": False, "note": f"探针能力不存在: {capability}"}
    t0 = time.monotonic()
    try:
        r = svc._execute(cap, args, {"id": f"probe:{capability}"})
        ok = bool(r.get("ok"))
        return {"ran": True, "ok": ok,
                "note": f"{capability} {'ok' if ok else 'fail'} {int((time.monotonic()-t0)*1000)}ms",
                "status": r.get("status")}
    except Exception as e:  # noqa: BLE001
        return {"ran": True, "ok": False,
                "note": f"{capability} {type(e).__name__}: {str(e)[:120]}"}


def _finish(svc, rid: str, state: str, note: str) -> None:
    with svc.store.tx() as c:
        c.execute("UPDATE rotations SET state=?,note=?,finished_at=? WHERE id=?",
                  (state, note[:300], now(), rid))


def _ssh_keypair() -> tuple[str, str]:
    """返回 (OpenSSH 私钥文本, OpenSSH 公钥文本)。"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    k = ed25519.Ed25519PrivateKey.generate()
    priv = k.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH).decode()
    return priv, pub


def history(svc, credential: str, limit: int = 20) -> list[dict]:
    rows = svc.store._meta.execute(
        "SELECT * FROM rotations WHERE credential=? ORDER BY created_at DESC LIMIT ?",
        (credential, limit))
    return [dict(r) for r in rows]
