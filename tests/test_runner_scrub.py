"""B08 回归测试：credvault runner 的脱敏清单必须在 secrets.clear() 之前快照。

缺陷：runner._execute 里 `finally { secrets.clear(); }` 在 try 正常退出时
**先于**其后的脱敏调用执行，secrets 已清空 → `list(secrets.values())` 为空列表
→ 第 2..N 条凭据明文不参与脱敏，会随响应体和审计预览流回调用方。

覆盖：
  1. 响应体中回显的第 2 条凭据明文必须被脱敏
  2. 审计 args_preview 中回显的第 2 条凭据明文必须被脱敏
  3. 第 1 条（primary）凭据仍然脱敏（不回归）
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from credvault import config as config_mod          # noqa: E402
from credvault import registry, runner              # noqa: E402
from credvault.service import Service                # noqa: E402

POLICY = """
version: 1
defaults:
  deny_by_default: true
  allow_private_upstream: false
  response_bytes: 4096
  quota_per_min: 50
  quota_per_day: 500
agents:
  - id: ai
    allow_exec: true
    visible_credentials: [TOKEN_A, TOKEN_B]
    capabilities:
      - {name: t_two_secrets, allow: true}
      - {name: "*", allow: false}
"""

CAPS = """
version: 1
capabilities:
  - name: t_two_secrets
    kind: http
    description: 同时使用两条凭据，验证第 2 条凭据也参与脱敏。
    read_only: true
    secret_refs: [TOKEN_A, TOKEN_B]
    http:
      method: GET
      base_url: http://127.0.0.1:9
      path: /echo
      allow_private_upstream: true
      inject: {type: header, name: X-Auth}
"""

TOKEN_A = "aaa-plain-secret-value-0001"
TOKEN_B = "bbb-plain-secret-value-0002"


class _FakeStore:
    def __init__(self, values: dict[str, str]):
        self._values = values

    def get_secret(self, ref: str, kek) -> bytes:
        return self._values[ref].encode()

    def touch_credential(self, ref: str) -> None:
        pass


class _FakeSvc:
    """最小 svc 替身：只提供 runner._execute 用到的接口。"""

    def __init__(self, echoed: str,
                 values: dict[str, str] | None = None):
        self.echoed = echoed
        self.cfg = {"redact.max_hits": 200}
        self.policy = type("P", (), {"response_bytes": 4096})()
        self.store = _FakeStore(values or {"TOKEN_A": TOKEN_A, "TOKEN_B": TOKEN_B})
        self.audit = type("A", (), {"append": staticmethod(self._append)})()
        self._preview_calls: list[list[str]] = []

    def kek(self):
        return b"k" * 32

    def _append(self, *a, **kw):
        self.last_preview = kw.get("args_preview", "")
        return {}

    def _safe_args_preview(self, args: dict, secrets: list[str]) -> str:
        # 记录实际传给脱敏的明文清单：这是本缺陷的直接观测点。
        self._preview_calls.append(list(secrets))
        from credvault import redact
        raw = json.dumps(args, ensure_ascii=False, default=str)
        clean, _ = redact.scrub(raw, secrets, max_hits=200)
        return clean[:240]

    def _do_http(self, cap, args, secrets, primary):
        return {"ok": True, "code": 0, "text": self.echoed,
                "structured": None, "status": 200, "note": "HTTP 200"}


class T25RunnerScrubOrder(unittest.TestCase):
    """B08：非首位凭据必须参与脱敏。"""

    def _run(self, echoed: str, args: dict | None = None):
        svc = _FakeSvc(echoed)
        cap = registry.Capability(
            name="t_two_secrets", kind="http",
            secret_refs=["TOKEN_A", "TOKEN_B"])
        agent = {"id": "ai"}
        out = runner._execute(svc, cap, args or {}, agent)
        return svc, out

    def test_second_secret_in_response_is_scrubbed(self):
        echoed = f"response contains {TOKEN_A} and {TOKEN_B}"
        _svc, out = self._run(echoed)
        self.assertNotIn(TOKEN_B, out["text"],
                         "第 2 条凭据明文未被脱敏（secrets.clear() 早于脱敏）")
        self.assertIn("[REDACTED:value]", out["text"])

    def test_primary_secret_still_scrubbed(self):
        echoed = f"response contains {TOKEN_A} and {TOKEN_B}"
        _svc, out = self._run(echoed)
        self.assertNotIn(TOKEN_A, out["text"], "第 1 条凭据明文未被脱敏")

    def test_second_secret_in_args_preview_is_scrubbed(self):
        echoed = "ok"
        args = {"token": TOKEN_B, "note": "hello"}
        svc, _out = self._run(echoed, args)
        self.assertNotIn(TOKEN_B, svc.last_preview,
                         "审计 args_preview 含第 2 条凭据明文")

    def test_scrub_receives_all_secret_values(self):
        """直接观测脱敏入口拿到的明文清单必须包含全部两条凭据。"""
        svc, _out = self._run("ok")
        passed = svc._preview_calls[-1]
        self.assertIn(TOKEN_A, passed, "脱敏清单缺第 1 条凭据")
        self.assertIn(TOKEN_B, passed, "脱敏清单缺第 2 条凭据")


class T26RunnerRotateKind(unittest.TestCase):
    """rotate 能力没有 secret_refs 也不应因快照逻辑而崩。"""

    def test_rotate_without_secrets_still_works(self):
        svc = _FakeSvc("ok")
        cap = registry.Capability(name="t_rot", kind="rotate", secret_refs=[])
        svc._do_rotate = lambda cap, args, agent: {
            "ok": True, "code": 0, "text": "rotated", "structured": None,
            "status": 200, "note": "rotate ok"}
        out = runner._execute(svc, cap, {}, {"id": "ai"})
        self.assertTrue(out["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
