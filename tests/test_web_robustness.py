"""test_web_robustness.py — Web 面回归测试（stdlib unittest，无第三方依赖）

覆盖本轮修复
- A23 `/api/audit` 的 `hours`/`limit` 非法整数不再 500（回退默认值）
- A24 会话表 `SESSIONS` 有过期清理与容量上限，不再无限增长

跑法：cd credvault && python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from credvault import config as config_mod      # noqa: E402
from credvault.service import Service           # noqa: E402

POLICY = """
version: 1
defaults:
  deny_by_default: true
  allow_private_upstream: false
  response_bytes: 4096
  quota_per_min: 5
  quota_per_day: 50
deny: []
agents:
  - id: ai
    allow_exec: true
    visible_credentials: [AUTH_TOKEN]
    capabilities:
      - {name: "*", allow: true}
"""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class WebBase(unittest.TestCase):
    def setUp(self):
        from credvault import web
        self.web = web
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        (self.home / "capabilities").mkdir(parents=True, exist_ok=True)
        (self.home / "config.yaml").write_text(
            f"home: {self.home.as_posix()}\n"
            "approval:\n  ttl_min: 5\n"
            "exec:\n  enabled: true\n"
            "web:\n  session_ttl_min: 60\n", encoding="utf-8")
        (self.home / "policy.yaml").write_text(POLICY, encoding="utf-8")
        self.cfg = config_mod.load(str(self.home / "config.yaml"))
        self.cfg.home = self.home
        self.svc = Service(self.cfg)
        self.svc.kek(create=True)
        self.svc._sync_capabilities()

        web.ensure_user(self.svc.store, "admin", "admin-pass-123")
        web.SESSIONS.clear()
        self.srv = web.make_server(self.svc, "127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.svc.close()
        self.web.SESSIONS.clear()
        self.tmp.cleanup()

    # ── 工具 ──
    def login(self, user="admin", pwd="admin-pass-123"):
        """登录并返回 (cookie 串, 响应)。"""
        data = json.dumps({"user": user, "password": pwd}).encode()
        req = urllib.request.Request(self.base + "/login", data=data,
                                     headers={"Content-Type": "application/json"})
        op = urllib.request.build_opener(_NoRedirect)
        try:
            resp = op.open(req, timeout=5)
            return resp.headers.get("Set-Cookie", ""), resp.status
        except urllib.error.HTTPError as e:
            return e.headers.get("Set-Cookie", ""), e.code

    def get_json(self, path, cookie=None):
        headers = {"Cookie": cookie} if cookie else {}
        req = urllib.request.Request(self.base + path, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"raw": raw[:200].decode("utf-8", "replace")}


# ══════════════════════════════════════════════════════════════════
# A23 —— /api/audit 非法整数参数不再 500
# ══════════════════════════════════════════════════════════════════
class TestAuditQueryTolerance(WebBase):
    def setUp(self):
        super().setUp()
        self.cookie, _ = self.login()

    def test_hours_non_numeric_not_500(self):
        st, d = self.get_json("/api/audit?hours=abc", self.cookie)
        self.assertNotEqual(st, 500, d)
        self.assertEqual(st, 200, d)
        self.assertTrue(d.get("ok"), d)

    def test_limit_non_numeric_not_500(self):
        st, d = self.get_json("/api/audit?limit=1e5", self.cookie)
        self.assertNotEqual(st, 500, d)
        self.assertEqual(st, 200, d)
        self.assertTrue(d.get("ok"), d)

    def test_both_params_non_numeric_not_500(self):
        st, d = self.get_json("/api/audit?hours=xyz&limit=abc", self.cookie)
        self.assertNotEqual(st, 500, d)
        self.assertEqual(st, 200, d)

    def test_empty_param_not_500(self):
        st, d = self.get_json("/api/audit?hours=&limit=", self.cookie)
        self.assertNotEqual(st, 500, d)
        self.assertEqual(st, 200, d)

    def test_valid_params_still_work(self):
        st, d = self.get_json("/api/audit?hours=24&limit=100", self.cookie)
        self.assertEqual(st, 200, d)
        self.assertTrue(d.get("ok"), d)
        self.assertIn("records", d)


# ══════════════════════════════════════════════════════════════════
# A24 —— SESSIONS 有过期清理与容量上限
# ══════════════════════════════════════════════════════════════════
class TestSessionTableBounds(WebBase):
    def test_expired_sessions_are_swept_on_login(self):
        """登录时应清掉已过期会话（不再只在被访问时惰性剔除）。"""
        web = self.web
        web.SESSIONS["stale-sid"] = {"user": "admin", "role": "admin",
                                     "csrf": "x", "expires_at": time.time() - 10}
        self.assertIn("stale-sid", web.SESSIONS)
        self.login()
        self.assertNotIn("stale-sid", web.SESSIONS,
                         "过期会话应在登录时被清理掉")

    def test_session_count_bounded(self):
        """连续登录不应让 SESSIONS 无限增长（超过上限时淘汰最早的）。"""
        web = self.web
        old_max = web.MAX_SESSIONS
        web.MAX_SESSIONS = 5
        try:
            for _ in range(12):
                self.login()
            self.assertLessEqual(
                len(web.SESSIONS), 5,
                f"会话数应受上限约束，实际 {len(web.SESSIONS)}")
            self.assertEqual(len(web.SESSIONS), 5)
        finally:
            web.MAX_SESSIONS = old_max

    def test_purge_sessions_helper_removes_expired(self):
        web = self.web
        web.SESSIONS["expired"] = {"user": "u", "role": "admin", "csrf": "x",
                                   "expires_at": time.time() - 1}
        web.SESSIONS["alive"] = {"user": "u", "role": "admin", "csrf": "x",
                                 "expires_at": time.time() + 3600}
        removed = web.purge_sessions()
        self.assertEqual(removed, 1)
        self.assertNotIn("expired", web.SESSIONS)
        self.assertIn("alive", web.SESSIONS)

    def test_login_still_works_after_sweep(self):
        """清扫逻辑不应破坏正常登录。"""
        cookie, st = self.login()
        self.assertEqual(st, 302)
        self.assertIn("cvsid=", cookie)
        st, d = self.get_json("/api/audit", cookie)
        self.assertEqual(st, 200, d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
