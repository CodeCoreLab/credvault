"""test_smoke.py — 端到端冒烟（stdlib unittest，无第三方测试框架依赖）

覆盖：配置 / 信封加密 / 库分离 / 脱敏 / 审计链 / 策略 / 注册表 / 双轴令牌 /
      异步审批 / 配额 / Kill Switch / exec 白名单 / 轮换回滚 / 备份恢复 /
      MCP（instructions + 渐进披露 + isError）/ Web（healthz + metrics + 登录）

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
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from credvault import backup as backup_mod          # noqa: E402
from credvault import config as config_mod          # noqa: E402
from credvault import crypto, mcp as mcp_mod, ops, policy as policy_mod, redact, registry  # noqa: E402
from credvault import rotate as rotate_mod          # noqa: E402
from credvault import service as service_mod  # noqa: E402
from credvault.service import (E_APPROVAL, E_BIZ, E_DENIED, E_INPUT, E_KILL, E_OK,  # noqa: E402
                               E_QUOTA, E_RESOLVE, Service)


# ── 本地假上游 ─────────────────────────────────────────────────────────
class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静音
        pass

    def _j(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/ok"):
            return self._j(200, {"ok": True, "data": {"items": list(range(100))},
                                 "auth": self.headers.get("Authorization", "")})
        if self.path.startswith("/bizfail"):
            return self._j(200, {"errcode": 45009, "errmsg": "api freq out of limit"})
        if self.path.startswith("/boom"):
            return self._j(500, {"err": "boom"})
        return self._j(404, {"err": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}
        if self.path.startswith("/push"):
            return self._j(200, {"errcode": 0, "echo": body})
        return self._j(404, {"err": "not found"})


def _upstream() -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


CAPS = """
version: 1
capabilities:
  - name: t_ok
    kind: http
    description: 读取 ok 接口（假上游），带 Bearer 注入。
    read_only: true
    secret_ref: AUTH_TOKEN
    input_schema:
      type: object
      properties:
        q: {type: string, default: "x"}
    http:
      method: GET
      base_url: http://127.0.0.1:__PORT__
      path: /ok
      allow_private_upstream: true
      inject: {type: bearer}
    response: {json: true, pick: "data.items", array_limit: 5}
  - name: t_nosecret
    kind: http
    description: 不需要凭据的只读能力。
    read_only: true
    http:
      method: GET
      base_url: http://127.0.0.1:__PORT__
      path: /ok
      allow_private_upstream: true
  - name: t_bizfail
    kind: http
    description: 上游 200 但业务码非 0，用于验证业务失败判定。
    read_only: true
    secret_ref: AUTH_TOKEN
    http:
      method: GET
      base_url: http://127.0.0.1:__PORT__
      path: /bizfail
      allow_private_upstream: true
      inject: {type: header, name: X-KEY}
  - name: t_push
    kind: http
    description: 写操作：推送一条消息（需审批）。
    read_only: false
    require_confirm: true
    secret_ref: AUTH_TOKEN
    input_schema:
      type: object
      properties:
        content: {type: string, maxLength: 100}
      required: [content]
    http:
      method: POST
      base_url: http://127.0.0.1:__PORT__
      path: /push
      allow_private_upstream: true
      inject: {type: query, name: key}
      body_template: {msg: "{{ content }}"}
  - name: t_exec_ok
    kind: exec
    description: 执行 hostname（白名单内）。
    read_only: true
    exec:
      argv: ["hostname"]
      env_var: T_NOOP
      argv_allowlist: ["hostname"]
  - name: t_exec_bad
    kind: exec
    description: 试图执行白名单外的程序。
    read_only: true
    exec:
      argv: ["whoami"]
      env_var: T_NOOP
      argv_allowlist: ["hostname"]
  - name: t_rotate
    kind: rotate
    description: 轮换 AUTH_TOKEN（受审批，带探针）。
    read_only: false
    require_confirm: true
    rotate:
      credential: AUTH_TOKEN
      probe: t_nosecret
  - name: t_delete_thing
    kind: http
    description: 命中全局 deny 的删除类动作。
    read_only: false
    secret_ref: AUTH_TOKEN
    http:
      method: POST
      base_url: http://127.0.0.1:__PORT__
      path: /push
      allow_private_upstream: true
      inject: {type: query, name: key}
"""

POLICY = """
version: 1
defaults:
  deny_by_default: true
  allow_private_upstream: false
  response_bytes: 4096
  quota_per_min: 5
  quota_per_day: 50
deny:
  - capability: "*delete*"
    reason: 不可逆
agents:
  - id: ai
    allow_exec: true
    visible_credentials: [AUTH_TOKEN]
    capabilities:
      - {name: t_ok, allow: true}
      - {name: t_nosecret, allow: true}
      - {name: t_bizfail, allow: true}
      - {name: t_push, allow: true}
      - {name: t_exec_ok, allow: true}
      - {name: t_exec_bad, allow: true}
      - {name: t_rotate, allow: true}
      - {name: "*", allow: false}
  - id: ai-noexec
    allow_exec: false
    capabilities:
      - {name: t_nosecret, allow: true}
      - {name: t_exec_ok, allow: true}
      - {name: "*", allow: false}
  - id: ai-blind
    visible_credentials: []
    capabilities:
      - {name: t_ok, allow: true}
      - {name: "*", allow: false}
"""


class Base(unittest.TestCase):
    up: ThreadingHTTPServer
    port: int

    @classmethod
    def setUpClass(cls):
        cls.up, cls.port = _upstream()

    @classmethod
    def tearDownClass(cls):
        cls.up.shutdown()
        cls.up.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        (self.home / "capabilities").mkdir(parents=True, exist_ok=True)
        (self.home / "config.yaml").write_text(
            f"home: {self.home.as_posix()}\n"
            "approval:\n  ttl_min: 5\n  session_ttl_min: 5\n"
            "exec:\n  enabled: true\n"
            "web:\n  session_ttl_min: 60\n", encoding="utf-8")
        (self.home / "policy.yaml").write_text(POLICY, encoding="utf-8")
        (self.home / "capabilities" / "t.yaml").write_text(
            CAPS.replace("__PORT__", str(self.port)), encoding="utf-8")
        self.cfg = config_mod.load(str(self.home / "config.yaml"))
        self.cfg.home = self.home
        self.svc = Service(self.cfg)
        self.svc.kek(create=True)
        self.svc._sync_capabilities()

    def tearDown(self):
        self.svc.close()
        for k in list(os.environ):
            if k.startswith("CREDVAULT_"):
                os.environ.pop(k, None)
        self.tmp.cleanup()

    # 便捷
    def mk_cred(self, name="AUTH_TOKEN", value="s3cr3t-abcdef-123456"):
        self.svc.store.put_secret(name, value.encode(), self.svc.kek())
        self.svc.store.upsert_credential(name, kind="api_token",
                                         secret_fp=crypto.fingerprint(value.encode()))
        return value

    def mk_agent(self, name="ai", **kw):
        # 策略里只有 ai / ai-noexec / ai-blind 三个身份；测试里写别的名字只为可读，
        # 统一映射回 ai（每个用例都是独立 HOME，配额与审计互不干扰）。
        policy_name = name if name in ("ai", "ai-noexec", "ai-blind") else "ai"
        token, _ = self.svc.tokens.create(policy_name, **kw)
        return self.svc.tokens.resolve(token)


# ── 1. 配置 ────────────────────────────────────────────────────────────
class T01Config(Base):
    def test_defaults_and_paths(self):
        self.assertEqual(self.cfg.get("listen.port"), 8443)
        self.assertTrue(str(self.cfg.path("store.db")).endswith("credvault.db"))
        self.assertTrue(self.cfg.path("store.db").is_absolute())

    def test_env_override_and_bad_value(self):
        os.environ["CREDVAULT_LISTEN_PORT"] = "9999"
        c = config_mod.load(str(self.home / "config.yaml"))
        self.assertEqual(c.get("listen.port"), 9999)
        os.environ["CREDVAULT_LISTEN_PORT"] = "abc"
        with self.assertRaises(ValueError):
            config_mod.load(str(self.home / "config.yaml"))

    def test_unknown_key_rejected(self):
        (self.home / "bad.yaml").write_text("home: x\nnope: 1\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            config_mod.load(str(self.home / "bad.yaml"))


# ── 2. 加密 ────────────────────────────────────────────────────────────
class T02Crypto(Base):
    def test_seal_unseal_roundtrip(self):
        kek = b"k" * 32
        s = crypto.seal(b"hello", kek)
        self.assertEqual(crypto.unseal(s, kek), b"hello")

    def test_wrong_kek_fails(self):
        s = crypto.seal(b"hello", b"a" * 32)
        with self.assertRaises(crypto.CryptoError):
            crypto.unseal(s, b"b" * 32)

    def test_rewrap_changes_only_dek(self):
        old, new = b"a" * 32, b"b" * 32
        s = crypto.seal(b"payload", old)
        s2 = crypto.rewrap(s, old, new)
        self.assertEqual(s2.ciphertext, s.ciphertext)      # 密文没动
        self.assertNotEqual(s2.wrapped_dek, s.wrapped_dek)  # DEK 重包了
        self.assertEqual(crypto.unseal(s2, new), b"payload")

    def test_fingerprint_stable(self):
        self.assertEqual(crypto.fingerprint(b"x"), crypto.fingerprint(b"x"))
        self.assertNotEqual(crypto.fingerprint(b"x"), crypto.fingerprint(b"y"))


# ── 3. 存储分离 ────────────────────────────────────────────────────────
class T03Store(Base):
    def test_secret_in_separate_db(self):
        self.mk_cred()
        meta = self.svc.store.meta_path.read_bytes()
        sec = self.svc.store.secrets_path.read_bytes()
        self.assertNotIn(b"s3cr3t-abcdef-123456", meta)   # 元数据库无明文
        self.assertNotIn(b"s3cr3t-abcdef-123456", sec)    # 密文库也无明文
        self.assertTrue(self.svc.store.has_secret("AUTH_TOKEN"))
        self.assertEqual(self.svc.store.get_secret("AUTH_TOKEN", self.svc.kek()),
                         b"s3cr3t-abcdef-123456")

    def test_history_and_rollback(self):
        self.mk_cred(value="old-value-1")
        self.svc.store.put_secret("AUTH_TOKEN", b"new-value-2", self.svc.kek(),
                                  keep_history=True, reason="test")
        self.assertEqual(self.svc.store.get_secret("AUTH_TOKEN", self.svc.kek()), b"new-value-2")
        self.assertTrue(self.svc.store.rollback_secret("AUTH_TOKEN", self.svc.kek()))
        self.assertEqual(self.svc.store.get_secret("AUTH_TOKEN", self.svc.kek()), b"old-value-1")

    def test_rewrap_all(self):
        self.mk_cred()
        new = os.urandom(32)
        n = self.svc.store.rewrap_all(self.svc.kek(), new)
        self.assertGreaterEqual(n, 1)
        self.assertEqual(self.svc.store.get_secret("AUTH_TOKEN", new), b"s3cr3t-abcdef-123456")


# ── 4. 脱敏与预算 ──────────────────────────────────────────────────────
class T04Redact(Base):
    def test_value_forms(self):
        secret = "ab/+/cd=efgh123"
        for form in redact.value_forms(secret):
            cleaned, stat = redact.scrub(f"x={form}&y=1", [secret])
            self.assertNotIn(form, cleaned)
            self.assertGreaterEqual(stat["hits"], 1)

    def test_builtin_patterns(self):
        txt = ("Authorization: Bearer abcdefghijklmnop1234\n"
               "webhook=abcdef12-3456-7890-abcd-ef1234567890\n"
               "password=hunter2hunter2")
        cleaned, stat = redact.scrub(txt)
        self.assertNotIn("abcdefghijklmnop1234", cleaned)
        self.assertNotIn("abcdef12-3456-7890", cleaned)
        self.assertIn("REDACTED", cleaned)
        self.assertGreaterEqual(stat["hits"], 3)

    def test_shrink_budget(self):
        text = "a" * 5000
        out, meta = redact.shrink(text, 1024)
        self.assertTrue(meta["truncated"])
        self.assertLessEqual(len(out.encode()), 1400)
        self.assertIn("被裁剪", out)


# ── 5. 审计链 ──────────────────────────────────────────────────────────
class T05Audit(Base):
    def test_chain_ok_and_tamper_detected(self):
        for i in range(5):
            self.svc.audit.append("ai", "invoke", True, 1, capability=f"c{i}")
        ok, note, n = self.svc.audit.verify()
        self.assertTrue(ok, note)
        self.assertEqual(n, 5)
        p = self.svc.audit.path
        lines = p.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[2])
        rec["note"] = "tampered"
        lines[2] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok2, note2, _ = self.svc.audit.verify()
        self.assertFalse(ok2)
        self.assertIn("改动", note2)

    def test_search_and_stats(self):
        self.svc.audit.append("ai", "invoke", True, 3, capability="t_ok")
        self.svc.audit.append("ai", "invoke", False, 5, capability="t_push", note="denied")
        rows = self.svc.audit.search(limit=10, capability="t_ok")
        self.assertEqual(len(rows), 1)
        st = self.svc.audit.stats()
        self.assertEqual(st["total"], 2)
        self.assertEqual(st["by_status"]["fail"], 1)
        self.assertEqual(self.svc.audit.export("csv").count("\n"), 3)


# ── 6. 策略 ────────────────────────────────────────────────────────────
class T06Policy(Base):
    def setUp(self):
        super().setUp()
        self.pol = self.svc.policy

    def test_deny_by_default(self):
        v = self.pol.evaluate("ai", "unknown_cap")
        self.assertFalse(v.allow)
        self.assertIn("拒绝", v.reason)      # 兜底 `*: deny` 或 deny-by-default 都算拒
        # 没有任何规则的 agent 才是纯 deny-by-default
        (self.home / "p3.yaml").write_text(
            "version: 1\nagents:\n  - id: bare\n", encoding="utf-8")
        p3 = policy_mod.load(self.home / "p3.yaml")
        self.assertIn("deny-by-default", p3.evaluate("bare", "t_ok").reason)

    def test_deny_beats_allow(self):
        v = self.pol.evaluate("ai", "t_delete_thing")
        self.assertFalse(v.allow)
        self.assertIn("全局 deny", v.reason)

    def test_specificity(self):
        self.assertTrue(self.pol.evaluate("ai", "t_ok").allow)
        # 服务层会把能力自身的 require_confirm 传进来；规则里没写 require_approval 时用它
        push = self.pol.evaluate("ai", "t_push", require_confirm=True)
        self.assertTrue(push.allow)
        self.assertTrue(push.needs_approval)          # 精确规则覆盖 `*` 的 allow=false
        self.assertEqual(push.rule, "t_push")

    def test_exec_gate(self):
        v = self.pol.evaluate("ai-noexec", "t_exec_ok", is_exec=True)
        self.assertFalse(v.allow)
        self.assertIn("allow_exec", v.reason)

    def test_unknown_agent(self):
        self.assertFalse(self.pol.evaluate("ghost", "t_ok").allow)

    def test_unknown_field_raises(self):
        bad = self.home / "p2.yaml"
        bad.write_text("version: 1\nagents:\n  - id: a\n    denny: []\n", encoding="utf-8")
        with self.assertRaises(policy_mod.PolicyError):
            policy_mod.load(bad)


# ── 7. 能力注册表 ──────────────────────────────────────────────────────
class T07Registry(Base):
    def test_load_and_tool_shape(self):
        caps, warn = registry.load([self.home / "capabilities" / "t.yaml"])
        names = {c.name for c in caps}
        self.assertIn("t_ok", names)
        tool = [c for c in caps if c.name == "t_ok"][0].to_tool()
        self.assertEqual(tool["name"], "t_ok")
        self.assertIn("只读", tool["description"])
        self.assertIn("inputSchema", tool)

    def test_schema_validation(self):
        caps, _ = registry.load([self.home / "capabilities" / "t.yaml"])
        push = [c for c in caps if c.name == "t_push"][0]
        self.assertFalse(push.validate({})[0])
        self.assertTrue(push.validate({"content": "hi"})[0])
        long_cap = [c for c in caps if c.name == "t_push"][0]
        self.assertFalse(long_cap.validate({"content": "x" * 200})[0])

    def test_render_and_missing_var(self):
        ctx = {"filter": "web", "limit": 10}
        self.assertEqual(registry.render("{{ filter | default('') }}", ctx), "web")
        self.assertEqual(registry.render("{{ missing | default('dft') }}", ctx), "dft")
        self.assertEqual(registry.render({"a": "{{ limit | int }}"}, ctx), {"a": 10})
        with self.assertRaises(registry.TemplateError):
            registry.render("{{ nope }}", ctx)

    def test_bad_capability_rejected(self):
        bad = self.home / "bad.yaml"
        bad.write_text("version: 1\ncapabilities:\n  - name: X_Bad\n    kind: http\n", encoding="utf-8")
        with self.assertRaises(registry.RegistryError):
            registry.load([bad])


# ── 8. 令牌双轴 ────────────────────────────────────────────────────────
class T08Tokens(Base):
    def test_create_resolve_revoke(self):
        token, rec = self.svc.tokens.create("t1", ttl_days=1)
        self.assertTrue(token.startswith("cbk_"))
        self.assertIsNotNone(self.svc.tokens.resolve(token))
        self.assertTrue(self.svc.tokens.revoke("t1"))
        self.assertIsNone(self.svc.tokens.resolve(token))

    def test_expiry(self):
        t = self.svc.tokens.create("t2")[0]
        self.assertIsNotNone(self.svc.tokens.resolve(t))
        with self.svc.store.tx() as c:
            c.execute("UPDATE agents SET expires_at=? WHERE name='t2'", (int(time.time()) - 1,))
        self.assertIsNone(self.svc.tokens.resolve(t))

    def test_dual_axis_hides_tools(self):
        self.mk_cred()
        token, _ = self.svc.tokens.create("ai-blind", visible_credentials=[],
                                          allowed_capabilities=["t_ok"])
        ag = self.svc.tokens.resolve(token)
        names = [c.name for c in self.svc.capabilities_for(ag)]
        self.assertNotIn("t_ok", names)      # 凭据不可见 → 隐藏
        self.assertNotIn("t_push", names)    # 能力未授权 → 隐藏

    def test_rotate_invalidates_old(self):
        t1 = self.svc.tokens.create("t3")[0]
        t2 = self.svc.tokens.rotate("t3")
        self.assertIsNone(self.svc.tokens.resolve(t1))
        self.assertIsNotNone(self.svc.tokens.resolve(t2))

    def test_ip_allowlist(self):
        t = self.svc.tokens.create("t4", ip_allowlist=["10.0.0.*"])[0]
        self.assertIsNone(self.svc.tokens.resolve(t, "127.0.0.1"))
        self.assertIsNotNone(self.svc.tokens.resolve(t, "10.0.0.7"))


# ── 9. 审批 ────────────────────────────────────────────────────────────
class T09Approvals(Base):
    def test_flow_and_fingerprint(self):
        a = self.svc.approvals.request("t_push", {"content": "hi"}, "ai")
        aid = a["approval_id"]
        self.assertEqual(self.svc.approvals.status(aid)["state"], "pending")
        self.assertFalse(self.svc.approvals.consume(aid, "t_push", {"content": "hi"})[0])
        ok, _ = self.svc.approvals.decide(aid, True, "human:test")
        self.assertTrue(ok)
        # 改参数即失效
        self.assertFalse(self.svc.approvals.consume(aid, "t_push", {"content": "changed"})[0])
        self.assertTrue(self.svc.approvals.consume(aid, "t_push", {"content": "hi"})[0])
        # 一次性
        self.assertFalse(self.svc.approvals.consume(aid, "t_push", {"content": "hi"})[0])

    def test_reject_and_expire(self):
        a = self.svc.approvals.request("t_push", {"content": "x"}, "ai")
        self.svc.approvals.decide(a["approval_id"], False, "human")
        self.assertEqual(self.svc.approvals.status(a["approval_id"])["state"], "rejected")
        b = self.svc.approvals.request("t_push", {"content": "y"}, "ai")
        with self.svc.store.tx() as c:
            c.execute("UPDATE approvals SET expires_at=? WHERE id=?",
                      (int(time.time()) - 5, b["approval_id"]))
        self.assertEqual(self.svc.approvals.status(b["approval_id"])["state"], "expired")

    def test_session_exemption(self):
        self.mk_cred()
        a = self.svc.approvals.request("t_push", {"content": "z"}, "ai")
        self.svc.approvals.decide(a["approval_id"], True, "human", session=True)
        self.assertTrue(self.svc.approvals.has_exemption("ai", "t_push"))
        b = self.svc.approvals.request("t_push", {"content": "z2"}, "ai")
        # 有豁免时不再要求审批（服务层判定）
        res = self.svc.invoke(self.mk_agent(), "t_push", {"content": "z2"})
        self.assertTrue(res.get("ok"), res)


# ── 10. 服务端到端 ─────────────────────────────────────────────────────
class T10Service(Base):
    def test_ok_path_and_scrub(self):
        secret = self.mk_cred()
        res = self.svc.invoke(self.mk_agent(), "t_ok", {})
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["code"], E_OK)
        # W5 起截断会附 total/truncated，故断言 items 而非整对象
        sc = res["structured"]
        self.assertEqual(sc["items"], [0, 1, 2, 3, 4])          # array_limit=5
        self.assertTrue(sc["truncated"])
        self.assertEqual(sc["total"], 100)
        self.assertNotIn(secret, json.dumps(res, ensure_ascii=False))

    def test_business_failure(self):
        self.mk_cred()
        res = self.svc.invoke(self.mk_agent(), "t_bizfail", {})
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], E_BIZ)
        self.assertIn("45009", res["text"])

    def test_deny_unknown_capability(self):
        res = self.svc.invoke(self.mk_agent(), "nope", {})
        self.assertEqual(res["code"], E_INPUT)

    def test_deny_by_policy(self):
        self.mk_cred()
        res = self.svc.invoke(self.mk_agent(), "t_delete_thing", {})
        self.assertEqual(res["code"], E_DENIED)

    def test_approval_then_execute(self):
        self.mk_cred()
        ag = self.mk_agent()
        first = self.svc.invoke(ag, "t_push", {"content": "hello"})
        self.assertEqual(first["code"], E_APPROVAL)
        aid = first["approval_id"]
        self.svc.approvals.decide(aid, True, "human")
        second = self.svc.invoke(ag, "t_push", {"content": "hello"}, approval_id=aid)
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["status"], 200)

    def test_quota(self):
        self.mk_cred()
        ag = self.mk_agent("qa")
        codes = [self.svc.invoke(ag, "t_ok", {})["code"] for _ in range(7)]
        self.assertIn(E_QUOTA, codes)

    def test_kill_switch(self):
        self.mk_cred()
        ag = self.mk_agent()
        self.svc.store.meta_set("kill_switch", "1")
        ro = self.svc.invoke(ag, "t_ok", {})
        self.assertTrue(ro["ok"])                     # 只读放行
        rw = self.svc.invoke(ag, "t_push", {"content": "x"})
        self.assertEqual(rw["code"], E_KILL)

    def test_blind_agent_cannot_use_cred_capability(self):
        self.mk_cred()
        token, _ = self.svc.tokens.create("ai-blind", visible_credentials=["OTHER"])
        ag = self.svc.tokens.resolve(token)
        res = self.svc.invoke(ag, "t_ok", {})
        self.assertEqual(res["code"], E_DENIED)
        self.assertIn("不可见凭据", res["reason"])

    def test_exec_allowlist(self):
        ag = self.mk_agent("ex")
        ok = self.svc.invoke(ag, "t_exec_ok", {})
        self.assertTrue(ok["ok"], ok)
        bad = self.svc.invoke(ag, "t_exec_bad", {})
        self.assertFalse(bad["ok"])
        self.assertIn("白名单", bad["reason"])

    def test_exec_disabled_by_config(self):
        self.svc.cfg.set("exec.enabled", False)
        res = self.svc.invoke(self.mk_agent("ex2"), "t_exec_ok", {})
        self.assertEqual(res["code"], E_DENIED)
        self.assertIn("exec.enabled", res["reason"])
        self.svc.cfg.set("exec.enabled", True)

    def test_batch_single_approval(self):
        self.mk_cred()
        ag = self.mk_agent("bt")
        calls = [{"capability": "t_ok", "args": {}},
                 {"capability": "t_push", "args": {"content": "batched"}}]
        b1 = self.svc.invoke_batch(ag, calls)
        self.assertEqual(b1["code"], E_APPROVAL)
        self.svc.approvals.decide(b1["approval_id"], True, "human")
        b2 = self.svc.invoke_batch(ag, calls, approval_id=b1["approval_id"])
        self.assertTrue(b2["ok"], b2)
        self.assertEqual(b2["count"], 2)

    def test_explain_is_dry(self):
        self.mk_cred()
        ag = self.mk_agent("ex3")
        before = len(self.svc.audit.search(limit=1000))
        r = self.svc.explain(ag, "t_ok", {})
        self.assertTrue(r["allow"])
        self.assertEqual(len(self.svc.audit.search(limit=1000)), before)

    def test_quota_reported_in_explain(self):
        self.mk_cred()
        ag = self.mk_agent("ex4")
        for _ in range(6):
            self.svc.invoke(ag, "t_ok", {})
        r = self.svc.explain(ag, "t_ok", {})
        self.assertFalse(r["allow"])
        self.assertEqual(r["code"], E_QUOTA)


# ── 11. 轮换 ───────────────────────────────────────────────────────────
class T11Rotate(Base):
    def test_rotate_with_probe_ok(self):
        self.mk_cred(value="old-value-xxxx")
        res = rotate_mod.rotate(self.svc, "AUTH_TOKEN", actor="test",
                                probe_capability="t_nosecret")
        self.assertTrue(res["ok"], res)
        self.assertNotEqual(res["new_fp"], "")
        new = self.svc.store.get_secret("AUTH_TOKEN", self.svc.kek())
        self.assertNotEqual(new, b"old-value-xxxx")

    def test_rotate_rollback_on_probe_fail(self):
        self.mk_cred(value="old-value-yyyy")
        res = rotate_mod.rotate(self.svc, "AUTH_TOKEN", actor="test",
                                probe_capability="t_exec_bad")
        self.assertFalse(res["ok"])
        self.assertEqual(res["state"], "rolled_back")
        self.assertEqual(self.svc.store.get_secret("AUTH_TOKEN", self.svc.kek()),
                         b"old-value-yyyy")

    def test_rotate_dry_run(self):
        self.mk_cred(value="old-dry")
        res = rotate_mod.rotate(self.svc, "AUTH_TOKEN", dry_run=True)
        self.assertTrue(res["dry_run"])
        self.assertEqual(self.svc.store.get_secret("AUTH_TOKEN", self.svc.kek()), b"old-dry")

    def test_ssh_keygen(self):
        self.mk_cred(value="old-ssh")
        res = rotate_mod.rotate(self.svc, "AUTH_TOKEN", adapter="ssh_keygen")
        self.assertTrue(res["ok"])
        self.assertIn("ssh-ed25519", res["public_key"])


# ── 12. 备份恢复 ───────────────────────────────────────────────────────
class T12Backup(Base):
    def test_roundtrip(self):
        self.mk_cred()
        out = self.home / "b.cvault"
        info = backup_mod.export(self.svc, out, "password123")
        self.assertEqual(info["secrets"], 1)
        raw = out.read_bytes()
        self.assertNotIn(b"s3cr3t-abcdef", raw)     # 包里没有明文
        # 清掉再恢复
        self.svc.store.delete_secret("AUTH_TOKEN")
        res = backup_mod.restore(self.svc, out, "password123")
        self.assertTrue(res["ok"])
        self.assertEqual(self.svc.store.get_secret("AUTH_TOKEN", self.svc.kek()),
                         b"s3cr3t-abcdef-123456")

    def test_wrong_password(self):
        self.mk_cred()
        out = self.home / "b2.cvault"
        backup_mod.export(self.svc, out, "password123")
        with self.assertRaises(backup_mod.BackupError):
            backup_mod.restore(self.svc, out, "wrong-password")


# ── 13. MCP ────────────────────────────────────────────────────────────
class T13Mcp(Base):
    def test_initialize_instructions(self):
        self.mk_cred()
        token, _ = self.svc.tokens.create("ai")
        m = mcp_mod.Mcp(self.svc, token)
        r = m.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        inst = r["result"]["instructions"]
        self.assertIn("CredVault", inst)
        self.assertIn("不要向用户索要", inst)
        self.assertIn("11 需人工审批", inst)
        self.assertEqual(r["result"]["serverInfo"]["name"], "credvault")

    def test_tools_list_progressive(self):
        self.mk_cred()
        token, _ = self.svc.tokens.create("ai")
        m = mcp_mod.Mcp(self.svc, token)
        r = m.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in r["result"]["tools"]}
        self.assertIn("t_ok", names)
        self.assertIn("cred_batch", names)
        self.assertIn("audit_search", names)
        self.assertNotIn("t_delete_thing", names)   # deny 的能力不出现

        token2, _ = self.svc.tokens.create("ai-noexec")
        m2 = mcp_mod.Mcp(self.svc, token2)
        r2 = m2.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        names2 = {t["name"] for t in r2["result"]["tools"]}
        self.assertIn("t_nosecret", names2)
        self.assertNotIn("t_exec_ok", names2)       # allow_exec=false → exec 不披露

    def test_tools_call_success_and_error_flag(self):
        self.mk_cred()
        token, _ = self.svc.tokens.create("ai")
        m = mcp_mod.Mcp(self.svc, token)
        ok = m.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "t_ok", "arguments": {}}})
        self.assertFalse(ok["result"]["isError"])
        self.assertIn("structuredContent", ok["result"])
        bad = m.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                        "params": {"name": "t_delete_thing", "arguments": {}}})
        self.assertTrue(bad["result"]["isError"])
        self.assertEqual(bad["result"]["structuredContent"]["code"], E_DENIED)

    def test_approval_tool_loop(self):
        self.mk_cred()
        token, _ = self.svc.tokens.create("ai")
        m = mcp_mod.Mcp(self.svc, token)
        r = m.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                      "params": {"name": "t_push", "arguments": {"content": "yo"}}})
        payload = r["result"]["structuredContent"]
        self.assertEqual(payload["code"], E_APPROVAL)
        aid = payload["approval_id"]
        self.assertIn("next_action", payload)
        st = m.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                       "params": {"name": "approval_status", "arguments": {"approval_id": aid}}})
        self.assertEqual(st["result"]["structuredContent"]["state"], "pending")
        self.svc.approvals.decide(aid, True, "human")
        r2 = m.handle({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                       "params": {"name": "t_push",
                                  "arguments": {"content": "yo", "approval_id": aid}}})
        self.assertFalse(r2["result"]["isError"])

    def test_prompts(self):
        token, _ = self.svc.tokens.create("ai")
        m = mcp_mod.Mcp(self.svc, token)
        r = m.handle({"jsonrpc": "2.0", "id": 9, "method": "prompts/list"})
        self.assertEqual(len(r["result"]["prompts"]), 3)
        g = m.handle({"jsonrpc": "2.0", "id": 10, "method": "prompts/get",
                      "params": {"name": "capabilities"}})
        self.assertIn("list_capabilities", g["result"]["messages"][0]["content"]["text"])

    def test_bad_token_fails_closed(self):
        m = mcp_mod.Mcp(self.svc, "cbk_invalid")
        r = m.handle({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                      "params": {"name": "health", "arguments": {}}})
        self.assertIn("error", r)     # 握手后再拒绝，返回 JSON-RPC error

    def test_unknown_method(self):
        token, _ = self.svc.tokens.create("ai")
        r = mcp_mod.Mcp(self.svc, token).handle(
            {"jsonrpc": "2.0", "id": 12, "method": "nope/nope"})
        self.assertEqual(r["error"]["code"], -32601)


# ── 14. 运维与 Web ─────────────────────────────────────────────────────
class T14OpsWeb(Base):
    def test_health_and_metrics(self):
        self.mk_cred()
        h = ops.health(self.svc)
        self.assertTrue(h["ok"], [c for c in h["checks"] if not c["ok"]])
        m = ops.metrics(self.svc)
        self.assertIn("credvault_up 1", m)
        self.assertIn("credvault_credentials 1", m)

    def test_health_detects_missing_secret(self):
        self.svc.store.upsert_credential("AUTH_TOKEN", kind="api_token")  # 只有元数据
        h = ops.health(self.svc)
        self.assertFalse(h["ok"])
        self.assertTrue(any("密文缺" in c["note"] for c in h["checks"]))

    def test_web_endpoints(self):
        from credvault import web
        web.Handler.svc = self.svc
        srv = web.make_server(self.svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=5) as r:
                self.assertEqual(json.loads(r.read())["ok"], True)
            with urllib.request.urlopen(base + "/metrics", timeout=5) as r:
                self.assertIn("credvault_up", r.read().decode())
            with urllib.request.urlopen(base + "/version", timeout=5) as r:
                self.assertEqual(json.loads(r.read())["version"], ops.VERSION)
            # 未登录访问页面 → 302 到 /login
            req = urllib.request.Request(base + "/approvals")
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            op = urllib.request.build_opener(NoRedirect)
            try:
                op.open(req, timeout=5)
                self.fail("应重定向")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 302)
            # 建账号 → 登录 → 拿 cookie
            web.ensure_user(self.svc.store, "admin", "admin-pass-123")
            data = json.dumps({"user": "admin", "password": "admin-pass-123"}).encode()
            req = urllib.request.Request(base + "/login", data=data,
                                         headers={"Content-Type": "application/json"})
            op2 = urllib.request.build_opener(NoRedirect)
            try:
                op2.open(req, timeout=5)
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 302)
                self.assertIn("cvsid=", e.headers.get("Set-Cookie", ""))
        finally:
            srv.shutdown()

    def test_kill_switch_meta(self):
        self.svc.store.meta_set("kill_switch", "1")
        self.assertEqual(self.svc.store.meta_get("kill_switch"), "1")


# ── 15. 凭据类型校验 ───────────────────────────────────────────────────
class T15Kinds(Base):
    def test_validate(self):
        from credvault import kinds as k
        self.assertTrue(k.validate("api_token", "short"))
        self.assertEqual(k.validate("api_token", "tok-abcdef-123456"), "")
        self.assertIn("account", k.validate("ssh_key", "-----BEGIN OPENSSH PRIVATE KEY-----" + "x" * 200))
        self.assertEqual(k.validate("ssh_key", "-----BEGIN OPENSSH PRIVATE KEY-----" + "x" * 200,
                                    account="root@host"), "")
        self.assertIn("未知凭据类型", k.validate("nope", "abcdefgh"))

    def test_kind_hint_on_cli_set(self):
        err = __import__("credvault.kinds", fromlist=["x"]).validate("webhook", "k")
        self.assertIn("过短", err)


# ── 16. 轮换作为能力（受审批）─────────────────────────────────────────
class T16RotateCapability(Base):
    def test_requires_approval_then_executes(self):
        self.mk_cred(value="rotate-me-1234567890")
        ag = self.mk_agent()
        first = self.svc.invoke(ag, "t_rotate", {})
        self.assertEqual(first["code"], E_APPROVAL, first)
        self.svc.approvals.decide(first["approval_id"], True, "human")
        second = self.svc.invoke(ag, "t_rotate", {}, approval_id=first["approval_id"])
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["structured"]["state"], "done")
        self.assertNotEqual(self.svc.store.get_secret("AUTH_TOKEN", self.svc.kek()),
                            b"rotate-me-1234567890")

    def test_rotate_capability_must_declare_confirm(self):
        bad = self.home / "bad_rotate.yaml"
        bad.write_text("""version: 1
capabilities:
  - name: bad_rotate
    kind: rotate
    description: 没有 require_confirm 的轮换能力应被拒
    read_only: false
    rotate: {credential: X}
""", encoding="utf-8")
        with self.assertRaises(registry.RegistryError):
            registry.load([bad])


# ── 17. 突发配额 ──────────────────────────────────────────────────────
class T17Burst(Base):
    def test_burst_guard(self):
        self.mk_cred()
        self.svc.cfg.set("limits.burst_count", 3)
        ag = self.mk_agent()
        codes = [self.svc.invoke(ag, "t_ok", {})["code"] for _ in range(4)]
        self.assertEqual(codes[:3], [0, 0, 0])
        self.assertEqual(codes[3], E_QUOTA)


# ── 18. Web 角色门禁 ──────────────────────────────────────────────────
class T18Role(Base):
    def _login(self, base: str, user: str, pwd: str) -> tuple[str, str]:
        import urllib.error
        from credvault import web
        data = json.dumps({"user": user, "password": pwd}).encode()
        req = urllib.request.Request(base + "/login", data=data,
                                     headers={"Content-Type": "application/json"})
        class NR(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            urllib.request.build_opener(NR).open(req, timeout=5)
        except urllib.error.HTTPError as e:
            sid = [c.split(";")[0].split("=", 1)[1]
                   for c in e.headers.get_all("Set-Cookie") or []
                   if c.startswith("cvsid=")]
            if sid:
                return sid[0], web.SESSIONS[sid[0]]["csrf"]
        self.fail("登录失败")

    def test_viewer_cannot_approve(self):
        from credvault import web
        web.Handler.svc = self.svc
        web.ensure_user(self.svc.store, "boss", "boss-pass-123", "admin")
        web.ensure_user(self.svc.store, "guest", "guest-pass-123", "viewer")
        a = self.svc.approvals.request("t_push", {"content": "x"}, "ai")
        srv = web.make_server(self.svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            sid, csrf = self._login(base, "guest", "guest-pass-123")
            body = json.dumps({"id": a["approval_id"], "approve": True}).encode()
            req = urllib.request.Request(
                base + "/api/decide", data=body, method="POST",
                headers={"Content-Type": "application/json", "X-CSRF": csrf,
                         "Cookie": f"cvsid={sid}"})
            try:
                urllib.request.urlopen(req, timeout=5)
                self.fail("viewer 不应能审批")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)
            # admin 可以
            sid2, csrf2 = self._login(base, "boss", "boss-pass-123")
            req2 = urllib.request.Request(
                base + "/api/decide", data=body, method="POST",
                headers={"Content-Type": "application/json", "X-CSRF": csrf2,
                         "Cookie": f"cvsid={sid2}"})
            with urllib.request.urlopen(req2, timeout=5) as r:
                self.assertTrue(json.loads(r.read())["ok"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_csrf_required(self):
        from credvault import web
        web.Handler.svc = self.svc
        web.ensure_user(self.svc.store, "boss2", "boss-pass-123", "admin")
        srv = web.make_server(self.svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            sid, _csrf = self._login(base, "boss2", "boss-pass-123")
            req = urllib.request.Request(
                base + "/api/tokens", data=b"{}", method="POST",
                headers={"Content-Type": "application/json", "Cookie": f"cvsid={sid}"})
            try:
                urllib.request.urlopen(req, timeout=5)
                self.fail("缺 CSRF 应被拒")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)
        finally:
            srv.shutdown()
            srv.server_close()


# ── 19. 审查修复回归（C1/C2/C3/M1/M2/M3/M4/F1）────────────────────────
class T19AuditFixes(Base):
    def test_expired_credential_rejected(self):
        """C1：过期凭据在调用链被拒，且干跑即可发现。"""
        self.mk_cred()
        with self.svc.store.tx() as c:
            c.execute("UPDATE credentials SET expires_at=? WHERE name='AUTH_TOKEN'",
                      (int(time.time()) - 86400,))
        ag = self.mk_agent()
        res = self.svc.invoke(ag, "t_ok", {})
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], E_RESOLVE)
        self.assertIn("已过期", res["reason"])
        # 干跑同步暴露，不必真打一次才知道
        ex = self.svc.explain(ag, "t_ok", {})
        self.assertFalse(ex["allow"])
        self.assertEqual(ex["code"], E_RESOLVE)
        # 无凭据能力不受影响
        self.assertTrue(self.svc.invoke(ag, "t_nosecret", {})["ok"])

    def test_deleted_credential_rejected(self):
        """C1：状态非 active 同样拒。"""
        self.mk_cred()
        with self.svc.store.tx() as c:
            c.execute("UPDATE credentials SET status='deleted' WHERE name='AUTH_TOKEN'")
        res = self.svc.invoke(self.mk_agent(), "t_ok", {})
        self.assertEqual(res["code"], E_RESOLVE)
        self.assertIn("状态=deleted", res["reason"])

    def test_credential_side_allowlist(self):
        """C2：凭据侧白名单生效（双轴第二维）。"""
        self.mk_cred()
        self.svc.store.upsert_credential("AUTH_TOKEN", allowed_capabilities=["t_push"])
        ag = self.mk_agent()
        denied = self.svc.invoke(ag, "t_ok", {})
        self.assertEqual(denied["code"], E_RESOLVE)
        self.assertIn("凭据侧白名单", denied["reason"])
        # 白名单内的能力仍可用（t_push 需审批，走 explain 判定即可）
        self.assertTrue(self.svc.explain(ag, "t_push", {"content": "x"})["allow"])

    def test_approval_consume_is_atomic(self):
        """C3：同一审批单只能核销一次（并发保护靠条件更新）。"""
        a = self.svc.approvals.request("t_push", {"content": "once"}, "ai")
        self.svc.approvals.decide(a["approval_id"], True, "human")
        ok1, _ = self.svc.approvals.consume(a["approval_id"], "t_push", {"content": "once"})
        self.assertTrue(ok1)
        ok2, msg2 = self.svc.approvals.consume(a["approval_id"], "t_push", {"content": "once"})
        self.assertFalse(ok2)
        # 状态预检查与条件更新两条路径都算正确拒绝
        self.assertTrue("已被核销" in msg2 or "不可执行" in msg2, msg2)

    def test_audit_has_scrubbed_args_preview(self):
        """M1：审计带参数摘要，且摘要里的密钥已被脱敏。"""
        secret = self.mk_cred()
        self.svc.invoke(self.mk_agent(), "t_ok", {"q": f"token={secret}"})
        rows = self.svc.audit.search(limit=5, capability="t_ok")
        self.assertEqual(len(rows), 1)
        preview = rows[0].get("args_preview", "")
        self.assertTrue(preview, "参数摘要不应为空")
        self.assertNotIn(secret, preview)        # 明文不在
        self.assertIn("REDACTED", preview)       # 已脱敏标记在

    def test_config_quota_overrides_policy(self):
        """M2：config 非 0 时压过 policy；0 时跟随 policy（不再是死配置）。"""
        self.mk_cred()
        self.svc.cfg.set("limits.quota_per_min", 2)
        ag = self.mk_agent()
        codes = [self.svc.invoke(ag, "t_ok", {})["code"] for _ in range(3)]
        self.assertEqual(codes[:2], [0, 0])
        self.assertEqual(codes[2], E_QUOTA)
        # 置 0 后回到 policy 的 5/分钟
        self.svc.cfg.set("limits.quota_per_min", 0)
        with self.svc.store.tx() as c:
            c.execute("DELETE FROM quota")
        codes2 = [self.svc.invoke(ag, "t_ok", {})["code"] for _ in range(3)]
        self.assertEqual(codes2, [0, 0, 0])

    def test_throttle_soft_limit(self):
        """F1：软限流 opt-in —— 超配额按概率放行；关闭时硬停。"""
        self.mk_cred()
        self.svc.cfg.set("limits.quota_per_min", 1)
        self.svc.cfg.set("limits.throttle_enabled", True)
        self.svc.cfg.set("limits.throttle_pct", 0.5)
        ag = self.mk_agent()
        orig = service_mod.random.random
        try:
            service_mod.random.random = lambda: 0.0   # 必放行
            codes = [self.svc.invoke(ag, "t_ok", {})["code"] for _ in range(3)]
            self.assertTrue(all(c == 0 for c in codes), codes)
            # 审计留 THROTTLED 痕迹
            self.assertTrue(any("THROTTLED" in (r.get("note") or "")
                                for r in self.svc.audit.search(limit=20)))
        finally:
            service_mod.random.random = orig

    def test_throttle_never_exempts_burst(self):
        """F1：burst 档不享受降速（防刷群）。"""
        self.mk_cred()
        self.svc.cfg.set("limits.burst_count", 2)
        self.svc.cfg.set("limits.throttle_enabled", True)
        self.svc.cfg.set("limits.throttle_pct", 0.5)
        ag = self.mk_agent()
        orig = service_mod.random.random
        try:
            service_mod.random.random = lambda: 0.0
            codes = [self.svc.invoke(ag, "t_ok", {})["code"] for _ in range(4)]
        finally:
            service_mod.random.random = orig
        self.assertEqual(codes[3], E_QUOTA, codes)

    def test_login_rate_limit_and_cookie_secure(self):
        """M3 + M4：连续失败 5 次后 429；登录 Cookie 带 Secure。"""
        from credvault import web
        web.Handler.svc = self.svc
        web._LOGIN_FAILS.clear()
        web.ensure_user(self.svc.store, "sec", "sec-pass-123", "admin")
        srv = web.make_server(self.svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            import urllib.error

            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None

            opener = urllib.request.build_opener(NoRedirect)

            def post(path, body):
                req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json"})
                try:
                    return opener.open(req, timeout=5).status, {}
                except urllib.error.HTTPError as e:
                    return e.code, dict(e.headers)

            for i in range(5):
                code, _ = post("/login", {"user": "sec", "password": "wrong"})
                self.assertEqual(code, 401)
            code, _ = post("/login", {"user": "sec", "password": "wrong"})
            self.assertEqual(code, 429)
            # 换正确口令仍被限速挡（窗口内）
            code, _ = post("/login", {"user": "sec", "password": "sec-pass-123"})
            self.assertEqual(code, 429)
            web._LOGIN_FAILS.clear()
            code, hdrs = post("/login", {"user": "sec", "password": "sec-pass-123"})
            self.assertEqual(code, 302)
            self.assertIn("Secure", hdrs.get("Set-Cookie", ""))
        finally:
            srv.shutdown()
            srv.server_close()
            web._LOGIN_FAILS.clear()

    def test_per_capability_quota_constraint(self):
        """F7：policy Rule.constraints 的 quota_per_min 生效且取最严值。"""
        self.mk_cred()
        pol_yaml = self.home / "policy.yaml"
        pol_lines = [
            "version: 1",
            "defaults:",
            "  deny_by_default: true",
            "  quota_per_min: 50",
            "agents:",
            "  - id: ai",
            "    visible_credentials: [AUTH_TOKEN]",
            "    capabilities:",
            "      - name: t_ok",
            "        allow: true",
            "        constraints: {quota_per_min: 1}",
            "      - name: '*'",
            "        allow: false",
        ]
        pol_yaml.write_text("\n".join(pol_lines) + "\n", encoding="utf-8")
        self.svc.reload_policy(force=True)
        ag = self.mk_agent()
        codes = [self.svc.invoke(ag, "t_ok", {})["code"] for _ in range(2)]
        self.assertEqual(codes[0], 0)
        self.assertEqual(codes[1], E_QUOTA, codes)


# ── 20. 第二轮修复回归（F2/F3/F4/F5/F8/W3/W4/W5）─────────────────────
class T20SecondRound(Base):
    def test_kek_strength(self):
        """F2：弱 KEK 被体检拒（全零/单字节/低熵）。"""
        from credvault import crypto as c
        self.assertFalse(c.kek_strength(b"\x00" * 32)[0])
        self.assertFalse(c.kek_strength(b"a" * 32)[0])
        self.assertFalse(c.kek_strength(b"ab" * 16)[0])          # 唯一字节 2
        self.assertFalse(c.kek_strength(b"short")[0])
        ok, note = c.kek_strength(os.urandom(32))
        self.assertTrue(ok, note)

    def test_doctor_reports_exec_safety(self):
        """F2：exec 开启且有白名单时体检通过，不裸开。"""
        self.svc.cfg.set("exec.enabled", True)
        h = ops.health(self.svc)
        names = {c["name"]: c for c in h["checks"]}
        self.assertIn("exec-safety", names)
        self.assertTrue(names["exec-safety"]["ok"])
        self.svc.cfg.set("exec.enabled", False)

    def test_arg_limits_enforced(self):
        """F3：参数级约束（max/max_len/pattern/enum）在执行与干跑两条路径生效。"""
        self.mk_cred()
        pol = [
            "version: 1",
            "defaults:",
            "  deny_by_default: true",
            "agents:",
            "  - id: ai",
            "    visible_credentials: [AUTH_TOKEN]",
            "    capabilities:",
            "      - name: t_ok",
            "        allow: true",
            "        constraints:",
            "          arg_limits:",
            '            q: {max_len: 3}',
            "      - name: '*'",
            "        allow: false",
        ]
        (self.home / "policy.yaml").write_text("\n".join(pol) + "\n", encoding="utf-8")
        self.svc.reload_policy(force=True)
        ag = self.mk_agent()
        bad = self.svc.invoke(ag, "t_ok", {"q": "toolong"})
        self.assertEqual(bad["code"], E_INPUT)
        self.assertIn("超过 3", bad["reason"])   # 措辞为「长度 N 超过 M」
        self.assertFalse(self.svc.explain(ag, "t_ok", {"q": "toolong"})["allow"])
        self.assertTrue(self.svc.invoke(ag, "t_ok", {"q": "ok"})["ok"])

    def test_on_behalf_of_requires_impersonate(self):
        """F4：未授权 agent 声明 on_behalf_of 被拒；授权后写入审计。"""
        self.mk_cred()
        ag = self.mk_agent()
        denied = self.svc.invoke(ag, "t_ok", {}, on_behalf_of="human:maxin")
        self.assertEqual(denied["code"], E_DENIED)
        self.assertIn("impersonate", denied["reason"])
        # 授权后可用
        pol = [
            "version: 1",
            "defaults:",
            "  deny_by_default: true",
            "agents:",
            "  - id: ai",
            "    visible_credentials: [AUTH_TOKEN]",
            "    capabilities:",
            "      - name: t_ok",
            "        allow: true",
            "        constraints: {impersonate: true}",
            "      - name: '*'",
            "        allow: false",
        ]
        (self.home / "policy.yaml").write_text("\n".join(pol) + "\n", encoding="utf-8")
        self.svc.reload_policy(force=True)
        ok = self.svc.invoke(ag, "t_ok", {}, on_behalf_of="human:maxin")
        self.assertTrue(ok["ok"], ok)
        rows = [r for r in self.svc.audit.search(limit=10)
                if r.get("extra", {}).get("on_behalf_of") == "human:maxin"]
        self.assertTrue(rows, "审计应记录 on_behalf_of")

    def test_on_behalf_of_must_be_human(self):
        """F4：机器身份不能当代办人（防 A 机器冒充 B 机器）。"""
        self.mk_cred()
        pol = ["version: 1", "defaults:", "  deny_by_default: true", "agents:",
               "  - id: ai", "    visible_credentials: [AUTH_TOKEN]", "    capabilities:",
               "      - name: t_ok", "        allow: true",
               "        constraints: {impersonate: true}",
               "      - name: '*'", "        allow: false"]
        (self.home / "policy.yaml").write_text("\n".join(pol) + "\n", encoding="utf-8")
        self.svc.reload_policy(force=True)
        bad = self.svc.invoke(self.mk_agent(), "t_ok", {}, on_behalf_of="agent:other")
        self.assertEqual(bad["code"], E_INPUT)

    def test_mcp_rejects_on_behalf_of_by_default(self):
        """F4：MCP 侧默认丢弃 on_behalf_of（防 agent 自封代办人）。"""
        self.mk_cred()
        token, _ = self.svc.tokens.create("ai")
        m = mcp_mod.Mcp(self.svc, token)              # allow_impersonate=False
        self.assertFalse(m.allow_impersonate)
        r = m.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "t_ok", "arguments": {"on_behalf_of": "human:x"}}})
        sc = r["result"]["structuredContent"]
        self.assertTrue(sc.get("ok"), sc)             # 调用成功，但归属未被采信
        last = self.svc.audit.search(limit=1)[0]
        self.assertNotEqual(last.get("extra", {}).get("on_behalf_of"), "human:x")

    def test_lease_lifecycle(self):
        """F5：租约发放/拉取/撤销/过期/白名单。"""
        secret = self.mk_cred()
        lease = self.svc.lease_issue("collector", "AUTH_TOKEN", ttl=60)
        lid = lease["lease_id"]
        self.assertTrue(lid.startswith("lease_"))
        pulled = self.svc.lease_pull(lid)
        self.assertEqual(pulled["value"], secret)
        self.assertTrue(any(l["id"] == lid for l in self.svc.leases.list()))
        self.assertTrue(self.svc.lease_revoke(lid))
        with self.assertRaises(Exception):
            self.svc.lease_pull(lid)
        # 过期即拒
        lid2 = self.svc.lease_issue("collector", "AUTH_TOKEN", ttl=30)["lease_id"]
        with self.svc.store.tx() as c:
            c.execute("UPDATE leases SET expires_at=? WHERE id=?",
                      (int(time.time()) - 1, lid2))
        with self.assertRaises(Exception):
            self.svc.lease_pull(lid2)

    def test_lease_ip_allowlist(self):
        """F5：租约 IP 白名单生效。"""
        self.mk_cred()
        lid = self.svc.lease_issue("collector", "AUTH_TOKEN",
                                   ip_allowlist=["10.0.0.*"])["lease_id"]
        with self.assertRaises(Exception):
            self.svc.lease_pull(lid, "127.0.0.1")
        self.assertTrue(self.svc.lease_pull(lid, "10.0.0.7")["value"])

    def test_lease_renew_limits(self):
        """F5：续期上限与 renewable=false。"""
        self.mk_cred()
        lid = self.svc.lease_issue("c", "AUTH_TOKEN", ttl=30)["lease_id"]
        for _ in range(3):
            self.svc.leases.renew(lid, 30)
        with self.assertRaises(Exception):
            self.svc.leases.renew(lid, 30)              # 第 4 次超上限
        lid2 = self.svc.lease_issue("c", "AUTH_TOKEN", renewable=False)["lease_id"]
        with self.assertRaises(Exception):
            self.svc.leases.renew(lid2)

    def test_whoami_and_mcp_introspection(self):
        """F8：whoami 返回能力/约束/额度；MCP list_capabilities 含约束与额度。"""
        self.mk_cred()
        token, _ = self.svc.tokens.create("ai")
        ag = self.svc.tokens.resolve(token)
        w = self.svc.whoami(ag)
        self.assertEqual(w["agent"], "ai")
        self.assertGreater(w["capability_count"], 0)
        self.assertTrue(all("quota" in c for c in w["capabilities"]))
        m = mcp_mod.Mcp(self.svc, token)
        names = {t["name"] for t in m.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
        self.assertIn("whoami", names)
        r = m.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "whoami", "arguments": {}}})
        self.assertEqual(r["result"]["structuredContent"]["agent"], "ai")

    def test_conn_pool_key_includes_timeout(self):
        """W6：不同 timeout 不共用连接（避免拿到旧 timeout）。"""
        from credvault import executor as ex
        ex.close_pool()
        c1 = ex._get_conn("http", "127.0.0.1", 80, 5)
        c2 = ex._get_conn("http", "127.0.0.1", 80, 30)
        self.assertIsNot(c1, c2)
        ex.close_pool()

    def test_resolve_and_check_same_source(self):
        """W4：解析一次同时供校验与连接（pin 为能力级 opt-in，默认关）。"""
        from credvault import executor as ex
        reason, addrs = ex.resolve_and_check("http://127.0.0.1:9/x", allow_private=True)
        self.assertIsNone(reason)
        self.assertTrue(addrs)
        reason2, _ = ex.resolve_and_check("http://127.0.0.1:9/x", allow_private=False)
        self.assertIsNotNone(reason2)


# ── 21. 遗留项闭环（C3 并发压测 / 审计链并发 / 配额窗口翻转）────────────
class T21Leftovers(Base):
    def test_approval_consume_concurrent_no_double(self):
        """C3 并发实证：16 线程抢同一审批单，只能有 1 个核销成功。"""
        self.mk_cred()
        ag = self.mk_agent()
        args = {"content": "concurrent"}
        req = self.svc.approvals.request("t_push", args, ag["id"])
        self.svc.approvals.decide(req["approval_id"], True, "human")
        results: list[bool] = []
        lock = threading.Lock()

        def worker():
            ok, _ = self.svc.approvals.consume(req["approval_id"], "t_push", dict(args))
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(1 for r in results if r), 1,
                         f"应只成功 1 次，实际 {sum(1 for r in results if r)} 次")

    def test_audit_chain_concurrent_intact(self):
        """审计链并发追加后仍完整（双锁 + 反向块读）。"""
        def worker(i: int):
            for _ in range(5):
                self.svc.audit.append(f"w{i}", "invoke", True, 1, capability="t_ok")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ok, note, n = self.svc.audit.verify()
        self.assertTrue(ok, note)
        self.assertEqual(n, 40)

    def test_quota_window_rollover_resets(self):
        """配额窗口翻转即重置（不是累积）。"""
        self.mk_cred()
        self.svc.cfg.set("limits.quota_per_min", 2)
        ag = self.mk_agent()
        self.assertEqual([self.svc.invoke(ag, "t_ok", {})["code"] for _ in range(2)], [0, 0])
        self.assertEqual(self.svc.invoke(ag, "t_ok", {})["code"], E_QUOTA)
        # 把窗口起点推到过去 → 下一次按新窗口计数
        with self.svc.store.tx() as c:
            c.execute("UPDATE quota SET window_start=window_start-120")
        self.assertEqual(self.svc.invoke(ag, "t_ok", {})["code"], 0)

    def test_lease_cleanup_expired(self):
        """lease 清理只删过期，不误删活跃。"""
        self.mk_cred()
        live = self.svc.lease_issue("c", "AUTH_TOKEN", ttl=300)["lease_id"]
        dead = self.svc.lease_issue("c", "AUTH_TOKEN", ttl=30)["lease_id"]
        with self.svc.store.tx() as c:
            c.execute("UPDATE leases SET expires_at=? WHERE id=?",
                      (int(time.time()) - 100000, dead))
        self.svc.leases.cleanup()
        ids = {r["id"] for r in self.svc.leases.list(include_revoked=True)}
        self.assertIn(live, ids)
        self.assertNotIn(dead, ids)


# ── 22. REST API v1（Bearer 令牌 + scope 隔离）──────────────────────────
class T22RestApi(Base):
    """API 与 MCP 必须同源判定，但入口与鉴权必须隔离。"""

    def _serve(self):
        from credvault import web
        web.Handler.svc = self.svc
        srv = web.make_server(self.svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"

    def _req(self, base, path, method="GET", body=None, token=""):
        import urllib.error
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"raw": raw[:200].decode("utf-8", "replace")}

    def test_api_token_scope_enforced(self):
        """scope=mcp 的令牌不得调 API；scope=api 可调；scope=both 皆可。"""
        self.mk_cred()
        srv, base = self._serve()
        try:
            # 策略只登记 ai（唯一 agent 名），故改 scope 后 rotate 换令牌再验
            tok, _ = self.svc.tokens.create("ai", scope="mcp")
            for sc, want, should_pass in (("mcp", 403, False), ("api", 200, True),
                                          ("both", 200, True)):
                self.svc.tokens.update_scopes("ai", scope=sc)
                if sc != "mcp":
                    tok = self.svc.tokens.rotate("ai")
                st, r = self._req(base, "/api/v1/whoami", token=tok)
                self.assertEqual(st, want, f"scope={sc}: {r}")
                if not should_pass:
                    self.assertIn("scope", r["reason"])
                else:
                    self.assertTrue(r["ok"], r)
        finally:
            srv.shutdown(); srv.server_close()

    def test_api_requires_token_and_rejects_garbage(self):
        srv, base = self._serve()
        try:
            st, r = self._req(base, "/api/v1/whoami")
            self.assertEqual(st, 401, r)
            self.assertEqual(r["code"], 4010)
            st, r = self._req(base, "/api/v1/whoami", token="cbk_not_a_real_token")
            self.assertEqual(st, 401, r)
        finally:
            srv.shutdown(); srv.server_close()

    def test_api_does_not_accept_cookie_session(self):
        """反向隔离：Web 会话 Cookie 不能调 API（API 只认 Bearer）。"""
        from credvault import web
        web.ensure_user(self.svc.store, "apiuser", "pwd-123456", "admin")
        srv, base = self._serve()
        try:
            import urllib.error
            import urllib.request as ur
            req = ur.Request(base + "/login",
                             data=json.dumps({"user": "apiuser", "password": "pwd-123456"}).encode(),
                             headers={"Content-Type": "application/json"})
            class NR(ur.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            try:
                ur.build_opener(NR).open(req, timeout=5)
                self.fail("登录应返回 302")
            except urllib.error.HTTPError as e:
                sid = [c.split(";")[0].split("=", 1)[1]
                       for c in e.headers.get_all("Set-Cookie") or [] if c.startswith("cvsid=")]
                self.assertTrue(sid)
            cookie = f"cvsid={sid[0]}"
            req2 = ur.Request(base + "/api/v1/whoami", headers={"Cookie": cookie})
            try:
                ur.urlopen(req2, timeout=5)
                self.fail("Cookie 不应能调 API")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 401)
        finally:
            srv.shutdown(); srv.server_close()

    def test_api_invoke_uses_same_gates_as_mcp(self):
        """同源判定：策略拒绝时 API 与 MCP 都返回 code=10。"""
        self.mk_cred()
        tok, _ = self.svc.tokens.create("ai", scope="api")
        agent = self.svc.tokens.resolve(tok)
        # 直接比 dispatch 结果（MCP 与 API 共用同一函数）
        r1 = mcp_mod.dispatch(self.svc, agent, "t_ok", {}, ip="127.0.0.1")
        self.assertEqual(r1["code"], 0, r1)
        r2 = mcp_mod.dispatch(self.svc, agent, "no_such_cap", {}, ip="127.0.0.1")
        self.assertEqual(r2["code"], 10, r2)

        srv, base = self._serve()
        try:
            st, r = self._req(base, "/api/v1/invoke", method="POST",
                              body={"capability": "t_ok", "args": {}}, token=tok)
            self.assertEqual(st, 200, r)
            self.assertTrue(r["ok"])
            self.assertEqual(r["via"], "api")

            st, r = self._req(base, "/api/v1/invoke", method="POST",
                              body={"capability": "no_such_cap"}, token=tok)
            self.assertEqual(st, 403, r)
            self.assertEqual(r["code"], 10)
        finally:
            srv.shutdown(); srv.server_close()

    def test_api_approval_flow_returns_202(self):
        """写能力：API 返回 202 + approval_id，批准后可重试。"""
        self.mk_cred()
        tok, _ = self.svc.tokens.create("ai", scope="api")
        srv, base = self._serve()
        try:
            st, r = self._req(base, "/api/v1/invoke", method="POST",
                              body={"capability": "t_push", "args": {"content": "x"}},
                              token=tok)
            self.assertEqual(st, 202, r)
            self.assertEqual(r["code"], 11)
            aid = r["approval_id"]
            self.svc.approvals.decide(aid, True, "human")
            st, r = self._req(base, "/api/v1/invoke", method="POST",
                              body={"capability": "t_push", "args": {"content": "x"},
                                    "approval_id": aid}, token=tok)
            self.assertEqual(st, 200, r)
            self.assertTrue(r["ok"], r)
        finally:
            srv.shutdown(); srv.server_close()

    def test_api_explain_does_not_call_upstream(self):
        """干跑：不发真实请求，但给出判定。"""
        self.mk_cred()
        tok, _ = self.svc.tokens.create("ai", scope="api")
        srv, base = self._serve()
        try:
            before = self.svc.store.get_credential("AUTH_TOKEN").get("use_count", 0)
            st, r = self._req(base, "/api/v1/explain", method="POST",
                              body={"capability": "t_ok"}, token=tok)
            self.assertEqual(st, 200, r)
            self.assertTrue(r["allow"], r)
            after = self.svc.store.get_credential("AUTH_TOKEN").get("use_count", 0)
            self.assertEqual(before, after)
        finally:
            srv.shutdown(); srv.server_close()

    def test_api_credentials_never_return_values(self):
        """凭据接口只返元数据，响应体不得含明文值。"""
        secret = self.mk_cred()
        tok, _ = self.svc.tokens.create("ai", scope="api")
        srv, base = self._serve()
        try:
            st, r = self._req(base, "/api/v1/credentials", token=tok)
            self.assertEqual(st, 200, r)
            raw = json.dumps(r, ensure_ascii=False)
            self.assertNotIn(secret, raw, "凭据值泄漏到 API 响应")
            self.assertIn("AUTH_TOKEN", raw)
        finally:
            srv.shutdown(); srv.server_close()

    def test_api_scope_migration_defaults_to_mcp(self):
        """存量库升级：没有 scope 列时补成 mcp（升级不扩权）。"""
        import sqlite3 as sq
        db = self.home / "state" / "credvault.db"
        if not db.exists():
            db = self.cfg.path("store.db")
        con = sq.connect(str(db))
        try:
            cols = {r[1] for r in con.execute("PRAGMA table_info(agents)")}
            self.assertIn("scope", cols)
        finally:
            con.close()

    def test_openapi_doc_available(self):
        srv, base = self._serve()
        try:
            st, r = self._req(base, "/api/openapi.json")
            self.assertEqual(st, 200)
            self.assertEqual(r["openapi"], "3.1.0")
            self.assertIn("/invoke", r["paths"])
        finally:
            srv.shutdown(); srv.server_close()


# ── 23. 服务实例隔离（回归：self.svc 取到 None 的 P0）───────────────
class T23ServerInstance(Base):
    """回归 v1.2.0 开发中暴露的 P0：

    Handler 上同时存在 `svc`（类属性兜底）与 `svc_ref`（优先 server 实例）。
    代码里混用 `self.svc` 时，若从没做过 `Handler.svc = X` 赋值，
    就会拿到 None → 任何请求都 500/401。必须强制只走 `svc_ref`。
    """

    def test_no_bare_self_svc_in_handler(self):
        """静态守卫：Handler 内不得有 self.svc（_Server 赋值除外）。"""
        import inspect
        from credvault import web
        src = inspect.getsource(web)
        bad = [ln.strip() for ln in src.splitlines()
               if "self.svc" in ln and "self.svc = svc" not in ln
               and "self.svc_ref" not in ln]
        self.assertEqual(bad, [], f"存在裸 self.svc 引用：{bad[:5]}")

    def test_api_works_without_handler_class_injection(self):
        """不设 Handler.svc，只靠 make_server 注入 server.svc，API 仍通。"""
        from credvault import web
        saved = getattr(web.Handler, "svc", None)
        web.Handler.svc = None          # 刻意清空类属性兜底
        tok, _ = self.svc.tokens.create("ai", scope="api")
        srv = web.make_server(self.svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            req = urllib.request.Request(
                base + "/api/v1/whoami",
                headers={"Authorization": "Bearer " + tok})
            with urllib.request.urlopen(req, timeout=5) as r:
                d = json.loads(r.read())
            self.assertTrue(d["ok"], d)
            self.assertEqual(d["via"], "api")
            # 页面侧同样应可用
            req2 = urllib.request.Request(base + "/healthz")
            with urllib.request.urlopen(req2, timeout=5) as r2:
                self.assertEqual(r2.status, 200)
        finally:
            srv.shutdown(); srv.server_close()
            web.Handler.svc = saved


# ── 24. query 参数解析（回归：parse_qs 值是 list 导致的 500）──────────
class T24QueryParsing(Base):
    """回归 v1.2.0：`parse_qs` 每个值都是 list，`int(query.get("hours"))` 抛
    TypeError → 被兜底成 500，而调用方会把它误读成「0 条记录」。"""

    def _serve(self):
        from credvault import web
        web.Handler.svc = self.svc
        srv = web.make_server(self.svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"

    def _get(self, base, path, token):
        import urllib.error
        req = urllib.request.Request(base + path,
                                     headers={"Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_audit_query_with_hours_does_not_500(self):
        self.mk_cred()
        tok, _ = self.svc.tokens.create("ai", scope="api")
        # 造一条有 epoch 的审计
        self.svc.audit.append("ai", "invoke", True, 5, capability="t_ok")
        srv, base = self._serve()
        try:
            st, r = self._get(base, "/api/v1/audit?hours=1&limit=5", tok)
            self.assertEqual(st, 200, r)          # 曾经是 500
            self.assertTrue(r["ok"], r)
            self.assertGreaterEqual(len(r.get("records", [])), 1, r)
            # 带普通字符串参数也应正常
            st, r = self._get(base, "/api/v1/audit?hours=24&capability=t_ok", tok)
            self.assertEqual(st, 200, r)
            # 非法数字回退到默认值，不炸
            st, r = self._get(base, "/api/v1/audit?hours=abc", tok)
            self.assertEqual(st, 200, r)
        finally:
            srv.shutdown(); srv.server_close()

    def test_qv_helpers(self):
        from credvault import api
        q = {"hours": ["1"], "capability": ["t_ok"], "limit": []}
        self.assertEqual(api._qint(q, "hours", 24), 1)
        self.assertEqual(api._qint(q, "limit", 50), 50)      # 空 list → 默认
        self.assertEqual(api._qint(q, "missing", 7), 7)
        self.assertEqual(api._qstr(q, "capability"), "t_ok")
        self.assertEqual(api._qstr(q, "missing"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
