"""web.py — 人工辅助面（I15/I16）：只有三个视图 + 登录

刻意不做的事：凭据 CRUD 后台、仪表盘、报表、租户、菜单权限。
理由见设计文档 §7：AI 主用场景下，人只在「审批 / 审计 / 令牌」三处出现；
多做的每一个页面都是需要长期维护、却几乎没人点的东西。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import api as api_mod
from . import kinds as kinds_mod
from . import mcp as mcp_mod
from . import ops
from . import webui
from .store import now

COOKIE = "cvsid"
SESSIONS: dict[str, dict] = {}

# 登录失败限速（M3）：内存滑动窗口。进程重启清零是可接受代价——爆破需要持续在线
_LOGIN_FAILS: dict[str, list[float]] = {}
_LOGIN_WINDOW = 300          # 5 分钟
_LOGIN_MAX = 5               # 窗口内最多 5 次失败


def login_blocked(key: str) -> bool:
    now = time.time()
    hits = [t for t in _LOGIN_FAILS.get(key, []) if now - t < _LOGIN_WINDOW]
    _LOGIN_FAILS[key] = hits
    return len(hits) >= _LOGIN_MAX


def login_fail(key: str) -> int:
    _LOGIN_FAILS.setdefault(key, []).append(time.time())
    return len(_LOGIN_FAILS[key])


def login_ok(key: str) -> None:
    _LOGIN_FAILS.pop(key, None)


# ── 口令 ──
def hash_password(pwd: str, iterations: int = 120_000) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${h.hex()}"


def verify_password(pwd: str, stored: str) -> bool:
    try:
        algo, it, salt, h = stored.split("$")
        if algo != "pbkdf2":
            return False
        got = hashlib.pbkdf2_hmac("sha256", pwd.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(got.hex(), h)
    except (ValueError, TypeError):
        return False


def ensure_user(store, name: str, pwd: str, role: str = "admin") -> bool:
    if store._meta.execute("SELECT 1 FROM users WHERE name=?", (name,)).fetchone():
        return False
    import uuid
    with store.tx() as c:
        c.execute("INSERT INTO users(id,name,pwd_hash,role,created_at) VALUES(?,?,?,?,?)",
                  (uuid.uuid4().hex[:12], name, hash_password(pwd), role, now()))
    return True


def set_password(store, name: str, pwd: str) -> bool:
    with store.tx() as c:
        cur = c.execute("UPDATE users SET pwd_hash=? WHERE name=?", (hash_password(pwd), name))
    return cur.rowcount > 0


class Handler(BaseHTTPRequestHandler):
    # 每个 server 自带 svc（make_server 走 server.svc），不使用全局类属性，
    # 否则同进程起两个实例（测试/多租户）会互相污染。
    svc = None            # 兼容旧用法：无 server 绑定时作为兜底（测试/单例脚本）
    server_version = "credvault/" + ops.VERSION

    @property
    def svc_ref(self):
        """优先 server 实例，其次类属性兜底。"""
        return getattr(self.server, "svc", None) or type(self).svc
    protocol_version = "HTTP/1.1"

    # ── 基础设施 ──
    def log_message(self, fmt: str, *args) -> None:  # 静音默认 access log
        pass

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json")

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if n <= 0 or n > 1_000_000:
            return {}
        raw = self.rfile.read(n)
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace")).items()}

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _session(self) -> dict | None:
        sid = self._cookie(COOKIE)
        if not sid:
            return None
        rec = SESSIONS.get(sid)
        if not rec:
            return None
        if rec["expires_at"] < time.time():
            SESSIONS.pop(sid, None)
            return None
        return rec

    def _require_session(self) -> dict | None:
        s = self._session()
        if not s:
            if self.path.startswith("/api/"):
                self._json(401, {"ok": False, "reason": "未登录"})
            else:
                self._send(302, b"", headers={"Location": "/login"})
            return None
        return s

    def _can(self, s: dict, need: str) -> bool:
        """最小角色门禁：viewer 只读；approver 可审批；admin 全部。"""
        role = s.get("role", "viewer")
        allow = {"read": {"admin", "approver", "viewer"},
                 "approve": {"admin", "approver"},
                 "admin": {"admin"}}[need]
        return role in allow

    def _require_csrf(self, s: dict) -> bool:
        got = self.headers.get("X-CSRF") or ""
        if not hmac.compare_digest(got, s["csrf"]):
            self._json(403, {"ok": False, "reason": "CSRF 校验失败"})
            return False
        return True

    # ── 路由 ──
    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        u = urllib.parse.urlsplit(self.path)
        p, q = u.path, urllib.parse.parse_qs(u.query)
        if p == "/healthz":
            return self._json(200, {"ok": True, "version": ops.VERSION})
        if p == "/readyz":
            h = ops.health(self.svc_ref, deep=False)
            return self._json(200 if h["ok"] else 503, {"ok": h["ok"], "blocking": h["blocking"]})
        if p == "/version":
            return self._json(200, {"version": ops.VERSION, "protocol": mcp_mod.PROTOCOL})
        if p == "/metrics":
            return self._send(200, ops.metrics(self.svc_ref).encode(), "text/plain; version=0.0.4")
        # ── REST API（Bearer 鉴权，与 Web 会话完全独立，故置于会话校验之前）──
        if p == "/api/v1" or p.startswith("/api/v1/"):
            return self._api_v1("GET", p, q, {})
        if p == "/api/openapi.json":   # 接口描述：公开文档，不含任何凭据信息
            return self._json(200, api_mod.openapi())
        if p == "/login":
            return self._send(200, webui.page_login().encode())
        if p in ("/", ""):
            return self._send(302, b"", headers={"Location": "/approvals"})
        s = self._require_session()
        if not s:
            return
        if p == "/approvals":
            return self._send(200, webui.page_approvals(s, self.svc_ref).encode())
        if p == "/audit":
            return self._send(200, webui.page_audit(s, self.svc_ref).encode())
        if p == "/tokens":
            return self._send(200, webui.page_tokens(s, self.svc_ref).encode())
        if p == "/api/approvals":
            return self._json(200, {"ok": True, "pending": self.svc_ref.approvals.pending(),
                                    "recent": self.svc_ref.approvals.recent(30),
                                    "exemptions": self.svc_ref.approvals.exemptions()})
        if p == "/api/audit":
            hours = int((q.get("hours") or ["24"])[0])
            rows = self.svc_ref.audit.search(limit=int((q.get("limit") or ["100"])[0]),
                                         since_epoch=now() - hours * 3600,
                                         capability=(q.get("capability") or [""])[0],
                                         keyword=(q.get("q") or [""])[0])
            return self._json(200, {"ok": True, "records": rows,
                                    "stats": self.svc_ref.audit.stats(now() - hours * 3600)})
        if p == "/api/tokens":
            return self._json(200, {"ok": True, "agents": self.svc_ref.tokens.list()})
        if p == "/api/health":
            return self._json(200, ops.health(self.svc_ref))
        return self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        u = urllib.parse.urlsplit(self.path)
        p = u.path
        if p == "/login":
            return self._login()
        if p == "/logout":
            s = self._session()
            if s:
                SESSIONS.pop(self._cookie(COOKIE), None)
            return self._send(302, b"", headers={"Location": "/login",
                                                 "Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0"})
        if p == "/mcp":
            return self._mcp()
        # ── REST API（Bearer 鉴权；不要求 CSRF——没有 Cookie 就没有 CSRF 面）──
        if p == "/api/v1" or p.startswith("/api/v1/"):
            return self._api_v1("POST", p, {}, self._body())
        s = self._require_session()
        if not s:
            return
        if not self._require_csrf(s):
            return
        body = self._body()
        if p == "/api/decide" and not self._can(s, "approve"):
            return self._json(403, {"ok": False, "reason": "当前角色无审批权限"})
        if p.startswith("/api/tokens") and not self._can(s, "admin"):
            return self._json(403, {"ok": False, "reason": "当前角色无令牌管理权限"})
        if p == "/api/kinds":
            return self._json(200, {"ok": True, "kinds": kinds_mod.describe_all()})
        if p == "/api/decide":
            aid = str(body.get("id", ""))
            approve = bool(body.get("approve"))
            session = bool(body.get("session"))
            by = s["user"]
            ok, msg = self.svc_ref.approvals.decide(aid, approve, by,
                                                str(body.get("reason", "")), session)
            return self._json(200 if ok else 400, {"ok": ok, "message": msg})
        if p == "/api/tokens/create":
            try:
                token, rec = self.svc_ref.tokens.create(
                    str(body.get("name", "")).strip(),
                    ttl_days=int(body.get("ttl_days") or 0),
                    visible_credentials=_csv(body.get("visible_credentials")),
                    allowed_capabilities=_csv(body.get("allowed_capabilities")),
                    ip_allowlist=_csv(body.get("ip_allowlist")))
            except Exception as e:  # noqa: BLE001
                return self._json(400, {"ok": False, "reason": str(e)})
            self.svc_ref.audit.append(s["user"], "token.create", True, 0, note=rec["name"])
            return self._json(200, {"ok": True, "token": token, "agent": rec,
                                    "note": "令牌明文只显示这一次"})
        if p == "/api/tokens/rotate":
            try:
                token = self.svc_ref.tokens.rotate(str(body.get("name", "")))
            except Exception as e:  # noqa: BLE001
                return self._json(400, {"ok": False, "reason": str(e)})
            self.svc_ref.audit.append(s["user"], "token.rotate", True, 0,
                                  note=str(body.get("name", "")))
            return self._json(200, {"ok": True, "token": token})
        if p == "/api/tokens/revoke":
            ok = self.svc_ref.tokens.revoke(str(body.get("name", "")))
            return self._json(200, {"ok": ok})
        if p == "/api/exemption/clear":
            ok = self.svc_ref.approvals.clear_exemption(str(body.get("id", "")))
            return self._json(200, {"ok": ok})
        return self._send(404, b"not found", "text/plain")

    # ── REST API v1（Bearer 令牌，不是 Cookie）──
    def _api_v1(self, method: str, path: str, query: dict, body: dict) -> None:
        """把 /api/v1/xxx 交给 api.handle，统一做错误映射。

        与 Web 后台的三点区别：
          1. 鉴权走 Bearer 令牌（scope 须为 api/both），**不需要 Cookie 与 CSRF**
          2. 无会话 → 无 Cookie 面 → 天然不受 CSRF 影响
          3. 状态码按 api.STATUS 映射，让脚本能按 HTTP 语义写重试逻辑
        """
        auth = self.headers.get("Authorization") or ""
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        sub = path[len(api_mod.API_PREFIX):] or "/"
        try:
            status, payload = api_mod.handle(
                self.svc_ref, method, sub, query, body, token, self.client_address[0])
        except Exception as e:  # noqa: BLE001 —— 绝不把栈泄给外部调用方
            status, payload = 500, {"ok": False, "code": 17,
                                    "reason": f"{type(e).__name__}: {str(e)[:200]}",
                                    "next_action": "查服务端日志；不要把本次请求当成功"}
        return self._json(status, payload)

    # ── 登录 ──
    def _login(self) -> None:
        body = self._body()
        name = str(body.get("user", "")).strip()
        pwd = str(body.get("password", ""))
        key = f"{self.client_address[0]}|{name}"
        if login_blocked(key):
            self.svc_ref.audit.append(f"human:{name or '-'}", "login", False, 0,
                                  note=f"RATE-LIMITED ip={self.client_address[0]}")
            return self._send(429, webui.page_login("失败次数过多，请 5 分钟后再试").encode())
        row = self.svc_ref.store._meta.execute(
            "SELECT * FROM users WHERE name=?", (name,)).fetchone()
        if not row or not verify_password(pwd, row["pwd_hash"]):
            n = login_fail(key)
            self.svc_ref.audit.append(f"human:{name or '-'}", "login", False, 0,
                                  note=f"bad credentials (fail {n}/{_LOGIN_MAX})")
            return self._send(401, webui.page_login("用户名或密码错误").encode())
        sid = secrets.token_urlsafe(24)
        csrf = secrets.token_urlsafe(16)
        ttl = int(self.svc_ref.cfg.get("web.session_ttl_min", 480)) * 60
        SESSIONS[sid] = {"user": name, "role": row["role"], "csrf": csrf,
                         "expires_at": time.time() + ttl}
        with self.svc_ref.store.tx() as c:
            c.execute("INSERT INTO sessions(id,user_id,csrf,created_at,expires_at)"
                      " VALUES(?,?,?,?,?)", (sid, row["id"], csrf, now(), now() + ttl))
        login_ok(key)
        self.svc_ref.audit.append(f"human:{name}", "login", True, 0)
        secure = "; Secure" if self.svc_ref.cfg.get("web.cookie_secure", True) else ""
        self._send(302, b"", headers={
            "Location": "/approvals",
            "Set-Cookie": f"{COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax{secure}",
        })

    # ── MCP over HTTP（单次请求-响应；stdio 为主通道）──
    def _mcp(self) -> None:
        auth = self.headers.get("Authorization") or ""
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            return self._json(401, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32001, "message": "缺少 Bearer Token"}})
        try:
            ag = self.svc_ref.authenticate(token, self.client_address[0])
        except Exception as e:  # noqa: BLE001
            return self._json(401, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32001, "message": str(e)}})
        # scope 校验：scope=api 的令牌不得走 MCP 入口（与 /api/v1 反向对称）
        if (ag.get("scope") or "mcp") not in ("mcp", "both"):
            return self._json(403, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32003,
                                              "message": f"该令牌 scope={ag.get('scope')}，"
                                                         "不能用于 MCP 入口"}})
        body = self._body()
        try:
            res = mcp_mod.handle_http(self.svc_ref, token, body, self.client_address[0])
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"jsonrpc": "2.0", "id": body.get("id"),
                                    "error": {"code": -32603, "message": str(e)[:200]}})
        return self._json(200, res or {})


def _csv(v) -> list[str] | None:
    if v is None:
        return None
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    items = [x.strip() for x in str(v).replace("\n", ",").split(",")]
    items = [x for x in items if x]
    return items or None


class _Server(ThreadingHTTPServer):
    """把 svc 挂在 server 实例上（而非 Handler 类属性），多实例互不污染。

    兼容旧用法：`Handler.svc = X` 仍可作为**兜底**被读取（见 Handler.svc_of）。
    """

    daemon_threads = True

    def __init__(self, addr, handler, svc):
        self.svc = svc
        super().__init__(addr, handler)


def make_server(svc, host: str, port: int) -> ThreadingHTTPServer:
    return _Server((host, port), Handler, svc)
