"""executor.py — 两种执行器：HTTP 代发 与 子进程注入

安全边界（每条都有实测教训背书）：
  - SSRF：解析全部 A/AAAA，任一落到私网且未显式放行 → 拒（不只看字面 IP）
  - 非幂等方法不重试：POST 遇连接错误重发会重复写库/重复推送
  - 连接池上限 + 失败连接立即摘除：长驻进程按站点数无界增长
  - 不跟随重定向：3xx 原样返回，避免被诱导到未授权主机
  - exec：argv 列表（不接受 shell 字符串）+ argv[0] 白名单 + env 最小化
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import subprocess
import threading
import urllib.parse
from typing import Any

MAX_POOL = 32
_POOL: dict[tuple, http.client.HTTPConnection] = {}
_POOL_ORDER: list[tuple] = []
_POOL_LOCK = threading.Lock()


class ExecError(RuntimeError):
    pass


# ── SSRF ────────────────────────────────────────────────────────────────
def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_reserved or a.is_multicast or a.is_unspecified)


def resolve_and_check(url: str, allow_private: bool) -> tuple[str | None, list[str]]:
    """解析并校验，一次解析同时供校验与连接使用（W4：消除 DNS rebinding 窗口）。

    返回 (拒绝原因或 None, 已解析 IP 列表)。调用方应把 IP 列表传给 http_request，
    由其用 IP 建连（Host 头保留原域名），避免「校验时解析到公网、连接时解析到内网」。
    """
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError as e:
        return f"URL 解析失败: {e}"
    if u.scheme not in ("http", "https"):
        return f"只允许 http/https，收到 {u.scheme!r}"
    host = u.hostname or ""
    if not host:
        return "URL 缺少主机名"
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return f"域名解析失败: {e}"
    addrs = sorted({i[4][0] for i in infos})
    if not allow_private:
        bad = [a for a in addrs if _is_private(a)]
        if bad:
            return f"目标解析到私网地址 {bad}（该能力未开 allow_private_upstream）", addrs
    return None, addrs


def check_ssrf(url: str, allow_private: bool) -> str | None:
    reason, _ = resolve_and_check(url, allow_private)
    return reason


# ── HTTPS 定型连接（pinned IP 建连 + 原域名 SNI）─────────────────────────
class _PinnedHTTPS(http.client.HTTPSConnection):
    """用 pinned IP 建连，但 TLS SNI 仍发原域名（否则上游按 SNI 拒绝握手）。

    W4 的「解析一次、连接同源」若直接用 IP 建连，SNI 会变成 IP，多数反代/CDN 直接
    回 TLSV1_ALERT_INTERNAL_ERROR（实测部分自签证书上游即如此）。故必须显式覆盖 wrap_socket。
    """

    def __init__(self, host: str, port: int, timeout: int, server_hostname: str):
        super().__init__(host, port, timeout=timeout)
        self._sni = server_hostname

    def connect(self) -> None:
        super().connect()
        # 上面的 super().connect() 已用 IP 完成 TCP + 默认 SNI 握手；此处重建以带正确 SNI
        try:
            self.sock.close()
        except Exception:  # noqa: BLE001
            pass
        self.sock = self._create_connection((self.host, self.port), self.timeout,
                                            self.source_address)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._sni)


# ── 连接池 ──
def _get_conn(scheme: str, host: str, port: int, timeout: int,
              sni: str = "") -> http.client.HTTPConnection:
    # W6：timeout 进 key —— 同一站点不同超时复用同一连接会拿到旧 timeout
    key = (scheme, host, port, timeout, sni)
    with _POOL_LOCK:
        conn = _POOL.get(key)
        if conn is not None:
            return conn
        if scheme == "https" and sni and sni != host:
            conn = _PinnedHTTPS(host, port, timeout, sni)
        else:
            cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = cls(host, port, timeout=timeout)
        while len(_POOL) >= MAX_POOL and _POOL_ORDER:
            old = _POOL_ORDER.pop(0)
            oldc = _POOL.pop(old, None)
            if oldc is not None:
                try:
                    oldc.close()
                except Exception:  # noqa: BLE001
                    pass
        _POOL[key] = conn
        _POOL_ORDER.append(key)
        return conn


def _drop_conn(key: tuple) -> None:
    with _POOL_LOCK:
        c = _POOL.pop(key, None)
        if key in _POOL_ORDER:
            _POOL_ORDER.remove(key)
    if c is not None:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass


def close_pool() -> int:
    with _POOL_LOCK:
        n = len(_POOL)
        for c in _POOL.values():
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
        _POOL.clear()
        _POOL_ORDER.clear()
    return n


# ── HTTP ────────────────────────────────────────────────────────────────
def http_request(url: str, method: str = "GET", headers: dict | None = None,
                 body: bytes = b"", timeout: int = 20, retry_ok: bool = False,
                 max_retry: int = 1, pinned_host: str = "") -> tuple[int, dict, bytes]:
    """pinned_host 非空时用它建连（SSRF 校验已解析到的 IP），但 Host 头保留原域名。"""
    u = urllib.parse.urlsplit(url)
    path = urllib.parse.urlunsplit(("", "", u.path or "/", u.query, ""))
    connect_host = pinned_host or (u.hostname or "")
    sni = (u.hostname or "") if pinned_host else ""
    key = (u.scheme, connect_host, u.port or (443 if u.scheme == "https" else 80))
    attempts = (1 + max_retry) if retry_ok else 1
    if pinned_host and pinned_host != (u.hostname or ""):
        host_hdr = u.hostname if u.port is None or u.port == (443 if u.scheme == "https" else 80) \
            else f"{u.hostname}:{u.port}"
        headers = {**(headers or {}), "Host": host_hdr}
    last: Exception | None = None
    for i in range(attempts):
        conn = _get_conn(key[0], key[1], key[2], timeout, sni)
        try:
            conn.request(method.upper(), path, body=body or None, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, {k: v for k, v in resp.getheaders()}, data
        except (http.client.HTTPException, OSError) as e:
            last = e
            _drop_conn(key)
            if i + 1 >= attempts:
                break
    raise ExecError(f"{type(last).__name__}: {last}")


# ── 子进程 ──────────────────────────────────────────────────────────────
_ENV_KEEP = frozenset({
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP",
    "HOME", "USERPROFILE", "USERNAME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE",
    "TZ", "TERM", "PWD", "HOSTNAME", "SHELL", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    "PROGRAMFILES", "PROGRAMFILES(X86)", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "OS", "PYTHONIOENCODING", "PYTHONUTF8", "PYTHONPATH", "VIRTUAL_ENV", "SSH_AUTH_SOCK",
})
_SECRETISH = ("pass", "pwd", "secret", "token", "key", "credential", "auth", "cookie",
              "bearer", "signature", "webhook")


def sanitized_env(inject: dict[str, str]) -> dict[str, str]:
    """白名单透传 + 阻断凭据样式变量名 + 注入本次所需的那几个。"""
    env: dict[str, str] = {}
    for k, v in os.environ.items():
        if k in _ENV_KEEP:
            env[k] = v
            continue
        if any(s in k.lower() for s in _SECRETISH):
            continue
        if k.startswith(("MSYS_", "MINGW", "__CF", "PROCESSOR_")):
            env[k] = v
    env.update(inject)
    return env


def run_exec(argv: list[str], inject: dict[str, str], allowlist: list[str],
             timeout: int = 30, cwd: str = "") -> tuple[int, str, str]:
    if not isinstance(argv, list) or not argv:
        raise ExecError("argv 必须是非空列表")
    exe = os.path.basename(str(argv[0]))
    allowed = {os.path.basename(a) for a in allowlist}
    if exe not in allowed:
        raise ExecError(f"可执行文件 {exe} 不在白名单 {sorted(allowed)} 内")
    if any(isinstance(a, str) and ("\n" in a or "\x00" in a) for a in argv):
        raise ExecError("argv 含非法字符")
    try:
        p = subprocess.run([str(a) for a in argv], capture_output=True,
                           encoding=("gb18030" if os.name == "nt" else "utf-8"),
                           errors="replace", timeout=timeout,
                           env=sanitized_env(inject), cwd=cwd or None)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        raise ExecError(f"执行超时（{timeout}s）") from e
    except FileNotFoundError as e:
        raise ExecError(f"命令不存在: {e}") from e


def apply_inject(headers: dict, query: list, body: Any, inject: dict, secret: str,
                 url: str) -> tuple[dict, str, bytes]:
    """按配置把凭据注入 header / query / body；返回 (headers, url, body_bytes)。"""
    import base64
    import json
    t = (inject or {}).get("type", "header")
    name = (inject or {}).get("name") or ""
    prefix = (inject or {}).get("prefix") or ""
    if not secret:
        raise ExecError("凭据为空，拒绝注入")
    if t == "bearer":
        headers[name or "Authorization"] = f"{prefix or 'Bearer '}{secret}"
    elif t == "header":
        if not name:
            raise ExecError("inject.type=header 必须给 name")
        headers[name] = f"{prefix}{secret}"
    elif t == "basic":
        headers[name or "Authorization"] = "Basic " + base64.b64encode(secret.encode()).decode()
    elif t == "query":
        u = urllib.parse.urlsplit(url)
        q = [(k, v) for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)
             if k != (name or "key")]
        q.append((name or "key", secret))
        url = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path,
                                       urllib.parse.urlencode(q), u.fragment))
    elif t == "body":
        if isinstance(body, dict):
            body = {**body, name or "token": secret}
        else:
            raise ExecError("inject.type=body 需要 body 是 JSON 对象")
    else:
        raise ExecError(f"未知注入方式 {t}")
    return headers, url, body
