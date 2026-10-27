"""webui.py — 三个视图的 HTML 渲染（纯函数，无 IO、无状态）

从 web.py 拆出的原因：路由层（鉴权/CSRF/探针/JSON API）与渲染层混在 508 行的单文件里，
改样式会碰到鉴权代码的上下文，违背「变更半径最小」。此处只允许纯渲染，便于独立改版。
"""
from __future__ import annotations

import json

from .store import now


_CSS = """
:root{--bg:#f7f8fa;--card:#fff;--line:#e3e6ea;--txt:#1f2328;--mute:#5f6b7a;
--acc:#185fa5;--ok:#1d9e75;--warn:#ba7517;--bad:#a32d2d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.6 -apple-system,
"Segoe UI","Microsoft YaHei",sans-serif}
header{display:flex;gap:16px;align-items:center;padding:14px 24px;background:var(--card);
border-bottom:1px solid var(--line)}
header b{font-weight:600}
nav a{margin-right:14px;color:var(--mute);text-decoration:none;padding:4px 2px}
nav a.on{color:var(--acc);border-bottom:2px solid var(--acc)}
main{padding:20px 24px;max-width:1180px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);
vertical-align:top;font-size:13px}
th{background:#f1f4f7;font-weight:500;color:var(--mute)}
tr:last-child td{border-bottom:none}
code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.tag{display:inline-block;padding:1px 7px;border-radius:10px;font-size:12px;
border:1px solid var(--line);color:var(--mute)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
button{font:inherit;padding:5px 12px;border-radius:6px;border:1px solid var(--line);
background:#fff;cursor:pointer}
button.p{background:var(--ok);border-color:var(--ok);color:#fff}
button.d{background:#fff;border-color:var(--bad);color:var(--bad)}
input{font:inherit;padding:6px 9px;border:1px solid var(--line);border-radius:6px;
width:100%;max-width:360px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;
margin-bottom:16px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:6px 0}
h2{font-size:15px;font-weight:600;margin:0 0 10px}
.hint{color:var(--mute);font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.kpi b{display:block;font-size:22px;font-weight:600}
"""


def _shell(active: str, body: str, s: dict | None = None) -> str:
    who = f'<span class="hint">已登录 {s["user"]}（{s["role"]}）</span>' if s else ""
    return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CredVault · {active}</title><style>{_CSS}</style></head><body>
<header><b>CredVault</b>
<nav><a href="/approvals" class="{'on' if active=='待审批' else ''}">待审批</a>
<a href="/audit" class="{'on' if active=='审计' else ''}">审计</a>
<a href="/tokens" class="{'on' if active=='令牌' else ''}">令牌</a></nav>
<span style="flex:1"></span>{who}
<form method="post" action="/logout" style="margin:0"><button>退出</button></form>
</header><main>{body}</main>
<script>window.CSRF={json.dumps(s["csrf"]) if s else '""'};</script>
</body></html>"""


def page_login(err: str = "") -> str:
    msg = f'<p class="bad">{err}</p>' if err else ""
    return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>CredVault · 登录</title><style>{_CSS}</style></head><body>
<main style="max-width:380px;margin:80px auto">
<div class="card"><h2>CredVault 登录</h2>{msg}
<form method="post" action="/login">
<div class="row"><input name="user" placeholder="用户名" autofocus></div>
<div class="row"><input name="password" type="password" placeholder="密码"></div>
<div class="row"><button class="p">登录</button></div>
</form>
<p class="hint">首次使用：<code>credvault user add admin</code> 创建账号</p>
</div></main></body></html>"""


_JS = """
async function post(url, body){
  const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json',
    'X-CSRF':window.CSRF},body:JSON.stringify(body||{})});
  return await r.json().catch(()=>({ok:false,reason:'响应不是 JSON'}));
}
document.addEventListener('click', async (e)=>{
  const b = e.target.closest('button[data-act]'); if(!b) return;
  const act = b.dataset.act, id = b.dataset.id||'', name = b.dataset.name||'';
  let r;
  if(act==='approve') r = await post('/api/decide',{id,approve:true,
      session: !!document.querySelector('#sess-'+id)?.checked});
  else if(act==='reject') r = await post('/api/decide',{id,approve:false});
  else if(act==='revoke') r = await post('/api/tokens/revoke',{name});
  else if(act==='rotate') r = await post('/api/tokens/rotate',{name});
  else if(act==='create') r = await post('/api/tokens/create',{
      name: document.querySelector('#t-name').value,
      ttl_days: document.querySelector('#t-ttl').value,
      allowed_capabilities: document.querySelector('#t-caps').value,
      visible_credentials: document.querySelector('#t-creds').value,
      ip_allowlist: document.querySelector('#t-ips').value});
  else if(act==='clear') r = await post('/api/exemption/clear',{id});
  if(r && r.token){ alert('令牌（只显示一次）：\\n'+r.token); }
  if(r && r.message){ alert(r.message); }
  if(r && !r.ok && r.reason){ alert('失败：'+r.reason); }
  if(r && (r.ok!==false)) location.reload();
});
"""


def page_approvals(s: dict, svc) -> str:
    pend = svc.approvals.pending()
    ex = svc.approvals.exemptions()
    rows = "".join(
        f"""<tr><td class="mono">{a['id']}</td><td>{a['capability']}</td>
<td>{a['requested_by']}</td><td class="mono">{a['args_preview'][:110]}</td>
<td>{a['remaining_sec']//60} 分钟</td>
<td><label class="hint"><input type="checkbox" id="sess-{a['id']}"
 style="width:auto;margin-right:4px">会话豁免</label></td>
<td><button class="p" data-act="approve" data-id="{a['id']}">批准</button>
<button class="d" data-act="reject" data-id="{a['id']}">拒绝</button></td></tr>"""
        for a in pend)
    if not rows:
        rows = '<tr><td colspan="7" class="hint">没有待审批项</td></tr>'
    ex_rows = "".join(
        f'<tr><td class="mono">{e["id"]}</td><td>{e["capability"]}</td>'
        f'<td>{e["agent_id"]}</td><td>{max(0,e["expires_at"]-now())//60} 分钟</td>'
        f'<td><button data-act="clear" data-id="{e["id"]}">撤销</button></td></tr>'
        for e in ex) or '<tr><td colspan="5" class="hint">无</td></tr>'
    body = f"""<h2>待审批（{len(pend)}）</h2>
<div class="card" style="padding:0;overflow:hidden"><table>
<tr><th>审批号</th><th>能力</th><th>申请方</th><th>参数</th><th>剩余</th>
<th>豁免</th><th>动作</th></tr>{rows}</table></div>
<h2>会话豁免</h2>
<div class="card" style="padding:0;overflow:hidden"><table>
<tr><th>ID</th><th>能力</th><th>Agent</th><th>剩余</th><th></th></tr>{ex_rows}</table></div>
<p class="hint">批准后 AI 带同一审批号重试即可执行；勾选「会话豁免」后同类能力在本会话内不再重复申请。</p>
<script>{_JS}</script>"""
    return _shell("待审批", body, s)


def page_audit(s: dict, svc) -> str:
    st = svc.audit.stats(now() - 86400)
    rows = svc.audit.search(limit=120)
    trs = "".join(
        f"<tr><td class='mono'>{r.get('ts','')[11:19]}</td><td>{r.get('actor','')}</td>"
        f"<td>{r.get('capability') or r.get('tool','')}</td>"
        f"<td class='mono'>{r.get('credential','')}</td>"
        f"<td class='{'ok' if r.get('ok') else 'bad'}'>{'成功' if r.get('ok') else '失败'}</td>"
        f"<td>{r.get('dur_ms',0)}</td><td class='hint'>{(r.get('note') or '')[:90]}</td></tr>"
        for r in rows) or '<tr><td colspan="7" class="hint">暂无记录</td></tr>'
    ok, note, n = svc.audit.verify()
    body = f"""<div class="grid">
<div class="kpi"><span class="hint">24h 调用</span><b>{st['total']}</b></div>
<div class="kpi"><span class="hint">失败</span><b class="bad">{st['by_status']['fail']}</b></div>
<div class="kpi"><span class="hint">链完整性</span>
<b class="{'ok' if ok else 'bad'}">{'完整' if ok else '断裂'}</b>
<span class="hint">{n} 条</span></div>
<div class="kpi"><span class="hint">待审批</span><b>{len(svc.approvals.pending())}</b></div>
</div>
<h2>最近调用（时间倒序）</h2>
<div class="card" style="padding:0;overflow:hidden"><table>
<tr><th>时间(UTC)</th><th>调用方</th><th>能力</th><th>凭据</th><th>结果</th>
<th>耗时 ms</th><th>备注</th></tr>{trs}</table></div>
<p class="hint">审计为哈希链追加：任何一行被改都会在 <code>credvault audit verify</code>
与上方「链完整性」中暴露。导出：<code>credvault audit export --format csv</code></p>"""
    return _shell("审计", body, s)


def page_tokens(s: dict, svc) -> str:
    agents = svc.tokens.list()
    caps = [c.name for c in svc.caps]
    rows = "".join(
        f"<tr><td class='mono'>{a['name']}</td>"
        f"<td>{'已吊销' if a['revoked'] else ('过期' if a['expires_at'] and a['expires_at']<now() else '有效')}</td>"
        f"<td class='mono'>{a['expires_at'] or '永不'}</td>"
        f"<td class='mono'>{(a['allowed_capabilities'] or ['全部'])[:4] if isinstance(a['allowed_capabilities'],list) else '全部'}</td>"
        f"<td class='mono'>{a['visible_credentials'] or '全部'}</td>"
        f"<td><button data-act='rotate' data-name='{a['name']}'>轮换</button>"
        f"<button class='d' data-act='revoke' data-name='{a['name']}'>吊销</button></td></tr>"
        for a in agents) or '<tr><td colspan="6" class="hint">还没有令牌</td></tr>'
    body = f"""<h2>签发令牌</h2>
<div class="card">
<div class="row"><input id="t-name" placeholder="agent 名称，如 workbuddy-local"></div>
<div class="row"><input id="t-ttl" placeholder="有效期天数（0=永不）" value="90"></div>
<div class="row"><input id="t-caps" placeholder="允许能力（逗号分隔，空=由策略决定）"></div>
<div class="row"><input id="t-creds" placeholder="可见凭据（逗号分隔，空=全部）"></div>
<div class="row"><input id="t-ips" placeholder="IP 白名单（逗号分隔，空=不限）"></div>
<div class="row"><button class="p" data-act="create">签发</button>
<span class="hint">明文只显示一次；双轴授权 + IP 白名单，令牌被带走也能限制范围</span></div>
</div>
<h2>现有令牌（{len(agents)}）</h2>
<div class="card" style="padding:0;overflow:hidden"><table>
<tr><th>名称</th><th>状态</th><th>到期</th><th>能力范围</th><th>可见凭据</th><th>动作</th></tr>
{rows}</table></div>
<p class="hint">可用能力共 {len(caps)} 个：<span class="mono">{', '.join(sorted(caps)[:18])}</span></p>
<script>{_JS}</script>"""
    return _shell("令牌", body, s)


