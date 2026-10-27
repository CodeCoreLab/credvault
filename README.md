# CredVault

[![CI](https://github.com/CodeCoreLab/credvault/actions/workflows/ci.yml/badge.svg)](https://github.com/CodeCoreLab/credvault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![deps](https://img.shields.io/badge/deps-cryptography%20%2B%20pyyaml-green)
![tests](https://img.shields.io/badge/tests-109%20passing-brightgreen)

**AI 主用、人工辅助的凭据平台。** 给 AI 的是「任务级能力」，不是「一把能读所有密码的钥匙」：
凭据只在内核里出现一次，AI 永远拿到脱敏后的结果；人只在**审批 / 审计 / 令牌**三处出现。

```
AI 客户端 ──MCP(stdio/HTTP+Bearer)──> 能力注册表 ──> 策略 ──> 审批 ──> 注入 ──> 脱敏 ──> 哈希链审计
                                        ▲                                      │
                                    capabilities/*.yaml（加一行=多一个工具）     └──> 脱敏后的结构化结果
```

## 为什么是这个形态（而不是又一个密码管理器）

个人密码管理器解决「人记不住密码」；桌面 AI 金库（如 Sigil 掌玺）解决「AI 别拿到明文」，
但要求**桌面端常开且已解锁**，服务器场景不成立。CredVault 解决的是第三个问题：
**在无人值守的服务器上，让 AI 用得对、用得省、出问题查得到。**

| 判据 | 本项目的做法 |
|---|---|
| AI 能不能自己发现「能做什么」 | `initialize.instructions` 动态生成中文引导 + `list_capabilities` 自省；未授权的能力**不出现**在工具列表里 |
| 调用是不是任务语义 | 工具名是 `zabbix_host_list`，不是 `call_api(credential, url, method)` —— AI 不用知道 URL 形态 |
| 会不会烧掉上下文 | 返回体默认 32KB 硬预算 + `summary_only` 结构化裁剪 + `structuredContent` |
| 失败了能不能自愈 | 20 个错误码（0/10–20）+ `next_action`，instructions 里写明每种码该怎么处置 |
| 需审批会不会卡死 | 异步审批：返回 `approval_id` → 人点 Web/企微 → AI 轮询 `approval_status` 后重试；支持会话豁免 |
| 人要不要会命令行 | 不用。审批在 Web 三视图里点，事件可推企微 |

## 5 分钟上手

```bash
# 1) 安装（幂等：重复执行不覆盖数据）
./install.sh                        # 数据目录默认 ~/.credvault
export CREDVAULT_HOME=~/.credvault

# 2) 录一条凭据（值不回显；kind 决定必填字段与形态校验）
credvault cred set ZABBIX_TOKEN --kind api_token --value-stdin < /dev/stdin

# 3) 签一个 AI 令牌（明文只显示一次）
credvault token add workbuddy-local --ttl-days 90

# 4) 接进 MCP 客户端
#    {"mcpServers":{"credvault":{"command":"credvault","args":["mcp"],
#      "env":{"CREDVAULT_TOKEN":"cbk_..."}}}}

# 5) 起 Web（审批/审计/令牌三视图）
credvault user add admin
credvault serve --mode web          # http://127.0.0.1:8443
```

自检与验证：

```bash
credvault doctor                     # 8 项探针：策略/能力/凭据/密文/KEK/审计链/开关/到期
credvault policy-check               # 逐条列出授权，防「以为放开了其实没有」
credvault invoke zabbix_host_list --agent workbuddy-local --explain   # 干跑，不发起真实调用
credvault audit verify               # 哈希链完整性
```

## 两条程序入口：MCP 与 REST API

同一套六道闸门、同一个 `dispatch`，只是入口与鉴权方式不同。**令牌带 scope，两条路互不越界**：

| scope | MCP（stdio / HTTP `/mcp`） | REST API（`/api/v1/*`） |
|---|---|---|
| `mcp`（默认） | ✅ | ❌ 403 |
| `api` | ❌ 403 | ✅ |
| `both` | ✅ | ✅ |

默认 `mcp` 而不是 `both`：**升级不扩权**——已有令牌不会因为升级而顺带获得脚本调用能力。
存量库升级时 `agents.scope` 自动补成 `mcp`（同上原则）。

### MCP（给 AI 客户端）

```json
{"mcpServers":{"credvault":{"command":"credvault","args":["mcp"],
  "env":{"CREDVAULT_TOKEN":"cbk_..."}}}}
```

HTTP 形态：`POST /mcp`，`Authorization: Bearer cbk_...`。工具清单按双轴授权**渐进披露**，
未授权的能力不会出现在 `tools/list` 里。

### REST API（给脚本 / CI / 监控探针）

```bash
credvault token add ci-probe --ttl-days 30 --scope api      # 特意签发 api 专用令牌

export CV=http://127.0.0.1:8443/api/v1
export T="Authorization: Bearer cbk_..."

curl -H "$T" $CV/whoami                       # 我是谁、能调什么、还剩多少额度
curl -H "$T" $CV/capabilities                 # 能力清单（含约束与配额）
curl -H "$T" $CV/credentials                  # 凭据元数据（永不返回值）
curl -H "$T" "$CV/audit?hours=24&limit=50"    # 审计检索
curl -H "$T" $CV/health                       # 平台自检

# 干跑：不发真实请求，先看判定
curl -X POST -H "$T" -H 'Content-Type: application/json' \
     -d '{"capability":"zabbix_host_list","args":{"limit":5}}' $CV/explain

# 真实调用
curl -X POST -H "$T" -H 'Content-Type: application/json' \
     -d '{"capability":"zabbix_host_list","args":{"limit":5}}' $CV/invoke

# 需审批的写操作：返回 202 + approval_id，人工批准后带上它重试
curl -X POST -H "$T" -H 'Content-Type: application/json' \
     -d '{"capability":"wecom_send_text","args":{"content":"x"}}' $CV/invoke
# → 202 {"code":11,"approval_id":"..."}   ← 人点 Web 审批 → 重试同一请求并附 approval_id
```

接口描述：`GET /api/openapi.json`（OpenAPI 3.1，公开文档，不含任何凭据信息）。

**HTTP 状态码与业务码分离**——脚本可按状态码写重试逻辑，按 `code` 写业务分支：

| HTTP | 含义 | 对应 `code` |
|---|---|---|
| 200 | 成功 / 业务失败（读 `code` 再判断） | 0、15、20 |
| 202 | 已受理待审批（**不是错误**） | 11 |
| 400 | 参数非法 | 16 |
| 401 | 令牌无效/过期/吊销/IP 不符 | 4010 |
| 403 | scope 不符 / 策略拒绝 / 安全拦截 | 4011、10、12 |
| 404 | 凭据不可用 | 13 |
| 429 | 超出配额 | 18 |
| 502 | 上游网络失败 | 14 |
| 503 | Kill Switch 只读 | 19 |

**三条硬边界**（不因为是「API」而放松）：

1. **没有读凭据值的接口**。取明文只有 `lease pull`（带 TTL、可撤销、只出现一次）
2. API 只认 **Bearer 令牌**，不认 Web 会话 Cookie；反之 `/mcp` 也不认 Cookie
3. 所有调用进哈希链审计，`actor=api:<agent>`，参数摘要先脱敏再落盘

## 写一个能力（加一段 YAML = 多一个 AI 工具）

```yaml
version: 1
capabilities:
  - name: zabbix_host_list                # ^[a-z][a-z0-9_]{2,60}$
    kind: http                            # http | exec | rotate
    description: 列出 Zabbix 主机（只读）。用于晨检与资产盘点。   # 必填，AI 靠它选工具
    read_only: true                       # Kill Switch 期间只读能力仍放行
    require_confirm: false                # 写操作建议 true
    secret_ref: ZABBIX_TOKEN              # 只写名字，值由内核注入
    input_schema:                         # JSON Schema 子集，错参数当场拒
      type: object
      properties:
        filter: {type: string, maxLength: 64}
        limit:  {type: integer, default: 50, minimum: 1, maximum: 500}
    http:
      method: POST                        # 固定方法，不接受调用方改写
      base_url: https://zabbix.example.com
      path: /api_jsonrpc.php              # 固定路径，可含 {{ 变量 }}
      inject: {type: header, name: Authorization, prefix: "Bearer "}
      allow_private_upstream: true        # 内网地址需显式开启（默认禁）
      body_template:
        jsonrpc: "2.0"
        method: host.get
        params: {output: [hostid, host], search: {host: "{{ filter | default('') }}"}}
        id: 1
    response: {json: true, pick: result, array_limit: 50}   # 结构化裁剪，省 token
```

> **不支持把 method / path 交给调用方拼**：那等于又回到「URL 白名单代理」，
> 放行 `/api_jsonrpc.php` 之后 AI 仍能发 `host.delete` —— 只有把动作固化成能力，最小权限才成立。

`kind: exec` 需要 `argv`（列表，不接受 shell 字符串）+ `env_var` + `argv_allowlist`；
`kind: rotate` 需要 `rotate.credential` 且必须 `read_only: false` + `require_confirm: true`。

## 授权策略

```yaml
version: 1
defaults: {deny_by_default: true, quota_per_min: 60, quota_per_day: 2000}
deny:                                  # deny 永远优先于 allow
  - {capability: "*delete*", reason: 不可逆动作走人工}
agents:
  - id: workbuddy-local
    allow_exec: false                  # exec 注入默认关闭（第二把锁在 exec.enabled）
    visible_credentials: [ZABBIX_TOKEN] # 双轴之一：连「能看见哪些凭据名」都受限
    capabilities:
      - {name: zabbix_host_list, allow: true}
      - {name: wecom_send_text, allow: true, require_approval: true}
      - {name: "*", allow: false}
```

铁律：未显式 allow 一律拒 / deny 优先 / 未知字段直接报错（拼错 `deny` 不会静默放开）/
最具体规则胜出（与书写顺序无关）。

## 审批闭环（AI 视角三步，人只需点一下）

1. AI 调写能力 → 得到 `{"code":11,"approval_id":"6afd7fde","next_action":...}`
2. 人收到企微通知或打开 Web「待审批」→ 批准（可勾「会话豁免」，同类本会话不再问）
3. AI 调 `approval_status("6afd7fde")` 看到 `approved` → 带同一个 `approval_id` 重试**原参数**
   （参数一改即失效，防「批准 A 执行 B」）

## 部署形态

| 形态 | 命令 | 说明 |
|---|---|---|
| 源码/venv | `./install.sh` | 依赖只有 `cryptography` + `pyyaml` |
| 单目录可执行 | `./build.sh binary` | PyInstaller onedir，解压即跑，无需 Python |
| 容器 | `docker build -t credvault .` | 非 root（uid 10001），`/data` 卷，内置 healthcheck |
| systemd | `./install.sh --systemd` | `ProtectSystem=strict` + 专用账号 + `ReadWritePaths` 只开数据目录 |
| 离线 | `./build.sh wheel && ./install.sh --offline dist/wheels` | air-gap 可装 |

升级：替换程序 → `credvault doctor` → 数据自动向前迁移；升级前先 `credvault backup export`。
回滚：程序回退一版即可，数据层只增字段不删字段。

## 安全模型（能做与不能做）

**做得到的**
- 信封加密：KEK（file 0600 / env）→ 每凭据独立 DEK → AES-256-GCM；KEK 轮换只重包 DEK（`keys rewrap`），不重加密数据
- **凭据可用性闸门**：过期 / 状态非 active / 凭据侧白名单不含本能力 → 调用与干跑同源拒绝（`service._credential_gate`）
- **软限流**（litellm 模式，默认关）：超配额按 `throttle_pct` 概率放行、其余降速；burst 档永不降速，每次现算不复利
- **参数级策略**：`constraints.arg_limits` 对 max / max_len / pattern / enum 做逐参数收窄（warden 模式）
- **on-behalf-of 归属**：审计记「agent 替谁办事」；仅策略显式 `impersonate: true` 且形如 `human:*` 才接受，MCP 侧默认丢弃
- **lease 化分发**：`lease issue/pull/renew/revoke`，默认 300s、最长 3600s、续期 ≤3 次，值只在 pull 时出现一次
- **SSRF 与连接同源**：解析一次即固定 IP 建连（Host 头保留域名），消除 DNS rebinding 窗口
- 元数据与密文**分库**：拖走 `credvault.db` 拿不到密文；拖走 `secrets.db` 没有 KEK 也解不开
- 明文生命周期限于单次调用（`finally` 清理）；响应脱敏覆盖原值/URL 编码/JSON 转义/base64 三种形态
- 审计哈希链：改任何一行即断链，`audit verify` 与 Web「链完整性」都会暴露
- 双轴令牌 + IP 白名单 + TTL/轮换/吊销；令牌只存 sha256
- SSRF：解析全部 A/AAAA，任一落私网即拒（不只看字面 IP）；不跟随重定向
- 非幂等方法不重试；连接池有上限；exec 走 argv 白名单 + 环境最小化

**做不到的（不吹）**
- 客户端拿到脱敏结果后怎么用，平台看不到 —— 审计是**事后可追溯**，不是实时阻断
- 全自动改所有上游密码：平台不知道每个系统的改密方式，轮换只做「生成 → 落库 → 探针验证 → 失败回滚」，远端投放由能力完成
- 防住已有 root 的攻击者：他能读 KEK 文件。此形态定位是单机/单容器，不是多租户 SaaS

## 可移植性硬指标（15 条）

| # | 指标 | 落点 |
|---|---|---|
| 1 | 单产物 / 解压即用 | `build.sh` + `install.sh` |
| 2 | 零外部中间件（无 Redis/MySQL/JVM/Node） | SQLite + 标准库 HTTP |
| 3 | 离线可装 | `install.sh --offline` |
| 4 | 配置全外置、代码零硬编码路径 | `config.py`（`CREDVAULT_HOME` + 环境变量覆盖） |
| 5 | 状态与运行身份解耦 | 所有路径锚定 HOME，不再探测 `/opt/...` |
| 6 | 可升级/可回滚 | 数据层只增字段；升级前备份 |
| 7 | 可观测 | `/healthz` `/readyz` `/version` `/metrics`（Prometheus）+ JSONL 审计 |
| 8 | 单端口 | Web 与 MCP-over-HTTP 复用同一端口 |
| 9 | 无外呼 | 审计 sink 与审批通知默认 `none`，显式配置才外发 |
| 10 | 最小权限 | KEK/库/history 均 600（Windows 走 icacls） |
| 11 | 幂等部署 | `install.sh` 可重复执行，不覆盖已有 KEK/库/策略 |
| 11b | 运行时自省 | `credvault whoami` / MCP `whoami`：可用能力+约束+剩余额度+Kill Switch |
| 12 | 跨平台 | Linux 主 / Windows 次（编码按 gb18030 兜底） |
| 13 | 体积 | onedir 约 40–60MB（Python 运行时的物理下限） |
| 14 | UTF-8 内部 + 本地编码出口 | 子进程输出显式 `encoding` + `errors=replace` |
| 15 | 时间统一 | 存储 epoch/UTC，展示按 `timezone` |

## 测试

```bash
python -m unittest discover -s tests -v     # 109 个用例，全绿
```

覆盖：配置合并与环境覆盖、信封加密/错钥/重包、密文与元数据分离、脱敏三形态、审计链篡改检测、
策略四条铁律、注册表校验与模板渲染、双轴令牌/IP 白名单、审批状态机与指纹绑定、配额与突发、
Kill Switch、exec 白名单、轮换探针失败回滚、备份包往返、MCP 握手/渐进披露/isError、Web 登录/角色/CSRF、
**凭据到期/状态/凭据侧白名单、审批原子核销、审计参数摘要、config 配额优先级、软限流与 burst 豁免、
登录限速与 Cookie Secure、参数级约束、on-behalf-of、lease 生命周期/IP 白名单/续期上限、whoami 自省、
连接池按超时隔离、SSRF 同源解析、弱 KEK 体检、审批并发核销（16 线程）、
审计链并发追加（8×5）、配额窗口翻转、lease 过期清理、
sqlite 跨线程串行化（`_LockedConn`：execute/commit 复合操作互斥）**。

## 目录

```
credvault/
├── credvault/            # 包（24 个模块，见下）
│   ├── config.py         # 配置外置 + 路径锚定
│   ├── crypto.py         # KEK→DEK 信封加密
│   ├── store.py          # 元数据库 / 密文库（分离）
│   ├── kinds.py          # 凭据类型注册表（必填字段 + 形态校验）
│   ├── registry.py       # 能力注册表（YAML → 工具 + 参数校验 + 模板）
│   ├── policy.py         # 能力级授权（deny-by-default / deny 优先）
│   ├── approvals.py      # 异步审批 + 会话豁免 + 通知
│   ├── tokens.py         # 双轴令牌 + IP + TTL
│   ├── executor.py       # HTTP 代发 / 子进程注入（SSRF、白名单、池上限）
│   ├── redact.py         # 脱敏 + 返回体预算
│   ├── audit.py          # 哈希链审计
│   ├── rotate.py         # 轮换（探针 + 回滚）
│   ├── service.py        # 装配 + 公开面（闸门/配额/执行委托）
│   ├── gates.py          # 闸门链（static→policy→credential→quota→approval）
│   ├── quota.py          # 配额 + 软限流（config>policy>默认）
│   ├── runner.py         # 执行器（唯一明文边界：解出→注入→脱敏）
│   ├── cli/              # 命令行：_common/lifecycle/health/creds/access/parser
│   ├── mcp.py            # MCP 服务（手写 JSON-RPC，不依赖 SDK）
│   ├── web.py            # 路由 + 登录 + 探针 + MCP-over-HTTP
│   ├── webui.py          # 三视图 HTML 渲染（纯函数）
│   ├── dist.py           # lease 化凭据分发
│   ├── backup.py         # .cvault 备份包
│   ├── ops.py            # 自检 / 指标
│   └── cli.py            # 命令行
├── capabilities/         # 能力定义（加 YAML 即加工具）
├── deploy/               # systemd 单元 + 环境投影示例
├── tests/                # 109 个用例
└── pyproject.toml       # 打包元数据（extras 预留）
```

## 明确不做

多租户与套餐、全功能管理后台、仪表盘报表、会话录屏、资产录屏级审计、OAuth 授权服务器、
自研 HSM —— 与「凭据底座」正交，做进来只会让交付物变重、责任面变大。

## 许可

MIT
