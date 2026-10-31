# OSS 调研：凭据/密钥存储与调用 × AI 接入 —— 源码级分析与集成方案

> 日期 2026-10-26 · 方法：GitHub 检索（检索式见 §1）+ 代表性项目源码级阅读（每个项目给出关键文件路径）
> 产出：可集成方案与功能清单（§5，含优先级/改造点/收益/风险）
> 适用基线：本平台 = `credvault` v1.0.0（capability 注册表 + 信封加密 + 哈希链审计 + 异步审批 + MCP 面）

---

## 0. 结论摘要（先看这段）

| # | 结论 |
|---|------|
| 1 | 检索到的 14 个项目里，**没有一个是「我们的全部」**：密钥平台（Infisical/OpenBao）缺 AI 调用链；AI 网关（LiteLLM/Bifrost）只管 LLM key 不管通用凭据；Agent 网关（Warden/Coral）方向一致但都是 Go/Rust 重写。**结论：不引入任何外部系统，只吸收机制** —— 与 ADR 0001（不换技术栈）一致 |
| 2 | 最值得抄的 5 个机制：**① LiteLLM 的软限流**（超配额降速而非硬停，保住无人值守任务）② **Warden 的参数级策略 + on-behalf-of 归属** ③ **OpenBao 的 lease 语义**（lease_id/ttl/renewable/revoke，正好补 P2 的凭据分发）④ **LiteLLM 的 master_key_boot_check**（启动时查弱主密钥）⑤ **Infisical 的盲索引**（加密状态下按名检索） |
| 3 | 一个方向性验证：**Warden 与 Bifrost 的 `injectedauth.go` 证明「凭据注入点放在执行器」是我们 v0.2 已做对的**；行业收敛点一致，无需架构返工 |
| 4 | 最高风险的borrow：**插件管线**（IBM mcp-context-forge 的 plugins 模式）——若开放第三方代码加载就是供应链攻击面，必须只做「内置闸门显式排序」 |
| 5 | 许可证：HashiCorp Vault 是 **BUSL（非 OSI）**，只能借概念不能拷代码；其余均为 MIT/Apache-2.0/MPL-2.0，概念借鉴 + 自行实现无合规问题 |

---

## 1. 调研范围与方法

**检索式**（GitHub search API，2026-10-26）：

```
infisical ｜ litellm ｜ openbao ｜ mcp gateway ｜ secrets management in:name,description stars:>2000 pushed:>2025-06-01
```

**筛选标准**（命中 ≥2 条才进入深读）：
① 涉及凭据/密钥的**存储或调用**任一环节；② 有 **AI 能力接入**（MCP / Agent / LLM 网关）实现；
③ 活跃（近 6 个月有提交）；④ 许可证可借鉴（非强 copyleft 传染或非开源则降级为"概念参照"）。

**深读方式**：读目录结构 + 关键源码文件（每个项目 1–3 个），不做运行时验证 ——
结论分「源码观察」与「README/文档转述」两级标注。

## 2. 深读项目（8 个）+ 简评项目（6 个）

### 2.1 Infisical（30,000⭐ · TypeScript · MIT 核心）— 密钥平台的完整性参照

**架构观察**（`backend/src/services/` 目录清单，服务即模块边界）：
密钥面 `secret / secret-v2 / secret-folder / secret-blind-index / secret-import / secret-sharing`；
密钥管理面 `cmek / kms / project-key / encryption-key-rotation / hsm-connector`；
身份面 `identity-{aws,gcp,azure,ldap,oidc,spiffe,kubernetes,token,tls-cert,...}`（13+ 种机器身份）；
治理面 `secret-access-approval-* / secret-validation-rule / approval-policy`。

**源码细读**：`secret-blind-index/secret-blind-index-service.ts`
- 每个操作第一步都调 `permissionService.getProjectPermission(...)` —— **服务层逐方法重查权限**，不是只在路由层查一次；盲索引管理还要 `Admin` 角色（deny-by-default + 显式升级）。
- `generateSecretBlindIndexBySalt(secretName, blindIndexCfg)`：对**名字本身**做 per-project salt 的 HMAC，把盲索引存回 secret 行 —— 于是「按名检索/改名/去重」在密文态完成，不泄露明文名。

**优点**：模块边界以服务工厂为单位（DAL/Service 分离，可测）；机器身份种类最全；加密密钥有 CMEK（客户自带密钥）与轮换服务。
**边界**：无 AI 调用链（它的 agent 叙事指 Infisical Agent 平台，非「凭据代理执行」）；TS 全家桶 + Postgres，重；MIT 核心之外有 EE 目录（许可受限部分需甄别）。

### 2.2 BerriAI/litellm（62,060⭐ · Python · MIT）— AI 网关的治理参照

**架构观察**（`litellm/proxy/auth/` 清单）：
`user_api_key_auth.py`（虚拟密钥鉴权主链）、`auth_checks.py`/`route_checks.py`（能力/模型级检查）、
`ip_address_utils.py`（IP 白名单）、`login_throttle.py`（登录限速）、`master_key_boot_check.py`（启动密钥体检）、
`budget_throttle.py`、`team_grants.py`、`roles.py`、`oauth2_check.py`。

**源码细读**：`budget_throttle.py`（全文）
- 超预算密钥可**降速不硬停**：`throttled_limit(limit, pct) = max(1, floor(limit*pct))` —— 保底 1 保住"涓流"。
- 三个安全细节都对：① 必须 per-key **显式 opt-in**（`metadata.throttle_on_budget_exceeded is True`）；② **安全默认是硬停**（无 TPM/RPM 限制的密钥没有可降的东西，保持阻断）；③ pct 在**每次请求时从原始 limit 重算**，注释明确写了"so it never compounds across requests"（防 0.8×0.8×… 复利归零）。

**优点**：把"治理"做成了**可独立测试的小模块**（每个文件单一职责）；`master_key_boot_check` 在启动期拒绝弱主密钥；虚拟密钥 = 团队/用户/密钥三层归属。
**边界**：只管 LLM provider key，不是通用凭据库；虚拟密钥的 spend 统计依赖 DB 回写，对非 LLM 场景无意义。

### 2.3 OpenBao（8,709⭐ · Go · MPL-2.0）— 动态秘密与租约的语义来源

**架构观察**：`internal/builtin/logical/{kv, database, pki, ssh, totp, transit, rabbitmq, kubernetes}` ——
动态秘密引擎（database/ssh/pki 按需铸造短时凭据）+ transit（加密即服务，密钥版本化管理）。
`hashicorp/vault`（36,436⭐，**BUSL 许可**）是同一概念的上游，只能借概念。

**优点**：**lease 是一等公民**（lease_id / ttl / renewable / revoke，控制面可列举可撤销任意租约）；
transit 的 `min_decryption_version` 与密钥版本轮换——我们 v1.0 的 `key_version` + rewrap 已同构，方向获验证。
**边界**：Go 单体 + 存储后端（integrated Raft 等），对单人维护是重资产；**不引入，只借 lease 语义**。

### 2.4 maximhq/bifrost（9,108⭐ · Go · Apache-2.0）— 虚拟密钥与预算周期

**架构观察**：`core/injectedauth.go` / `injectedtools.go` —— **凭据注入发生在 provider 执行层**（与我们 `service._execute` 的位置一致）；`plugins/governance/` 含 `budgetcycle / ratelimitreset / permits / virtualmcpaccess / mcpauthorization / store.go / tracker.go`（+ 每个文件同名 `_test.go`，治理逻辑全量带测）。
**优点**：预算周期（budget cycle）显式建模；`permits` ≈ 我们的审批单；MCP 授权与虚拟密钥打通。
**边界**：面向 LLM/MCP 流量，无 SSH/DB/通用 HTTP 凭据治理。

### 2.5 stephnangue/warden（179⭐ · Go · MPL-2.0 · OpenBao 官方 Integrator）— 最接近我们定位的项目

**架构转述**（README，`credential/` 目录佐证：`minting_service.go / keyvault.go / revoke.go / exchange.go / driver_coordinator.go`）：
Agent 只出示**身份**（JWT / TLS 客户端证书 / SPIFFE SVID / K8s SA token），网关逐请求做策略并注入真实凭据；
甚至可以**平台不持密钥**（keyless）：向上游证明"调用者是谁"让上游自己铸造（AWS SigV4、GitHub App、DB IAM token），
或每请求从外部 vault 取用即忘。

**三个独有设计**（全行业只有它做全了）：
1. **参数级策略**：MCP 流量下策略"到达每个工具调用的**参数**"——哪个工具、哪些参数。
2. **on-behalf-of 双身份**：请求可携带第二个身份（agent 代办的那个**人**），上游按真人授权与归因。
3. **运行时自省**：Agent 运行时问"我能访问哪些系统、有哪些角色配方"，新挂载系统无需重发配置。

**边界**：179⭐ 单人项目，生产成熟度未知；Go 重写与我们栈不符；文档强于实现（需自行验证）。

### 2.6 oomol-lab/open-connector（6,092⭐ · TypeScript · Apache-2.0）— 连接器网关

**架构转述**（README + 目录）：凭据边界在 runtime 内（"Provider secrets stay behind the runtime boundary"）；
runtime tokens + scopes + **action allow/block 策略**；run logs **redacted**（脱敏后的运行日志）；
支持 GitHub App **按需铸造 1 小时 installation token**（平台存 App 私钥，不存 PAT）；SQLite/PG 可切换。
**优点**：OAuth 刷新作为一等凭据类型；action 级 allow/block。**边界**：面向 SaaS 连接器，无内网/SSH 场景。

### 2.7 IBM/mcp-context-forge（4,694⭐ · Python/FastAPI）— 同栈的插件化网关

MCP/A2A/REST 统一端点 + 集中发现 + guardrails + **plugins 管线** + JWT 中间件。与 credvault 同栈（FastAPI + asyncio），
是**插件管线与令牌签发**的最佳参照。⚠️ 风险：它的 plugins 是可扩展第三方代码加载 —— 对我们不可直接照搬（§5 R-4）。

### 2.8 hashicorp/vault（36,436⭐ · Go · **BUSL**）

概念源头（lease / dynamic secrets / transit / agent 模板）。**BUSL 非 OSI 许可：只借概念，禁止拷码。**

### 2.9 简评（未深读，按 README/定位）

| 项目 | 星 | 定位 | 对本平台的启示 |
|---|---|---|---|
| Portkey-AI/gateway | 13,274 | AI 网关 + 50 护栏 | 护栏分类学（pre/post call） |
| Kong / Tyk | 44k / 10.9k | API+AI 网关，支持 MCP | 企业部署形态参照，过重 |
| casdoor | 14,666 | IAM + MCP/Agent 网关 | 若未来要 OIDC，集成它而非自研 |
| OmniRoute | 81,319 | AI 网关（省 token/回退） | 与凭据无直接交集 |
| tellerops/teller | 3,233 | CLI 聚合多后端秘密 | 已被 `.cvault`/migrate 覆盖 |
| zifeo/lade | 136 | **临时访问**：一条命令包住人与 agent，用完即收 | "临时性"产品化表达，P2 lease 的 UX 参考 |

---

## 3. 对比矩阵

| 维度 | Infisical | litellm | OpenBao | bifrost | warden | open-connector | **credvault 现状** |
|---|---|---|---|---|---|---|---|
| 通用凭据（SSH/DB/HTTP） | ✅ | ❌ 只 LLM | ✅ | ❌ 只 LLM | ✅ | ❌ 只 SaaS | ✅ |
| AI 能力接入 | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ |
| 加密 | CMEK+项目密钥+轮换 | 主密钥 | 封印+transit 版本化 | — | 可 keyless | 加密+刷新 | KEK→DEK+rewrap |
| 最小权限粒度 | 项目/角色/环境 | 密钥→模型 | 策略路径 | 虚拟密钥→provider | **工具+参数** | action allow/block | 能力名 |
| 归因 | actor+authMethod | key→team/user | lease→entity | key | **agent+真人双身份** | connection alias | agent（缺真人） |
| 限流 | — | RPM/TPM+**软限流** | lease 数量 | 预算周期+限速 | — | — | 三级配额（硬停） |
| 审计 | 完整事件流 | spend+callbacks | 审计设备 | tracker | 决策级含参数 | 脱敏运行日志 | 哈希链（无参数） |
| 密钥在平台内存留 | 存 | 存 | 可动态生成（不留存） | 存 | **可不存** | 存 | 存（信封加密） |

**行业收敛点**（四家以上一致，视为共识）：凭据注入点在执行器层；机器身份与凭据分离；限流/预算按主体分层；
审计含决策与归因；密钥版本化轮换。credvault 在这五点上全部已对齐。

---

## 4. 落地可行性评估

**技术栈匹配**：我们是 Python 3.11+ / SQLite / 标准库 HTTP / 自写 MCP —— 上表机制全部可在现有模块内实现，
无新依赖。**不引入** Infisical/OpenBao/litellm 作为组件（依赖重量 + 场景错配），只移植机制。

**业务场景匹配**（跳板机 + 中台巡检 + 企微推送）：
- 软限流：巡检类 agent 是长周期低频调用，硬停会打断晨检/日报链路 → **高价值**。
- on-behalf-of：gf-duty 等代办场景天然需要归属链 → **高价值、低成本**（一个审计字段+参数）。
- lease 分发：39 台主机的 collector 拉凭据目前是静态下发 → lease 化后可撤销可追溯 → **中高价值**。
- 盲索引：我们凭据名本来就是元数据，收益低 → **低优先**。
- keyless：仅 GitHub App/DB IAM 类上游可行，我们当前无此类 → **暂缓**。

## 5. 集成方案与功能清单（按优先级）

### P0 —— 安全与健壮性直接增强（2–3 人日）

| # | 功能 | 来源 | 改造点 | 预期收益 | 风险与对策 |
|---|------|------|--------|---------|-----------|
| F1 | **软限流（throttle 模式）** | litellm `budget_throttle.py` | `service._limits()` 增加 throttle 档：`policy.agents[].quota_throttle_pct`（0<pct≤1）+ `limits.throttle_*`；超配额时按 `max(1, floor(limit*pct))` 降速而非拒；**每次请求从原始限值重算**（防复利）；burst 优先级仍高于 throttle | 巡检/日报链路超配额不再全停；agent 降级可用 | 降速仍可能压上游 → 默认关闭（pct 缺省=硬停），开启需显式配置+审计 note 记 `THROTTLED` |
| F2 | **启动密钥体检** | litellm `master_key_boot_check.py` | `ops.health` 增 3 项：KEK 是否 ≥32B 且非重复字符/全零；kek 文件权限；`exec.enabled=true` 且 `argv_allowlist` 为空 → 告警 | 防「示例 KEK 上生产」「exec 裸开」 | 无 |
| F3 | **参数级策略** | warden 参数级策略 | `policy.Rule.constraints` 落地：`arg_limits: {参数名: {max, pattern, enum}}`；`invoke` 在 schema 校验后追加约束校验；`explain` 同步显示 | MCP 工具调用收窄到参数级；deny 理由可解释 | 过严导致误拒 → `policy-check` 输出每条约束供评审 |
| F4 | **on-behalf-of 归属** | warden 双身份 | `Service.invoke(..., on_behalf_of="human:maxin")`；写入审计 `extra["on_behalf_of"]` 与 `policy_explain`；**仅接受 CLI/Web/网关注入**，MCP 侧若声明需 agent 在策略里被授予 `impersonate: true` | 代办操作可追到人；审计满足「谁授权、谁执行、为谁办事」 | 伪造归属 → 默认 MCP 不可传；策略显式开 `impersonate` 才允许 |

### P1 —— 结构增强（3–5 人日）

| # | 功能 | 来源 | 改造点 | 预期收益 | 风险与对策 |
|---|------|------|--------|---------|-----------|
| F5 | **lease 化凭据分发** | OpenBao lease 语义 | 新模块 `dist.py`：`lease_create(consumer, credential, ttl, renewable)` / `lease_renew` / `lease_revoke` / `lease_list`；拉取端点返回短时值+lease_id；审计绑定 lease；`cleanup()` 复用 approvals 的过期清扫 | 消费方凭据可撤销、可追溯、有寿命；替代一次性静态下发 | 新状态表 → 迁移只增不改；lease 泄露窗口=ttl → 默认 ttl ≤ 300s |
| F6 | **内置闸门管线** | mcp-context-forge plugins（收敛版） | `service.invoke` 拆成显式管线：`authn → quota → policy → approval → pre_hooks → resolve → execute → post_hooks(redact/shrink/audit)`；hooks 为**内置注册表**（redact/audit/quota/burst），支持排序开关，**不加载第三方代码** | 闸门顺序显式可测；新增治理点不用改 invoke 主体 | 开放插件加载=供应链面 → 永不接受运行时第三方代码，只接受配置开关 |
| F7 | **per-capability 限额** | bifrost provider-scoped limits | `policy.Rule.constraints.quota_per_min/per_day`（覆盖全局默认），配额桶 key 加入 capability 粒度（现有 quota 表已支持） | 高危能力单独收紧（如 `wecom_send_text` 3/分钟），普通能力宽松 | 无 |
| F8 | **whoami 增强（运行时自省）** | warden agent flow | `broker_whoami` 返回：可用能力 + 每个能力的约束/审批要求 + 凭据可见集 + 剩余额度；`instructions` 引导 AI 先自省 | AI 减少"试错式调用"（试了才知道被拒） | 无 |
| F9 | **审批事件分级** | open-connector 通知 | `approvals._notify` 增加 severity（capability.tags 含 `写`/`高危` → 高优先级通知模板） | 高危审批不被淹没 | 无 |

### P2 —— 按需（有明确场景再做）

| # | 功能 | 来源 | 说明 |
|---|------|------|------|
| F10 | 盲索引（凭据名 HMAC 索引） | Infisical | 仅当未来要把**凭据名也加密**时才有意义；当前名=元数据，不做 |
| F11 | keyless 上行铸造 | warden | GitHub App / DB IAM 类上游"平台不持密钥"；当前无此类上游 |
| F12 | OAuth2 刷新型凭据 kind | open-connector | `kinds.py` 加 `oauth2_refresh`（refresh token 自动续期）；接 SaaS 时做 |
| F13 | CMEK（客户自带 KEK，KMS 适配） | Infisical | 交付给安全要求高的客户时做；现状 file/env 已覆盖内部场景 |

## 6. 许可证合规

| 项目 | 许可 | 对本项目的含义 |
|---|---|---|
| hashicorp/vault | **BUSL-1.1**（非 OSI） | **只借概念，禁拷代码** |
| openbao / warden | MPL-2.0 | 概念借鉴 + 自行实现（Go→Python 重写）可行；若拷文件需保留许可头——本方案不拷 |
| Infisical / litellm | MIT（Infisical 另有 EE 目录） | 机制移植自由；EE 目录不引用 |
| bifrost / open-connector | Apache-2.0 | 同上 |
| mcp-context-forge | Apache-2.0 | 同上 |

## 7. 明确不采纳（防返工）

| 不采纳 | 理由 |
|---|---|
| 引入 Infisical/OpenBao 作为存储后端 | 双真相源（与 ADR 0001 §D3 同理）；运维重量与单人维护不匹配 |
| 复刻 Sigil/warden 的桌面端或 SPIFFE 身份 | 服务器场景无 SPIFFE 基础设施；身份已有 agent 双轴+IP 白名单覆盖 |
| litellm 的 spend 回写体系 | 面向 LLM token 计费，与凭据调用无关 |
| 运行时第三方插件加载 | 供应链风险 > 收益（F6 只做内置闸门排序） |
| Kong/Tyk/casdoor 整体引入 | 网关能力与我们重叠但重 100 倍；未来要 OIDC 时单点集成 casdoor |

## 8. 证据索引

| 项目 | 读取的文件 | 类型 |
|---|---|---|
| Infisical/infisical | `backend/src/services/`（目录）、`secret-blind-index/secret-blind-index-service.ts`（全文） | 源码 |
| BerriAI/litellm | `litellm/proxy/auth/`（目录）、`auth/budget_throttle.py`（全文） | 源码 |
| openbao/openbao | `internal/builtin/logical/`（目录） | 源码结构 |
| maximhq/bifrost | `/`、`core/`、`plugins/governance/`（目录） | 源码结构 |
| stephnangue/warden | `/`、`credential/`（目录）、`README.md`（全文） | 目录 + 文档 |
| oomol-lab/open-connector | `README.md`（全文） | 文档 |
| IBM/mcp-context-forge | 检索结果与 README 要点 | 文档 |
| hashicorp/vault | 检索结果（仅概念参照） | — |

_检索于 2026-10-26 经 GitHub API（GitHub Connector）；星数为当日值。_
