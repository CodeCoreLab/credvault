# 全量修复交付报告（AUDIT 19 项 + OSS F1–F8 落地）

> 日期 2026-10-26 · 基线 `credvault` v1.0.0 → **v1.1.0** · 改前快照 `credvault/.bak_credvault_20261026_auditfix`
> 测试：**70 → 92 用例，全绿**（`python -m unittest discover -s tests`）
> 端到端：CLI 与 MCP 双通道真实 Zabbix 调用均 200（含修复过程中发现并回归的 HTTPS 陷阱）

## 1. 修复清单（逐项映射到证据）

| # | 缺陷/需求 | 处置 | 落地位置 | 回归用例 |
|---|---|---|---|---|
| **C1** | 凭据到期完全不拦 | 新增 `_credential_gate()`：过期 / 状态非 active / 凭据侧白名单三判据，**审批之前**判（避免白拿审批），`invoke` 与 `explain` 同源 | `service.py` `_credential_gate` | `T19.test_expired_credential_rejected` / `test_deleted_credential_rejected` |
| **C2** | 凭据侧 `allowed_capabilities` 死字段 | 并入同一闸门：`meta.allowed_capabilities` 不含本能力即拒 | 同上 | `T19.test_credential_side_allowlist` |
| **C3** | 审批核销非原子（TOCTOU） | 改**条件更新** `WHERE id=? AND state='approved' AND args_fp=?` + `rowcount` 判定 | `approvals.py` `consume` | `T19.test_approval_consume_is_atomic` |
| **M1** | 审计无参数摘要 | `audit.append(args_preview=…)`；摘要先 `redact.scrub` **再**截断（顺序反了会把密钥切半漏网） | `service._safe_args_preview` | `T19.test_audit_has_scrubbed_args_preview` |
| **M2** | config 配额是死配置 | 取值收敛为**config 非 0 优先、0 跟随 policy**；`config.example.yaml` 同步注释 | `service._limits` | `T19.test_config_quota_overrides_policy` |
| **M3** | 登录无失败限速 | 内存滑动窗口：5 次/5 分钟 → 429，审计记 `RATE-LIMITED` | `web.login_blocked/login_fail` | `T19.test_login_rate_limit_and_cookie_secure` |
| **M4** | Cookie 缺 Secure | `web.cookie_secure` 配置，默认 true | `web._login` | 同上 |
| **W1** | 错误码 17→20 文档不同步 | README 与 MCP instructions 同步（含 18/19/20 处置） | `README.md` / `mcp.build_instructions` | 端到端 instructions 1328 字 |
| **W2** | web.py 508 行超阈值 | 拆出 `webui.py`（纯渲染 205 行），路由 345 行；**消除 webui→web 反向依赖**（改显式传 `svc`） | `web.py` / `webui.py` | 92 用例全过 |
| **W3** | `Handler.svc` 类属性多实例污染 | 改 `_Server.svc` 实例绑定 + `svc_ref` 兜底（兼容旧写法） | `web._Server` | Web 相关 6 用例 |
| **W4** | SSRF 校验与连接不同源 | `resolve_and_check()` 一次解析同时供校验与建连；**pin 改能力级 opt-in**（见 §3 实测） | `executor.py` | `T20.test_resolve_and_check_same_source` |
| **W5** | 数组截断不告知 | 截断返回 `{items,total,shown,truncated,note}` | `service._shape` | `T10.test_ok_path_and_scrub`（已适配） |
| **W6** | 连接池 key 不含 timeout | key 加 `timeout` 与 `sni` | `executor._get_conn` | `T20.test_conn_pool_key_includes_timeout` |
| **W7** | ts 时区语义未说明 | docstring 明确「存 UTC，展示按 timezone」 | `audit.__init__` | — |
| **S1** | 缺 oauth2 刷新类型 | **未做**（无上游需求，P2） | — | — |
| **S2** | registry 缺原样嵌入过滤 | 加 `{{ var \| raw }}` | `registry._apply_filter` | — |
| **S3** | 备份迭代数硬编码 | `backup.pbkdf2_iterations` 可配，100k–2M 夹取 | `backup._iterations` | 备份往返用例 |
| **S4** | 缺 lease 分发 | 见 **F5** | `dist.py` | `T20.test_lease_*` ×3 |

## 2. OSS 调研项落地（F1–F8）

| # | 来源 | 实现 | 关键安全约束 | 回归 |
|---|---|---|---|---|
| **F1** 软限流 | litellm `budget_throttle` | 超配额按 `throttle_pct` 概率放行（`_throttled`），放行时审计记 `THROTTLED` | ① 默认**关**（硬停）② **burst 档永不降速**（防刷群）③ 每次现算不复利 | `T19.test_throttle_soft_limit` / `test_throttle_never_exempts_burst` |
| **F2** 启动密钥体检 | litellm `master_key_boot_check` | `crypto.kek_strength()`：长度 / 单字节 / 唯一字节数<16 三类拒；doctor 增 `exec-safety`（exec 开但无白名单点名） | 弱 KEK 直接阻断（block 级） | `T20.test_kek_strength` / `test_doctor_reports_exec_safety` |
| **F3** 参数级策略 | warden 参数级 | `Policy.check_arg_limits()`：`max/min/max_len/pattern/enum`，`invoke` 与 `explain` 同源 | 参数级收窄在策略层，不在能力模板里藏 | `T20.test_arg_limits_enforced` |
| **F4** on-behalf-of | warden 双身份 | `invoke(on_behalf_of=…)`；必须 `human:*` 且策略 `impersonate: true`；审计 `extra.on_behalf_of` | **MCP 侧默认丢弃**（`allow_impersonate=False`），防 agent 自封代办人 | `T20.test_on_behalf_of_*` ×3 |
| **F5** lease 分发 | OpenBao lease | `dist.Leases`：create/pull/renew/revoke/list/cleanup；默认 300s、最长 3600s、续期 ≤3、可 IP 白名单 | 值只在 `pull` 出现一次；审计只记 lease_id + 指纹 | `T20.test_lease_lifecycle` / `_ip_allowlist` / `_renew_limits` |
| **F8** 运行时自省 | warden agent flow | `Service.whoami()` + MCP `whoami` 工具 + `list_capabilities` 附 constraints/quota | 只读，不触发执行 | `T20.test_whoami_and_mcp_introspection` |
| **F7** per-capability 限额 | bifrost | `_effective_limit()` 读 `Rule.constraints.quota_per_<bucket>`，多规则取**最小值**（最严胜） | 与 deny 优先同向 | `T19.test_per_capability_quota_constraint` |
| F6/F9–F13 | — | 未做（F6 闸门管线重构收益低、F9–F13 无需求触发） | — | — |

## 3. 修复过程中发现并回归的新问题（必须记录）

**HTTPS pinned IP 破坏 TLS 握手**——按 W4 想「解析一次、用 IP 建连」后，`zabbix.example.com` 实测返回
`TLSV1_ALERT_INTERNAL_ERROR`；即便显式带 SNI（`_PinnedHTTPS` 覆写 `wrap_socket`）仍失败。
**处置**：`pin_resolved_ip` 改为**能力级 opt-in，默认关**。默认路径仍是「解析→校验→按域名建连」，
DNS rebinding 窗口靠「校验时把全部 A/AAAA 都检查（任一私网即拒）」收敛，而非靠 pin。
**证据**：修复前 `code=14 dur=55ms`；改 opt-in 后同一命令 `code=0 status=200 dur=168ms/output 3 台主机`。

## 4. 端到端验收（CLI + MCP 双通道）

```
CLI:  credvault invoke zabbix_host_list --args '{"limit":3,"filter":"10.80"}'  → HTTP 200 / 168ms / 3 台主机
MCP:  tools/call zabbix_host_list {"limit":2}                                → ok=True / 200 / 134ms
MCP:  tools/call whoami                                                     → agent=workbuddy-local / caps=4
MCP:  initialize.instructions                                               → 1328 字（含 20 码处置表 + 软限流提示）
审计: verify → 链完整 8 条；tail 可见 lease.create / zabbix 两次成功 / 一次 SSL 失败（如实留痕）
doctor: 阻断 1（仅 91 条 ENC_ 密文缺口，设计行为）/ 告警 2 / 检查 8
```

## 5. 未做与未验证（强制披露）

| 项 | 状态 | 原因 |
|---|---|---|
| S1 oauth2_refresh 类型 | **未做** | 无上游需求；接了 SaaS 再做 |
| F6 内置闸门管线重构 | **未做** | `invoke` 现有顺序已隐式正确，抽出管线属纯重构，收益 < 风险 |
| F9–F13 | **未做** | 无场景触发（盲索引/keyless/OAuth2/CMEK/审批分级） |
| C3 真实并发双核销压测 | **未验证** | 单元已证明「条件更新 + rowcount」语义；未做多线程/多进程竞争压测 |
| lease 与消费方真实联调 | **未做** | 需在跳板机起 collector 侧拉取端；本次仅 CLI 演练（issue/pull/renew/revoke 全过） |
| Windows 之外的平台 | **未验证** | 本次仍在 Windows 验证；Linux 分支代码（chmod / utf-8 编码）未实跑 |

## 6. 规模变化

| 项 | 修复前 | 修复后 |
|---|---|---|
| 包模块 | 20 | **22**（+`dist.py`、+`webui.py`） |
| 包代码行 | 4768 | **~5400**（新增闸门/软限流/lease/自省/参数级策略） |
| 测试用例 | 70 | **92**（+10 审查修复回归、+13 第二轮回归；含 1 条修正断言） |
| SKILL 侧 | dev-expert v2.2.0 | v2.3.0（独立交付，见 `docs/dev-expert-skill-review.md`） |

## 7. 复现命令

```bash
cd credvault
python -m unittest discover -s tests -v          # 92 tests OK
export CREDVAULT_HOME=$PWD/.migration
credvault doctor                                  # 阻断 1（ENC_ 缺口）/ 其余全绿
credvault invoke zabbix_host_list --agent workbuddy-local --args '{"limit":3}'
credvault whoami --agent workbuddy-local
credvault lease issue ZABBIX_TOKEN --consumer collector-test --ttl 120
credvault audit verify
```
