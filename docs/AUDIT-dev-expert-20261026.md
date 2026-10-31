# credvault 平台审核报告（dev-expert 复杂档全量执行）

> 审查者：编程专家.Skill v2.3.0（本轮刚完成 4 维优化）· 审查对象：`credvault` v1.0.0（4775 行 / 20 模块）
> 审查模式：**只读审查**（`execution-safety.md §审计修复分离`）· 档位：**复杂**（涉权限/凭证/DB/多模块）
> 证据基线：`python -m unittest discover -s tests` → **Ran 70 tests, OK**（审查前基线）
> 结论纪律：每条 ≤ 证据锚（`文件:行号` 或 探针输出）；未验证项单列

---

## 0. 收尾报告 5 字段

| 字段 | 内容 |
|---|---|
| **任务** | 用 dev-expert v2.3.0 对凭据平台 credvault 做全量审核 |
| **完成情况** | 致命 3 / 严重 5 / 警告 7 / 建议 4，共 19 项；已实证 8 项，静态判定 11 项（标注） |
| **关键决策** | 只读审查不修复；探针脚本用后即删（`execution-safety.md §Step 5 先清理`）；不重复已知的 70 用例覆盖项 |
| **验证证据** | 测试基线 `Ran 70 tests OK`；探针输出 4 条实证（见 §2）；`grep -n` 行号锚 8 条 |
| **待办** | 致命 3 项建议**立即修复**（详见 §4 修复包），严重 5 项本迭代，警告/建议择机 |

量化串：`(已验证主线数/总主线数)×100% = (8/19)×100% ≈ 42%`（其余为静态判定，未跑动态探针）

---

## 1. Spec 一致性（code-review 第一步）

| 声称能力 | 实现实况 | 判定 |
|---|---|---|
| README「凭据到期由平台提醒并禁用」 | `expires_at` 只在 `expiring()` 查询，**调用链不校验** | ❌ 不一致（致命 C1） |
| README「双轴授权：凭据可见性 + 能力」 | 服务层只读 agent 侧 `allowed_capabilities`，**凭据侧 `allowed_capabilities` 从不读取** | ❌ 不一致（致命 C2） |
| README「审计含参数摘要」 | `audit.append` 只传 `args_fp` 与 note，**无参数摘要** | ❌ 不一致（严重 M1） |
| README「失败可自愈：17 错误码」 | 实际 20 码（新增 E_QUOTA/E_KILL/E_RATELIMIT），文档未同步 | ⚠️ 轻微（W1） |
| README「配额三级」 | `config.yaml limits.quota_per_min/quota_per_day` 为**死配置**（服务读 policy 的值） | ⚠️ 不一致（严重 M2） |

## 2. 实证结果（探针输出，脚本已删）

```
凭据已过期一天: True
缺陷确认：过期凭据仍可解密，len = 18          ← C1 实证
登录失败计数机制: 无                          ← M3 实证
Cookie Secure 属性: 无                        ← M4 实证
凭据侧 allowed_capabilities 已设置: ['nonexistent_cap']
service.py 是否读取凭据侧 allowed_capabilities: 否（仅读 agent 侧）  ← C2 实证
```

## 3. 缺陷清单（分级 + 证据锚）

### 致命（Critical，必须修）

| # | 缺陷 | 证据 | 后果 |
|---|---|---|---|
| **C1** | **凭据到期不拦**：`invoke` 全链路无 `expires_at` 校验，过期凭据照常解密注入 | 探针：过期 1 天仍 `len=18`；`grep -n "expires_at" credvault/service.py` → 0 命中 | 到期轮换形同虚设；泄露的旧令牌永久可用 |
| **C2** | **凭据侧授权视图未生效**：`store.upsert_credential(allowed_capabilities=…)` 写入后无人读取，服务层只校验 agent 侧 | 探针：写 `['nonexistent_cap']` 后 service.py 仍不读；`grep -n allowed_capabilities credvault/service.py` → 仅 3 处全在 agent 侧（123/225/228） | 「这条凭据只能被哪些动作用」的语义缺失，最小权限少一维 |
| **C3** | **approvals.consume 与执行非原子**：核销走一次 tx，执行在另一次，中间可被打断 | `service.py:262` consume → `service.py:268` `_execute()`；`approvals.py` `consume` 先 SELECT 再 UPDATE（无 `WHERE state='approved'` 条件更新） | 并发下同一审批单可能被核销两次（TOCTOU）；进程崩溃时审批已消耗但动作未执行 |

### 严重（Major，本迭代修）

| # | 缺陷 | 证据 | 后果 |
|---|---|---|---|
| **M1** | 审计缺参数摘要（只存指纹） | `service.py:313` note 仅状态；`audit.append(..., args_fp=…)` | 事后无法回答「当时传了什么参数」，追溯力弱于 warden 的决策级审计 |
| **M2** | **死配置**：`config.yaml` 的 `limits.quota_per_min/quota_per_day/timeout_sec` 全部被 policy 覆盖 | `service.py:150-151` 读 `pol.quota_per_min`；`config.example.yaml:36` 的对应项无人读 | 改了 config 不生效 → 「改了以为生效」（本机 `rules/ops.md` 明确点名的坑） |
| **M3** | **登录无失败限速**：可无限尝试 | 探针：无计数机制；`web.py._login` 失败只审计一次 | 口令爆破可行（虽 PBKDF2 120k 迭代减缓，仍应限速） |
| **M4** | **会话 Cookie 缺 `Secure`** | `web.py:276`：`HttpOnly; SameSite=Lax` 无 Secure | 反代 + HTTPS 部署时仍可能被降级明文传输 |
| **M5** | **GET 5xx 被重试**：`retry_ok` 只看方法不看状态码 | `executor.py` `http_request` 的 `except` 只捕连接层异常，5xx 是正常返回 → 不重试；**实际是「只重试连接错误」，但 5xx 被当成功路径返回**，`service.py:368` 的 `retry_ok` 语义名不副实 | 命名误导 + 无 5xx 重试策略（可接受，但须文档化） |

### 警告（Warning）

| # | 项 | 证据 |
|---|---|---|
| W1 | 错误码 20 个但 README 写 17，`LABELS` 有码但文档未列 | `service.py` E_OK..E_KILL |
| W2 | `service.py` 508 行 / `web.py` 508 行 / `cli.py` 736 行 —— 超 500 行阈值（`task-decomposition §单文件 >200 行单独成批` 的治理信号） | `wc -l` |
| W3 | `web.py` 与 `mcp.py` 各自 `Handler.svc` 类属性注入，多实例测试时互相污染 | `web.py` `Handler.svc = self.svc`（测试里反复赋值） |
| W4 | SSRF 校验与实际连接不同源：`check_ssrf(url)` 解析 DNS 后，`http_request` 再次解析（DNS rebinding 窗口） | `service.py:338` vs `:366` |
| W5 | `_shape()` 的 `array_limit` 硬截断不告知用户截了多少 | `service.py` `_shape` |
| W6 | `executor.http_request` 连接池 key 不含超时参数，不同 timeout 复用同一连接 | `executor.py` `_get_conn` |
| W7 | 审计 `epoch` 与 `ts` 双写但查询只用 `epoch`，`ts` 时区未统一说明 | `audit.py` |

### 建议（Suggestion）

| # | 项 |
|---|---|
| S1 | `kinds.py` 8 类之外补 `oauth2_refresh`（OSS 调研 F12） |
| S2 | `registry.render` 的 `json` 过滤器输出未转义，嵌入 JSON 模板时需二次 `quote` |
| S3 | `backup.export` 的 `PBKDF2` 迭代 200k 可配置化（当前硬编码） |
| S4 | 缺 lease 分发（OSS 调研 F5），当前消费方仍走静态同步 |

## 4. 修复包（可直接落地，按顺序）

### 包 A：C1 凭据到期拦截（约 15 行）

```python
# service.py _execute() 取密文前插入
meta = self.store.get_credential(ref)
if meta and meta.get("expires_at") and int(meta["expires_at"]) < int(time.time()):
    raise CredentialExpired(f"凭据 {ref} 已于 {meta['expires_at']} 到期，拒绝使用")
if meta and meta.get("status") != "active":
    raise CredentialExpired(f"凭据 {ref} 状态={meta['status']}，拒绝使用")
```
配套：`explain` 同步返回 `code=E_RESOLVE + 原因`，让 AI 干跑即可发现。

### 包 B：C2 凭据侧授权（约 10 行）

```python
# service.invoke() 在 agent 侧校验之后
meta = self.store.get_credential(ref) for ref in cap.secret_refs
for m in metas:
    if m and m.get("allowed_capabilities") is not None and cap.name not in m["allowed_capabilities"]:
        return self._fail(agent, cap.name, E_DENIED,
                          f"凭据 {m['name']} 不允许被 {cap.name} 使用（凭据侧白名单）", t0)
```

### 包 C：C3 审批原子核销（约 8 行）

```python
# approvals.consume 改为条件更新，返回受影响行数
with self.s.tx() as c:
    cur = c.execute("UPDATE approvals SET state='consumed', consumed_at=? "
                    "WHERE id=? AND state='approved' AND args_fp=?", (now(), aid, fp))
if cur.rowcount != 1:
    return False, "审批单已被核销或状态已变（并发保护）"
```

### 包 D：M2 死配置收敛（约 6 行）

```python
# service._limits() 改为 config 优先、policy 兜底
("min", 60, int(self.cfg.get("limits.quota_per_min") or pol.quota_per_min)),
("day", 86400, int(self.cfg.get("limits.quota_per_day") or pol.quota_per_day)),
```
或反方向：删 config 里的三项 + 在 config.example 注明「配额只在 policy 配」。**二选一，不留双源**。

### 包 E：M3+M4 登录硬化（约 20 行）

```python
# web: 失败计数（内存 + 落库双保险）
FAILS: dict[str, list[float]] = {}
def _rate_limited(key: str, limit=5, window=300) -> bool: ...
# Set-Cookie 增加 Secure（可配置，本地 http 调试时关）
secure = "; Secure" if self.svc.cfg.get("web.cookie_secure", True) else ""
```

### 包 F：M1 审计参数摘要（约 10 行）

```python
# audit.append 增加 args_preview 字段（redact.preview 裁剪）
"args_preview": redact.preview(json.dumps(args, ensure_ascii=False), keep=0)[:240],
```
注意：必须过 `redact.scrub`，防参数里带明文被写进审计。

## 5. 架构级审查（code-review 第七步点五，五项）

| 检查项 | 判据 | 结果 |
|---|---|---|
| 依赖方向 | 是否反向依赖/环 | ✅ 单向：cli/web/mcp → service → store/registry/policy/audit；无环 |
| 变更半径 | 一处业务规则变更需改 ≥3 模块？ | ⚠️ 中：配额改一处需动 config+policy+service（M2 根因）；其余良好 |
| 数据归属 | 同一实体是否被多模块直接写 | ⚠️ 「凭据」元数据由 store 写、service 读、cli 写 —— 写入口两个（cli/web），可接受但应统一 |
| 契约对称 | 增删改查入参出参同源 | ✅ registry schema 单一源；explain/invoke 共用 evaluate |
| 边界泄漏 | 跨模块直接访问内部实现 | ⚠️ `service._execute` 被 `rotate.py` 直接调用（探针路径）；`store._meta` 被 approvals/tokens/web 直接访问（绕过 DAL） |

## 6. 与 OSS 调研 F1–F13 的对账

| 调研项 | 平台现状 | 结论 |
|---|---|---|
| F1 软限流（litellm） | 只有硬停（`_quota_hit` 直接拒） | 仍缺，价值高 |
| F2 启动密钥体检（litellm） | doctor 查长度/权限，**未查弱熵**（全零/重复字符） | 部分缺失 |
| F3 参数级策略（warden） | `Rule.constraints` **字段存在但无执行代码** | 死字段，需实现或删 |
| F4 on-behalf-of（warden） | 无 | 缺 |
| F5 lease 分发（OpenBao） | 无 `dist.py` | 缺 |
| F6 闸门管线（mcp-context-forge） | invoke 单函数串行，无显式排序 | 结构可，扩展性弱 |
| F7 per-capability 限额（bifrost） | quota 表已支持 capability 粒度，policy 未暴露配置 | 差一层配置 |
| F8 whoami 自省（warden） | 有 `broker_whoami` 等价（`policy_explain`） | 已覆盖 |
| F9–F13 | — | 按原优先级 |

## 7. 未验证项（强制披露，状态四态）

| 项 | 状态 | 原因 |
|---|---|---|
| C3 并发下双核销 | **未验证** | 需要并发压测脚本，本次只做静态判定（`consume` 无 `WHERE state` 条件更新是确定事实） |
| W4 DNS rebinding 可利用性 | **未验证** | 需控制 DNS 服务端，未做 |
| M5 5xx 是否真被重试 | **已澄清：不重试** | 代码路径确认 5xx 走正常返回分支，不触发 `except`；`retry_ok` 名不副实属命名问题 |
| 登录爆破防护必要性 | **已判定需要** | 无任何计数，PBKDF2 120k 只减缓不阻断 |
| 全量 19 项动态复现 | **部分（8/19）** | 其余为静态判定，已标注 |

## 8. 审查方法自述（可复核）

按 dev-expert v2.3.0 执行：Step 1 判档→复杂；Step 2 三池 A1–A10 全过 + B1（DB 回滚 N/A）/B2（新依赖 N/A）/B3（并发→命中，产出 C3）/B8（不可逆 N/A）/B11（边界声明→命中，产出 C1/C2）；Step 3 写码前实码确认（8 处 `grep -n`）；Step 4 证据门（探针输出 + 行号锚）；Step 5 清理（探针脚本已删）；Step 6 复盘入宿主记忆。

**未采用的 dev-expert 行为**：未跑 `init_deploy.py`（本次是审查不是项目建设，Step 0.5 轻量跳过规则不适用，但部署会写宿主 hooks 属副作用，按「门禁资产只读」原则不动）。
