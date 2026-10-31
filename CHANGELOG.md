# 变更日志 — 凭据平台（credvault）

本文件记录本项目的变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

## [1.3.0] - 2026-10-31

> 本版把散落三处的改动合并为单一版本：GitHub `d179c9e9` 治理修复（8 项）、
> 本地未提交草稿（已被治理版全面覆盖）、以及打包与版本一致性收口。

### 安全

- **鉴权失败不落审计 → 已修复**：凭据平台自身审计链断裂。
  `web` 层 401 分支补 `api.auth` / `mcp.auth` 审计，区分失败原因且不记令牌
- **HTTP access log 被显式静音 → 恢复并改走 logging**：
  `setup_web_logging()` 统一 stderr + 可选 `RotatingFileHandler`（5MB×5，
  经 `CREDVAULT_LOG_FILE`）；query string 按 12 类敏感键脱敏
- **WebUI 存储型 XSS → 全部插值点 `html.escape`**；
  `_send` 统一加 `Content-Security-Policy` 与 `X-Frame-Options: DENY`
- **IP 白名单空 ip 静默跳过 → fail-closed**：`resolve()` 重构为
  `resolve_ex(token, ip, check_ip)`，返回 `(agent, reason, name)` 三态；
  stdio MCP 废除硬编码 `127.0.0.1` 伪装回环，改显式 `check_ip=False` 跳过

### 修复

- `update_scopes` 的 f-string 拼 SQL → `FIELD_MAP` 查表 + CLI scope 校验
- 备份包剥离 `pwd_hash`（restore 兼容旧包并提示重建账号）
- Windows `perm_ok` 恒返回 True → `icacls` 反查真实 ACL
  （继承已移除 + 授权主体仅当前用户与 SYSTEM/Administrators）
- `executor` 4 处裸 `except: pass` → 分级 logging（不含凭据）

### 变更

- **CLI 新增 `--json` 结构化输出模式**：令牌明文不再落到 stdout
  （stdout 常被 CI 日志、终端录屏、管道缓存收集），改写入 stderr；
  stdout 保持纯 JSON，便于 `| jq` 直接消费。所有子命令均可用该参数
- **WebUI 令牌展示改为一次性横幅**：替代阻塞式 `alert()` 模态框，
  令牌 5 秒后自动从 DOM 移除，并提供复制按钮

### 修复

- **补齐 `_common` 符号导入，消除运行期 `NameError`**：
  `cli/access.py` 调用 `_prog()`、`cli/creds.py` 调用 `_import_env()`，
  但两者都未从 `cli/_common.py` 导入。异常发生在令牌**已创建之后**，
  用户看到的是「报错了但令牌确实发了」——既拿不到 client_config，
  也不知道该不该重试。影响 `token add` 与 `cred import-env` 两条路径
- `capabilities/ops.yaml` 与 `README.md` 中 4 处真实内网信息泄露
  （内网监控地址、数据库名、实例 IP）已替换为 RFC 5737 文档专用网段
  与示例主机名
- **`credvault init` 在源码目录不可用 → 已修复（本版实测）**：
  `cli/lifecycle.py` 原固定 `tpl = 包目录`，而 `policy.yaml` 在仓库根，
  导致源码态 init 静默不落策略、随后 `Service` 加载报 `PolicyError`。
  改为三候选按序探测（包目录 → 仓库根 → 再上一层），安装态行为不变。
  实测：`init --home <dir>` 输出「策略/能力 5 个」且 `policy.yaml` 落盘

### 新增

- `web/make_dist.py` 打包器：45 项扁平 zip，与线上已发布包结构对齐；
  内置 6 条敏感信息自检规则，并支持按规则粒度的测试目录豁免
  （测试固件中的构造性假值不算泄露，但内部域名、数据库连接串仍会被拦下）
- `requirements.lock.txt` 依赖锁文件
- `docs/` 历史交付文档入库（v1.1.0 测定报告、ADR、迁移演练）
  —— 内网地址已全部脱敏为 RFC 5737 示例网段

- 回归基线：`python -m pytest tests/ -q` → **109 passed**（零回归）

- **CLI 新增 `--json` 结构化输出模式**：令牌明文不再落到 stdout
  （stdout 常被 CI 日志、终端录屏、管道缓存收集），改写入 stderr；
  stdout 保持纯 JSON，便于 `| jq` 直接消费。所有子命令均可用该参数
- **WebUI 令牌展示改为一次性横幅**：替代阻塞式 `alert()` 模态框，
  令牌 5 秒后自动从 DOM 移除，并提供复制按钮
- **已知问题（待修复）**：`credvault init` 在源码目录下不可用 ——
  `cli/lifecycle.py` 的模板查找路径取 `credvault/` 包目录，而 `policy.yaml`
  实际位于仓库根，导致策略骨架不落盘、随后 Service 加载策略失败。
  正式安装路径（`install.sh`）不受影响

### 修复

- **补齐 `_common` 符号导入，消除运行期 `NameError`**：
  `cli/access.py` 调用 `_prog()`、`cli/creds.py` 调用 `_import_env()`，
  但两者都未从 `cli/_common.py` 导入。异常发生在令牌**已创建之后**，
  用户看到的是「报错了但令牌确实发了」——既拿不到 client_config，
  也不知道该不该重试。影响 `token add` 与 `cred import-env` 两条路径
- `capabilities/ops.yaml` 与 `README.md` 中 4 处真实内网信息泄露
  （内网监控地址、数据库名、实例 IP）已替换为 RFC 5737 文档专用网段
  与示例主机名

### 新增

- `web/make_dist.py` 打包器：输出 45 项扁平 zip，与线上已发布包结构对齐；
  内置 6 条敏感信息自检规则，并支持按规则粒度的测试目录豁免
  （测试固件中的构造性假值不算泄露，但内部域名、数据库连接串仍会被拦下）

## [1.2.0] - 2026-10-26

### 新增

- **能力注册表 YAML 化**：加一行 = 多一个 AI 工具，
  `capabilities/*.yaml` 声明式定义，代码零分支
- **信封加密**：KEK → DEK 两层，主密钥不落盘
- **六道闸门按序判定**：作用域 → 策略 → 审批 → 注入 → 脱敏 → 审计
- **哈希链审计**：防篡改，可校验完整性（`credvault audit verify`）
- **异步审批**：不阻塞调用方，凭 `approval_id` 轮询状态后重试，支持会话豁免
- **MCP 与 REST 双入口**：令牌带 scope（`mcp` / `api` / `both`）互不越界；
  默认 `mcp`，存量库升级时自动补成 `mcp`（升级不扩权）
- **渐进式披露**：未授权的能力不出现于工具列表，`initialize.instructions`
  按当前身份动态生成中文引导
- **上下文预算**：返回体默认 32 KB 硬预算 + `summary_only` 结构化裁剪
- **20 个错误码**（0 / 10–20）+ `next_action`，instructions 里写明每种码怎么处置
- **32 模块 / 6046 行**，109 项用例全绿
- CI：Python 3.11 / 3.12 / 3.13 三版本矩阵

### 安全

- 凭据只在内核出现一次，AI 永远拿到脱敏后的结构化结果
- 人只在**审批 / 审计 / 令牌**三处出现
- 默认 `mcp` scope 而非 `both`：已有令牌不会因升级而顺带获得脚本调用能力
