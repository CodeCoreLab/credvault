# 变更日志 — 凭据平台（credvault）

本文件记录本项目的变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

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
