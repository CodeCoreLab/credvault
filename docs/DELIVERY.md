# 交付对照表（I1–I17）与验收命令

> 每个条目给出「实现文件 → 一条能复现的验收命令 → 本次实测结果」。
> 实测环境：Windows 11 + Python 3.13.14（venv），2026-10-26 本地跑通；未在 Linux 上重跑（差异点见文末）。

## P0 —— 让定位成立

| # | 条目 | 实现 | 验收命令 | 实测 |
|---|------|------|---------|------|
| I1 | 能力注册表（YAML→工具，不改代码） | `registry.py` + `capabilities/ops.yaml` | `credvault cap list` | ✅ 5 个能力加载，`cap list` 正常 |
| I2 | server `instructions`（随部署动态生成） | `mcp.build_instructions()` | MCP `initialize` 响应 | ✅ 1179 字，含「不要索要 token」「按 code 分支处置」「安全红线」 |
| I3 | 返回体预算 + `structuredContent` + `isError` | `redact.shrink()` + `mcp._tool_result()` | 测试 `T04Redact.test_shrink_budget` / `T13Mcp` | ✅ 越界裁剪附「省略 N 字节」；失败置 `isError=true` |
| I4 | 只读自省工具组 | `mcp.INTROSPECTION`（9 个） | `tools/list` | ✅ 13 个工具 = 4 能力 + 9 自省 |
| I5 | 异步审批（轮询 + 会话豁免 + 事件 + 人不碰 shell） | `approvals.py` + `web.py` 待审批页 | `credvault invoke wecom_send_text --agent workbuddy-local --args '{"content":"x"}'` | ✅ 返回 `code=11` + `approval_id`；Web 批准后带 id 重试成功；`--session` 生成 120 分钟豁免 |
| I6 | 默认收 exec 权 + argv 白名单 + 去掉无审批的 rotate 工具 | `config.yaml exec.enabled=false` + `policy.allow_exec` + `executor.run_exec` | 测试 `T10Service.test_exec_allowlist` / `test_exec_disabled_by_config` | ✅ 白名单外程序被拒；配置关闭时连白名单内也拒 |
| I7 | 令牌双轴 + IP 白名单 | `tokens.py` | `credvault token add <name> --creds X --caps Y --ips 10.0.0.*` | ✅ 不可见凭据的能力**不出现在**工具列表；IP 不符直接 fail-closed |

## P1 —— 做成可交付的产品

| # | 条目 | 实现 | 验收命令 | 实测 |
|---|------|------|---------|------|
| I8 | 凭据类型 schema（必填字段 + 形态校验） | `kinds.py`（8 类） | `credvault cred kinds` / `credvault cred set K --kind ssh_key --value x` | ✅ 未知类型/缺 account/值过短当场拒 |
| I9 | KEK→DEK 信封加密 + 密文/元数据分离 + rewrap | `crypto.py` + `store.py`（两个 sqlite 文件） | 测试 `T03Store.test_secret_in_separate_db` / `test_rewrap_all` | ✅ 元数据库与密文库均无明文；rewrap 只换 DEK 包裹体 |
| I10 | 通用配额（突发/分钟/日） | `service._limits/_quota_hit/_quota_bump` | 测试 `T17Burst` | ✅ 第 4 次调用起 `code=18` |
| I11 | Kill Switch（全局只读） | `cli.killswitch` + `service.invoke` | `credvault killswitch on` → 调写能力 | ✅ 返回 `code=19`，只读能力仍放行 |
| I12 | `/healthz /readyz /version /metrics` + 单产物打包 | `web.py` + `ops.py` + `Dockerfile`/`install.sh`/`build.sh`/`credvault.spec` | `curl /healthz /metrics`；`./build.sh` | ✅ 四个端点实测通过，`/metrics` 40 行；**打包脚本未实测**（见文末） |
| I13 | 备份导出 `.cvault` | `backup.py` | `credvault backup export b.cvault --password ...` → `restore` | ✅ 包内无明文；错误主密码被拒；往返恢复密文成功 |
| I14 | 审计外部 sink（默认关） | `config.audit.sink` + `audit._push_sink` | 配置 `sink.type=http` | ⚠️ 代码路径已实现，**未接真实 sink 实测** |

## P2 —— 人工辅助面

| # | 条目 | 实现 | 验收命令 | 实测 |
|---|------|------|---------|------|
| I15 | 三视图（待审批/审计/令牌），不做全功能后台 | `web.py`（3 页 + 登录） | 浏览器打开 `:8443` | ✅ 登录页/审批页/审计页/令牌页渲染正常，未登录 302 |
| I16 | 审批人身份 + 审计归属（最小 RBAC） | `web.hash_password/ensure_user` + `Handler._can` + `sessions` | 测试 `T18Role` | ✅ viewer 审批 403、缺 CSRF 403、admin 通过；审计 actor 记 `human:<user>` |
| I17 | 轮换能力化（受审批 + 探针 + 回滚） | `rotate.py` + `registry kind: rotate` | 测试 `T16RotateCapability` | ✅ 未审批 `code=11`；批准后轮换成功；探针失败自动回滚到上一版值 |

## 统一验收（一条命令看全貌）

```bash
credvault doctor          # 期望：阻断 0
credvault policy-check    # 期望：无告警 + 逐条授权可见
python -m unittest discover -s tests   # 期望：70 tests OK
```

本次实测输出：`doctor` → **阻断 0 / 告警 2 / 检查 8**；测试 → **Ran 70 tests, OK**。

## 未实测项（如实列出）

| 项 | 原因 | 影响 |
|---|---|---|
| `./build.sh binary`（PyInstaller） | 需联网安装 pyinstaller，本机未执行 | 产物体积/隐式依赖未验证；源码与容器路径不受影响 |
| `docker build` | 本机 Docker 未启动 | 同上；Dockerfile 为非 root + /data 卷 + healthcheck |
| `./install.sh` | 会改写用户级 site-packages 与 systemd，未在本机执行 | 脚本逻辑为幂等设计，但未实跑 |
| 审计 HTTP sink 真链路 | 避免向外部端点发数据 | 失败仅丢审计外发，不影响主链路 |
| Linux 实跑 | 本次只在 Windows 验证 | 已知差异：文件权限走 `chmod`（Windows 走 icacls）、子进程编码 `utf-8`（Windows `gb18030`）；两处都有分支代码 |

## 与旧 `cred_broker` 的兼容与迁移

```bash
# 只导元数据（name/type/consumers → 凭据名/kind/tags），不动源文件
credvault migrate --index ~/.workbuddy/tools/credential-registry/CREDENTIALS_INDEX.yaml

# 导明文项（ENC_ 密文会跳过并计数——KEK 不同源，需重录）
credvault migrate --env /opt/workbuddy/.scripts/config/env.sh

# 复用旧 agent 令牌（只存 sha256，令牌本身继续沿用）
python -c "from credvault.service import Service; from credvault import config; \
s=Service(config.load()); print(s.tokens.import_legacy('~/.workbuddy/.state/cred_broker/agents.json'))"
```

旧 `cred_broker` 可继续运行（两者不共享状态），迁移是**并行**而非替换，回退只需停新服务。
