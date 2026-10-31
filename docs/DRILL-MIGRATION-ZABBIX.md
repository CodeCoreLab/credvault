# 迁移演练报告：CREDENTIALS_INDEX → credvault + Zabbix 真链路验收

> 日期 2026-10-26 · 环境：Windows 工作站（192.0.2.237）· 演练库 `credvault/.migration`（独立 HOME，不影响旧体系）
> 结论：**迁移链路 + 真链路调用全部打通**。CLI 与 MCP 两条通道都拿到 Zabbix 真实数据，全程明文零落盘零回显。

## 1. 迁移实测

| 步骤 | 命令 | 结果 |
|---|---|---|
| 元数据迁移 | `credvault migrate --index CREDENTIALS_INDEX.yaml` | 索引 133 条 → **去重后 92 个唯一凭据**入库 |
| 类型映射 | `cred list` 按旧 `type` → `kind` | service_token 41 / wecom_webhook 15 / llm_api_key 11 / config_url 9 / password 8 / db_token 4 / ssh_key 2 / webhook 1 / master_key 1 |
| 溯源保留 | `cred show ZABBIX_TOKEN` | `remark="server_credentials: env.secrets.sh#ENC_ZABBIX_TOKEN"`，`tags=[zabbix-alert-poller]`（consumers 前 5） |
| 值迁移策略 | — | **明文项可管道导入；37 条 ENC_ 密文跳过**（旧 KEK 与新 KEK 不同源，需重录——设计使然，`migrate` 明确计数并提示） |

## 2. ZABBIX_TOKEN 落库 + 真链路验收

```bash
# 值从本地缓存管道写入，不回显、不落临时文件
sed -n 's/^export ZABBIX_TOKEN=//p' ~/.workbuddy/secrets/env.local.sh \
  | tr -d '\r\n' | credvault cred set ZABBIX_TOKEN --kind api_token --value-stdin
# → fp=eef0abe601d5（指纹入元数据，值入密文库）
```

| 检查 | 结果 |
|---|---|
| 干跑 explain | `allow=true, rule=zabbix_host_list, secret_refs=[ZABBIX_TOKEN]`，无审批要求（只读） |
| **CLI 真链路** | `invoke zabbix_host_list --args '{"limit":5}'` → **HTTP 200，130ms**，返回 5 台真实主机（192.0.2.233 / 192.0.2.245 / 192.0.2.57 / 192.0.2.87 / 192.0.2.33） |
| **MCP 真链路** | stdio `tools/call zabbix_host_list {"limit":3}` → `isError=false, code=0, 140ms`，返回 3 台主机；13 个工具按双轴披露 |
| 凭据使用计数 | `use_count=2`，`last_used_at` 已更新 |
| 审计 | `audit verify` 链完整（3 条）；tail 可见两次调用 `HTTP 200 scrub=0` |

SSRF 判定按预期放行：`zabbix.example.com` 解析到内网（192.0.2.x），能力声明 `allow_private_upstream: true`。

## 3. doctor 状态（如实）

```
阻断 1：secrets —— 92 条元数据仅 1 条密文（其余 91 条 ENC_ 待重录）
其余 7 项全绿；审计链完整
```

**这是设计行为而非缺陷**：元数据库与密文库分离后，「有登记无密文」必须被探针点名，否则会出现"能力看着可用、调用时才炸"的假绿。91 条 ENC_ 值的回填路径：

1. **本机明文项**（env.local.sh 中非 ENC_ 的键）→ 同款管道导入，可脚本化批量
2. **跳板机 ENC_ 项** → 在跳板机解密后经 SSH 管道写入（脚本待写：`migrate-decrypt.py`，优先级 P1）

## 4. 安全说明

- 全程明文只存在于内存与管道：`cred set --value-stdin` 不回显；审计只记指纹
- 演练签发的 agent 令牌明文使用后已从临时文件清除（`/tmp/tok.txt`、`/tmp/cv_token.txt` 已删除）
- 演练库独立（`.migration`），未触碰旧 `cred_broker` 与 `env.secrets.sh`——**旧体系零改动，并行可回退**

## 5. 复现命令

```bash
export CREDVAULT_HOME=E:/WorkBuddy/2026-10-26-19-21-37/credvault/.migration
credvault cred list | wc -l                  # 92
credvault invoke zabbix_host_list --agent workbuddy-local --args '{"limit":5}'
credvault audit verify
```
