# 插件清单（Manifest）规范 v1

本规范定义 Stage 4 插件生态的元数据、签名与版本约束，适用于 Server 插件市场与 Agent 侧加载校验。

## 基本字段

- `apiVersion`: 固定为 `v1`
- `name`: 插件名称（唯一）
- `version`: 语义化版本（semver）
- `entry`: 插件入口（例如 `./plugin.so` 或启动命令）
- `artifactDigest`: 插件包的 SHA256（64 位 hex）
- `minAgentVersion` / `maxAgentVersion`（可选）：支持的 Agent 版本范围
- `tasks`: 插件提供的任务列表，`kind` 取值：respond | baseline | inventory | supplychain | bas | action | audit
- `targets`（可选）：限定 OS/Arch
- `resources`（可选）：资源预算（cpu/memory/timeout）
- `signature`: ed25519 签名（详见下文）
- `metadata.sandbox`: 若填 `required`，Agent 将强制沙箱执行

## 签名要求

- 算法：`ed25519`
- `publicKey`: Base64 编码，32 字节
- `value`: Base64 编码，签名的载荷为以下字段的 JSON（按字段顺序确定性编码）：
  - `apiVersion`、`name`、`version`、`entry`、`artifactDigest`
  - `minAgentVersion`、`maxAgentVersion`
  - `signedAt`（可选，RFC3339）
  - `tasks`、`targets`、`resources`
  - `metadata`（按 key 排序）
  - `trustedPublishers`（可选）

## YAML 示例

```yaml
apiVersion: v1
name: respond-risk-score
version: 1.2.3
entry: ./plugin.so
artifactDigest: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
minAgentVersion: 1.0.0
tasks:
  - name: respond-risk-score
    kind: respond
    capabilities: [scan, ti]
targets:
  - os: linux
    arch: amd64
resources:
  cpu: 500m
  memory: 256Mi
  timeout: 5m
signature:
  algorithm: ed25519
  publicKey: <base64-public-key>
  value: <base64-signature>
```

## 校验流程

1) Server/Ops Console 上传时读取 manifest，校验字段与 semver、SHA256 长度、任务种类与目标平台。
2) 使用 `signature` 中的公钥和 `value` 对 canonical payload 做 ed25519 验证。
3) 比对实际插件包的 SHA256 与 `artifactDigest`。
4) 若验证失败必须拒绝安装并记录审计；成功后才进入沙箱/灰度加载流程。

## 资源与沙箱约束

- Server/Agent 会解析 `resources.cpu/memory/timeout`，并与平台设定的上限比较（超限即拒绝）。
- 若 `metadata.sandbox=required` 或平台配置强制沙箱，插件任务执行必须走沙箱运行时，并向市场/监控上报安装/回滚事件。
