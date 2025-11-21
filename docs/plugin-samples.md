# 插件示例合集

Stage 4 提供 3 个示例插件，覆盖响应、检测、BAS 场景，帮助开发者快速了解 Runner、Manifest、签名及安装流程。

## 目录结构

```
agent/internal/plugin/examples/
├── respond_example/    # 示例响应插件
├── detect_example/     # 示例检测插件
└── bas_example/        # 示例 BAS 插件
```

每个示例均包含下列内容：

| 文件 | 说明 |
|------|------|
| `*_example.go` | `tasks.TaskRunner` 实现，展示如何读取 `TaskRequest` 并返回 `TaskResult` |
| `manifest.yaml` | 对应插件的 OpenSpec Manifest，包含任务声明、资源、沙箱策略与签名字段 |
| `Makefile` / `build.sh` | 构建与签名示例命令，默认启用 `GOOS=linux`、`-buildmode=plugin` |

## 构建步骤

以 respond 示例为例：

```bash
cd agent/internal/plugin/examples/respond_example
GOOS=linux GOARCH=amd64 go build -buildmode=plugin -o respond-example.so .
shasum -a256 respond-example.so | awk '{print $1}'   # 写入 manifest.yaml
go run ../signer/main.go --manifest manifest.yaml --private-key keys/respond-example.key > signed-manifest.yaml
```

## 安装到 Server

1. 登录 Ops Console → 「插件市场」，选择 “安装 / 升级”，将 `signed-manifest.yaml` 粘贴或使用 base64 上传。
2. 或直接调用 API：

```bash
BASE64=$(base64 -w0 signed-manifest.yaml)
curl -X POST https://d-eyes.example.com/api/v1/plugins \
  -H 'Content-Type: application/json' \
  -d "{\"manifest\":\"$BASE64\",\"encoding\":\"base64\"}"
```

安装成功后即可在 Agent/Server 任务调度里使用 `respond-example` / `detect-example` / `bas-example`。

## Stage 4 发布检查清单

| 项 | 说明 |
|----|------|
| 语义化版本 | `manifest.version` 必须遵循 `MAJOR.MINOR.PATCH`，并与 `CHANGELOG` 同步。 |
| 兼容声明 | `minAgentVersion` / `maxAgentVersion` 覆盖当前发布的 Agent 版本（Stage4 默认 `>= 4.0.0`）。 |
| 资源与沙箱 | 在 manifest 中设置 `resources`、`metadata.sandbox`，并在示例插件内实现 `tasks.TaskRunner` 的节流逻辑。 |
| 观测性 | 插件应在执行结果中填充 `metadata`（例如命中率、资源使用），以便 Ops Console / Prometheus 展示。 |
| 自动化校验 | 在提交 PR 前运行 `scripts/docs-lint.sh`、`go test ./agent/internal/plugin/...`，保证文档和示例同步更新。 |

推荐在 plugin 仓库中引入以下流程：

1. 将插件文档编写在 `docs/` 下，并通过 `scripts/docs-release.sh <version>` 生成快照。
2. 每次发版更新 `docs/version.yaml.current`，在 Ops Console 的插件市场上传最新 manifest。
3. 如果插件依赖外部资产（如签名密钥、TI 配置），在文档中显式记录并纳入 Stage 4 发布 checklist。
