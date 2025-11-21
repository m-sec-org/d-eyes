# 示例插件快速开始

本目录包含三个示例插件，展示如何实现 Runner、编译为 Go 插件、生成 Manifest 并通过 Server 插件市场安装。

## 结构

```
respond_example/   # 示例响应插件
detect_example/    # 示例检测插件
bas_example/       # 示例 BAS 插件
```

## 构建

以 respond 示例为例：

```bash
cd agent/internal/plugin/examples/respond_example
GOOS=linux GOARCH=amd64 go build -buildmode=plugin -o respond-example.so .
shasum -a256 respond-example.so | awk '{print $1}'   # 更新 manifest.yaml 中的 artifactDigest
```

## 安装

1. 将 `manifest.yaml` 更新为真实 digest 与签名（参见 `docs/plugin-manifest.md`）。
2. 通过插件市场（Ops Console → 插件市场 → 安装/升级）粘贴签名清单，或调用 API：

```bash
BASE64=$(base64 -w0 manifest.yaml)
curl -X POST /api/v1/plugins -H 'Content-Type: application/json' \
  -d "{\"manifest\":\"$BASE64\",\"encoding\":\"base64\"}"
```

> 签名请使用 ed25519 对 manifest 的 canonical payload 签名；Server/Agent 会校验签名与 artifactDigest。
