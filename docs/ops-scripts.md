# 运维脚本模板（部署 / 回滚 / 观测闭环）

Stage4 要求运维流程标准化，以下脚本示例可直接落地，也可根据环境改写。所有脚本默认在仓库根目录运行，并依赖 `scripts/docs-lint.sh`、`scripts/docs-release.sh`、`server/tools/perfcheck` 等内置工具。

## 1. 部署流水线脚本 `deploy.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-stage4}"

echo "[deploy] build images/binaries..."
make -C server build
make -C agent build

echo "[deploy] run docs lint before发布..."
"$ROOT/scripts/docs-lint.sh"

echo "[deploy] apply k8s manifest..."
kubectl apply -f deploy/server-deployment.yaml
kubectl rollout status deployment/d-eyes-server -n security

echo "[deploy] record docs版本..."
"$ROOT/scripts/docs-release.sh" "$VERSION"
```

要点：

- 在发布前同时构建 Server/Agent，并运行 `docs-lint` 确保文档同步。
- 成功发布后调用 `scripts/docs-release.sh` 生成 `docs/releases/<version>`，方便回溯文档。

## 2. 回滚脚本 `rollback.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET_REV="${1:-previous}"
NAMESPACE="security"

echo "[rollback] reverting server deployment..."
kubectl rollout undo deployment/d-eyes-server -n "$NAMESPACE" --to-revision="$TARGET_REV"
kubectl rollout status deployment/d-eyes-server -n "$NAMESPACE"

echo "[rollback] reverting agent daemonset..."
kubectl rollout undo daemonset/d-eyes-agent -n "$NAMESPACE" --to-revision="$TARGET_REV"
kubectl rollout status daemonset/d-eyes-agent -n "$NAMESPACE"

echo "[rollback] verifying perf 指标..."
server/tools/perfcheck --prom "https://prom.local" --window 5m --threshold.cpu 80 --threshold.fail 0.01
```

- 回滚完成后立即执行 `perfcheck`（参见 `server/docs/LOADTEST.md`），验证 CPU、失败率与 P95 SLA。
- 可结合 `docs/observability-api.md` 中的 API 拉取最新结果并写入运维记录。

## 3. 健康与审批巡检脚本 `health_check.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

API="https://d-eyes.example.com/api/v1"
API_KEY="${API_KEY:?API_KEY 未设置}"

check_endpoint() {
  local path="$1"
  status=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $API_KEY" "$API$path")
  if [[ "$status" != "200" ]]; then
    echo "ERROR: $path 返回 $status" >&2
    exit 1
  fi
}

check_endpoint "/tasks/stream?limit=1"
check_endpoint "/bas-scenarios"
check_endpoint "/playbooks"

echo "[health] checking待审批 BAS 场景..."
pending=$(curl -s -H "X-API-Key: $API_KEY" "$API/bas-scenarios" | jq '[.[] | select(.requires_approval and .status!="approved")] | length')
echo "[health] 待审批场景: $pending"
```

- 适用于定时巡检或 GitOps 流程，确保关键 API 可访问且审批链路未堆积。
- 若需要观测数据，可在脚本尾部追加 PromQL 查询或 `perfcheck` 调用。

## 4. 与 Docs-as-Code 集成

建议在流水线中串联以下动作：

1. `scripts/docs-lint.sh` —— 阻止缺少标题/断链的文档合入。
2. `scripts/docs-release.sh <version>` —— 每次发布（或回滚）后生成文档快照。
3. 将 `docs/releases/<version>.zip` 上传到制品库（GitHub Release、OSS、内部制品仓库），并在变更记录里附上链接。

## 5. 扩展与自定义

- 可将上述脚本迁移到 Ansible、Terraform、Argo CD 等平台，保留 `perfcheck`、Docs 流程和审批巡检逻辑。
- 若需要更多模板（如 BAS 自愈、日志聚合），可直接在 `docs/ops-scripts.md` 追加脚本段落，并运行 `scripts/docs-lint.sh` 确认格式。

借助这些模板，运维团队能够以统一方式执行部署、回滚、巡检与文档发布，匹配 Stage4 的流程化交付要求。
