# 自动化部署 / 升级 / 回滚与灰度策略（多环境）

本指南结合 `scripts/ops/*.sh` 提供的脚本，帮助运维团队标准化部署流程。

## 1. 环境分类
- `dev`：单节点或 Docker Compose，适配本地调试。
- `stage`：Kubernetes 集群，镜像仓库与 CI 集成。
- `prod`：多实例、带告警/日志/混沌守门。
- `edge`：边缘节点，可能无集中式控制面，使用 `ssh + systemd` 或 `docker-compose`。

建议通过环境变量 `ENV=dev|stage|prod|edge`、`NAMESPACE` 等参数差异化配置脚本。

## 2. 通用准备
- 配置目标环境（Kubernetes context、Docker registry 等）。
- 确保 `VERSION` / `IMAGE_TAG`、`NAMESPACE`、`ENV` 等环境变量已设置。
- `edge` 环境可通过 `ssh user@edge-node "docker pull ... && docker run ..."` 等方式运行脚本。

## 2. 部署脚本（首次或全量部署）

```bash
VERSION=stage4 \
NAMESPACE=d-eyes \
scripts/ops/deploy.sh
```

脚本执行步骤：
1. `docker build` 生成镜像 `registry.local/d-eyes/server:<VERSION>`。
2. `docker push` 推送到镜像仓库。
3. `kubectl set image` 更新 Deployment，并等待 `kubectl rollout status` 成功。

## 3. 升级脚本

```bash
IMAGE_TAG=registry.local/d-eyes/server:stage4.1 \
NAMESPACE=d-eyes \
scripts/ops/upgrade.sh
```

仅更新镜像并等待 rollout 完成，可用于微调配置或热补丁。

## 4. 回滚脚本

```bash
NAMESPACE=d-eyes REVISION=3 scripts/ops/rollback.sh
```

依赖 Kubernetes Deployment 的 revision 历史。回滚后建议运行 `scripts/ci-gates.sh` 及 `scripts/perf-baseline.sh` 复核。

## 5. 灰度策略

```bash
IMAGE_CANARY=registry.local/d-eyes/server:stage4-canary \
IMAGE_STABLE=registry.local/d-eyes/server:stage4 \
NAMESPACE=d-eyes \
scripts/ops/gray-release.sh
```

- 创建 `d-eyes-server-canary` Deployment（1 个副本，标签 `role=canary`）。
- 主 Deployment 继续运行稳定版本。
- 结合流量入口（Service/Ingress）设置权重，如利用 `Service` selector 或 Service Mesh 进行 80/20 分流。
- 验证指标、日志与 `scripts/task-trace.sh` 输出后，再将主 Deployment 升级到新版本。

## 6. 关联文档
- 配合 `docs/ops-scripts.md`、`docs/monitoring-guide.md`、`docs/logging-trace-guide.md`。
- 发布过程中执行 `scripts/ci-gates.sh`、`scripts/perf-baseline.sh`，并更新 `docs/release-notes/<version>.md`。
