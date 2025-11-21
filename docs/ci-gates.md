# CI 门禁（Coverage / Performance / Plugin Compatibility）

为满足 Stage4 的测试与发布要求，在 CI 或本地发布流程中执行 `scripts/ci-gates.sh`，它会串联以下步骤：

1. `scripts/test-matrix.sh` – 运行 Server/Agent/BAS/前端/Docs 测试矩阵。
2. `scripts/coverage-report.sh` – 生成 agent/server 覆盖率报告（默认 agent 100%，server 无强制阈值，可通过 `COVER_THRESHOLD_*` 环境变量配置）。
3. `scripts/plugin-compat.sh` – 对插件示例运行 `go test` 并构建示例 `.so`，确保市场兼容性。
4. `scripts/perf-baseline.sh` – 当 `PROM_URL` 提供 Prometheus 地址时验证调度/资源 P95 与失败率（可通过 `PERF_WINDOW`、`--threshold.*` 参数覆盖）。
5. `scripts/check-release-notes.sh` – 校验发布说明与 `docs/changelog.md` 同步。

示例：

```bash
PROM_URL=https://prom.example.com COVER_THRESHOLD_AGENT=100 COVER_THRESHOLD_SERVER=85 \
  scripts/ci-gates.sh --threshold.cpu 80 --threshold.mem 85
```

> 如需在 CI 上拆分任务，可单独调用上述脚本，或通过 Makefile/Workflow 将 `ci-gates.sh` 拆解成多个 stage。
