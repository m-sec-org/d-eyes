## 报告中心接口说明

里程碑 F3 在 Server 侧提供统一的任务结果汇总与导出能力，当前主要通过 REST 接口供 Web 前端消费。

### 汇总查询

```
GET /api/v1/reports/summary?type=bas&limit=50
Header: X-API-Key: <key>
```

- `type`（可选）：按任务类型过滤，例如 `bas`、`baseline`。
- `limit`（可选）：返回结果条数，默认 50。

响应示例（部分）：

```json
{
  "items": [
    {
      "result_id": "5b1c...",
      "task_id": "84d1...",
      "task_type": "bas",
      "status": "succeeded",
      "scenario_id": "initial-access",
      "completed_at": "2025-11-06T10:00:31Z"
    }
  ],
  "totals": {"bas": 12, "baseline": 8},
  "status_totals": {"succeeded": 18, "failed": 2}
}
```

### 历史导出

```
GET /api/v1/reports/export?format=html&type=bas&limit=100
```

- `format` 支持 `json`（默认）或 `html`，响应带附件头，可直接下载。
- JSON 导出为标准数组；HTML 导出为带表格的自包含页面。

### 实时监控

配套 SSE 端点 `/api/v1/tasks/stream` 会推送任务状态变化与实时统计，可在前端同时订阅以刷新 UI。

结合模板接口与上述报告能力，可以在 Web 管控面构建“计划执行 + 实时监控 + 历史报告”一体化体验。***
