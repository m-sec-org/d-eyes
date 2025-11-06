# 任务模板 API 使用说明

服务器新增 `/api/v1/task-templates` 相关接口，用于在 Web 管控面管理任务模板、参数及调度，下发多 Agent 任务。调用需携带 `X-API-Key`。

## 模板基本操作

### 创建模板

```http
POST /api/v1/task-templates
{
  "name": "BAS 初始访问",
  "task_type": "bas",
  "profile": "auto",
  "flags": {"scenario-id": "initial-access"},
  "metadata": {"required_capabilities": "bas"},
  "targets": ["dmz-agents"],
  "priority": 5,
  "created_by": "security-team",
  "schedule": {
    "enabled": true,
    "interval_minutes": 60,
    "targets": ["dmz-agents"]
  }
}
```

### 列表与详情

- `GET /api/v1/task-templates` 返回模板数组；
- `GET /api/v1/task-templates/{id}` 返回单个模板。

### 更新 / 删除

- `PUT /api/v1/task-templates/{id}` 覆写模板内容；
- `DELETE /api/v1/task-templates/{id}` 删除模板。

> 模板默认保存在 `config.templates.persist_path` 指定的 JSON 文件中，重启后自动加载。

## 下发任务

```http
POST /api/v1/task-templates/{id}/deploy
{
  "targets": ["dmz-agents", "prod-agents"],
  "flags": {"scenario-id": "privilege-escalation"},
  "created_by": "soar-automation"
}
```

返回示例：

```json
{
  "task_ids": ["b5d6aa92-..."]
}
```

部署时可覆写模板的 flags / metadata / priority 等参数。任务 metadata 中会记录 `template_id`、`template_name` 与 `target_agents` 便于审计与报告。

## 调度执行

- 模板 Schedule 启用后，调度器每分钟轮询，若到期则自动调用模板进行下发；
- 最近一次下发时间与下一次计划时间会反写到模板的 `schedule.last_run`、`schedule.next_run`；
- 调度下发的任务默认 `created_by` 为 `scheduler`。

## 错误码

- 400：参数缺失或模板不存在；
- 500：任务创建或入队失败（可查看 Server 日志）。

结合已有任务 API，模板接口可快速支撑 Web 配置器，实现模板化参数、定时调度与多 Agent 协同执行。***
