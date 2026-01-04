# D-Eyes Frontend 发布与文档指南

## 1. 打包与质量流程
1. 安装依赖：`pnpm install`
2. 质量检查：`pnpm lint`
3. 单元测试（可选，按需运行）：`pnpm test -- --runInBand`
4. 构建：`pnpm build`，产物位于 `dist/`
5. 预览：`pnpm preview`

> 若受限于环境不便执行测试，可先提交测试脚本，待 CI 或具备运行条件后执行。

## 2. 环境变量与 Mock
| 变量 | 说明 | 默认 |
|------|------|------|
| `VITE_API_BASE_URL` | REST API 地址 | `/api/v1` |
| `VITE_WS_BASE_URL`  | SSE/WS 地址 | `/api/v1/tasks/stream` |
| `VITE_USE_MSW`      | 是否启用 MSW Mock | `true` |
| `VITE_USE_MOCK_SSE` | 是否使用 Mock EventSource | `true` |
| `VITE_AUTO_LOGIN`   | 是否自动登录 mock 账号（默认 admin） | `true` |

切换真实服务时，将 `VITE_USE_MSW`、`VITE_USE_MOCK_SSE` 置为 `false` 并提供真实 API/SSE 地址。

## 3. RBAC 与角色
- `operator`：访问任务/风险/资产视图，可执行任务操作。
- `auditor`：访问风险视图与审计日志，可导出数据。
- `admin`：拥有所有入口，包括系统配置、命令队列等。

`AuthProvider` 的 Auto Login 默认使用 admin 账号，调试其他角色可在 `src/app/providers/AuthProvider.tsx` 中修改。

## 3.1 Detect 远程调度（Ops Console）

前端任务创建/报告展示已对齐 Server 的 task catalog 与 audit/detect report/read 面，发布时请确认以下依赖满足：

- **依赖 API**：
  - task catalog：`GET /api/v1/task-types`、`GET /api/v1/task-profiles`
  - 创建任务：`POST /api/v1/tasks`
  - 报告读取：`GET /api/v1/tasks/{id}/audit/report`、`GET /api/v1/tasks/{id}/detect/report`
- **权限要求**：读取报告需要 `reports.view`；缺失时前端会提示 403（permission denied）。
- **memscan gating**：`detect.memscan` 为 Windows-only，且要求 Agent 显式 opt-in（`remote.labels.allow_memscan="true"`）；审批字段与 `error_code` 口径见 `docs/detect-remote-dispatch.md`。

## 4. 部署建议
1. 将 `dist/` 作为静态资源部署（Nginx、K8s Ingress 或静态容器）。
2. 与 Server 共享域名/反向代理，确保 Cookie/token 可用。
3. 在 CI 中执行 `pnpm lint && pnpm test && pnpm build`；无法运行测试时至少保留脚本，待可运行环境执行。
4. 记录版本号与提交 ID，便于回溯。

## 5. 测试覆盖
- **任务视图**：Vitest 覆盖筛选/视图保存/抽屉交互；计划在 Playwright 中补充 E2E（命令面板、快捷键）。
- **风险/资产视图**：资产虚拟滚动性能测试、风险时间线渲染测试；契约测试验证 `/reports/summary`、`/assets`、`/assets/{id}` 数据结构。
- **配置/审计视图**：基础渲染单测确保表单/过滤控件存在。

后续可在 CI 中引入 axe/Playwright 执行可访问性与端到端测试。

## 6. 文档与支持
- `README.md`：快速开始、脚本、RBAC、发布说明。
- `docs/RELEASE.md`（本文）：发行与部署指引。
- 若与 Server 真实 API 对接，需同步更新接口契约及测试。
