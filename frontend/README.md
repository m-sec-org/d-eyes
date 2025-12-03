# D-Eyes Frontend

基于 **React 18 + TypeScript + Vite** 的 D-Eyes Web 控制台。当前阶段集成了深浅色主题、命令面板、MSW Mock、SSE 模拟通道等基础能力，可在本地无后端依赖地运行与演示。

## 快速开始

> 运行前请确保安装了 [pnpm](https://pnpm.io)（已在根目录使用）及 Node.js ≥ 18。

```bash
cd frontend
pnpm install          # 安装依赖
pnpm dev              # 启动开发服务器（http://localhost:5173）
```

默认启用了 MSW/Mock 接口与 Mock SSE，首次启动会自动完成「ops.lead / Passw0rd!」账户的 Auto Login，可直接体验命令面板、主题切换与实时操作时间线。

### 自定义环境变量

在 `frontend/.env`（或 `.env.local`）中覆盖下面变量：

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `VITE_API_BASE_URL` | REST API Base | `/api/v1` |
| `VITE_WS_BASE_URL`  | 任务 SSE 地址 | `/api/v1/tasks/stream` |
| `VITE_QUEUE_STREAM_URL` | 队列 SSE 地址 | `/api/v1/queues/stream` |
| `VITE_THREAT_INTEL_STREAM_URL` | Threat Intel SSE 地址 | `/api/v1/threat-intel/stream` |
| `VITE_USE_MSW`      | 是否启用 MSW Mock | `true` |
| `VITE_USE_MOCK_SSE` | 是否使用 Mock EventSource | `true` |
| `VITE_AUTO_LOGIN`   | 是否自动登录 mock 用户 | `true` |

当后端接口准备就绪时，将上述开关置为 `false` 即可接入真实服务。

## 常用脚本

```bash
pnpm dev       # 本地开发（含 MSW Mock）
pnpm build     # 生成生产构建（tsc -b + vite build）
pnpm preview   # 预览生产构建
pnpm lint      # ESLint 检查
pnpm test      # Vitest 单元测试（计划中，随 Milestone B 开展）
```

## 目录结构概览

```
frontend/
├── src/
│   ├── app/                # Providers、全局上下文
│   ├── components/         # UI 组件（布局、命令面板、Timeline 等）
│   ├── hooks/              # useTheme / useCommandPalette / useTaskStream
│   ├── mocks/              # MSW handlers、Mock SSE、Mock 数据
│   ├── services/           # API SDK（axios + zod）、SSE 适配层
│   ├── store/              # Zustand 事件存储
│   ├── styles/             # 设计 Token、全局样式
│   └── main.tsx            # 入口（集成 MSW、Router、Providers）
└── vite.config.ts          # Vite 配置（含 @ 路径别名）
```

## 当前里程碑能力概览
- React/Vite 脚手架 + 质量工具（ESLint、Vitest、Playwright 预留）。
- 企业级 App Shell：顶栏/侧栏/主内容、深浅色主题、命令面板、响应式布局。
- 统一认证（Mock 登录 + Refresh Token）与 API SDK（axios + zod）。
- MSW Mock + EventSource Mock，模拟 `/api/v1/tasks|reports|assets|audit|task-templates` 与 `/tasks/stream`。
- useTaskStream + OperationTimeline：实时展示任务事件与审计操作。
- 任务/队列/威胁情报三大视图已对齐后端契约：TaskOverview 使用服务器分页 + 视图保存、QueueMonitor 展示真实队列摘要与 SSE、ThreatIntelWorkspace 直接消费 `/threat-intel/jobs|samples` 并同步 SSE 状态。
- 风险/资产/配置/审计视图：风险趋势、资产详情与批量标记、系统配置中心、审计日志过滤导出。
- RBAC：依据角色（普通用户/审计用户/超级管理员）控制路由、命令面板与侧栏入口。

更多实现细节参考 `openspec/changes/add-frontend-operations-console/milestone-*` 以及 `docs/RELEASE.md` 发布指南。如需接入真实后端，请按 Milestone 规划逐步关闭 Mock 并对齐 Server API 字段。

## RBAC 说明
- `operator`：可访问任务、风险、资产视图并执行任务操作。
- `auditor`：可访问风险/审计视图，可导出审计日志。
- `admin`：拥有所有入口（含系统配置、命令队列），可修改全局参数与模板。

Mock 登录默认扮演 `ops.lead`（admin），可在 `AuthProvider` 的 Auto Login 账号修改角色以验证权限差异。

## 可访问性与键盘操作
- 页面顶部提供 “跳至主要内容” 的 Skip Link，Tab 聚焦后可直接进入主视图（`#main-content`）。
- 命令面板 (`⌘K / Ctrl+K`) 具有 `dialog` 与 `listbox` ARIA 语义，可通过上下文搜索快速跳转；Esc 关闭。
- 列表/表格/抽屉等关键组件增加 `aria-label`、`aria-live` 与按钮描述，屏幕阅读器可读性增强。
- 操作按钮均支持键盘触发；任务/资产表格在加载时会暴露 `aria-busy=true`，提示当前状态。
- 本系统定位桌面端，暂不支持平板/移动断点；相关决策记录在 `openspec/changes/refine-frontend-ui-ux`。

## 发布与部署建议
1. `pnpm build` 生成 `dist/`，结合 Server 静态托管（Nginx、容器等）。
2. 若需切换真实接口，在 `.env.production` 设置 `VITE_API_BASE_URL`、`VITE_WS_BASE_URL` 并关闭 `VITE_USE_MSW`、`VITE_USE_MOCK_SSE`。
3. 建议在 CI 中执行 `pnpm lint && pnpm test && pnpm build`；完成后上传 `dist/` 静态资源。
4. RBAC、配置中心、审计日志依赖 Server 的 JWT/角色声明及 `/api/v1` 系列接口，发布前请确认字段对齐与鉴权策略。
