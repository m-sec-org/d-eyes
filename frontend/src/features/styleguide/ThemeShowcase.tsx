import {
  AppBulkToolbar,
  AppStickyToolbar,
  AppSummaryCard,
  Button,
  Checkbox,
  FormField,
  Select,
  Textarea,
  TextInput,
} from '@/components/ui';
import type { ButtonVariant } from '@/components/ui';

const BUTTON_VARIANTS: ButtonVariant[] = ['primary', 'secondary', 'ghost', 'danger', 'ghost-danger'];

const TOKEN_REFERENCES = [
  { name: '--color-accent', usage: '主操作按钮、链接高亮' },
  { name: '--color-border', usage: '默认控件边框/卡片描边' },
  { name: '--color-danger', usage: '危险操作、错误提示' },
  { name: '--color-control-bg', usage: '输入框/下拉背景' },
  { name: '--color-focus-ring', usage: '键盘焦点可视化' },
  { name: '--color-text-secondary', usage: '辅助文案/表单 hint' },
];

interface TrendMetricPreview {
  label: string;
  value: string | number;
  delta: number;
  trend: 'up' | 'down' | 'flat';
  tone?: 'danger' | 'warning' | 'success' | 'info';
}

const RISK_TRENDS_DEMO: TrendMetricPreview[] = [
  { label: '总风险事件', value: '1,280', delta: 18, trend: 'up' },
  { label: '失败 / 高危', value: 34, tone: 'danger', delta: -12, trend: 'down' },
  { label: '处理中', value: 9, tone: 'warning', delta: 6, trend: 'up' },
];

const QUEUE_TYPE_DEMO = [
  { label: 'Respond', percent: 76, count: 18 },
  { label: 'Baseline', percent: 52, count: 11 },
  { label: 'BAS', percent: 34, count: 7 },
];

export function ThemeShowcase() {
  return (
    <div className="stack ui-showcase">
      <section className="card">
        <header className="card-header">
          <div>
            <h2>按钮与状态</h2>
            <p className="muted">所有按钮均由 `ui-button` 驱动，可组合尺寸/禁用/块级模式。</p>
          </div>
        </header>
        <div className="ui-showcase-grid">
          {BUTTON_VARIANTS.map((variant) => (
            <Button key={variant} variant={variant}>
              {variant}
            </Button>
          ))}
          <Button variant="primary" disabled>
            主操作（禁用）
          </Button>
          <Button variant="ghost" size="sm">
            Ghost / Small
          </Button>
          <Button variant="secondary" block>
            Block Button
          </Button>
        </div>
      </section>

      <section className="card">
        <header className="card-header">
          <div>
            <h2>表单控件</h2>
            <p className="muted">`FormField` 提供 label/hint/error，`ui-control` 保证焦点与错误态一致。</p>
          </div>
        </header>
        <div className="field-grid">
          <FormField label="主机名" hint="用于任务上下文展示">
            <TextInput placeholder="ops-core-01" />
          </FormField>
          <FormField label="端口范围" error="端口范围必须在 1-65535">
            <TextInput type="text" defaultValue="0-70000" invalid />
          </FormField>
          <FormField label="任务类型" required>
            <Select defaultValue="respond">
              <option value="respond">Respond</option>
              <option value="inventory">Inventory</option>
              <option value="baseline">Baseline</option>
            </Select>
          </FormField>
          <FormField label="执行策略" hint="按住 Ctrl/Command 多选">
            <Select multiple defaultValue={['detect']}>
              <option value="detect">仅检测</option>
              <option value="contain">阻断隔离</option>
              <option value="eradicate">整改</option>
            </Select>
          </FormField>
          <FormField label="备注">
            <Textarea rows={3} placeholder="自定义说明，支持多行输入。" />
          </FormField>
          <FormField>
            <Checkbox label="启用 Sandbox" defaultChecked />
          </FormField>
        </div>
      </section>

      <section className="card">
        <header className="card-header">
          <div>
            <h2>主题 Token</h2>
            <p className="muted">所有颜色/边框/阴影均来自 `tokens.css`，可通过 `data-theme` 实现暗色模式。</p>
          </div>
        </header>
        <div className="table-wrapper">
          <table className="token-table">
            <thead>
              <tr>
                <th>变量</th>
                <th>示例</th>
                <th>用途</th>
              </tr>
            </thead>
            <tbody>
              {TOKEN_REFERENCES.map((token) => (
                <tr key={token.name}>
                  <td>
                    <code>{token.name}</code>
                  </td>
                  <td>
                    <span className="token-swatch" style={{ background: `var(${token.name})` }} />
                  </td>
                  <td>{token.usage}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <header className="card-header">
          <div>
            <h2>实时工作台模式</h2>
            <p className="muted">虚拟时间线、Tab 面板与粘性工具栏组件示例，可直接复用到 Events / Queue / Respond 等实时页面。</p>
          </div>
        </header>
        <AppStickyToolbar
          headline={
            <>
              <h3>运行洞察</h3>
              <p className="muted">SSE 连接成功 · 队列深度 12 · 运行 6</p>
            </>
          }
          actions={
            <Button size="sm" variant="ghost">
              刷新
            </Button>
          }
        />
        <div className="ui-showcase-grid">
          <AppSummaryCard label="事件总数" value={1280} />
          <AppSummaryCard label="告警 (High)" value={32} tone="danger" />
          <AppSummaryCard label="告警 (Medium)" value={64} tone="warning" />
          <AppSummaryCard label="成功 Respond" value={18} tone="success" />
        </div>
        <AppBulkToolbar
          summary={
            <>
              <strong>已选 5 项 Respond 任务</strong>
              <span className="muted">批量执行操作</span>
            </>
          }
          actions={
            <>
              <Button size="sm">批量重试</Button>
              <Button size="sm" variant="ghost">
                清除选择
              </Button>
            </>
          }
        />
      </section>

      <section className="card">
        <header className="card-header">
          <div>
            <h2>列表筛选与批量操作</h2>
            <p className="muted">资产/列表页可复用的搜索 + 批量标记布局，配合 `AppBulkToolbar` 展示“已选 X 项”。</p>
          </div>
        </header>
        <div className="asset-actions-demo">
          <FormField label="搜索资产">
            <TextInput placeholder="搜索主机 / 标签 / IP" />
          </FormField>
          <FormField label="批量标签">
            <TextInput placeholder="如 critical/database" />
          </FormField>
          <div className="demo-inline-actions">
            <Button type="primary" size="sm">
              应用标签
            </Button>
            <span className="muted">已选 8 项</span>
          </div>
        </div>
        <AppBulkToolbar
          summary={
            <>
              <strong>已选 8 台资产</strong>
              <span className="muted">批量标记 / 导出 / 隔离</span>
            </>
          }
          actions={
            <>
              <Button size="sm">标记所选</Button>
              <Button size="sm">导出所选</Button>
              <Button size="sm" danger>
                隔离所选
              </Button>
            </>
          }
        />
      </section>

      <section className="card">
        <header className="card-header">
          <div>
            <h2>风险 &amp; 队列组件规范</h2>
            <p className="muted">
              风险仪表盘与 Queue Monitor 共享的趋势统计、横向条图与 SSE 摘要模式，便于 Respond / Ops View 复用。
            </p>
          </div>
        </header>
        <div className="risk-queue-grid">
          <div className="risk-queue-panel">
            <h3>趋势指标卡</h3>
            <p className="muted">`AppSummaryCard` + TrendChip 展示“较前 24 小时 ±X%”，与 `/reports/summary` 返回值保持一致。</p>
            <div className="risk-trend-grid">
              {RISK_TRENDS_DEMO.map((metric) => (
                <AppSummaryCard
                  key={metric.label}
                  label={metric.label}
                  value={metric.value}
                  tone={metric.tone}
                  hint={<TrendChip period="较前 24 小时" delta={metric.delta} trend={metric.trend} />}
                />
              ))}
            </div>
          </div>
          <div className="risk-queue-panel">
            <h3>Queue 类型条图</h3>
            <p className="muted">类型列表使用横向条图 + “显示 X/Y 种任务”摘要，搭配 SSE badge 表示连接状态。</p>
            <div className="queue-bar-list" aria-label="queue type distribution preview">
              {QUEUE_TYPE_DEMO.map((row) => (
                <div key={row.label} className="queue-bar-row">
                  <span className="queue-bar-label">{row.label}</span>
                  <div className="queue-bar-meter">
                    <span style={{ width: `${row.percent}%` }} />
                  </div>
                  <span className="muted">{row.count} 次</span>
                </div>
              ))}
              <span className="muted queue-count-hint">显示 {QUEUE_TYPE_DEMO.length} / {QUEUE_TYPE_DEMO.length} 种任务</span>
            </div>
            <AppStickyToolbar
              headline={
                <>
                  <h4>运行洞察</h4>
                  <p className="muted">SSE: Connected · 队列深度 12 · 运行 6</p>
                </>
              }
              actions={
                <Button size="sm" variant="ghost">
                  刷新
                </Button>
              }
            />
          </div>
        </div>
      </section>
    </div>
  );
}

interface TrendChipProps {
  period: string;
  delta: number;
  trend: 'up' | 'down' | 'flat';
}

function TrendChip({ period, delta, trend }: TrendChipProps) {
  const formattedDelta = `${delta > 0 ? '+' : ''}${delta}%`;
  const isFlat = trend === 'flat' || delta === 0;
  return (
    <span className={`trend-chip ${trend}`}>
      {period} {isFlat ? '—' : ''} {formattedDelta}
    </span>
  );
}
