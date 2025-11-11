import { Button, Checkbox, FormField, Select, Textarea, TextInput } from '@/components/ui';
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
    </div>
  );
}
