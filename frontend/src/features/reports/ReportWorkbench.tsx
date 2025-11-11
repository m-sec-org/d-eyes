import { useState } from 'react';
import useSWR from 'swr';

import {
  createReportTemplate,
  deleteReportTemplate,
  generateReport,
  listReportTemplates,
  updateReportTemplate,
} from '@/services/api/reportTemplates';
import type { ReportTemplate } from '@/services/api/reportTemplates';
import { Button, FormField, Select, Textarea, TextInput } from '@/components/ui';

const FORMATS = [
  { label: 'JSON', value: 'json' },
  { label: 'HTML', value: 'html' },
];

export function ReportWorkbench() {
  const { data: templates, mutate } = useSWR('report-templates', listReportTemplates);
  const [active, setActive] = useState<ReportTemplate | null>(null);
  const [form, setForm] = useState({ name: '', format: 'html', body: '<h1>{{ .task.ID }}</h1>' });
  const [taskId, setTaskId] = useState('');
  const [format, setFormat] = useState('html');
  const [loading, setLoading] = useState(false);

  const handleEdit = (tpl: ReportTemplate) => {
    setActive(tpl);
    setForm({ name: tpl.name, format: tpl.format, body: tpl.body });
  };

  const handleDelete = async (tpl: ReportTemplate) => {
    if (!window.confirm(`删除模板 ${tpl.name}?`)) return;
    await deleteReportTemplate(tpl.id);
    setActive(null);
    await mutate();
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!form.name.trim() || !form.body.trim()) return;
    if (active) {
      await updateReportTemplate(active.id, { ...active, ...form });
    } else {
      await createReportTemplate({ name: form.name, format: form.format, body: form.body });
    }
    setActive(null);
    setForm({ name: '', format: 'html', body: '<h1>{{ .task.ID }}</h1>' });
    await mutate();
  };

  const handleGenerate = async () => {
    if (!taskId.trim() || !active) return;
    setLoading(true);
    try {
      const blob = await generateReport({ taskId: taskId.trim(), templateId: active.id, format });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `report-${taskId}.${format === 'json' ? 'json' : 'html'}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="stack">
      <section className="card">
        <header className="section-heading">
          <div>
            <h2>报告模板</h2>
            <p className="muted">维护多格式模板，自动化导出任务报告。</p>
          </div>
        </header>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>名称</th>
                <th>格式</th>
                <th>更新时间</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(templates ?? []).map((tpl) => (
                <tr key={tpl.id}>
                  <td>{tpl.name}</td>
                  <td>{tpl.format.toUpperCase()}</td>
                  <td>{tpl.updated_at ? new Date(tpl.updated_at).toLocaleString() : '—'}</td>
                  <td>
                    <div className="step-actions">
                      <Button type="button" variant="ghost" size="sm" onClick={() => handleEdit(tpl)}>
                        编辑
                      </Button>
                      <Button type="button" variant="ghost-danger" size="sm" onClick={() => handleDelete(tpl)}>
                        删除
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
              {!templates?.length && (
                <tr>
                  <td colSpan={4} className="muted">
                    暂无模板
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <h3>{active ? `编辑模板 ${active.name}` : '新建模板'}</h3>
        <form className="form-grid" onSubmit={handleSubmit}>
          <FormField label="名称" required>
            <TextInput value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </FormField>
          <FormField label="格式">
            <Select value={form.format} onChange={(e) => setForm({ ...form, format: e.target.value })}>
              {FORMATS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          </FormField>
          <FormField label="Body (Go Template)">
            <Textarea
              rows={6}
              value={form.body}
              onChange={(e) => setForm({ ...form, body: e.target.value })}
              required
            />
          </FormField>
          <div className="actions">
            <Button type="submit" variant="primary">
              {active ? '更新' : '保存'}
            </Button>
            {active && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setActive(null);
                  setForm({ name: '', format: 'html', body: '<h1>{{ .task.ID }}</h1>' });
                }}
              >
                取消
              </Button>
            )}
          </div>
        </form>
      </section>

      <section className="card">
        <h3>生成报告</h3>
        <div className="actions">
          <TextInput placeholder="任务 ID" value={taskId} onChange={(e) => setTaskId(e.target.value)} />
          <Select value={format} onChange={(e) => setFormat(e.target.value)}>
            {FORMATS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
          <Button type="button" variant="primary" disabled={!active || !taskId} onClick={handleGenerate}>
            {loading ? '生成中…' : '生成'}
          </Button>
        </div>
        {!active && <p className="muted">请选择一个模板后生成。</p>}
      </section>
    </div>
  );
}
