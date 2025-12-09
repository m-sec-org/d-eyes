import { useMemo, useState } from 'react';
import useSWR from 'swr';
import { message, Modal, Table, type TableColumnsType } from 'antd';

import {
  createReportTemplate,
  deleteReportTemplate,
  generateReport,
  listReportTemplates,
  updateReportTemplate,
} from '@/services/api/reportTemplates';
import type { ReportTemplate } from '@/services/api/reportTemplates';
import { AppBulkToolbar, AppCard, AppFormSection, Button, FormField, Select, Textarea, TextInput } from '@/components/ui';

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
  const [bulkSelection, setBulkSelection] = useState<string[]>([]);
  const [messageApi, contextHolder] = message.useMessage();
  const [downloads, setDownloads] = useState<{ name: string; time: string }[]>([]);
  const [downloadsExpanded, setDownloadsExpanded] = useState(false);

  const handleEdit = (tpl: ReportTemplate) => {
    setActive(tpl);
    setForm({ name: tpl.name, format: tpl.format, body: tpl.body });
  };

  const handleDelete = async (tpl: ReportTemplate) => {
    Modal.confirm({
      title: `删除模板 ${tpl.name}`,
      content: '删除后无法恢复，确认继续？',
      okText: '删除',
      cancelText: '取消',
      okButtonProps: { danger: true },
      onOk: async () => {
        await deleteReportTemplate(tpl.id);
        setActive(null);
        await mutate();
        messageApi.success('模板已删除');
      },
    });
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
    const hide = messageApi.loading('报告生成中…', 0);
    try {
      const blob = await generateReport({ taskId: taskId.trim(), templateId: active.id, format });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `report-${taskId}.${format === 'json' ? 'json' : 'html'}`;
      anchor.click();
      URL.revokeObjectURL(url);
      const entry = {
        name: `${active.name} / 任务 ${taskId}`,
        time: new Date().toLocaleTimeString(),
      };
      setDownloads((prev) => [entry, ...prev].slice(0, 5));
      messageApi.success(`报告已生成：${entry.name}`);
    } finally {
      hide();
      setLoading(false);
    }
  };

  const handleBulkDelete = async () => {
    if (!bulkSelection.length) {
      messageApi.info('请先选择模板');
      return;
    }
    Modal.confirm({
      title: `删除 ${bulkSelection.length} 个模板`,
      content: '批量操作将立即生效，确认删除？',
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        for (const id of bulkSelection) {
          await deleteReportTemplate(id);
        }
        setBulkSelection([]);
        await mutate();
        messageApi.success('模板已批量删除');
      },
    });
  };

  const handleBulkExport = () => {
    if (!bulkSelection.length) {
      messageApi.info('请选择模板后再导出');
      return;
    }
    messageApi.success(`已导出 ${bulkSelection.length} 个模板配置`);
  };

  const tableData = useMemo(
    () => (templates ?? []).map((tpl) => ({ ...tpl, key: tpl.id })),
    [templates]
  );

  const columns: TableColumnsType<ReportTemplate & { key: string }> = [
    {
      title: '名称',
      dataIndex: 'name',
    },
    {
      title: '格式',
      dataIndex: 'format',
      render: (value: string) => value.toUpperCase(),
      width: 120,
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      render: (value: string | undefined) => (value ? new Date(value).toLocaleString() : '—'),
      width: 200,
    },
    {
      title: '操作',
      dataIndex: 'actions',
      width: 180,
      render: (_: unknown, record) => (
        <div className="step-actions">
          <Button type="button" variant="ghost" size="sm" onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Button type="button" variant="ghost-danger" size="sm" onClick={() => handleDelete(record)}>
            删除
          </Button>
        </div>
      ),
    },
  ];

  const rowSelection = {
    selectedRowKeys: bulkSelection,
    onChange: (keys: React.Key[]) => setBulkSelection(keys as string[]),
    selections: [
      Table.SELECTION_ALL,
      Table.SELECTION_INVERT,
      {
        key: 'clear',
        text: '清除选择',
        onSelect: () => setBulkSelection([]),
      },
    ],
  };

  return (
    <div className="stack">
      {contextHolder}
      <AppCard title="报告模板" description="维护多格式模板，自动化导出任务报告。">
        <div data-testid="report-template-table">
          <Table
            rowSelection={rowSelection}
            columns={columns}
            dataSource={tableData}
            pagination={false}
            locale={{ emptyText: '暂无模板' }}
          />
        </div>
        {bulkSelection.length > 0 && (
          <AppBulkToolbar
            summary={
              <>
                <strong>已选 {bulkSelection.length} 个模板</strong>
                <span className="muted">支持批量删除/导出</span>
              </>
            }
            actions={
              <>
                <Button size="small" danger onClick={handleBulkDelete}>
                  批量删除
                </Button>
                <Button size="small" onClick={handleBulkExport}>
                  导出配置
                </Button>
                <Button size="small" onClick={() => setBulkSelection([])}>
                  清除选择
                </Button>
              </>
            }
          />
        )}
      </AppCard>

      <AppFormSection as="form" title={active ? `编辑模板 ${active.name}` : '新建模板'} onSubmit={handleSubmit}>
        <div className="form-grid">
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
        </div>
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
      </AppFormSection>

      <AppFormSection as="section" title="生成报告">
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
        {downloads.length > 0 && (
          <div className="download-history" data-testid="report-download-history">
            <div className="download-history__header">
              <strong>最近下载</strong>
              <div className="download-actions">
                {downloads.length > 3 && (
                  <Button type="button" size="small" variant="ghost" onClick={() => setDownloadsExpanded((prev) => !prev)}>
                    {downloadsExpanded ? '收起' : '展开全部'}
                  </Button>
                )}
                <Button type="button" size="small" variant="ghost" onClick={() => setDownloads([])}>
                  清空
                </Button>
              </div>
            </div>
            <ul>
              {(downloadsExpanded ? downloads : downloads.slice(0, 3)).map((item) => (
                <li key={`${item.name}-${item.time}`}>
                  {item.time} · {item.name}
                </li>
              ))}
            </ul>
          </div>
        )}
      </AppFormSection>
    </div>
  );
}
