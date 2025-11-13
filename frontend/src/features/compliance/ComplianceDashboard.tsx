import './ComplianceDashboard.css';
import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import { Button, Card, Empty, Form, Input, List, message, Select, Space, Table, Tag, Timeline, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PageHeader } from '@/components/layout/PageHeader';
import { listComplianceFrameworks, listComplianceControls, listComplianceGaps, addRemediationNote } from '@/services/api/compliance';
import type { ComplianceFramework, ComplianceControl, ComplianceFinding } from '@/services/types';

const { Paragraph, Title } = Typography;

const statusOptions = [
  { label: '全部状态', value: '' },
  { label: 'Open', value: 'open' },
  { label: 'In Progress', value: 'in_progress' },
  { label: 'Resolved', value: 'resolved' },
];

const severityColor: Record<string, string> = {
  critical: 'magenta',
  high: 'volcano',
  medium: 'gold',
  low: 'geekblue',
};

const gapColor: Record<string, string> = {
  open: 'red',
  in_progress: 'blue',
  resolved: 'green',
};

export function ComplianceDashboard() {
  const [messageApi, contextHolder] = message.useMessage();
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedGap, setSelectedGap] = useState<ComplianceFinding | null>(null);
  const [form] = Form.useForm();

  const { data: frameworks } = useSWR<ComplianceFramework[]>('compliance-frameworks', listComplianceFrameworks);

  useEffect(() => {
    if (!selectedFramework && frameworks && frameworks.length > 0) {
      setSelectedFramework(frameworks[0].id);
    }
  }, [frameworks, selectedFramework]);

  const frameworkOptions = useMemo(() => frameworks ?? [], [frameworks]);

  const { data: controls } = useSWR<ComplianceControl[]>
    (selectedFramework ? ['compliance-controls', selectedFramework] : null, () => listComplianceControls(selectedFramework ?? ''));

  const { data: gaps, mutate: refreshGaps } = useSWR<ComplianceFinding[]>
    (selectedFramework ? ['compliance-gaps', selectedFramework, statusFilter] : null, () => listComplianceGaps({ framework_id: selectedFramework ?? undefined, status: statusFilter || undefined }));

  const controlColumns: ColumnsType<ComplianceControl> = [
    { title: '编号', dataIndex: 'code', key: 'code', width: 120 },
    { title: '标题', dataIndex: 'title', key: 'title' },
    {
      title: '级别',
      dataIndex: 'severity',
      key: 'severity',
      width: 120,
      render: (value: string) => <Tag color={severityColor[value?.toLowerCase()] ?? 'default'}>{value}</Tag>,
    },
  ];

  const gapTimeline = gaps ?? [];

  const handleRemediation = async () => {
    if (!selectedGap) {
      messageApi.warning('请选择一个待整改的项');
      return;
    }
    try {
      const values = await form.validateFields();
      await addRemediationNote(selectedGap.id, values.note, values.status || undefined);
      form.resetFields();
      setSelectedGap(null);
      await refreshGaps();
      messageApi.success('已记录整改备注');
    } catch (error) {
      messageApi.error((error as Error).message);
    }
  };

  return (
    <div className="compliance-dashboard">
      {contextHolder}
      <PageHeader
        title="合规仪表盘"
        description="查看框架、控制项与整改进度"
        breadcrumbs={[{ label: '治理', path: '/settings' }, { label: '合规管理' }]}
      />

      <div className="compliance-grid">
        <Card title="框架" className="compliance-card" styles={{ body: { padding: 0 } }}>
          <List
            dataSource={frameworkOptions}
            renderItem={(item) => (
              <List.Item
                className={item.id === selectedFramework ? 'selected' : ''}
                onClick={() => {
                  setSelectedFramework(item.id);
                  setSelectedGap(null);
                }}
              >
                <div>
                  <strong>{item.title}</strong>
                  <Paragraph type="secondary">{item.version || item.key}</Paragraph>
                </div>
              </List.Item>
            )}
          />
          {!frameworkOptions.length && <Empty description="暂无框架数据" style={{ margin: '2rem 0' }} />}
        </Card>

        <Card title="控制项" className="compliance-card">
          {controls && controls.length > 0 ? (
            <Table columns={controlColumns} dataSource={controls} rowKey="id" pagination={false} size="small" />
          ) : (
            <Empty description="请选择框架查看控制项" />
          )}
        </Card>
      </div>

      <div className="compliance-grid">
        <Card
          title="差距与整改"
          className="compliance-card"
          extra={
            <Space>
              <Select value={statusFilter} options={statusOptions} onChange={setStatusFilter} style={{ width: 160 }} />
              <Button size="small" onClick={() => refreshGaps()}>
                刷新
              </Button>
            </Space>
          }
        >
          {gapTimeline.length > 0 ? (
            <Timeline
              mode="left"
              items={gapTimeline.map((gap) => ({
                color: gapColor[gap.status?.toLowerCase()] ?? 'blue',
                label: new Date(gap.updated_at).toLocaleString(),
                children: (
                  <div className={`gap-item ${selectedGap?.id === gap.id ? 'active' : ''}`} onClick={() => setSelectedGap(gap)}>
                    <div className="gap-header">
                      <Tag color={gapColor[gap.status?.toLowerCase()] ?? 'blue'}>{gap.status?.toUpperCase()}</Tag>
                      <span>{gap.asset_ref || '未关联资产'}</span>
                    </div>
                    <Paragraph type="secondary">
                      控制项：{gap.control_id.slice(0, 8)}…
                    </Paragraph>
                    {gap.remediation_logs && gap.remediation_logs.length > 0 && (
                      <ul className="gap-notes">
                        {gap.remediation_logs.slice(-2).map((note) => (
                          <li key={`${note.author}-${note.timestamp}`}>
                            <strong>{note.author}</strong>：{note.note}
                          </li>
                        ))}
                        {gap.remediation_logs.length > 2 && <li>…</li>}
                      </ul>
                    )}
                  </div>
                ),
              }))}
            />
          ) : (
            <Empty description="暂无差距" />
          )}
        </Card>

        <Card title="记录整改" className="compliance-card">
          {selectedGap ? (
            <Form layout="vertical" form={form} initialValues={{ status: selectedGap.status }}>
              <Form.Item label="关联资产">
                <Input value={selectedGap.asset_ref || '未关联'} disabled />
              </Form.Item>
              <Form.Item name="status" label="状态">
                <Select options={statusOptions} placeholder="选择状态" />
              </Form.Item>
              <Form.Item name="note" label="整改备注" rules={[{ required: true, message: '请输入备注' }]}> <Input.TextArea rows={4} /> </Form.Item>
              <Button type="primary" onClick={handleRemediation} block>
                提交
              </Button>
            </Form>
          ) : (
            <Empty description="请选择时间线中的差距" />
          )}
        </Card>
      </div>
    </div>
  );
}
