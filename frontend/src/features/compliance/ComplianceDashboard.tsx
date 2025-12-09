import './ComplianceDashboard.css';
import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import { Affix, Button, Card, Empty, Form, Input, List, message, Select, Space, Table, Tag, Timeline, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PageHeader } from '@/components/layout/PageHeader';
import { listComplianceFrameworks, listComplianceControls, listComplianceGaps, addRemediationNote } from '@/services/api/compliance';
import type { ComplianceFramework, ComplianceControl, ComplianceFinding } from '@/services/types';

const { Paragraph } = Typography;

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
  const [isGapStacked, setIsGapStacked] = useState(() => {
    if (typeof window === 'undefined') return false;
    return window.innerWidth < 1024;
  });
  const [form] = Form.useForm();

  const { data: frameworks } = useSWR<ComplianceFramework[]>('compliance-frameworks', listComplianceFrameworks);

  useEffect(() => {
    if (!selectedFramework && frameworks && frameworks.length > 0) {
      setSelectedFramework(frameworks[0].id);
    }
  }, [frameworks, selectedFramework]);

  const frameworkOptions = useMemo(() => frameworks ?? [], [frameworks]);
  const activeFramework = useMemo(
    () => frameworkOptions.find((item) => item.id === selectedFramework) ?? null,
    [frameworkOptions, selectedFramework]
  );

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
  const gapStats = useMemo(() => {
    return gapTimeline.reduce(
      (acc, gap) => {
        const status = gap.status?.toLowerCase() ?? 'open';
        acc[status] = (acc[status] ?? 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );
  }, [gapTimeline]);
  const recentNotes = useMemo(() => {
    if (!selectedGap?.remediation_logs) return [];
    return selectedGap.remediation_logs.slice(-2).reverse();
  }, [selectedGap]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const handleResize = () => {
      setIsGapStacked(window.innerWidth < 1024);
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

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

      <div className="compliance-grid compliance-grid--primary">
        <Card title="框架" className="compliance-card" styles={{ body: { padding: 0 } }}>
          {frameworkOptions.length > 0 ? (
            <List
              className="framework-list"
              dataSource={frameworkOptions}
              renderItem={(item) => {
                const isActive = item.id === selectedFramework;
                return (
                  <List.Item className={`framework-item ${isActive ? 'is-active' : ''}`} key={item.id}>
                    <button
                      type="button"
                      className="framework-item__button"
                      onClick={() => {
                        setSelectedFramework(item.id);
                        setSelectedGap(null);
                      }}
                      aria-pressed={isActive}
                    >
                      <div className="framework-item__header">
                        <span className="framework-title">{item.title}</span>
                        {item.version && <Tag bordered={false}>{item.version}</Tag>}
                      </div>
                      <Paragraph type="secondary" ellipsis={{ rows: 2 }}>
                        {item.description || item.key}
                      </Paragraph>
                    </button>
                  </List.Item>
                );
              }}
            />
          ) : (
            <Empty description="暂无框架数据" style={{ margin: '2rem 0' }} />
          )}
        </Card>

        <Card
          title="控制项"
          className="compliance-card compliance-card--controls"
          extra={
            activeFramework && (
              <Space size="large" className="framework-meta">
                <div>
                  <div className="meta-label">框架 Key</div>
                  <span>{activeFramework.key}</span>
                </div>
                {activeFramework.updated_at && (
                  <div>
                    <div className="meta-label">最近更新</div>
                    <span>{new Date(activeFramework.updated_at).toLocaleDateString()}</span>
                  </div>
                )}
                <div>
                  <div className="meta-label">差距统计</div>
                  <Space size={4}>
                    <Tag color="red">Open {gapStats.open ?? 0}</Tag>
                    <Tag color="blue">处理中 {gapStats.in_progress ?? 0}</Tag>
                    <Tag color="green">Resolved {gapStats.resolved ?? 0}</Tag>
                  </Space>
                </div>
              </Space>
            )
          }
        >
          {activeFramework ? (
            <>
              <Paragraph className="framework-description" type="secondary">
                {activeFramework.description || '无详细描述，建议补充框架说明以便审核。'}
              </Paragraph>
              {controls && controls.length > 0 ? (
                <Table
                  columns={controlColumns}
                  dataSource={controls}
                  rowKey="id"
                  pagination={false}
                  size="small"
                  scroll={{ y: 280 }}
                />
              ) : (
                <Empty description="暂无控制项" />
              )}
            </>
          ) : (
            <Empty description="请选择框架查看控制项" />
          )}
        </Card>
      </div>

      <div
        className={`compliance-gap-layout ${isGapStacked ? 'is-stacked' : ''}`}
        data-testid="gap-layout"
        data-layout-mode={isGapStacked ? 'stacked' : 'split'}
      >
        <Card
          title="差距时间线"
          className="compliance-card gap-card"
          extra={
            <Space>
              <Select value={statusFilter} options={statusOptions} onChange={setStatusFilter} style={{ width: 160 }} />
              <Button size="small" onClick={() => refreshGaps()}>
                刷新
              </Button>
            </Space>
          }
        >
          <div className="gap-timeline-scroll" data-testid="gap-timeline-scroll">
            {gapTimeline.length > 0 ? (
              <Timeline
                mode="left"
                items={gapTimeline.map((gap) => ({
                  color: gapColor[gap.status?.toLowerCase()] ?? 'blue',
                  label: new Date(gap.updated_at).toLocaleString(),
                  children: (
                    <div
                      className={`gap-item ${selectedGap?.id === gap.id ? 'active' : ''}`}
                      onClick={() => setSelectedGap(gap)}
                      role="button"
                      tabIndex={0}
                      aria-pressed={selectedGap?.id === gap.id}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          setSelectedGap(gap);
                        }
                      }}
                    >
                      <div className="gap-header">
                        <Tag color={gapColor[gap.status?.toLowerCase()] ?? 'blue'}>{gap.status?.toUpperCase()}</Tag>
                        <span>{gap.asset_ref || '未关联资产'}</span>
                      </div>
                      <Paragraph type="secondary" className="gap-meta">
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
          </div>
        </Card>

        <Affix offsetTop={96}>
          <Card title="记录整改" className="compliance-card gap-card gap-card--form">
            {selectedGap ? (
              <Form layout="vertical" form={form} initialValues={{ status: selectedGap.status }} className="remediation-form">
                <div className="gap-form-meta">
                  <div>
                    <div className="meta-label">当前状态</div>
                    <Tag color={gapColor[selectedGap.status?.toLowerCase()] ?? 'blue'}>{selectedGap.status?.toUpperCase()}</Tag>
                  </div>
                  <div>
                    <div className="meta-label">资产</div>
                    <span>{selectedGap.asset_ref || '未关联'}</span>
                  </div>
                </div>
                <Form.Item name="status" label="更新状态">
                  <Select options={statusOptions.filter((item) => item.value)} placeholder="选择状态" allowClear />
                </Form.Item>
                <Form.Item
                  name="note"
                  label="整改备注"
                  rules={[{ required: true, message: '请输入备注' }]}
                >
                  <Input.TextArea rows={4} placeholder="记录整改计划、责任人或期限" />
                </Form.Item>
                {recentNotes.length > 0 && (
                  <div className="gap-form-notes" data-testid="recent-remediation-notes">
                    <div className="meta-label">最近备注</div>
                    <ul>
                      {recentNotes.map((note) => (
                        <li key={`${note.author}-${note.timestamp}`}>
                          <strong>{note.author}</strong> · {new Date(note.timestamp).toLocaleString()}
                          <Paragraph type="secondary">{note.note}</Paragraph>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <Button type="primary" onClick={handleRemediation} block>
                  保存记录
                </Button>
              </Form>
            ) : (
              <Empty description="请选择时间线中的差距" />
            )}
          </Card>
        </Affix>
      </div>
    </div>
  );
}
