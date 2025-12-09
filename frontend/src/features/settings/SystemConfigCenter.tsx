import { useMemo, useState } from 'react';
import useSWR from 'swr';
import dayjs from 'dayjs';
import { message, Table, type TableColumnsType } from 'antd';
import { listTemplates, bulkDeployTemplates, bulkDeleteTemplates } from '@/services/api/templates';
import { listRbacPolicies } from '@/services/api/rbac';
import { AppBulkToolbar, Button, FormField, TextInput } from '@/components/ui';

const mockGlobalConfig = {
  risk_threshold: 70,
  asset_sampling_rate: 0.25,
  updated_at: '2025-02-18T21:12:00Z',
  updated_by: 'ops.lead',
};

export function SystemConfigCenter() {
  const { data: templates, mutate } = useSWR('task-templates', listTemplates);
  const { data: policies } = useSWR('rbac-policies', listRbacPolicies);
  const [riskThreshold, setRiskThreshold] = useState(mockGlobalConfig.risk_threshold);
  const [samplingRate, setSamplingRate] = useState(mockGlobalConfig.asset_sampling_rate);
  const [selectedTemplateIds, setSelectedTemplateIds] = useState<string[]>([]);
  const [messageApi, contextHolder] = message.useMessage();

  const templateData = useMemo(
    () => (templates ?? []).map((tpl) => ({ ...tpl, key: tpl.id })),
    [templates]
  );

  const policyData = useMemo(
    () =>
      (policies ?? []).map((policy) => ({
        ...policy,
        key: policy.role,
        permissionsText: policy.permissions.join(', '),
      })),
    [policies]
  );

  const templateColumns: TableColumnsType<(typeof templateData)[number]> = [
    { title: '模板名称', dataIndex: 'name' },
    { title: '任务类型', dataIndex: 'task_type' },
    { title: '优先级', dataIndex: 'priority', width: 120, render: (value) => value ?? '-' },
    {
      title: '调度',
      dataIndex: 'schedule',
      render: (schedule: (typeof templateData)[number]['schedule']) =>
        schedule?.enabled ? `每 ${schedule.interval_minutes} 分钟` : '手动',
    },
    {
      title: '操作',
      dataIndex: 'actions',
      width: 180,
      render: (_: unknown, record) => (
        <>
          <Button type="button" variant="ghost" size="sm">
            编辑
          </Button>
          <Button type="button" variant="secondary" size="sm" onClick={() => mutate()}>
            部署
          </Button>
        </>
      ),
    },
  ];

  const policyColumns: TableColumnsType<(typeof policyData)[number]> = [
    { title: '角色', dataIndex: 'role', width: 200 },
    { title: '权限列表', dataIndex: 'permissionsText' },
  ];

  const handleSave = () => {
    messageApi.loading('保存配置中…', 0);
    setTimeout(() => {
      messageApi.destroy();
      messageApi.success(`已保存：风险阈值 ${riskThreshold}，资产采样 ${samplingRate}`);
    }, 600);
  };

  const handleBulkDeploy = async () => {
    if (!selectedTemplateIds.length) {
      messageApi.info('请先选择模板');
      return;
    }
    await bulkDeployTemplates(selectedTemplateIds);
    messageApi.success(`已部署 ${selectedTemplateIds.length} 个模板`);
    setSelectedTemplateIds([]);
    mutate();
  };

  const handleBulkDelete = async () => {
    if (!selectedTemplateIds.length) {
      messageApi.info('请先选择模板');
      return;
    }
    await bulkDeleteTemplates(selectedTemplateIds);
    messageApi.warning(`已删除 ${selectedTemplateIds.length} 个模板`);
    setSelectedTemplateIds([]);
    mutate();
  };

  return (
    <div className="system-config">
      {contextHolder}
      <section className="section-heading">
        <div>
          <h1>系统配置中心</h1>
          <p className="muted">管理核心任务与全局参数，支持草稿/发布对比</p>
        </div>
        <div className="actions">
          <Button type="button" variant="primary" onClick={handleSave}>
            保存配置
          </Button>
          <Button type="button" variant="ghost">
            发布到生产
          </Button>
        </div>
      </section>

      <section className="card">
        <header className="card-header">
          <h2>全局参数</h2>
          <small>最近更新：{dayjs(mockGlobalConfig.updated_at).format('MM-DD HH:mm')} / {mockGlobalConfig.updated_by}</small>
        </header>
        <div className="drawer-form">
          <FormField label="风险阈值" required hint="0-100，超过阈值进入高危处置" htmlFor="risk-threshold">
            <TextInput
              id="risk-threshold"
              type="number"
              min={0}
              max={100}
              value={riskThreshold}
              onChange={(e) => setRiskThreshold(Number(e.target.value))}
            />
          </FormField>
          <FormField label="资产采样率" required hint="建议 0.2~0.5 之间" htmlFor="sampling-rate">
            <TextInput
              id="sampling-rate"
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={samplingRate}
              onChange={(e) => setSamplingRate(Number(e.target.value))}
            />
          </FormField>
        </div>
      </section>

      <section className="card" data-testid="template-table-section">
        <header className="card-header">
          <h2>任务模板</h2>
          <small>草稿/发布对比</small>
        </header>
        <Table
          rowSelection={{
            selectedRowKeys: selectedTemplateIds,
            onChange: (keys) => setSelectedTemplateIds(keys as string[]),
          }}
          columns={templateColumns}
          dataSource={templateData}
          pagination={false}
          locale={{ emptyText: '暂无模板' }}
        />
        {selectedTemplateIds.length > 0 && (
          <AppBulkToolbar
            summary={
              <>
                <strong>已选 {selectedTemplateIds.length} 个模板</strong>
                <span className="muted">可以批量部署或删除</span>
              </>
            }
            actions={
              <>
                <Button size="small" onClick={handleBulkDeploy}>
                  批量部署
                </Button>
                <Button size="small" danger onClick={handleBulkDelete}>
                  批量删除
                </Button>
              </>
            }
          />
        )}
      </section>

      <section className="card" data-testid="policy-table-section">
        <header className="card-header">
          <h2>权限策略</h2>
          <small>查看角色与权限矩阵</small>
        </header>
        <Table columns={policyColumns} dataSource={policyData} pagination={false} locale={{ emptyText: '暂无策略' }} />
      </section>
    </div>
  );
}
