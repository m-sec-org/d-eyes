import { useState } from 'react';
import useSWR from 'swr';
import dayjs from 'dayjs';
import { listTemplates } from '@/services/api/templates';
import { listRbacPolicies } from '@/services/api/rbac';
import { Button, FormField, TextInput } from '@/components/ui';

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

  const handleSave = () => {
    // TODO: 接入真实配置 API
    alert(`已保存：风险阈值 ${riskThreshold}，资产采样 ${samplingRate}`);
  };

  return (
    <div className="system-config">
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

      <section className="card">
        <header className="card-header">
          <h2>任务模板</h2>
          <small>草稿/发布对比</small>
        </header>
        <table className="config-table">
          <thead>
            <tr>
              <th>模板名称</th>
              <th>任务类型</th>
              <th>优先级</th>
              <th>调度</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {templates?.map((tmpl) => (
              <tr key={tmpl.id}>
                <td>{tmpl.name}</td>
                <td>{tmpl.task_type}</td>
                <td>{tmpl.priority ?? '-'}</td>
                <td>{tmpl.schedule?.enabled ? `每 ${tmpl.schedule.interval_minutes} 分钟` : '手动'}</td>
                <td>
                  <Button type="button" variant="ghost" size="sm">
                    编辑
                  </Button>
                  <Button type="button" variant="secondary" size="sm" onClick={() => mutate()}>
                    部署
                  </Button>
                </td>
              </tr>
            ))}
            {templates?.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  暂无模板
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="card">
        <header className="card-header">
          <h2>权限策略</h2>
          <small>查看角色与权限矩阵</small>
        </header>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>角色</th>
                <th>权限列表</th>
              </tr>
            </thead>
            <tbody>
              {policies?.map((policy) => (
                <tr key={policy.role}>
                  <td>{policy.role}</td>
                  <td>{policy.permissions.join(', ')}</td>
                </tr>
              ))}
              {!policies?.length && (
                <tr>
                  <td colSpan={2} className="empty">
                    暂无策略
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
