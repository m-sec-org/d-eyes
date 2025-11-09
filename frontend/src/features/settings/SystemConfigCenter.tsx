import { useState } from 'react';
import useSWR from 'swr';
import dayjs from 'dayjs';
import { listTemplates } from '@/services/api/templates';

const mockGlobalConfig = {
  risk_threshold: 70,
  asset_sampling_rate: 0.25,
  updated_at: '2025-02-18T21:12:00Z',
  updated_by: 'ops.lead',
};

export function SystemConfigCenter() {
  const { data: templates, mutate } = useSWR('task-templates', listTemplates);
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
          <p className="muted">管理任务模板与全局参数，支持草稿/发布对比</p>
        </div>
        <div className="actions">
          <button type="button" className="primary" onClick={handleSave}>
            保存配置
          </button>
          <button type="button" className="ghost">
            发布到生产
          </button>
        </div>
      </section>

      <section className="card">
        <header className="card-header">
          <h2>全局参数</h2>
          <small>最近更新：{dayjs(mockGlobalConfig.updated_at).format('MM-DD HH:mm')} / {mockGlobalConfig.updated_by}</small>
        </header>
        <div className="drawer-form">
          <label className="drawer-label">风险阈值</label>
          <input type="number" min={0} max={100} value={riskThreshold} onChange={(e) => setRiskThreshold(Number(e.target.value))} />
          <label className="drawer-label">资产采样率</label>
          <input type="number" min={0} max={1} step={0.05} value={samplingRate} onChange={(e) => setSamplingRate(Number(e.target.value))} />
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
                  <button type="button" className="ghost small">
                    编辑
                  </button>
                  <button type="button" className="ghost small" onClick={() => mutate()}>
                    部署
                  </button>
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
    </div>
  );
}
