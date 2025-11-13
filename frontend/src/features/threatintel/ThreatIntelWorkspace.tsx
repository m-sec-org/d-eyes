import './ThreatIntelWorkspace.css';
import { useMemo, useState } from 'react';
import useSWR from 'swr';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { Button, Checkbox, Input, Select, Space, Switch, Tag, message } from 'antd';
import type { CheckboxValueType } from 'antd/es/checkbox/Group';
import { PageHeader } from '@/components/layout/PageHeader';
import { lookupIndicator, fetchIndicator, fetchSample } from '@/services/api/threatIntel';
import { listAuditEvents } from '@/services/api/audit';
import type { ThreatIntelVerdict, ThreatIntelLookupResponse } from '@/services/types';
import { useThreatIntelStream } from '@/hooks/useThreatIntelStream';
import { useThreatIntelEventStore } from '@/store/threatIntelEvents';

dayjs.extend(relativeTime);

const INDICATOR_OPTIONS = [
  { label: '哈希', value: 'hash' },
  { label: 'IP', value: 'ip' },
  { label: '域名', value: 'domain' },
  { label: 'URL', value: 'url' },
];

const SOURCE_OPTIONS = [
  { label: 'OpenTIP', value: 'opentip' },
  { label: 'MetaDefender', value: 'metadefender' },
];

export function ThreatIntelWorkspace() {
  useThreatIntelStream();
  const [indicatorInput, setIndicatorInput] = useState('');
  const [indicatorKind, setIndicatorKind] = useState('hash');
  const [selectedSources, setSelectedSources] = useState<string[]>(SOURCE_OPTIONS.map((s) => s.value));
  const [forceServer, setForceServer] = useState(false);
  const [activeIndicator, setActiveIndicator] = useState<string | null>(null);
  const [lookupInfo, setLookupInfo] = useState<ThreatIntelLookupResponse | null>(null);
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(null);
  const [messageApi, contextHolder] = message.useMessage();

  const events = useThreatIntelEventStore((state) => state.events);
  const streamStatus = useThreatIntelEventStore((state) => state.status);

  const indicatorKey = activeIndicator ? ['threat-intel-indicator', activeIndicator] : null;
  const {
    data: indicatorData,
    isLoading: indicatorLoading,
    mutate: refreshIndicator,
  } = useSWR(indicatorKey, () => fetchIndicator(activeIndicator ?? ''), { keepPreviousData: true });

  const {
    data: auditData,
    isLoading: auditLoading,
  } = useSWR('threat-intel-audit', () => listAuditEvents({ action: 'threatintel', limit: 25 }), {
    refreshInterval: 60_000,
  });

  const {
    data: sampleDetail,
    isLoading: sampleLoading,
    mutate: refreshSample,
  } = useSWR(selectedSampleId ? ['threat-intel-sample', selectedSampleId] : null, () => fetchSample(selectedSampleId ?? ''));

  const handleLookup = async (evt: React.FormEvent) => {
    evt.preventDefault();
    const trimmed = indicatorInput.trim();
    if (!trimmed) {
      messageApi.warning('请输入要查询的 IOC');
      return;
    }
    try {
      const result = await lookupIndicator({
        indicator: trimmed,
        kind: indicatorKind,
        sources: selectedSources,
        force: forceServer,
      });
      setLookupInfo(result);
      setActiveIndicator(trimmed);
      messageApi.success(result.cached ? '命中缓存，已返回最新情报' : '已触发情报查询，稍后自动刷新');
      if (selectedSampleId) {
        refreshSample();
      }
    } catch (error: unknown) {
      const reason = extractApiError(error) ?? '情报查询失败';
      messageApi.error(reason);
    }
  };

  const verdictsBySource = useMemo(() => {
    const verdicts = indicatorData?.verdicts ?? lookupInfo?.verdicts ?? [];
    const map = new Map<string, ThreatIntelVerdict[]>();
    verdicts.forEach((verdict) => {
      const key = verdict.source ?? 'unknown';
      const list = map.get(key) ?? [];
      list.push(verdict);
      map.set(key, list);
    });
    return Array.from(map.entries());
  }, [indicatorData, lookupInfo]);

  const sampleSummaries = useMemo(() => {
    const map = new Map<string, SampleSummary>();
    events.forEach((event) => {
      if (!event.sample_id) return;
      const summary = map.get(event.sample_id) ?? {
        id: event.sample_id,
        indicator: event.indicator,
        status: event.status,
        lastEvent: event.event,
        updatedAt: event.timestamp,
        jobs: {} as Record<string, string>,
        classification: event.classification,
      };
      summary.indicator = event.indicator ?? summary.indicator;
      summary.status = event.status ?? summary.status;
      summary.classification = event.classification ?? summary.classification;
      summary.lastEvent = event.event;
      summary.updatedAt = event.timestamp;
      if (event.source && event.status) {
        summary.jobs[event.source] = event.status;
      }
      map.set(event.sample_id, summary);
    });
    return Array.from(map.values()).sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));
  }, [events]);

  const auditEvents = auditData?.items ?? [];
  const eventFeed = events.slice(0, 25);

  return (
    <div className="threat-intel-workspace">
      {contextHolder}
      <PageHeader
        title="威胁情报工作台"
        description="查询 IOC、跟踪样本扫描并洞察审计事件"
        breadcrumbs={[
          { label: '洞察', path: '/risks' },
          { label: '威胁情报' },
        ]}
        extra={
          <Space wrap>
            <span className="ti-connection-pill">SSE: {streamStatus}</span>
            {activeIndicator && (
              <Button onClick={() => refreshIndicator()} size="small">
                刷新结果
              </Button>
            )}
          </Space>
        }
      />

      <section className="ti-card">
        <header>
          <div>
            <h2>IOC 查询</h2>
            <p className="muted">支持哈希 / IP / 域名 / URL，自动落库并推送 SSE</p>
          </div>
        </header>
        <form className="ti-form" onSubmit={handleLookup}>
          <div className="ti-field-row">
            <Input
              placeholder="例如：d4c3b4... 或 8.8.8.8"
              value={indicatorInput}
              onChange={(e) => setIndicatorInput(e.target.value)}
              size="large"
            />
            <Select
              value={indicatorKind}
              options={INDICATOR_OPTIONS}
              onChange={(value) => setIndicatorKind(value)}
              style={{ minWidth: 160 }}
            />
            <Checkbox.Group
              options={SOURCE_OPTIONS}
              value={selectedSources}
              onChange={(values: CheckboxValueType[]) => setSelectedSources(values as string[])}
            />
            <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Switch checked={forceServer} onChange={(checked) => setForceServer(checked)} size="small" />
              强制 Server 扫描
            </label>
            <Button type="primary" htmlType="submit">
              查询
            </Button>
          </div>
        </form>
        {lookupInfo && (
          <div className="ti-lookup-summary">
            {lookupInfo.cached ? <Tag color="green">命中缓存</Tag> : <Tag color="blue">已提交 {lookupInfo.job_ids.length} 个任务</Tag>}
            {lookupInfo.job_ids.length > 0 && (
              <span>
                Job IDs: <code>{lookupInfo.job_ids.join(', ')}</code>
              </span>
            )}
            {lookupInfo.verdicts && lookupInfo.verdicts.length > 0 && <span>立即返回 {lookupInfo.verdicts.length} 条记录</span>}
          </div>
        )}
      </section>

      <section className="threat-intel-grid two-columns">
        <div className="ti-card">
          <header>
            <h3>IOC 情报</h3>
            {activeIndicator && <span className="muted">{activeIndicator}</span>}
          </header>
          {indicatorLoading && <div>加载中…</div>}
          {!indicatorLoading && verdictsBySource.length === 0 && <div className="muted">暂无情报，等待扫描结果。</div>}
          <div className="ti-verdict-list">
            {verdictsBySource.map(([source, list]) => (
              <div key={source} className="ti-verdict-item">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong>{source}</strong>
                  <Tag color={list[0]?.classification ? 'red' : 'blue'}>
                    {list[0]?.classification ?? '未知'}
                  </Tag>
                </div>
                <div className="ti-meta-row">
                  <span>置信度: {list[0]?.confidence ?? '-'}</span>
                  <span>更新: {dayjs(list[0]?.retrieved_at).fromNow()}</span>
                </div>
                {list.slice(1).map((verdict) => (
                  <div key={verdict.id} className="ti-meta-row">
                    <span>{dayjs(verdict.retrieved_at).format('MM-DD HH:mm')} · {verdict.classification ?? '未知'}</span>
                    {verdict.confidence && <span> ({verdict.confidence})</span>}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>

        <div className="ti-card">
          <header>
            <h3>样本进度</h3>
            <span className="muted">最近 {sampleSummaries.length} 条</span>
          </header>
          {sampleSummaries.length === 0 && <div className="muted">暂无样本事件</div>}
          <div className="ti-sample-list">
            {sampleSummaries.slice(0, 5).map((sample) => (
              <div key={sample.id} className="ti-sample-item">
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <strong>{sample.indicator ?? sample.id}</strong>
                  <Tag>{sample.status ?? sample.lastEvent}</Tag>
                </div>
                <div className="ti-meta-row">
                  <span>更新: {dayjs(sample.updatedAt).fromNow()}</span>
                  {sample.classification && <span>Verdict: {sample.classification}</span>}
                </div>
                {Object.keys(sample.jobs).length > 0 && (
                  <div className="ti-meta-row">
                    {Object.entries(sample.jobs).map(([src, status]) => (
                      <Tag key={src} color={status === 'succeeded' ? 'green' : status === 'failed' ? 'red' : 'blue'}>
                        {src}:{status}
                      </Tag>
                    ))}
                  </div>
                )}
                <Button size="small" onClick={() => setSelectedSampleId(sample.id)}>
                  查看详情
                </Button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {selectedSampleId && (
        <section className="ti-card">
          <header>
            <h3>样本详情</h3>
            <Space>
              <Button size="small" onClick={() => refreshSample()}>
                刷新
              </Button>
              <Button size="small" onClick={() => setSelectedSampleId(null)}>
                关闭
              </Button>
            </Space>
          </header>
          {sampleLoading && <div>加载中…</div>}
          {sampleDetail && (
            <div className="ti-sample-detail">
              <div className="ti-meta-row">
                <span>ID: {sampleDetail.id}</span>
                <span>状态: {sampleDetail.status}</span>
                {sampleDetail.hash && <span>Hash: {sampleDetail.hash}</span>}
              </div>
              <div className="ti-meta-row">
                <span>文件名: {sampleDetail.filename ?? '-'}</span>
                <span>大小: {sampleDetail.size ?? 0} bytes</span>
              </div>
              <table className="ti-audit-table" style={{ marginTop: '0.75rem' }}>
                <thead>
                  <tr>
                    <th>来源</th>
                    <th>状态</th>
                    <th>尝试</th>
                    <th>最近更新时间</th>
                  </tr>
                </thead>
                <tbody>
                  {sampleDetail.jobs.map((job) => (
                    <tr key={job.id}>
                      <td>{job.source}</td>
                      <td>{job.status}</td>
                      <td>{job.attempt ?? 0}</td>
                      <td>{dayjs(job.updated_at).format('MM-DD HH:mm')}</td>
                    </tr>
                  ))}
                  {sampleDetail.jobs.length === 0 && (
                    <tr>
                      <td colSpan={4} className="muted">
                        尚无扫描任务
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <section className="threat-intel-grid">
        <div className="ti-card">
          <header>
            <h3>威胁情报事件流</h3>
            <small className="muted">实时推送（最近 25 条）</small>
          </header>
          <div className="ti-event-feed">
            {eventFeed.map((event, index) => (
              <div
                key={`${event.event}-${event.timestamp}-${event.sample_id ?? event.job_id ?? ''}-${index}`}
                className="ti-event-row"
              >
                <strong>{event.event}</strong>
                <span className="muted">{dayjs(event.timestamp).format('MM-DD HH:mm:ss')}</span>
                {event.indicator && <span>IOC: {event.indicator}</span>}
                {event.sample_id && <span>样本: {event.sample_id}</span>}
                {event.source && <span>来源: {event.source}</span>}
                {event.status && <span>状态: {event.status}</span>}
                {event.message && <span>信息: {event.message}</span>}
              </div>
            ))}
            {eventFeed.length === 0 && <div className="muted">暂无事件</div>}
          </div>
        </div>

        <div className="ti-card">
          <header>
            <h3>操作审计</h3>
            <small className="muted">过滤 threatintel.* 行为</small>
          </header>
          {auditLoading && <div>加载中…</div>}
          {!auditLoading && (
            <table className="ti-audit-table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>操作者</th>
                  <th>行为</th>
                  <th>资源</th>
                </tr>
              </thead>
              <tbody>
                {auditEvents.map((event) => (
                  <tr key={event.id}>
                    <td>{dayjs(event.timestamp).format('MM-DD HH:mm')}</td>
                    <td>{event.actor}</td>
                    <td>{event.action}</td>
                    <td>{event.resource}</td>
                  </tr>
                ))}
                {auditEvents.length === 0 && (
                  <tr>
                    <td colSpan={4} className="muted">
                      暂无相关审计
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}

type SampleSummary = {
  id: string;
  indicator?: string;
  status?: string;
  classification?: string;
  lastEvent: string;
  updatedAt: string;
  jobs: Record<string, string>;
};

function extractApiError(error: unknown): string | null {
  if (typeof error === 'object' && error !== null) {
    const maybeResponse = (error as { response?: { data?: { error?: string } } }).response;
    if (maybeResponse?.data?.error) {
      return maybeResponse.data.error;
    }
    if ('message' in error && typeof (error as { message?: string }).message === 'string') {
      return (error as { message: string }).message;
    }
  }
  return null;
}
