import './PluginMarketplace.css';
import React, { useEffect, useState } from 'react';
import type { PluginRecord } from '@/services/api/plugins';
import { installPlugin, listPlugins, rollbackPlugin } from '@/services/api/plugins';

type EventMessage = {
  event: string;
  task_id: string;
  message?: string;
  metadata?: Record<string, string>;
  updated_at: string;
};

class PluginMarketplaceErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; message?: string }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, message: error?.message };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    if (import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.error('PluginMarketplace error boundary', error, errorInfo);
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, message: undefined });
    // simple refresh to re-fetch data and clear broken state
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="plugin-alert" role="alert">
          <div>插件市场发生错误：{this.state.message ?? ''}</div>
          <button onClick={this.handleReset}>刷新重试</button>
        </div>
      );
    }
    return this.props.children;
  }
}

export function PluginMarketplace() {
  const [plugins, setPlugins] = useState<PluginRecord[]>([]);
  const [manifest, setManifest] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [installing, setInstalling] = useState(false);

  useEffect(() => {
    fetchPlugins();
    const evtSource = new EventSource('/api/v1/plugins/stream');
    evtSource.onmessage = (e) => {
      try {
        const evt: EventMessage = JSON.parse(e.data);
        if (evt.event?.startsWith('plugin.')) {
          fetchPlugins();
        }
      } catch {
        // ignore malformed event
      }
    };
    return () => evtSource.close();
  }, []);

  const fetchPlugins = async () => {
    try {
      const data = await listPlugins();
      setPlugins(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err?.response?.data?.error ?? '获取插件列表失败');
    }
  };

  const handleInstall = async () => {
    setInstalling(true);
    setError(null);
    try {
      await installPlugin(manifest, 'plain');
      setManifest('');
      fetchPlugins();
    } catch (err: any) {
      setError(err?.response?.data?.error ?? '安装失败');
    } finally {
      setInstalling(false);
    }
  };

  const handleRollback = async (name: string) => {
    setError(null);
    try {
      await rollbackPlugin(name);
      fetchPlugins();
    } catch (err: any) {
      setError(err?.response?.data?.error ?? '回滚失败');
    }
  };

  return (
    <PluginMarketplaceErrorBoundary>
      <div className="plugin-marketplace">
        <header>
          <div>
            <h1>插件市场</h1>
            <p>安装/升级插件，实时查看状态，事件自动刷新。</p>
        </div>
      </header>

      {error && (
        <div className="plugin-alert" role="alert">
          {error}
        </div>
      )}

      <section className="plugin-form">
        <h2>安装/升级</h2>
        <textarea
          value={manifest}
          onChange={(e) => setManifest(e.target.value)}
          placeholder="粘贴插件 manifest (YAML)"
          rows={10}
        />
        <button onClick={handleInstall} disabled={installing || !manifest.trim()}>
          {installing ? '安装中…' : '安装 / 升级'}
        </button>
      </section>

      <section>
        <h2>已安装插件</h2>
        <table className="plugin-table">
          <thead>
            <tr>
              <th>名称</th>
              <th>版本</th>
              <th>状态</th>
              <th>原因</th>
              <th>安装时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {plugins.map((p) => (
              <tr key={p.manifest.name}>
                <td>{p.manifest.name}</td>
                <td>{p.manifest.version}</td>
                <td>{p.status}</td>
                <td>{p.reason ?? '-'}</td>
                <td>{new Date(p.installed_at).toLocaleString()}</td>
                <td>
                  <button onClick={() => handleRollback(p.manifest.name)}>回滚</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
    </PluginMarketplaceErrorBoundary>
  );
}
