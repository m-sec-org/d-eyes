import './PluginMarketplace.css';
import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Form, Input, Modal, Space, Table, Tag, message, theme } from 'antd';
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
  const [error, setError] = useState<string | null>(null);
  const [installing, setInstalling] = useState(false);
  const [loading, setLoading] = useState(true);
  const [form] = Form.useForm();
  const [messageApi, contextHolder] = message.useMessage();
  const { token } = theme.useToken();

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
      setLoading(true);
      const data = await listPlugins();
      setPlugins(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err?.response?.data?.error ?? '获取插件列表失败');
    } finally {
      setLoading(false);
    }
  };

  const handleInstall = async () => {
    try {
      const values = await form.validateFields();
      setInstalling(true);
      setError(null);
      await installPlugin(values.manifest, 'plain');
      messageApi.success('插件安装/升级成功');
      form.resetFields();
      fetchPlugins();
    } catch (err: any) {
      setError(err?.response?.data?.error ?? '安装失败');
    } finally {
      setInstalling(false);
    }
  };

  const handleRollback = async (name: string) => {
    Modal.confirm({
      title: `回滚插件 ${name}`,
      content: '确认回滚该插件至上一版本？',
      okText: '回滚',
      cancelText: '取消',
      onOk: async () => {
        setError(null);
        try {
          await rollbackPlugin(name);
          messageApi.success('插件已回滚');
          fetchPlugins();
        } catch (err: any) {
          setError(err?.response?.data?.error ?? '回滚失败');
        }
      },
    });
  };

  const tableData = useMemo(
    () =>
      plugins.map((plugin) => ({
        key: plugin.manifest.name,
        ...plugin,
      })),
    [plugins]
  );

  const columns = [
    {
      title: '名称',
      dataIndex: ['manifest', 'name'],
    },
    {
      title: '版本',
      dataIndex: ['manifest', 'version'],
      width: 120,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 140,
      render: (value: string) => (
        <Tag color={value === 'running' ? 'green' : value === 'failed' ? 'red' : 'blue'}>{value}</Tag>
      ),
    },
    {
      title: '原因',
      dataIndex: 'reason',
      render: (value: string | undefined) => value ?? '-',
    },
    {
      title: '安装时间',
      dataIndex: 'installed_at',
      render: (value: string) => new Date(value).toLocaleString(),
      width: 180,
    },
    {
      title: '操作',
      dataIndex: 'actions',
      width: 140,
      render: (_: unknown, record: PluginRecord) => (
        <Button size="small" onClick={() => handleRollback(record.manifest.name)}>
          回滚
        </Button>
      ),
    },
  ];

  return (
    <PluginMarketplaceErrorBoundary>
      <div className="plugin-marketplace" style={{ background: token.colorBgLayout }}>
        {contextHolder}
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <Card title="插件市场" variant="borderless" className="plugin-card">
            <p className="muted">安装/升级插件，实时查看状态，事件自动刷新。</p>
          </Card>

          {error && (
            <Alert
              message="操作失败"
              description={error}
              type="error"
              showIcon
              closable
              onClose={() => setError(null)}
            />
          )}

          <Card title="安装 / 升级" variant="borderless" className="plugin-card">
            <Form layout="vertical" form={form} onFinish={handleInstall}>
              <Form.Item
                name="manifest"
                label="插件 Manifest (YAML)"
                rules={[{ required: true, message: '请输入插件 manifest' }]}
              >
                <Input.TextArea rows={8} placeholder="粘贴插件 manifest (YAML)" />
              </Form.Item>
              <Button type="primary" htmlType="submit" loading={installing}>
                安装 / 升级
              </Button>
            </Form>
          </Card>

          <Card title="已安装插件" variant="borderless" className="plugin-card" extra={<Button onClick={fetchPlugins}>刷新</Button>}>
            <Table
              dataSource={tableData}
              columns={columns}
              loading={loading}
              pagination={{ pageSize: 8 }}
              rowKey={(record) => record.manifest.name}
              locale={{ emptyText: '暂无插件' }}
            />
          </Card>
        </Space>
      </div>
    </PluginMarketplaceErrorBoundary>
  );
}
