import { useMemo, useState } from 'react';
import useSWR from 'swr';
import dayjs from 'dayjs';
import { Alert, Button, Card, Form, Input, Space, Table, message } from 'antd';
import type { TablePaginationConfig, TableProps } from 'antd';
import { listAuditEvents } from '@/services/api/audit';
import type { AuditEvent } from '@/services/types';
import { OperationTimeline } from '@/components/OperationTimeline';

interface AuditTableRecord extends AuditEvent {
  key: string;
}

export function AuditLogView() {
  const [form] = Form.useForm();
  const [query, setQuery] = useState({ actor: '', resource: '', action: '' });
  const [pagination, setPagination] = useState<TablePaginationConfig>({ current: 1, pageSize: 20 });
  const [sorter, setSorter] = useState<{ field?: string; order?: 'ascend' | 'descend' }>({ field: 'timestamp', order: 'descend' });
  const { data, isLoading, mutate, error } = useSWR(['audit-events', query], () =>
    listAuditEvents({ actor: query.actor, resource: query.resource, action: query.action, limit: 200 })
  );

  const events = data?.items ?? [];

  const sortedEvents = useMemo(() => {
    if (!sorter.field) return events;
    const sorted = [...events].sort((a, b) => {
      const field = sorter.field as keyof AuditEvent;
      const aValue = a[field];
      const bValue = b[field];
      if (field === 'timestamp') {
        const diff = dayjs(a.timestamp).valueOf() - dayjs(b.timestamp).valueOf();
        return sorter.order === 'ascend' ? diff : -diff;
      }
      const aStr = String(aValue ?? '');
      const bStr = String(bValue ?? '');
      return sorter.order === 'ascend' ? aStr.localeCompare(bStr) : bStr.localeCompare(aStr);
    });
    return sorted;
  }, [events, sorter]);

  const pagedEvents = useMemo(() => {
    const current = pagination.current ?? 1;
    const pageSize = pagination.pageSize ?? 20;
    const start = (current - 1) * pageSize;
    return sortedEvents.slice(start, start + pageSize);
  }, [sortedEvents, pagination]);

  const tableData = pagedEvents.map((event) => ({ ...event, key: event.id }));

  const handleTableChange: TableProps<AuditTableRecord>['onChange'] = (pag, _filters, sort) => {
    setPagination(pag);
    if (!Array.isArray(sort)) {
      setSorter({ field: (sort.field as string) ?? 'timestamp', order: sort.order ?? undefined });
    }
  };

  const downloadJSON = () => {
    const payload = JSON.stringify(sortedEvents, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `audit-${Date.now()}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    message.success(`已导出 ${sortedEvents.length} 条审计记录`);
  };

  const columns = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      sorter: true,
      render: (value: string) => dayjs(value).format('MM-DD HH:mm'),
      width: 160,
    },
    {
      title: '操作人',
      dataIndex: 'actor',
      sorter: true,
      width: 160,
    },
    {
      title: '角色',
      dataIndex: 'role',
      width: 160,
      render: (value: string) => <span className="muted">{value}</span>,
    },
    {
      title: '行为',
      dataIndex: 'action',
      sorter: true,
    },
    {
      title: '资源',
      dataIndex: 'resource',
    },
  ];

  return (
    <div className="audit-log-view">
      <section className="section-heading">
        <div>
          <h1>审计日志</h1>
          <p className="muted">记录系统关键操作，支持过滤与导出</p>
        </div>
        <Space>
          <Button onClick={() => mutate()}>刷新</Button>
          <Button type="primary" onClick={downloadJSON}>
            导出 JSON
          </Button>
        </Space>
      </section>

      <Card className="card">
        {error && (
          <Alert
            type="error"
            showIcon
            message="获取审计日志失败"
            description={error instanceof Error ? error.message : '请稍后重试'}
            style={{ marginBottom: 16 }}
          />
        )}
        <Form
          layout="inline"
          form={form}
          onFinish={(values) => {
            setQuery({ actor: values.actor ?? '', resource: values.resource ?? '', action: values.action ?? '' });
            setPagination((prev) => ({ ...prev, current: 1 }));
          }}
        >
          <Form.Item name="actor" label="操作人">
            <Input placeholder="操作人" allowClear style={{ width: 180 }} />
          </Form.Item>
          <Form.Item name="resource" label="资源关键词">
            <Input placeholder="资源关键词" allowClear style={{ width: 200 }} />
          </Form.Item>
          <Form.Item name="action" label="行为关键词">
            <Input placeholder="行为关键词" allowClear style={{ width: 200 }} />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                查询
              </Button>
              <Button
                htmlType="button"
                onClick={() => {
                  form.resetFields();
                  setQuery({ actor: '', resource: '', action: '' });
                  setPagination({ current: 1, pageSize: pagination.pageSize });
                }}
              >
                重置
              </Button>
            </Space>
          </Form.Item>
        </Form>
        <Table
          className="audit-table"
          columns={columns}
          dataSource={tableData}
          loading={isLoading}
          onChange={handleTableChange}
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: sortedEvents.length,
            showSizeChanger: true,
            pageSizeOptions: ['10', '20', '50'],
          }}
          locale={{ emptyText: '暂无审计记录' }}
        />
      </Card>

      <Card className="card">
        <header className="card-header">
          <h2>最近操作</h2>
          <small>同步任务事件与审计数据</small>
        </header>
        <OperationTimeline />
      </Card>
    </div>
  );
}
