import { useMemo, useState } from 'react';
import dayjs from 'dayjs';
import { Button, Card, Col, Flex, Input, message, Row, Segmented, Space, Statistic, Table, Tag, Typography } from 'antd';
import type { ColumnsType, TableProps } from 'antd/es/table';
import { ReloadOutlined, TagOutlined } from '@ant-design/icons';
import { useAssets } from './hooks/useAssets';
import { useBatchTag } from './hooks/useBatchTag';
import { AssetDetailDrawer } from './components/AssetDetailDrawer';
import type { AssetSummary } from '@/services/types';
import { PageHeader } from '@/components/layout/PageHeader';

type AssetRecord = AssetSummary['items'][number];
type AssetStatusFilter = 'all' | 'online' | 'offline' | 'unknown';

const { Text } = Typography;

const STATUS_SEGMENTS = [
  { label: '全部资产', value: 'all' },
  { label: '在线', value: 'online' },
  { label: '离线', value: 'offline' },
  { label: '未知', value: 'unknown' },
];

const STATUS_COLORS: Record<AssetRecord['status'], string> = {
  online: 'success',
  offline: 'default',
  unknown: 'warning',
};

const RISK_COLORS: Record<AssetRecord['risk_level'], string> = {
  high: 'error',
  medium: 'warning',
  low: 'success',
};

export function AssetOverview() {
  const { summary, isLoading, refresh } = useAssets();
  const [status, setStatus] = useState<AssetStatusFilter>('all');
  const [search, setSearch] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [pendingTag, setPendingTag] = useState('');
  const [detailId, setDetailId] = useState<string | null>(null);
  const { loading: tagging, applyTag } = useBatchTag(refresh);
  const [messageApi, contextHolder] = message.useMessage();

  const filtered = useMemo(() => {
    const currentAssets = summary?.items ?? [];
    const keyword = search.trim().toLowerCase();
    return currentAssets.filter((item) => {
      if (status !== 'all' && item.status !== status) {
        return false;
      }
      if (!keyword) return true;
      return `${item.hostname} ${item.ip} ${item.tags.join(' ')}`.toLowerCase().includes(keyword);
    });
  }, [summary, status, search]);

  const columns: ColumnsType<AssetRecord> = [
    {
      title: '主机',
      dataIndex: 'hostname',
      key: 'hostname',
      render: (_: unknown, record) => (
        <Space direction="vertical" size={0}>
          <Text strong>{record.hostname}</Text>
          <Text type="secondary">{record.ip}</Text>
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (value: AssetRecord['status']) => <Tag color={STATUS_COLORS[value]}>{value}</Tag>,
    },
    {
      title: '风险',
      dataIndex: 'risk_level',
      key: 'risk_level',
      render: (value: AssetRecord['risk_level']) => <Tag color={RISK_COLORS[value]}>{value}</Tag>,
    },
    {
      title: '标签',
      dataIndex: 'tags',
      key: 'tags',
      render: (tags: string[]) =>
        tags.length > 0 ? (
          <Space size={[4, 4]} wrap>
            {tags.map((tag) => (
              <Tag key={tag}>{tag}</Tag>
            ))}
          </Space>
        ) : (
          <Text type="secondary">暂无</Text>
        ),
    },
    {
      title: '最近在线',
      dataIndex: 'last_seen',
      key: 'last_seen',
      render: (value: string) => dayjs(value).format('YYYY-MM-DD HH:mm'),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record) => (
        <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
          查看
        </Button>
      ),
    },
  ];

  const rowSelection: TableProps<AssetRecord>['rowSelection'] = {
    selectedRowKeys: selectedIds,
    onChange: (keys) => setSelectedIds(keys.map(String)),
  };

  const handleBatchTag = async () => {
    if (selectedIds.length === 0) {
      messageApi.info('请先选择资产');
      return;
    }
    if (!pendingTag.trim()) {
      messageApi.warning('请输入标签内容');
      return;
    }
    try {
      await applyTag(selectedIds, pendingTag.trim());
      messageApi.success('批量标记完成');
      setPendingTag('');
      setSelectedIds([]);
    } catch {
      messageApi.error('批量标记失败，请重试');
    }
  };

  return (
    <div className="asset-overview">
      {contextHolder}
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <PageHeader
          title="资产视图"
          description="基于 inventory 任务生成的资产摘要，支持标签与状态筛选"
          breadcrumbs={[
            { label: '洞察', path: '/assets' },
            { label: '资产' },
          ]}
          extra={
            <Flex align="center" justify="flex-end" wrap="wrap" gap={16}>
              <Segmented
                options={STATUS_SEGMENTS}
                value={status}
                onChange={(value) => setStatus(value as AssetStatusFilter)}
              />
              <Button icon={<ReloadOutlined />} onClick={() => refresh()} loading={isLoading}>
                刷新
              </Button>
            </Flex>
          }
        />

        <Row gutter={16}>
          <Col xs={24} md={8}>
            <Card bordered={false}>
              <Statistic title="在线资产" value={summary?.totals.online ?? 0} valueStyle={{ color: '#52c41a' }} />
            </Card>
          </Col>
          <Col xs={24} md={8}>
            <Card bordered={false}>
              <Statistic title="离线资产" value={summary?.totals.offline ?? 0} valueStyle={{ color: '#faad14' }} />
            </Card>
          </Col>
          <Col xs={24} md={8}>
            <Card bordered={false}>
              <Statistic title="高风险" value={summary?.totals.critical ?? 0} valueStyle={{ color: '#ff4d4f' }} />
            </Card>
          </Col>
        </Row>

        <Card
          title="资产列表"
          extra={<Text type="secondary">来自最新 inventory · {filtered.length} 条记录</Text>}
          bodyStyle={{ paddingTop: 0 }}
        >
          <Space style={{ marginBottom: 16 }} wrap>
            <Input.Search
              placeholder="搜索主机 / 标签 / IP"
              allowClear
              value={search}
              style={{ width: 260 }}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="资产搜索"
            />
            <Input
              placeholder="输入要批量添加的标签"
              value={pendingTag}
              onChange={(event) => setPendingTag(event.target.value)}
              prefix={<TagOutlined />}
              style={{ width: 220 }}
              aria-label="批量标签输入"
            />
            <Button
              type="primary"
              icon={<TagOutlined />}
              onClick={handleBatchTag}
              loading={tagging}
              disabled={selectedIds.length === 0}
              aria-label="批量标记选中资产"
            >
              批量标记 {selectedIds.length > 0 ? `(${selectedIds.length})` : ''}
            </Button>
          </Space>

          <Table
            rowKey="id"
            rowSelection={rowSelection}
            columns={columns}
            dataSource={filtered}
            pagination={{ pageSize: 10, showSizeChanger: true, pageSizeOptions: ['10', '20', '50'] }}
            loading={isLoading}
            scroll={{ x: 900 }}
            locale={{ emptyText: '暂无资产数据' }}
            aria-label="资产列表表格"
            aria-busy={isLoading}
          />
        </Card>
      </Space>

      <AssetDetailDrawer assetId={detailId} onClose={() => setDetailId(null)} />
    </div>
  );
}
