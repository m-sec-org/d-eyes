import dayjs from 'dayjs';
import { Drawer, Descriptions, Empty, List, Skeleton, Space, Tag, Typography } from 'antd';
import { useAssetDetail } from '../hooks/useAssetDetail';

interface AssetDetailDrawerProps {
  assetId: string | null;
  onClose: () => void;
}

const STATUS_COLORS = {
  online: 'success',
  offline: 'default',
  unknown: 'warning',
} as const;

const RISK_COLORS = {
  high: 'error',
  medium: 'warning',
  low: 'success',
} as const;

const TASK_STATUS_COLORS: Record<string, string> = {
  running: 'processing',
  failed: 'error',
  succeeded: 'success',
  pending: 'default',
};

const { Text } = Typography;

export function AssetDetailDrawer({ assetId, onClose }: AssetDetailDrawerProps) {
  const { detail, isLoading } = useAssetDetail(assetId);

  return (
    <Drawer title="资产详情" width={520} onClose={onClose} open={!!assetId} destroyOnClose aria-label="资产详情抽屉">
      {isLoading ? (
        <Skeleton active />
      ) : detail ? (
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="主机名">{detail.hostname}</Descriptions.Item>
            <Descriptions.Item label="IP">{detail.ip}</Descriptions.Item>
            <Descriptions.Item label="状态">
              <Tag color={STATUS_COLORS[detail.status]}>{detail.status}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="风险等级">
              <Tag color={RISK_COLORS[detail.risk_level]}>{detail.risk_level}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="最近在线">{dayjs(detail.last_seen).format('YYYY-MM-DD HH:mm')}</Descriptions.Item>
          </Descriptions>

          <Space direction="vertical" size={4}>
            <Text strong>标签</Text>
            {detail.tags.length > 0 ? (
              <Space size={[4, 4]} wrap>
                {detail.tags.map((tag) => (
                  <Tag key={tag}>{tag}</Tag>
                ))}
              </Space>
            ) : (
              <Text type="secondary">暂无标签</Text>
            )}
          </Space>

          <List
            size="small"
            header="最近任务"
            dataSource={detail.related_tasks}
            locale={{ emptyText: '暂无任务' }}
            renderItem={(task) => (
              <List.Item key={task.id}>
                <Space direction="vertical" size={0}>
                  <Space>
                    <Text strong>{task.type}</Text>
                    <Tag color={TASK_STATUS_COLORS[task.status] ?? 'default'}>{task.status}</Tag>
                  </Space>
                  <Text type="secondary">
                    {task.completed_at ? dayjs(task.completed_at).format('MM-DD HH:mm') : '未完成'}
                  </Text>
                </Space>
              </List.Item>
            )}
          />

          <List
            size="small"
            header="关联风险"
            dataSource={detail.related_risks}
            locale={{ emptyText: '暂无风险' }}
            renderItem={(risk) => (
              <List.Item key={risk.id}>
                <Space direction="vertical" size={0}>
                  <Space>
                    <Text strong>{risk.summary}</Text>
                    <Tag color={RISK_COLORS[risk.severity]}>{risk.severity}</Tag>
                  </Space>
                  <Text type="secondary">{dayjs(risk.timestamp).format('MM-DD HH:mm')}</Text>
                </Space>
              </List.Item>
            )}
          />

          <List
            size="small"
            header="操作日志"
            dataSource={detail.operations}
            locale={{ emptyText: '暂无记录' }}
            renderItem={(op) => (
              <List.Item key={op.timestamp}>
                <Space direction="vertical" size={0}>
                  <Text>
                    <Text strong>{op.actor}</Text> {op.action}
                  </Text>
                  <Text type="secondary">{dayjs(op.timestamp).format('MM-DD HH:mm')}</Text>
                </Space>
              </List.Item>
            )}
          />
        </Space>
      ) : (
        <Empty description="未加载资产详情" />
      )}
    </Drawer>
  );
}
