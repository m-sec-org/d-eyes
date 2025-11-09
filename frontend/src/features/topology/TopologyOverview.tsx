import { useState } from 'react';
import { Alert, Button, Card, Col, Empty, List, Row, Space, Tag, Typography } from 'antd';
import { CloudServerOutlined, DeploymentUnitOutlined } from '@ant-design/icons';
import { PageHeader } from '@/components/layout/PageHeader';

const { Paragraph, Text } = Typography;

const MOCK_SEGMENTS = [
  { name: '北向控制平面', status: 'online', nodes: 8 },
  { name: '生产区段', status: 'degraded', nodes: 42 },
  { name: '离线沙箱', status: 'offline', nodes: 12 },
];

const STATUS_COLOR: Record<string, 'success' | 'warning' | 'default'> = {
  online: 'success',
  degraded: 'warning',
  offline: 'default',
};

export function TopologyOverview() {
  const [docVisible, setDocVisible] = useState(false);

  return (
    <div className="topology-overview">
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <PageHeader
          title="拓扑视图"
          description="梳理指挥中心、Agent 与资产网络的连通情况，辅助排障与容量规划"
          breadcrumbs={[
            { label: '洞察', path: '/' },
            { label: '拓扑' },
          ]}
          extra={
            <Space>
              <Button icon={<DeploymentUnitOutlined />} onClick={() => setDocVisible(true)}>
                连接配置向导
              </Button>
            </Space>
          }
        />

        <Alert
          type="warning"
          showIcon
          message="研发中"
          description="拓扑图将在 Server /topology API 发布后提供实时节点/链路展示。当前为设计基线与巡检清单。"
        />

        <Row gutter={16}>
          {MOCK_SEGMENTS.map((segment) => (
            <Col xs={24} md={8} key={segment.name}>
              <Card>
                <Space direction="vertical" size={4}>
                  <Space align="center">
                    <CloudServerOutlined />
                    <Text strong>{segment.name}</Text>
                    <Tag color={STATUS_COLOR[segment.status]}>{segment.status}</Tag>
                  </Space>
                  <Text type="secondary">节点数：{segment.nodes}</Text>
                </Space>
              </Card>
            </Col>
          ))}
        </Row>

        <Card title="巡检步骤">
          <List
            dataSource={[
              '检查 Agent -> Router -> Server 的 TLS 证书是否同步',
              '确认变更窗口内是否存在大规模任务影响带宽',
              '验证资产采集任务能否在最近 15 分钟内完成全链路跳转',
            ]}
            renderItem={(item) => <List.Item>{item}</List.Item>}
          />
        </Card>

        <Card title="拓扑占位图">
          {docVisible ? (
            <Paragraph>
              请参阅《D-Eyes 设计指南 (docs/design-next.md)》中的“网络与拓扑”章节，了解分站部署、带宽评估与容灾策略；正式版本发布后会在此处呈现实时链路。
            </Paragraph>
          ) : (
            <Empty description="图形渲染将在数据接入后启用" />
          )}
        </Card>
      </Space>
    </div>
  );
}
