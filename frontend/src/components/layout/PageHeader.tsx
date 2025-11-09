import type { ReactNode } from 'react';
import { Breadcrumb, Card, Flex, Space, Typography } from 'antd';
import { Link } from 'react-router-dom';

interface BreadcrumbItem {
  label: string;
  path?: string;
}

interface PageHeaderProps {
  title: string;
  description?: string;
  breadcrumbs?: BreadcrumbItem[];
  extra?: ReactNode;
}

const { Title, Text } = Typography;

export function PageHeader({ title, description, breadcrumbs = [], extra }: PageHeaderProps) {
  return (
    <Card bordered={false}>
      <Space direction="vertical" style={{ width: '100%' }} size="small">
        {breadcrumbs.length > 0 && (
          <Breadcrumb
            items={breadcrumbs.map((item) => ({
              title: item.path ? <Link to={item.path}>{item.label}</Link> : item.label,
            }))}
          />
        )}
        <Flex justify="space-between" align="center" gap={16} wrap="wrap">
          <Space direction="vertical" size={0}>
            <Title level={3} style={{ margin: 0 }}>
              {title}
            </Title>
            {description && <Text type="secondary">{description}</Text>}
          </Space>
          {extra}
        </Flex>
      </Space>
    </Card>
  );
}
