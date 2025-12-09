import { useState } from 'react';
import { Card, Segmented, Input, Button, Select, Spin, Form, Modal, Row, Col } from 'antd';
import type { TaskFiltersState, TaskStatusFilter } from '../hooks/useTaskFilters';
import type { TaskView } from '@/services/types';

interface TaskFiltersProps {
  filters: TaskFiltersState;
  views: TaskView[];
  viewsLoading?: boolean;
  savingView?: boolean;
  onStatusChange: (status: TaskStatusFilter) => void;
  onSearchChange: (search: string) => void;
  onPageSizeChange: (size: number) => void;
  onSaveView: (name: string) => Promise<void> | void;
  onApplyView: (viewId: string) => void;
  onRemoveView: (viewId: string) => void;
}

const STATUSES: { label: string; value: TaskStatusFilter }[] = [
  { label: '全部', value: 'all' },
  { label: '待执行', value: 'pending' },
  { label: '进行中', value: 'running' },
  { label: '已完成', value: 'succeeded' },
  { label: '失败', value: 'failed' },
];

const PAGE_SIZE_OPTIONS = [
  { label: '每页 25 条', value: 25 },
  { label: '每页 50 条', value: 50 },
  { label: '每页 100 条', value: 100 },
];

export function TaskFilters({
  filters,
  views,
  viewsLoading = false,
  savingView = false,
  onStatusChange,
  onSearchChange,
  onPageSizeChange,
  onSaveView,
  onApplyView,
  onRemoveView,
}: TaskFiltersProps) {
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [viewName, setViewName] = useState('');
  const [viewError, setViewError] = useState<string | null>(null);
  const [selectedViewIds, setSelectedViewIds] = useState<string[]>([]);

  const openModal = () => {
    setViewModalOpen(true);
    setViewName('');
    setViewError(null);
  };

  const closeModal = () => {
    if (savingView) return;
    setViewModalOpen(false);
    setViewName('');
    setViewError(null);
  };

  const validateName = (name: string) => {
    if (!name.trim()) {
      return '请输入视图名称';
    }
    const duplicate = views.some((view) => view.name.toLowerCase() === name.trim().toLowerCase());
    if (duplicate) {
      return '已存在同名视图';
    }
    return null;
  };

  const handleSaveView = async () => {
    const error = validateName(viewName);
    if (error) {
      setViewError(error);
      return;
    }
    await Promise.resolve(onSaveView(viewName.trim()));
    setViewModalOpen(false);
    setViewName('');
    setViewError(null);
  };

  return (
    <>
      <div className="task-filters">
        <Card className="task-filters-card" styles={{ body: { padding: '16px 20px' } }}>
          <Form layout="vertical" className="task-filters-form">
            <Row gutter={[16, 12]}>
              <Col span={24}>
                <Form.Item label="任务状态">
                  <Segmented
                    value={filters.status}
                    onChange={(value) => onStatusChange(value as TaskStatusFilter)}
                    options={STATUSES.map((status) => ({ label: status.label, value: status.value }))}
                    block
                    aria-label="任务状态筛选"
                  />
                </Form.Item>
              </Col>
            </Row>
            <Row gutter={[16, 12]} align="bottom">
              <Col xs={24} lg={12}>
                <Form.Item label="任务搜索">
                  <Input
                    allowClear
                    placeholder="搜索任务 ID / 目标 / 场景..."
                    value={filters.search}
                    onChange={(event) => onSearchChange(event.target.value)}
                    aria-label="任务搜索"
                  />
                </Form.Item>
              </Col>
              <Col xs={12} lg={4}>
                <Form.Item label="每页条数">
                  <Select
                    value={filters.pageSize}
                    options={PAGE_SIZE_OPTIONS}
                    onChange={(value) => onPageSizeChange(value)}
                    aria-label="每页条数"
                  />
                </Form.Item>
              </Col>
              <Col xs={24} lg={8}>
                <Form.Item label="已保存视图">
                  <Select
                    showSearch
                    placeholder="选择或搜索视图"
                    value={filters.viewId}
                    options={views.map((view) => ({ label: view.name, value: view.id }))}
                    optionFilterProp="label"
                    aria-label="保存视图列表"
                    loading={viewsLoading}
                    allowClear
                    onChange={(value) => {
                      if (!value) {
                        onApplyView('');
                        return;
                      }
                      onApplyView(value);
                    }}
                    notFoundContent={viewsLoading ? <Spin size="small" /> : '暂无视图'}
                  />
                </Form.Item>
              </Col>
            </Row>
            <Row gutter={[16, 12]}>
              <Col xs={24} lg={12}>
                <Form.Item label="视图操作" colon={false}>
                  <div className="task-filters-actions">
                    <Button onClick={openModal} aria-label="保存当前筛选条件为视图">
                      保存视图
                    </Button>
                    {filters.viewId && (
                      <Button danger onClick={() => onRemoveView(filters.viewId!)} aria-label="删除当前视图">
                        删除视图
                      </Button>
                    )}
                  </div>
                </Form.Item>
              </Col>
            </Row>
          </Form>
        </Card>
      </div>
      <Modal
        title="保存筛选视图"
        open={viewModalOpen}
        onOk={handleSaveView}
        onCancel={closeModal}
        okText="保存"
        cancelText="取消"
        confirmLoading={savingView}
        destroyOnHidden
      >
        <Form layout="vertical">
          <Form.Item
            label="视图名称"
            validateStatus={viewError ? 'error' : undefined}
            help={viewError}
            required
          >
            <Input
              autoFocus
              placeholder="例如：失败任务 / 高优先级"
              value={viewName}
              onChange={(event) => {
                setViewName(event.target.value);
                if (viewError) setViewError(null);
              }}
              maxLength={60}
            />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
