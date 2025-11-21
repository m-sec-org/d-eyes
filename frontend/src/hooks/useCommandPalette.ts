import { useCallback, useEffect, useMemo, useState } from 'react';
import { usePermissions } from './usePermissions';

export type CommandType = 'view' | 'resource' | 'action' | 'help';

export interface CommandItem {
  id: string;
  type: CommandType;
  label: string;
  description?: string;
  shortcut?: string;
  keywords?: string[];
  route?: string;
}

const seedCommands: CommandItem[] = [
  {
    id: 'view-tasks',
    type: 'view',
    label: '跳转到任务视图',
    description: '查看最新任务队列',
    shortcut: 'G T',
    route: '/tasks',
    keywords: ['任务', 'task', '队列'],
  },
  {
    id: 'view-risks',
    type: 'view',
    label: '跳转到风险视图',
    description: '高危风险与趋势',
    shortcut: 'G R',
    route: '/risks',
    keywords: ['risk', '风险'],
  },
  {
    id: 'action-create-task',
    type: 'action',
    label: '创建响应任务',
    description: '基于模板快速调度',
    shortcut: 'C',
    route: '/tasks',
    keywords: ['create', '任务', 'respond'],
  },
  {
    id: 'view-assets',
    type: 'view',
    label: '跳转到资产视图',
    description: 'Inventory 摘要与批量标签',
    shortcut: 'G A',
    route: '/assets',
    keywords: ['资产', 'asset'],
  },
  {
    id: 'view-threat-intel',
    type: 'view',
    label: '打开威胁情报工作台',
    description: 'IOC 搜索与样本进度',
    shortcut: 'G I',
    route: '/threat-intel',
    keywords: ['threat', 'intel', '情报'],
  },
  {
    id: 'view-anomalies',
    type: 'view',
    label: '跳转到行为异常视图',
    description: '实时监控行为异常与拓扑',
    route: '/anomalies',
    keywords: ['anomaly', '行为', '异常'],
  },
  {
    id: 'view-queues',
    type: 'view',
    label: '跳转到命令队列',
    description: '查看排队与调度状态',
    route: '/queues',
    keywords: ['queue', '命令队列'],
  },
  {
    id: 'view-topology',
    type: 'view',
    label: '跳转到拓扑视图',
    description: '网络链路与区域状态',
    route: '/topology',
    keywords: ['topology', '拓扑'],
  },
  {
    id: 'view-bas',
    type: 'view',
    label: '跳转到 BAS 场景',
    description: '管理 BAS 场景与审批',
    route: '/bas',
    keywords: ['bas', 'scenario', '攻防'],
  },
  {
    id: 'view-playbooks',
    type: 'view',
    label: '打开 Playbook 控制台',
    description: '配置自动响应策略与动作',
    route: '/playbooks',
    keywords: ['playbook', '自动化'],
  },
  {
    id: 'view-compliance',
    type: 'view',
    label: '跳转到合规模块',
    description: '框架与差距仪表盘',
    route: '/compliance',
    keywords: ['compliance', '合规'],
  },
  {
    id: 'view-agents',
    type: 'view',
    label: '跳转到 Agent 管理',
    description: '查看节点状态与标签',
    route: '/agents',
    keywords: ['agent', '节点'],
  },
  {
    id: 'view-reports',
    type: 'view',
    label: '跳转到报告中心',
    description: '管理模板并导出报告',
    route: '/reports',
    keywords: ['report', '报告'],
  },
  {
    id: 'view-plugins',
    type: 'view',
    label: '打开插件市场',
    description: '安装/升级第三方插件',
    route: '/plugins',
    keywords: ['plugin', '插件'],
  },
];

export function useCommandPalette() {
  const { canAccess } = usePermissions();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');

  const accessibleCommands = useMemo(
    () => seedCommands.filter((item) => !item.route || canAccess(item.route)),
    [canAccess]
  );

  const filtered = useMemo(() => {
    const base = accessibleCommands;
    if (!query.trim()) {
      return base;
    }
    return base.filter((item) => {
      const haystack = [item.label, item.description, ...(item.keywords ?? [])]
        .join(' ')
        .toLowerCase();
      return haystack.includes(query.toLowerCase());
    });
  }, [accessibleCommands, query]);

  const toggle = useCallback(() => setOpen((prev) => !prev), []);
  const close = useCallback(() => setOpen(false), []);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }
    const handleKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen(true);
      }
      if (event.key === 'Escape') {
        close();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [close]);

  return {
    open,
    filtered,
    query,
    setQuery,
    toggle,
    close,
  };
}
