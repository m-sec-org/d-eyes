import { NavLink } from 'react-router-dom';
import { usePermissions } from '@/hooks/usePermissions';

interface SidebarProps {
  collapsed?: boolean;
}

const NAV_GROUPS = [
  {
    title: '运营',
    items: [
      { label: '总览', route: '/', icon: '📊', roles: ['operator', 'admin'] },
      { label: '任务', route: '/tasks', icon: '🧭', roles: ['operator', 'admin'] },
      { label: '命令队列', route: '/queues', icon: '📡', roles: ['admin'] },
    ],
  },
  {
    title: '洞察',
    items: [
      { label: '风险', route: '/risks', icon: '⚠️', roles: ['operator', 'auditor', 'admin'] },
      { label: '资产', route: '/assets', icon: '🧱', roles: ['operator', 'admin'] },
      { label: '拓扑', route: '/topology', icon: '🗺️', roles: ['admin'] },
    ],
  },
  {
    title: '治理',
    items: [
      { label: '系统配置', route: '/settings', icon: '⚙️', roles: ['admin'] },
      { label: '日志审计', route: '/audit', icon: '📜', roles: ['auditor', 'admin'] },
    ],
  },
];

export function Sidebar({ collapsed }: SidebarProps) {
  const { canAccess } = usePermissions();
  return (
    <nav className={`app-sidebar ${collapsed ? 'collapsed' : ''}`} aria-label="主导航">
      {NAV_GROUPS.map((group) => (
        <div key={group.title} className="nav-group">
          <div className="nav-group-title">{group.title}</div>
          <ul>
            {group.items.map((item) => {
              const allowed = canAccess(item.route, item.roles);
              return (
                <li key={item.route}>
                  {allowed ? (
                    <NavLink
                      to={item.route}
                      className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                    >
                      <span className="nav-icon" aria-hidden="true">
                        {item.icon}
                      </span>
                      <span>{item.label}</span>
                    </NavLink>
                  ) : (
                    <span className="nav-link disabled" aria-disabled="true" title="当前账号无访问权限">
                      <span className="nav-icon" aria-hidden="true">
                        {item.icon}
                      </span>
                      <span>{item.label}</span>
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}
