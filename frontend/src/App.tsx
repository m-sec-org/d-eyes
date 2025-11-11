import './App.css';
import { CommandPalette } from './components/CommandPalette';
import { Header } from './components/layout/Header';
import { Sidebar } from './components/layout/Sidebar';
import { useAuth } from './hooks/useAuth';
import { useCommandPalette, type CommandItem } from './hooks/useCommandPalette';
import { useTaskStream } from './hooks/useTaskStream';
import { OverviewDashboard } from './features/overview/OverviewDashboard';
import { TaskOverview } from './features/tasks/TaskOverview';
import { RiskDashboard } from './features/risks/RiskDashboard';
import { AssetOverview } from './features/assets/AssetOverview';
import { SystemConfigCenter } from './features/settings/SystemConfigCenter';
import { AuditLogView } from './features/audit/AuditLogView';
import { QueueMonitor } from './features/queues/QueueMonitor';
import { TopologyOverview } from './features/topology/TopologyOverview';
import { BASScenarioConsole } from './features/bas/BASScenarioConsole';
import { AgentDirectory } from './features/agents/AgentDirectory';
import { ReportWorkbench } from './features/reports/ReportWorkbench';
import { Route, Routes, useNavigate } from 'react-router-dom';
import { ProtectedRoute } from './app/routes/ProtectedRoute';
import { ThemeShowcase } from './features/styleguide/ThemeShowcase';

function App() {
  const { open, filtered, query, setQuery, toggle, close } = useCommandPalette();
  const { session, loading } = useAuth();
  const navigate = useNavigate();
  useTaskStream();

  const handleCommandSelect = (item: CommandItem) => {
    if (item.route) {
      navigate(item.route);
    }
    close();
  };
  if (loading) {
    return <div className="app-shell">加载中…</div>;
  }
  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">
        跳至主要内容
      </a>
      <Header onCommandPalette={toggle} user={session?.user} paletteOpen={open} />
      <div className="app-body">
        <Sidebar />
        <main className="app-main" id="main-content" role="main" tabIndex={-1}>
          <Routes>
            <Route
              path="/"
              element={
                <ProtectedRoute route="/" allowedRoles={['operator', 'admin']}>
                  <OverviewDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/tasks"
              element={
                <ProtectedRoute route="/tasks" allowedRoles={['operator', 'admin']}>
                  <TaskOverview />
                </ProtectedRoute>
              }
            />
            <Route
              path="/agents"
              element={
                <ProtectedRoute route="/agents" allowedRoles={['admin']}>
                  <AgentDirectory />
                </ProtectedRoute>
              }
            />
            <Route
              path="/risks"
              element={
                <ProtectedRoute route="/risks" allowedRoles={['operator', 'auditor', 'admin']}>
                  <RiskDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/assets"
              element={
                <ProtectedRoute route="/assets" allowedRoles={['operator', 'admin']}>
                  <AssetOverview />
                </ProtectedRoute>
              }
            />
            <Route
              path="/queues"
              element={
                <ProtectedRoute route="/queues" allowedRoles={['admin']}>
                  <QueueMonitor />
                </ProtectedRoute>
              }
            />
            <Route
              path="/topology"
              element={
                <ProtectedRoute route="/topology" allowedRoles={['admin']}>
                  <TopologyOverview />
                </ProtectedRoute>
              }
            />
            <Route
              path="/bas"
              element={
                <ProtectedRoute route="/bas" allowedRoles={['admin']}>
                  <BASScenarioConsole />
                </ProtectedRoute>
              }
            />
            <Route
              path="/reports"
              element={
                <ProtectedRoute route="/reports" allowedRoles={['admin']}>
                  <ReportWorkbench />
                </ProtectedRoute>
              }
            />
            <Route
              path="/settings"
              element={
                <ProtectedRoute route="/settings" allowedRoles={['admin']}>
                  <SystemConfigCenter />
                </ProtectedRoute>
              }
            />
            <Route
              path="/audit"
              element={
                <ProtectedRoute route="/audit" allowedRoles={['auditor', 'admin']}>
                  <AuditLogView />
                </ProtectedRoute>
              }
            />
            <Route
              path="/ui-guide"
              element={
                <ProtectedRoute route="/ui-guide" allowedRoles={['admin']}>
                  <ThemeShowcase />
                </ProtectedRoute>
              }
            />
            <Route path="*" element={<div className="card">功能开发中</div>} />
          </Routes>
        </main>
      </div>
      <CommandPalette
        open={open}
        items={filtered}
        query={query}
        onQueryChange={setQuery}
        onClose={close}
        onSelect={handleCommandSelect}
      />
    </div>
  );
}

export default App;
