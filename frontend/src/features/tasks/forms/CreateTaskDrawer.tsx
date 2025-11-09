import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import { listTemplates } from '@/services/api/templates';
import { createTask } from '@/services/api/taskActions';

interface CreateTaskDrawerProps {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}

export function CreateTaskDrawer({ open, onClose, onCreated }: CreateTaskDrawerProps) {
  const { data: templates } = useSWR('task-templates', listTemplates);
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [targets, setTargets] = useState('');
  const [priority, setPriority] = useState(3);
  const [notes, setNotes] = useState('');
  const template = useMemo(() => templates?.find((item) => item.id === selectedTemplate), [selectedTemplate, templates]);

  useEffect(() => {
    if (!open) {
      setSelectedTemplate('');
      setTargets('');
      setPriority(3);
      setNotes('');
    }
  }, [open]);

  if (!open) return null;

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    await createTask({
      type: template?.task_type ?? 'respond',
      profile: template?.profile ?? 'default',
      priority,
      metadata: {
        targets,
        notes,
      },
      created_by: 'ops.lead',
    });
    onCreated();
    onClose();
  };

  return (
    <aside className="task-drawer" role="dialog" aria-modal="true">
      <div className="task-drawer__header">
        <div>
          <h2>创建任务</h2>
          <p className="muted">选择模板并填写必要参数</p>
        </div>
        <button type="button" className="icon-button" onClick={onClose}>
          ✕
        </button>
      </div>
      <form className="drawer-form" onSubmit={handleSubmit}>
        <label className="drawer-label">任务模板</label>
        <select value={selectedTemplate} onChange={(event) => setSelectedTemplate(event.target.value)} required>
          <option value="">请选择模板</option>
          {templates?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} · {t.task_type}
            </option>
          ))}
        </select>
        <label className="drawer-label">目标/范围</label>
        <input value={targets} onChange={(event) => setTargets(event.target.value)} placeholder="例如 10.0.0.12 或 10.0.0.0/24" required />
        <label className="drawer-label">优先级</label>
        <input type="number" min={1} max={9} value={priority} onChange={(event) => setPriority(Number(event.target.value))} />
        <label className="drawer-label">备注</label>
        <textarea value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="可选：说明此次任务背景" rows={3} />
        <div className="actions">
          <button type="submit" className="primary">
            创建
          </button>
          <button type="button" className="ghost" onClick={onClose}>
            取消
          </button>
        </div>
      </form>
    </aside>
  );
}
