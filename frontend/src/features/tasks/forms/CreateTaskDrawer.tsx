import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';

import { listTaskProfiles, listTaskTypes } from '@/services/api/taskCatalog';
import { createTask } from '@/services/api/taskActions';
import type { TaskProfileParameter } from '@/services/types';
import { Button, Checkbox, FormField, Select, Textarea, TextInput } from '@/components/ui';

interface CreateTaskDrawerProps {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}

export function CreateTaskDrawer({ open, onClose, onCreated }: CreateTaskDrawerProps) {
  const { data: taskTypes } = useSWR('task-types', listTaskTypes);
  const [selectedTaskType, setSelectedTaskType] = useState('');
  const { data: taskProfiles } = useSWR(selectedTaskType ? ['task-profiles', selectedTaskType] : null, () =>
    listTaskProfiles(selectedTaskType)
  );
  const [selectedProfileId, setSelectedProfileId] = useState('');
  const [priority, setPriority] = useState(3);
  const [notes, setNotes] = useState('');
  const [parameterValues, setParameterValues] = useState<Record<string, unknown>>({});

  const selectedProfile = useMemo(
    () => taskProfiles?.find((profile) => profile.id === selectedProfileId),
    [taskProfiles, selectedProfileId]
  );

  useEffect(() => {
    if (!open) {
      setSelectedTaskType('');
      setSelectedProfileId('');
      setPriority(3);
      setNotes('');
      setParameterValues({});
    }
  }, [open]);

  useEffect(() => {
    setSelectedProfileId('');
    setParameterValues({});
  }, [selectedTaskType]);

  useEffect(() => {
    if (!selectedProfile) {
      setParameterValues({});
      return;
    }
    const defaults: Record<string, unknown> = { ...(selectedProfile.schema.defaults ?? {}) };
    selectedProfile.schema.parameters.forEach((param) => {
      if (param.default !== undefined && defaults[param.key] === undefined) {
        defaults[param.key] = param.default;
      }
    });
    setParameterValues(defaults);
  }, [selectedProfile]);

  if (!open) return null;

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selectedTaskType || !selectedProfile) return;

    const payload = Object.entries(parameterValues).reduce<Record<string, unknown>>((acc, [key, value]) => {
      if (value === '' || value === undefined) {
        return acc;
      }
      acc[key] = value;
      return acc;
    }, {});

    await createTask({
      type: selectedTaskType,
      profile: selectedProfile.id,
      priority,
      payload,
      metadata: notes ? { notes } : undefined,
      created_by: 'ops.lead',
    });
    onCreated();
    onClose();
  };

  const handleParamChange = (key: string, value: unknown) => {
    setParameterValues((prev) => ({ ...prev, [key]: value }));
  };

  const renderParameterField = (param: TaskProfileParameter) => {
    const value = parameterValues[param.key];
    const fieldProps = { key: param.key, label: param.label, required: param.required, hint: param.hint };

    switch (param.type) {
      case 'boolean':
        return (
          <FormField {...fieldProps}>
            <Checkbox
              checked={Boolean(value)}
              onChange={(event) => handleParamChange(param.key, event.target.checked)}
              label={param.hint ?? '启用'}
            />
          </FormField>
        );
      case 'number':
        return (
          <FormField {...fieldProps}>
            <TextInput
              type="number"
              value={typeof value === 'number' ? value : ''}
              min={param.min}
              max={param.max}
              required={param.required}
              onChange={(event) =>
                handleParamChange(param.key, event.target.value === '' ? undefined : Number(event.target.value))
              }
            />
          </FormField>
        );
      case 'enum':
        return (
          <FormField {...fieldProps}>
            <Select
              value={typeof value === 'string' ? value : param.options?.[0] ?? ''}
              required={param.required}
              onChange={(event) => handleParamChange(param.key, event.target.value)}
            >
              {param.options?.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </Select>
          </FormField>
        );
      case 'multiselect':
        return (
          <FormField {...fieldProps}>
            <Select
              multiple
              value={Array.isArray(value) ? (value as string[]) : []}
              onChange={(event) => {
                const selections = Array.from(event.target.selectedOptions).map((option) => option.value);
                handleParamChange(param.key, selections);
              }}
            >
              {param.options?.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </Select>
          </FormField>
        );
      case 'string_list':
      case 'cidr_list':
        return (
          <FormField {...fieldProps}>
            <Textarea
              value={Array.isArray(value) ? (value as string[]).join('\n') : ''}
              placeholder={param.hint ?? '每行一个条目'}
              required={param.required}
              onChange={(event) => {
                const entries = event.target.value
                  .split(/\n|,/)
                  .map((item) => item.trim())
                  .filter(Boolean);
                handleParamChange(param.key, entries);
              }}
            />
          </FormField>
        );
      default:
        return (
          <FormField {...fieldProps}>
            <TextInput
              type="text"
              value={typeof value === 'string' ? value : ''}
              placeholder={param.hint}
              required={param.required}
              onChange={(event) => handleParamChange(param.key, event.target.value)}
            />
          </FormField>
        );
    }
  };

  const canSubmit = Boolean(open && selectedTaskType && selectedProfileId);

  return (
    <aside className="task-drawer" role="dialog" aria-modal="true">
      <div className="task-drawer__header">
        <div>
          <h2>创建任务</h2>
          <p className="muted">选择任务类型与 Profile，系统将自动加载对应参数。</p>
        </div>
        <button type="button" className="icon-button" onClick={onClose} aria-label="关闭创建任务抽屉">
          ✕
        </button>
      </div>
      <form className="drawer-form" onSubmit={handleSubmit}>
        <FormField label="任务类型" required>
          <Select value={selectedTaskType} onChange={(event) => setSelectedTaskType(event.target.value)} required>
            <option value="">请选择</option>
            {taskTypes?.map((type) => (
              <option key={type.name} value={type.name}>
                {type.display_name ?? type.name}
              </option>
            ))}
          </Select>
        </FormField>

        {selectedTaskType && (
          <>
            <FormField label="Profile" required>
              <Select
                value={selectedProfileId}
                onChange={(event) => setSelectedProfileId(event.target.value)}
                required
                disabled={!taskProfiles?.length}
              >
                <option value="">请选择 Profile</option>
                {taskProfiles?.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.display_name} · v{profile.version}
                  </option>
                ))}
              </Select>
            </FormField>
          </>
        )}

        {selectedProfile && (
          <>
            <section aria-live="polite">
              <h3 className="drawer-section-title">参数配置</h3>
              <div className="field-grid">
                {selectedProfile.schema.parameters.map((param) => renderParameterField(param))}
              </div>
            </section>
          </>
        )}

        <FormField label="优先级" hint="1 为最高优先级，可配置 1-9">
          <TextInput
            type="number"
            min={1}
            max={9}
            value={priority}
            onChange={(event) => setPriority(Number(event.target.value))}
          />
        </FormField>

        <FormField label="备注" hint="可选：说明此次任务背景">
          <Textarea value={notes} onChange={(event) => setNotes(event.target.value)} rows={3} />
        </FormField>

        <div className="actions">
          <Button type="submit" variant="primary" disabled={!canSubmit}>
            创建
          </Button>
          <Button type="button" variant="ghost" onClick={onClose}>
            取消
          </Button>
        </div>
      </form>
    </aside>
  );
}
