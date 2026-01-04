import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';

import { listTaskProfiles, listTaskTypes } from '@/services/api/taskCatalog';
import { createTask } from '@/services/api/taskActions';
import type { TaskProfileParameter, TaskTypeDefinition } from '@/services/types';
import { Button, Checkbox, FormField, Select, Textarea, TextInput } from '@/components/ui';

interface CreateTaskDrawerProps {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}

const buildRequiredCapabilities = (taskType: string, taskTypes?: TaskTypeDefinition[]) => {
  const typ = taskTypes?.find((item) => item.name === taskType);
  const caps = (typ?.capabilities ?? []).map((cap) => cap.trim()).filter(Boolean);
  return caps.length > 0 ? caps.join(',') : taskType;
};

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
  const [memscanApproved, setMemscanApproved] = useState(false);
  const [memscanEvidenceApproved, setMemscanEvidenceApproved] = useState(false);

  const selectedProfile = useMemo(
    () => taskProfiles?.find((profile) => profile.id === selectedProfileId),
    [taskProfiles, selectedProfileId]
  );

  const isMemscanTask = selectedTaskType === 'detect.memscan';
  const showMemscanValidation = Boolean(isMemscanTask && selectedProfile);
  const memscanEvidenceRequested = Boolean(parameterValues.evidence) || Boolean(parameterValues.minidump);
  const memscanValidationErrors = useMemo(() => {
    if (!showMemscanValidation) {
      return {};
    }
    const errors: Record<string, string> = {};
    const allSelected = Boolean(parameterValues.all);
    const pid = typeof parameterValues.pid === 'number' ? parameterValues.pid : undefined;
    const pidProvided = pid !== undefined && !Number.isNaN(pid);

    if (allSelected && pidProvided) {
      errors.all = 'pid 与 all 必须二选一';
      errors.pid = 'pid 与 all 必须二选一';
    } else if (!allSelected && !pidProvided) {
      errors.all = '请选择 all 或填写 pid';
      errors.pid = '请选择 all 或填写 pid';
    } else if (pidProvided) {
      if (!Number.isInteger(pid) || pid < 1) {
        errors.pid = 'pid 必须为 >= 1 的整数';
      }
    }

    if (!memscanApproved) {
      errors.memscan_approved = '需要确认已获得 memscan 执行审批';
    }
    if (memscanEvidenceRequested && !memscanEvidenceApproved) {
      errors.memscan_evidence_approved = 'evidence/minidump 需要额外审批确认';
    }
    return errors;
  }, [
    memscanApproved,
    memscanEvidenceApproved,
    memscanEvidenceRequested,
    parameterValues.all,
    parameterValues.pid,
    showMemscanValidation,
  ]);

  useEffect(() => {
    if (!open) {
      setSelectedTaskType('');
      setSelectedProfileId('');
      setPriority(3);
      setNotes('');
      setParameterValues({});
      setMemscanApproved(false);
      setMemscanEvidenceApproved(false);
    }
  }, [open]);

  useEffect(() => {
    setSelectedProfileId('');
    setParameterValues({});
    setMemscanApproved(false);
    setMemscanEvidenceApproved(false);
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

  useEffect(() => {
    if (!memscanEvidenceRequested) {
      setMemscanEvidenceApproved(false);
    }
  }, [memscanEvidenceRequested]);

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

    const metadata: Record<string, string> = {};
    const trimmedNotes = notes.trim();
    if (trimmedNotes) {
      metadata.notes = trimmedNotes;
    }
    metadata.required_capabilities = buildRequiredCapabilities(selectedTaskType, taskTypes);

    if (isMemscanTask) {
      if (Object.keys(memscanValidationErrors).length > 0) {
        return;
      }
      metadata.memscan_approval_required = 'true';
      metadata.memscan_approved = 'true';
      if (memscanEvidenceRequested) {
        metadata.memscan_evidence_approved = 'true';
      }

      const allSelected = payload.all === true;
      const pid = typeof payload.pid === 'number' ? payload.pid : undefined;
      const pidProvided = pid !== undefined && !Number.isNaN(pid);
      if (allSelected) {
        delete payload.pid;
        payload.all = true;
      } else if (pidProvided) {
        delete payload.all;
        payload.pid = pid;
      }
    }

    await createTask({
      type: selectedTaskType,
      profile: selectedProfile.id,
      priority,
      payload,
      metadata,
      created_by: 'ops.lead',
    });
    onCreated();
    onClose();
  };

  const handleParamChange = (key: string, value: unknown) => {
    setParameterValues((prev) => {
      const next: Record<string, unknown> = { ...prev, [key]: value };
      if (isMemscanTask) {
        if (key === 'all') {
          if (value === true) {
            delete next.pid;
          } else {
            delete next.all;
          }
        }
        if (key === 'pid') {
          const pid = typeof value === 'number' ? value : undefined;
          if (pid !== undefined && !Number.isNaN(pid)) {
            delete next.all;
          }
        }
      }
      return next;
    });
  };

  const renderParameterField = (param: TaskProfileParameter) => {
    const value = parameterValues[param.key];
    const error = memscanValidationErrors[param.key];
    const fieldProps = {
      label: param.label,
      required: param.required,
      hint: param.hint,
      error,
    };

    switch (param.type) {
      case 'boolean':
        return (
          <FormField key={param.key} {...fieldProps}>
            <Checkbox
              checked={Boolean(value)}
              onChange={(event) => handleParamChange(param.key, event.target.checked)}
              label={param.hint ?? '启用'}
            />
          </FormField>
        );
      case 'number':
        return (
          <FormField key={param.key} {...fieldProps}>
            <TextInput
              type="number"
              value={typeof value === 'number' ? value : ''}
              min={param.min}
              max={param.max}
              step={param.key === 'pid' && isMemscanTask ? 1 : undefined}
              invalid={Boolean(error)}
              required={param.required}
              onChange={(event) =>
                handleParamChange(param.key, event.target.value === '' ? undefined : Number(event.target.value))
              }
            />
          </FormField>
        );
      case 'enum':
        return (
          <FormField key={param.key} {...fieldProps}>
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
          <FormField key={param.key} {...fieldProps}>
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
          <FormField key={param.key} {...fieldProps}>
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
          <FormField key={param.key} {...fieldProps}>
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

  const canSubmit =
    Boolean(open && selectedTaskType && selectedProfileId) &&
    (!showMemscanValidation || Object.keys(memscanValidationErrors).length === 0);

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

        {isMemscanTask && (
          <section aria-live="polite">
            <h3 className="drawer-section-title">Memscan 审批</h3>
            <p className="muted">
              Windows-only，且需要 Agent 侧 opt-in：<code>allow_memscan="true"</code>。如启用 evidence/minidump 还需额外审批。
            </p>
            <FormField label="执行审批" required error={memscanValidationErrors.memscan_approved}>
              <Checkbox
                checked={memscanApproved}
                onChange={(event) => {
                  setMemscanApproved(event.target.checked);
                }}
                label='已获得 memscan 执行审批（写入 metadata: memscan_approval_required="true", memscan_approved="true"）'
              />
            </FormField>

            {memscanEvidenceRequested && (
              <FormField
                label="Evidence/Minidump 审批"
                required
                error={memscanValidationErrors.memscan_evidence_approved}
              >
                <Checkbox
                  checked={memscanEvidenceApproved}
                  onChange={(event) => {
                    setMemscanEvidenceApproved(event.target.checked);
                  }}
                  label='已获得 evidence/minidump 审批（写入 metadata: memscan_evidence_approved="true"）'
                />
              </FormField>
            )}
          </section>
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
