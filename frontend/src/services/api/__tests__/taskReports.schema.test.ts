import { describe, it, expect } from 'vitest';
import { TaskAuditReportSchema, TaskDetectReportSchema } from '../schemas';

describe('Task audit/detect report schemas', () => {
  it('parses audit report payload', () => {
    const payload = {
      task_id: '00000000-0000-0000-0000-000000000001',
      task_type: 'audit',
      profile: 'scan',
      run_id: '00000000-0000-0000-0000-000000000002',
      agent_id: '00000000-0000-0000-0000-000000000003',
      task_status: 'succeeded',
      result: {
        status: 'succeeded',
        summary: {
          command: 'audit',
          status: 'succeeded',
          duration_seconds: 1.23,
          risks: { high: 1 },
          notes: ['ok'],
          outputs: [
            {
              path: 'C:\\\\reports\\\\audit.json',
              type: 'json',
              content_type: 'application/json',
              label: 'audit report',
            },
          ],
        },
        artifacts: [{ path: 'C:\\\\reports\\\\artifact.zip', label: 'artifacts' }],
        metadata: { module: 'audit' },
        exit_code: 0,
        reported_at: '2025-01-01T00:00:00.000Z',
      },
      run_metadata: { module: 'audit' },
      exit_code: 0,
      completed_at: '2025-01-01T00:00:00.000Z',
    };

    const parsed = TaskAuditReportSchema.parse(payload);
    expect(parsed.task_type).toBe('audit');
    expect(parsed.result.summary.command).toBe('audit');
  });

  it('parses detect report payload', () => {
    const payload = {
      task_id: '00000000-0000-0000-0000-000000000011',
      task_type: 'detect.memscan',
      run_id: '00000000-0000-0000-0000-000000000012',
      agent_id: '00000000-0000-0000-0000-000000000013',
      task_status: 'failed',
      result: {
        status: 'failed',
        summary: {
          command: 'memscan',
          status: 'failed',
          duration_seconds: 0.5,
        },
        error: 'approval required',
        error_code: 'detect.memscan.approval_required',
      },
      exit_code: 65,
      error_code: 'detect.memscan.approval_required',
    };

    const parsed = TaskDetectReportSchema.parse(payload);
    expect(parsed.task_type).toBe('detect.memscan');
    expect(parsed.exit_code).toBe(65);
  });
});

