import { describe, expect, it } from 'vitest';
import { filterJobs, getErrorDocLink, sortArtifacts, statusColor } from '../ThreatIntelWorkspace';
import type { ThreatIntelJob } from '@/services/types';

describe('ThreatIntelWorkspace helpers', () => {
  it('sorts artifacts by name', () => {
    const artifacts = [
      { id: '1', mime_type: 'b/text', sha256: 'b' },
      { id: '2', mime_type: 'a/json', sha256: 'a' },
    ];
    const sorted = sortArtifacts(artifacts, 'name');
    expect(sorted[0].id).toBe('2');
  });

  it('filters and sorts jobs by status', () => {
    const jobs: ThreatIntelJob[] = [
      { id: '1', source: 'opentip', status: 'failed', attempt: 1, updated_at: '2024-01-01T00:00:00Z' },
      { id: '2', source: 'metadefender', status: 'running', attempt: 1, updated_at: '2024-01-01T00:00:00Z' },
    ];
    const filtered = filterJobs(jobs, 'meta', 'status');
    expect(filtered).toHaveLength(1);
    expect(filtered[0].source).toBe('metadefender');
  });

  it('builds error doc link', () => {
    expect(getErrorDocLink('TI_PROVIDER_TIMEOUT')).toContain('#ti_provider_timeout');
  });

  it('maps status to color', () => {
    expect(statusColor('succeeded')).toBe('green');
    expect(statusColor('failed')).toBe('red');
  });
});
