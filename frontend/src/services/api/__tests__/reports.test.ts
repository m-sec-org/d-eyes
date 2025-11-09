import { describe, it, expect } from 'vitest';
import { ReportSummarySchema } from '../schemas';
import { mockReportSummary } from '@/mocks/data/reports';

describe('Report summary schema', () => {
  it('accepts mock risk summary data', () => {
    const parsed = ReportSummarySchema.parse(mockReportSummary);
    expect(parsed.items.length).toBeGreaterThan(0);
    expect(parsed.status.running).toBeDefined();
  });
});
