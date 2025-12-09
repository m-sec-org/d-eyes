import { render, screen, waitFor, within, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ComplianceDashboard } from '@/features/compliance/ComplianceDashboard';

const frameworkId = '11111111-1111-1111-1111-111111111111';
const controlId = '22222222-2222-2222-2222-222222222222';
const frameworks = [
  {
    id: frameworkId,
    key: 'cis',
    title: 'CIS Benchmarks',
    version: '1.0',
    description: 'CIS baseline',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

const controls = [
  {
    id: controlId,
    framework_id: frameworkId,
    code: 'AC-1',
    title: 'Access Control',
    severity: 'high',
    description: 'Restrict root logins',
    references: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

const remediationLogs = [
  { author: 'Alice', note: '初次排查', timestamp: new Date('2024-01-01T00:00:00Z').toISOString() },
  { author: 'Bob', note: '通知负责人', timestamp: new Date('2024-01-02T00:00:00Z').toISOString() },
  { author: 'Charlie', note: '提交整改计划', timestamp: new Date('2024-01-03T00:00:00Z').toISOString() },
];

const gaps = [
  {
    id: '33333333-3333-3333-3333-333333333333',
    framework_id: frameworkId,
    control_id: controlId,
    asset_ref: 'asset-prod-01',
    status: 'open',
    evidence: null,
    remediation_logs: remediationLogs,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

vi.mock('@/services/api/compliance', () => ({
  listComplianceFrameworks: vi.fn(async () => frameworks),
  listComplianceControls: vi.fn(async () => controls),
  listComplianceGaps: vi.fn(async () => gaps),
  addRemediationNote: vi.fn(async () => gaps[0]),
}));

if (!global.ResizeObserver) {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

const renderDashboard = () =>
  render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <ComplianceDashboard />
    </SWRConfig>
  );

describe('ComplianceDashboard remediation workflow', () => {
  beforeEach(() => {
    window.innerWidth = 1280;
  });

  it('surfaces the two most recent remediation notes inside the form panel', async () => {
    const user = userEvent.setup();
    renderDashboard();

    await screen.findByText('控制项');
    const assetButton = await screen.findByText('asset-prod-01');
    await user.click(assetButton);

    const notesContainer = await screen.findByTestId('recent-remediation-notes');
    const noteItems = within(notesContainer).getAllByRole('listitem');
    expect(noteItems).toHaveLength(2);
    expect(noteItems[0]).toHaveTextContent('Charlie');
    expect(noteItems[1]).toHaveTextContent('Bob');
    expect(notesContainer.textContent).not.toContain('Alice');
  });

  it('updates layout mode metadata when viewport shrinks to stacked mode', async () => {
    renderDashboard();
    const gapLayout = await screen.findByTestId('gap-layout');
    expect(gapLayout).toHaveAttribute('data-layout-mode', 'split');

    await act(async () => {
      window.innerWidth = 900;
      window.dispatchEvent(new Event('resize'));
      await waitFor(() => expect(gapLayout).toHaveAttribute('data-layout-mode', 'stacked'));
    });
  });
});
