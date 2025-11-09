export const mockReportSummary = {
  items: [
    {
      result_id: '5f7d01ff-1a1b-4df4-8f31-93434cb21b1d',
      task_id: '6a3c3a34-0b6e-4de5-8b02-51f0af812f5c',
      task_type: 'respond',
      status: 'running',
      scenario_id: 'resp-001',
      metadata: { risk_score: '75' },
      completed_at: '2025-02-19T02:43:12Z',
    },
    {
      result_id: 'e11365aa-513d-4f9e-b7ab-806cb3104baf',
      task_id: 'b1f1c5e4-0a20-4a5b-96ed-c9b7cc3c8890',
      task_type: 'inventory',
      status: 'succeeded',
      metadata: { hosts: '32' },
      completed_at: '2025-02-18T11:40:39Z',
    },
  ],
  totals: { respond: 128, inventory: 64 },
  status: { running: 4, succeeded: 97, failed: 27 },
};
