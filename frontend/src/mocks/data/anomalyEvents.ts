export const mockAnomalyEvents = [
  {
    event: 'created',
    timestamp: new Date(Date.now() - 60_000).toISOString(),
    anomaly: {
      id: '11111111-2222-3333-4444-555555555555',
      agent_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      task_id: '99999999-8888-7777-6666-555555555555',
      ioc: 'malicious.exe',
      entities: ['svchost.exe', '10.0.1.24:445'],
      severity: 'high',
      score: 82.3,
      summary: {
        reason: 'high_cpu',
        cpu_percent: 94.2,
        suspicious_remotes: ['10.0.1.24:445'],
      },
      status: 'open',
      created_at: new Date(Date.now() - 120_000).toISOString(),
      updated_at: new Date(Date.now() - 60_000).toISOString(),
    },
    graph: {
      nodes: [
        {
          id: '00000000-0000-0000-0000-000000000001',
          anomaly_id: '11111111-2222-3333-4444-555555555555',
          type: 'agent',
          label: 'srv-prod-01',
          properties: { max_cpu: 96, blocked: ['isolate_process'] },
          created_at: new Date(Date.now() - 60_000).toISOString(),
        },
        {
          id: '00000000-0000-0000-0000-000000000002',
          anomaly_id: '11111111-2222-3333-4444-555555555555',
          type: 'process_summary',
          label: 'Top Processes',
          properties: { top: [{ name: 'svchost.exe', count: 8 }] },
          created_at: new Date(Date.now() - 60_000).toISOString(),
        },
      ],
      edges: [
        {
          id: '00000000-0000-0000-0000-000000000003',
          anomaly_id: '11111111-2222-3333-4444-555555555555',
          source_node: '00000000-0000-0000-0000-000000000001',
          target_node: '00000000-0000-0000-0000-000000000002',
          type: 'runs',
          properties: {},
          created_at: new Date(Date.now() - 60_000).toISOString(),
        },
      ],
    },
  },
  {
    event: 'created',
    timestamp: new Date(Date.now() - 20_000).toISOString(),
    anomaly: {
      id: '22222222-3333-4444-5555-666666666666',
      agent_id: 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
      ioc: '104.26.8.46',
      entities: ['powershell.exe', '104.26.8.46:443'],
      severity: 'medium',
      score: 58.9,
      summary: {
        reason: 'telemetry_observed',
        keys: ['telemetry.process_tree', 'telemetry.net_connections'],
      },
      status: 'open',
      created_at: new Date(Date.now() - 40_000).toISOString(),
      updated_at: new Date(Date.now() - 20_000).toISOString(),
    },
    graph: {
      nodes: [
        {
          id: '00000000-0000-0000-0000-000000000004',
          anomaly_id: '22222222-3333-4444-5555-666666666666',
          type: 'agent',
          label: 'db-core-02',
          properties: { max_cpu: 72, window_seconds: 300 },
          created_at: new Date(Date.now() - 20_000).toISOString(),
        },
      ],
      edges: [],
    },
  },
];
