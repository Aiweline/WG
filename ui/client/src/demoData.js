export const demoStatus = {
  connection: 'connected',
  endpoint: '203.0.113.10',
  duration: '01:23:45',
  uploaded: '128.6 MB',
  downloaded: '512.3 MB',
  routingMode: 'AUTO',
  dnsUnchanged: true,
  dnsState: 'degraded',
};

export const demoRules = [
  { id: 'r1', target: 'api.example.com', type: '域名', action: 'TUNNEL', source: '手动', expires: '永久', note: '内部 API' },
  { id: 'r2', target: '10.0.0.0/8', type: 'CIDR', action: 'DIRECT', source: '手动', expires: '永久', note: '本地网络' },
  { id: 'r3', target: 'lan.local', type: '域名', action: 'DIRECT', source: '自动学习', expires: '永久', note: '' },
  { id: 'r4', target: '192.168.1.0/24', type: 'CIDR', action: 'DIRECT', source: '手动', expires: '永久', note: '家庭局域网' },
  { id: 'r5', target: 'oneupdate.microsoft.com', type: '域名', action: 'BLOCK', source: '自动学习', expires: '7 天', note: '' },
  { id: 'r6', target: '203.0.113.55', type: 'IP', action: 'TUNNEL', source: '手动', expires: '3 天', note: '测试主机' },
  { id: 'r7', target: 'cdn.example.net', type: '域名', action: 'AUTO', source: '自动学习', expires: '永久', note: '' },
  { id: 'r8', target: '8.8.8.8', type: 'IP', action: 'DIRECT', source: '手动', expires: '永久', note: '显式直连' },
];

export const demoDns = {
  state: 'degraded',
  snapshotId: 'dns-snapshot-20260716-084512',
  generatedAt: '2026-07-16 08:45:12',
  lastSync: '2026-07-16 08:45:12',
  generation: 27,
  upstreams: [
    { address: '192.168.1.1', state: 'unreachable', scope: 'wlan0' },
    { address: '1.1.1.1', state: 'ready', scope: 'wlan0' },
  ],
  cacheEntries: 1248,
  hitRate: '92.6%',
  ttl: '30s / 300s / 86400s',
  unchanged: true,
};

export const demoVersions = {
  bundle: '1.2.3',
  core: '1.2.3',
  ui: '1.0.0',
  scripts: '1.2.3',
  latest: '1.2.4',
  platform: 'linux-amd64',
};

export const demoHealth = [
  { id: 'tunnel', label: '隧道连接', state: 'normal', detail: '已连接到端点 203.0.113.10' },
  { id: 'routing', label: '分流引擎', state: 'normal', detail: '分流规则加载正常，运行中' },
  { id: 'dns', label: 'DNS（私有）', state: 'degraded', detail: '部分上游不可达' },
  { id: 'scripts', label: '脚本环境', state: 'normal', detail: '脚本签名有效，版本兼容' },
  { id: 'permissions', label: '系统权限', state: 'normal', detail: '所需系统权限充足' },
];

export const demoDiagnostics = {
  generatedAt: '2026-07-16 08:45:12',
  redacted: true,
  overall: 'DEGRADED',
  summary: '安全演示诊断；未读取真实系统状态。',
  health: demoHealth,
};

export const serverFingerprint = 'wgs-p7dz-k4m2-qc6n-b5ta-vr8x-y2hf-j3we-s9ku';
