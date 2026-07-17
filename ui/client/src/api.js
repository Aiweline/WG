const API_ROOT = '/api/v1';

export class ApiUnavailableError extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = 'ApiUnavailableError';
  }
}

export class ApiHttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.name = 'ApiHttpError';
    this.status = status;
    this.details = details;
  }
}

function operationId() {
  return globalThis.crypto?.randomUUID?.() || 'ui-' + Date.now() + '-' + Math.random().toString(16).slice(2);
}

function bytes(value, fallback) {
  if (typeof value !== 'number') return fallback;
  const units = ['B', 'KB', 'MB', 'GB'];
  let amount = value;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return amount.toFixed(index === 0 ? 0 : 1) + ' ' + units[index];
}

function duration(value, fallback) {
  if (typeof value !== 'number') return fallback;
  const hours = Math.floor(value / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  const seconds = Math.floor(value % 60);
  return [hours, minutes, seconds].map((part) => String(part).padStart(2, '0')).join(':');
}

function typeLabel(value) {
  const normalized = String(value || '').toUpperCase();
  if (normalized === 'IP') return 'IP';
  if (normalized === 'CIDR') return 'CIDR';
  return '域名';
}

function expiryLabel(value) {
  if (!value) return '永久';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString('zh-CN', { hour12: false });
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 1800);
  let response;
  try {
    response = await fetch(API_ROOT + path, {
      ...options,
      headers: {
        Accept: 'application/json',
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...options.headers,
      },
      signal: controller.signal,
    });
  } catch (error) {
    throw new ApiUnavailableError('WG 后台 API 当前不可用', error);
  } finally {
    window.clearTimeout(timeout);
  }

  if (!response.ok) {
    const details = await response.json().catch(() => null);
    const message = details?.error?.message || details?.message || (typeof details?.error === 'string' ? details.error : null) || (response.status === 501 ? '当前版本尚未实现此操作' : '请求失败（' + response.status + '）');
    throw new ApiHttpError(response.status, message, details);
  }
  if (response.status === 204) return null;
  return await response.json();
}

function post(path, payload = {}) {
  return request(path, { method: 'POST', body: JSON.stringify({ operation_id: operationId(), ...payload }) });
}

function normalizeStatus(payload) {
  const connection = payload?.connection || {};
  const routing = payload?.routing || {};
  const dns = payload?.dns || {};
  const versions = payload?.versions || {};
  return {
    status: {
      connection: String(connection.state || 'disconnected').toLowerCase(),
      endpoint: connection.endpoint || '—',
      duration: duration(connection.uptime_seconds, '—'),
      uploaded: bytes(connection.upload_bytes, '0 B'),
      downloaded: bytes(connection.download_bytes, '0 B'),
      routingMode: routing.mode || 'AUTO',
      dnsUnchanged: dns.system_dns_unchanged !== false,
      dnsState: String(dns.state || 'ready').toLowerCase(),
    },
    versions: {
      bundle: versions.bundle || '—',
      core: versions.core || '—',
      ui: versions.ui || '—',
      scripts: versions.scripts || '—',
      latest: versions.latest || versions.bundle || '—',
      platform: versions.platform || 'linux',
    },
  };
}

function normalizeRule(rule) {
  return {
    id: String(rule.id),
    target: rule.target,
    type: typeLabel(rule.target_type),
    action: String(rule.result || 'AUTO').toUpperCase(),
    source: String(rule.source || '').toLowerCase().includes('auto') ? '自动学习' : '手动',
    expires: expiryLabel(rule.expires_at),
    note: rule.note || '',
    revision: rule.revision,
  };
}

function normalizeRules(payload) {
  return (payload?.rules || []).map(normalizeRule);
}

function normalizeDns(payload) {
  return {
    state: String(payload?.state || 'ready').toLowerCase(),
    snapshotId: payload?.snapshot_id || '—',
    generatedAt: payload?.generated_at || '—',
    lastSync: payload?.last_synced_at || payload?.generated_at || '—',
    generation: payload?.generation || 0,
    upstreams: (payload?.upstreams || []).map((upstream) => typeof upstream === 'string' ? { address: upstream, state: 'ready', scope: 'system' } : {
      address: upstream.address,
      state: String(upstream.state || 'ready').toLowerCase(),
      scope: upstream.scope || 'system',
    }),
    cacheEntries: payload?.cache_entries || 0,
    hitRate: payload?.cache_hit_rate == null ? '—' : Number(payload.cache_hit_rate).toLocaleString('zh-CN', { style: 'percent', maximumFractionDigits: 1 }),
    ttl: payload?.min_ttl_seconds == null ? '—' : [payload.min_ttl_seconds, payload.avg_ttl_seconds, payload.max_ttl_seconds].filter((value) => value != null).map((value) => value + 's').join(' / '),
    unchanged: payload?.system_dns_unchanged !== false,
  };
}

const diagnosticChecks = [
  { needle: 'tunnel', id: 'tunnel', label: '隧道连接' },
  { needle: 'routing', id: 'routing', label: '分流引擎' },
  { needle: 'dns', id: 'dns', label: 'DNS（私有）' },
  { needle: 'script', id: 'scripts', label: '脚本环境' },
  { needle: 'privilege', id: 'permissions', label: '系统权限' },
  { needle: 'permission', id: 'permissions', label: '系统权限' },
];

function diagnosticState(value) {
  const state = String(value || '').toUpperCase();
  return ['HEALTHY', 'READY', 'CONNECTED', 'NORMAL', 'OK', 'NOT_REQUESTED'].includes(state) ? 'normal' : 'degraded';
}

function diagnosticTime(value) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString('zh-CN', { hour12: false });
}

export function normalizeDoctor(payload) {
  const health = (payload?.checks || []).map((check, index) => {
    const name = String(check?.name || '');
    const metadata = diagnosticChecks.find((item) => name.toLowerCase().includes(item.needle));
    return {
      id: metadata?.id || 'check-' + index,
      label: metadata?.label || name || '检查项 ' + (index + 1),
      state: diagnosticState(check?.state),
      rawState: String(check?.state || 'UNKNOWN').toUpperCase(),
      detail: check?.summary || '后台未提供详情',
    };
  });
  return {
    generatedAt: diagnosticTime(payload?.generated_at),
    redacted: payload?.redacted !== false,
    overall: String(payload?.overall || 'UNKNOWN').toUpperCase(),
    summary: payload?.summary || '',
    health,
  };
}

export function formatDiagnosticReport(report, systemDnsUnchanged = true) {
  if (!report) return '';
  const lines = [
    'WG 脱敏诊断报告',
    '检查时间：' + report.generatedAt,
    '总体状态：' + report.overall,
    ...report.health.map((item) => item.label + '：' + (item.state === 'normal' ? '正常' : '降级') + '；' + item.detail),
    '系统 DNS：' + (systemDnsUnchanged ? '未修改' : '状态异常'),
  ];
  if (report.summary) lines.push('摘要：' + report.summary);
  return lines.join('\n') + '\n';
}

export function normalizePairingValidation(payload) {
  return {
    valid: payload?.valid === true,
    validationId: payload?.validation_id || '',
    serverIp: payload?.server_ip || '',
    port: Number(payload?.port) || 0,
    fileName: payload?.file_name || '',
    fingerprint: payload?.fingerprint || '',
    expiresAt: payload?.expires_at || '',
    message: payload?.message || '',
  };
}

function rulePayload(rule) {
  const result = rule.action;
  const relativeExpiries = {
    '1 小时': 60 * 60 * 1000,
    '1 天': 24 * 60 * 60 * 1000,
    '3 天': 3 * 24 * 60 * 60 * 1000,
    '7 天': 7 * 24 * 60 * 60 * 1000,
  };
  let expiresAt;
  if (relativeExpiries[rule.expires]) {
    expiresAt = new Date(Date.now() + relativeExpiries[rule.expires]).toISOString();
  } else if (rule.expires && rule.expires !== '永久' && rule.expires !== '—') {
    const parsed = new Date(rule.expires);
    if (!Number.isNaN(parsed.getTime())) expiresAt = parsed.toISOString();
  }
  const editingManualRule = typeof rule.id === 'string' && rule.id.startsWith('rule-');
  if (editingManualRule && rule.revision == null) {
    throw new ApiHttpError(409, '规则版本缺失，请刷新列表后重试', null);
  }
  return {
    operation_id: operationId(),
    ...(editingManualRule ? { id: rule.id, expected_revision: rule.revision } : {}),
    target: rule.target,
    result,
    ...(expiresAt ? { expires_at: expiresAt } : {}),
    ...(rule.note ? { note: rule.note } : {}),
  };
}

export const api = {
  snapshot: () => request('/status').then(normalizeStatus),
  rules: () => request('/rules').then(normalizeRules),
  dns: () => request('/dns').then(normalizeDns),
  connect: () => post('/connection/connect'),
  disconnect: () => post('/connection/disconnect'),
  reconnect: () => post('/connection/reconnect'),
  saveRule: (rule) => request('/rules', { method: 'POST', body: JSON.stringify(rulePayload(rule)) }).then((payload) => payload?.rule ? normalizeRule(payload.rule) : null),
  deleteRule: (rule) => request('/rules/' + encodeURIComponent(rule.id), { method: 'DELETE', body: JSON.stringify({ operation_id: operationId(), ...(rule.revision == null ? {} : { expected_revision: rule.revision }) }) }),
  refreshDns: () => post('/dns/refresh').then((payload) => normalizeDns(payload?.dns || payload)),
  doctor: () => post('/diagnostics').then(normalizeDoctor),
  checkUpdate: () => post('/updates/check'),
  upgrade: () => post('/updates/upgrade'),
  rollback: () => post('/updates/rollback'),
  validatePairing: (payload) => request('/pairing/validate', { method: 'POST', body: JSON.stringify({
    server_ip: payload.serverIp,
    file_name: payload.fileName,
    ...(payload.fingerprint ? { fingerprint: payload.fingerprint } : {}),
  }) }).then(normalizePairingValidation),
  enroll: (payload) => post('/pairing/enroll', {
    server_ip: payload.serverIp,
    file_name: payload.fileName,
    validation_id: payload.validationId,
    fingerprint: payload.fingerprint,
    fingerprint_confirmed: Boolean(payload.fingerprintConfirmed),
    authorization_confirmed: Boolean(payload.authorizationConfirmed),
  }),
};
