import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, formatDiagnosticReport } from './api.js';

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function serverRule(overrides = {}) {
  return {
    id: 'rule-1',
    target: 'api.example.com',
    target_type: 'DOMAIN',
    result: 'TUNNEL',
    source: 'MANUAL',
    revision: 3,
    ...overrides,
  };
}

describe('API contracts', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('converts a relative expiry option to RFC3339 for the Go API', async () => {
    const start = Date.now();
    const fetchMock = vi.fn().mockResolvedValue(response({
      rule: serverRule({ expires_at: new Date(start + 60 * 60 * 1000).toISOString() }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    await api.saveRule({ target: 'api.example.com', action: 'TUNNEL', expires: '1 小时', note: '' });

    const requestBody = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(requestBody.expires_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    const delta = new Date(requestBody.expires_at).getTime() - start;
    expect(delta).toBeGreaterThanOrEqual(60 * 60 * 1000 - 1000);
    expect(delta).toBeLessThanOrEqual(60 * 60 * 1000 + 1000);
  });

  it('sends id and expected_revision only for an existing manual rule', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ rule: serverRule({ revision: 10 }) }));
    vi.stubGlobal('fetch', fetchMock);

    await api.saveRule({ id: 'rule-7', revision: 9, target: 'api.example.com', action: 'DIRECT', expires: '永久', note: '' });
    const manualBody = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(manualBody).toMatchObject({ id: 'rule-7', expected_revision: 9, target: 'api.example.com', result: 'DIRECT' });

    await api.saveRule({ id: 'auto-7', revision: 12, target: 'learned.example.com', action: 'TUNNEL', expires: '永久', note: '' });
    const learnedBody = JSON.parse(fetchMock.mock.calls[1][1].body);
    expect(learnedBody).not.toHaveProperty('id');
    expect(learnedBody).not.toHaveProperty('expected_revision');
  });

  it('normalizes doctor output and formats the same live data for copy and export', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({
      generated_at: '2026-07-17T01:02:03Z',
      redacted: true,
      overall: 'DEGRADED',
      checks: [
        { name: 'Tunnel connection', state: 'CONNECTED', summary: 'live tunnel detail' },
        { name: 'Private DNS', state: 'DEGRADED', summary: 'live DNS detail' },
      ],
      summary: 'live summary',
    })));

    const report = await api.doctor();
    expect(report.health).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: 'tunnel', state: 'normal', detail: 'live tunnel detail' }),
      expect.objectContaining({ id: 'dns', state: 'degraded', detail: 'live DNS detail' }),
    ]));
    const text = formatDiagnosticReport(report, true);
    expect(text).toContain('live tunnel detail');
    expect(text).toContain('live DNS detail');
    expect(text).toContain('live summary');
    expect(text).toContain('系统 DNS：未修改');
  });
});
