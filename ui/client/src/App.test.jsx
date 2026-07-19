import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from './App.jsx';

const liveStatus = {
  connection: { state: 'connected', endpoint: '203.0.113.10', uptime_seconds: 20, upload_bytes: 10, download_bytes: 20 },
  routing: { mode: 'AUTO' },
  dns: { state: 'ready', system_dns_unchanged: true },
  versions: { bundle: '1.2.3', core: '1.2.3', ui: '1.0.0', scripts: '1.2.3', latest: '1.2.4' },
};

const liveDns = { state: 'ready', system_dns_unchanged: true, upstreams: [], generation: 4 };

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function liveBackend(handler) {
  return vi.fn(async (url, options = {}) => {
    const custom = handler ? await handler(String(url), options) : undefined;
    if (custom !== undefined) return custom;
    if (String(url).endsWith('/status')) return response(liveStatus);
    if (String(url).endsWith('/rules') && !options.method) return response({ rules: [] });
    if (String(url).endsWith('/dns') && !options.method) return response(liveDns);
    return response({}, 404);
  });
}

describe('WG client', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
  });

  afterEach(() => {
    cleanup();
    Object.defineProperty(window.navigator, 'clipboard', { configurable: true, value: undefined });
    vi.unstubAllGlobals();
  });

  it('falls back to an explicit safe demo without hiding connection state', async () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: '连接' })).toBeInTheDocument();
    expect(await screen.findByText('安全演示 · 不修改系统')).toBeInTheDocument();
    expect(screen.getByText('未修改系统 DNS')).toBeInTheDocument();
  });

  it('keeps live state unchanged and does not show success when a live mutation loses the backend', async () => {
    const user = userEvent.setup();
    vi.stubGlobal('fetch', liveBackend((url) => {
      if (url.endsWith('/connection/disconnect')) throw new TypeError('connection lost');
      return undefined;
    }));

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '断开连接' }));

    expect(await screen.findByText(/无法确认操作结果/)).toBeInTheDocument();
    expect(screen.getAllByText('已连接').length).toBeGreaterThan(0);
    expect(screen.queryByText(/隧道已安全断开/)).not.toBeInTheDocument();
  });

  it('filters rules and restores a deleted override to AUTO in demo mode', async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText('安全演示 · 不修改系统');
    await user.click(screen.getByRole('button', { name: '智能分流' }));
    const search = screen.getByPlaceholderText('搜索域名或 IP');
    await user.type(search, 'api.example.com');
    const row = screen.getByText('api.example.com').closest('tr');
    expect(within(row).getByText('TUNNEL')).toBeInTheDocument();
    await user.click(within(row).getByRole('button', { name: '删除 api.example.com' }));
    await user.click(screen.getByRole('button', { name: '删除并恢复 AUTO' }));
    await waitFor(() => expect(within(row).getByText('AUTO')).toBeInTheDocument());
  });

  it('removes a successfully deleted live rule instead of retaining an invalid AUTO row', async () => {
    const user = userEvent.setup();
    const rule = { id: 'rule-7', target: 'api.example.com', target_type: 'DOMAIN', result: 'TUNNEL', source: 'MANUAL', revision: 9 };
    vi.stubGlobal('fetch', liveBackend((url, options) => {
      if (url.endsWith('/rules') && !options.method) return response({ rules: [rule] });
      if (url.endsWith('/rules/rule-7') && options.method === 'DELETE') return response({ state: 'DELETED' });
      return undefined;
    }));

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '智能分流' }));
    await user.click(screen.getByRole('button', { name: '删除 api.example.com' }));
    await user.click(screen.getByRole('button', { name: '删除并恢复 AUTO' }));

    await waitFor(() => expect(screen.queryByText('api.example.com')).not.toBeInTheDocument());
  });

  it('keeps an existing manual target read-only and sends its revision when edited', async () => {
    const user = userEvent.setup();
    const rule = { id: 'rule-7', target: 'api.example.com', target_type: 'DOMAIN', result: 'TUNNEL', source: 'MANUAL', revision: 9 };
    const fetchMock = liveBackend((url, options) => {
      if (url.endsWith('/rules') && !options.method) return response({ rules: [rule] });
      if (url.endsWith('/rules') && options.method === 'POST') return response({ rule: { ...rule, result: 'DIRECT', revision: 10 } });
      return undefined;
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '智能分流' }));
    await user.click(screen.getByRole('button', { name: '编辑 api.example.com' }));
    const drawer = screen.getByRole('dialog', { name: '编辑规则' });
    expect(within(drawer).getByLabelText('目标')).toHaveAttribute('readonly');
    await user.selectOptions(within(drawer).getByLabelText('结果'), 'DIRECT');
    await user.click(within(drawer).getByRole('button', { name: '保存' }));

    let saveCall;
    await waitFor(() => {
      saveCall = fetchMock.mock.calls.find(([url, options]) => String(url).endsWith('/rules') && options.method === 'POST');
      expect(saveCall).toBeTruthy();
    });
    const body = JSON.parse(saveCall[1].body);
    expect(body).toMatchObject({ id: 'rule-7', expected_revision: 9, target: 'api.example.com', result: 'DIRECT' });
  });

  it('keeps the rule editor open when the backend rejects a live save', async () => {
    const user = userEvent.setup();
    const rule = { id: 'rule-7', target: 'api.example.com', target_type: 'DOMAIN', result: 'TUNNEL', source: 'MANUAL', revision: 9 };
    vi.stubGlobal('fetch', liveBackend((url, options) => {
      if (url.endsWith('/rules') && !options.method) return response({ rules: [rule] });
      if (url.endsWith('/rules') && options.method === 'POST') return response({ error: { message: '规则版本已变化' } }, 409);
      return undefined;
    }));

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '智能分流' }));
    await user.click(screen.getByRole('button', { name: '编辑 api.example.com' }));
    await user.click(within(screen.getByRole('dialog', { name: '编辑规则' })).getByRole('button', { name: '保存' }));

    expect(await screen.findByText('规则版本已变化')).toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: '编辑规则' })).toBeInTheDocument();
  });

  it('turns an edited auto decision into a new manual override without auto id or revision', async () => {
    const user = userEvent.setup();
    const learned = { id: 'auto-12', target: 'learned.example.com', target_type: 'DOMAIN', result: 'DIRECT', source: 'AUTO', revision: 6 };
    const fetchMock = liveBackend((url, options) => {
      if (url.endsWith('/rules') && !options.method) return response({ rules: [learned] });
      if (url.endsWith('/rules') && options.method === 'POST') return response({ rule: { ...learned, id: 'rule-13', result: 'TUNNEL', source: 'MANUAL', revision: 7 } });
      return undefined;
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '智能分流' }));
    await user.click(screen.getByRole('button', { name: '编辑 learned.example.com' }));
    const drawer = screen.getByRole('dialog', { name: '创建手动覆盖' });
    expect(within(drawer).getByLabelText('目标')).toHaveAttribute('readonly');
    await user.selectOptions(within(drawer).getByLabelText('结果'), 'TUNNEL');
    await user.click(within(drawer).getByRole('button', { name: '保存' }));

    let saveCall;
    await waitFor(() => {
      saveCall = fetchMock.mock.calls.find(([url, options]) => String(url).endsWith('/rules') && options.method === 'POST');
      expect(saveCall).toBeTruthy();
    });
    const body = JSON.parse(saveCall[1].body);
    expect(body).not.toHaveProperty('id');
    expect(body).not.toHaveProperty('expected_revision');
    await waitFor(() => expect(screen.getAllByText('learned.example.com')).toHaveLength(1));
  });

  it('starts pairing at step 1 and uses the validated session data for IPv6 enrollment', async () => {
    const user = userEvent.setup();
    const futureExpiry = '2030-07-17T01:02:03Z';
    const fetchMock = liveBackend((url, options) => {
      if (url.endsWith('/pairing/validate')) {
        const body = JSON.parse(options.body);
        const second = body.server_ip.includes(':');
        return response({
          valid: true,
          validation_id: second ? 'validation-ipv6' : 'validation-ipv4',
          server_ip: body.server_ip,
          port: second ? 51999 : 9518,
          file_name: body.file_name,
          fingerprint: second ? 'wgs-ipv6-validated-fingerprint' : 'wgs-ipv4-validated-fingerprint',
          expires_at: futureExpiry,
        });
      }
      if (url.endsWith('/pairing/enroll')) return response({ state: 'ENROLLED' });
      return undefined;
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '首次配对' }));
    expect(screen.getByRole('heading', { name: '输入服务器 IP' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    expect(await screen.findByText('wgs-ipv4-validated-fingerprint')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /服务器 IP/ }));
    const serverInput = screen.getByLabelText('服务器 IP');
    await user.clear(serverInput);
    await user.type(serverInput, '2001:db8::10');
    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    await user.click(screen.getByRole('button', { name: '确认并继续' }));

    expect(await screen.findByText('wgs-ipv6-validated-fingerprint')).toBeInTheDocument();
    expect(screen.getByText(/\[2001:db8::10\]:51999/)).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: /独立渠道核对/ }));
    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    await user.click(screen.getByRole('checkbox', { name: /最小授权范围/ }));
    await user.click(screen.getByRole('button', { name: '授权并完成配对' }));
    expect(await screen.findByRole('heading', { name: '配对成功' })).toBeInTheDocument();
    await user.click(screen.getByText('返回连接页', { exact: true }));
    expect(screen.getByText('[2001:db8::10]:51999')).toBeInTheDocument();

    const validateCalls = fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/pairing/validate'));
    expect(validateCalls).toHaveLength(2);
    const enrollCall = fetchMock.mock.calls.find(([url]) => String(url).endsWith('/pairing/enroll'));
    expect(JSON.parse(enrollCall[1].body)).toMatchObject({
      validation_id: 'validation-ipv6',
      server_ip: '2001:db8::10',
      file_name: 'wg-pairing.wgp',
      fingerprint: 'wgs-ipv6-validated-fingerprint',
      fingerprint_confirmed: true,
      authorization_confirmed: true,
    });
  });

  it('uses the project demo fingerprint only after demo validation', async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText('安全演示 · 不修改系统');
    await user.click(screen.getByRole('button', { name: '首次配对' }));
    expect(screen.queryByText(/BLAKE2s-256/)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    expect(await screen.findByText(/BLAKE2s-256/)).toBeInTheDocument();
    expect(screen.getAllByText(/^wgs-/)[0]).toHaveTextContent('wgs-p7dz-k4m2-qc6n-b5ta-vr8x-y2hf-j3we-s9ku');
  });

  it('rejects a non-standard pairing filename before validation', async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText('安全演示 · 不修改系统');
    await user.click(screen.getByRole('button', { name: '首次配对' }));
    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    await user.upload(screen.getByLabelText('选择配对文件'), new File(['pairing'], 'other.wgp', { type: 'application/octet-stream' }));
    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    expect(screen.getByRole('alert')).toHaveTextContent('配对文件名必须精确为 wg-pairing.wgp');
  });

  it('uses normalized live diagnostics for health, DNS details, and clipboard output', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(window.navigator, 'clipboard', { configurable: true, value: { writeText } });
    const report = {
      generated_at: '2026-07-17T01:02:03Z',
      redacted: true,
      overall: 'DEGRADED',
      checks: [
        { name: 'Tunnel connection', state: 'CONNECTED', summary: 'live tunnel check' },
        { name: 'Smart routing', state: 'HEALTHY', summary: 'live generation 42' },
        { name: 'Private DNS', state: 'DEGRADED', summary: 'live upstream scope check' },
      ],
      summary: 'live redacted summary',
    };
    vi.stubGlobal('fetch', liveBackend((url) => url.endsWith('/diagnostics') ? response(report) : undefined));

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '健康与更新' }));
    expect(screen.getByText('尚未诊断')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '一键诊断' }));
    expect(await screen.findByText('live generation 42')).toBeInTheDocument();
    expect(screen.queryByText('分流规则加载正常，运行中')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '复制到剪贴板' }));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('live generation 42'));

    await user.click(screen.getByRole('button', { name: '私有 DNS' }));
    await user.click(screen.getByRole('button', { name: '诊断' }));
    expect(await screen.findByText('live upstream scope check')).toBeInTheDocument();
    expect(screen.getByText('live redacted summary WG 不会为了恢复而替换系统 DNS。')).toBeInTheDocument();
  });

  it('does not report a live 501 upgrade as successful', async () => {
    const user = userEvent.setup();
    vi.stubGlobal('fetch', liveBackend((url) => {
      if (url.endsWith('/updates/check')) return response({ available_version: '1.2.4', compatible: true, manifest_verified: true });
      if (url.endsWith('/updates/upgrade')) return response({ error: { message: '尚未实现' } }, 501);
      return undefined;
    }));

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '健康与更新' }));
    await user.click(screen.getByRole('button', { name: '检查更新' }));
    await screen.findByText('可更新');
    await user.click(screen.getByRole('button', { name: '升级' }));
    expect(await screen.findByText(/没有执行升级或回滚/)).toBeInTheDocument();
    expect(screen.getByText('可更新')).toBeInTheDocument();
    expect(screen.queryByText('已是最新')).not.toBeInTheDocument();
  });

  it('does not enable an update advertised by an unverified legacy flag', async () => {
    const user = userEvent.setup();
    vi.stubGlobal('fetch', liveBackend((url) => {
      if (url.endsWith('/updates/check')) return response({ available: true, latest: '9.9.9', compatible: true, manifest_verified: false, message: '签名清单未通过验证' });
      return undefined;
    }));

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '健康与更新' }));
    await user.click(screen.getByRole('button', { name: '检查更新' }));

    expect(await screen.findByText('无可用签名更新')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '升级' })).toBeDisabled();
    expect(screen.queryByText('可更新')).not.toBeInTheDocument();
  });
});
