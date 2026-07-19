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
const emptyProxyConfig = { servers: [], selected_endpoint: '', transport: 'tcp', udp_target: '1.1.1.1:53' };
const disconnectedProxy = {
  configured: false,
  connected: false,
  tcp_listener: false,
  udp_listener: false,
  managed: false,
  selected_endpoint: '',
  transport: 'tcp',
  udp_target: '1.1.1.1:53',
  servers: [],
};

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function backend(handler, { coreLive = true } = {}) {
  return vi.fn(async (input, options = {}) => {
    const url = String(input);
    const method = options.method || 'GET';
    const custom = handler ? await handler(url, method, options) : undefined;
    if (custom !== undefined) return custom;

    if (url === '/api/proxy/status' && method === 'GET') return response(disconnectedProxy);
    if (url === '/api/proxy/config' && method === 'GET') return response(emptyProxyConfig);
    if (url === '/api/v1/status' && coreLive) return response(liveStatus);
    if (url === '/api/v1/rules' && method === 'GET' && coreLive) return response({ rules: [] });
    if (url === '/api/v1/dns' && method === 'GET' && coreLive) return response(liveDns);
    if (url.startsWith('/api/v1/') && !coreLive) throw new TypeError('wg-core offline');
    return response({}, 404);
  });
}

async function fillServer(user, ip = '47.92.25.188', port = '9518') {
  await user.type(screen.getByLabelText('服务器名称'), '生产节点');
  await user.type(screen.getByLabelText('服务器 IP'), ip);
  await user.clear(screen.getByLabelText('端口'));
  await user.type(screen.getByLabelText('端口'), port);
}

describe('WG client', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows a real server configuration page when wg-core is offline', async () => {
    render(<App />);

    expect(screen.getByRole('heading', { name: '连接' })).toBeInTheDocument();
    expect(screen.getByLabelText('服务器 IP')).toBeInTheDocument();
    expect(screen.getByLabelText('端口')).toHaveValue(9518);
    expect(await screen.findByText('代理控制台 · 未连接')).toBeInTheDocument();
    expect(screen.queryByText(/演示/)).not.toBeInTheDocument();
  });

  it('saves the entered server and starts the real TCP and UDP proxy', async () => {
    const user = userEvent.setup();
    let config = { ...emptyProxyConfig };
    let runtime = { ...disconnectedProxy };
    const fetchMock = backend((url, method, options) => {
      if (url === '/api/proxy/config' && method === 'GET') return response(config);
      if (url === '/api/proxy/status' && method === 'GET') return response(runtime);
      if (url === '/api/proxy/config' && method === 'PUT') {
        config = JSON.parse(options.body);
        return response(config);
      }
      if (url === '/api/proxy/connect' && method === 'POST') {
        runtime = {
          ...disconnectedProxy,
          configured: true,
          connected: true,
          managed: true,
          tcp_listener: true,
          udp_listener: true,
          selected_endpoint: config.selected_endpoint,
          transport: config.transport,
          udp_target: config.udp_target,
          servers: config.servers,
          started_at: '2026-07-19T04:00:00Z',
        };
        return response(runtime);
      }
      return undefined;
    }, { coreLive: false });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    await screen.findByText('代理控制台 · 未连接');
    await fillServer(user);
    await user.selectOptions(screen.getByLabelText('连接模式'), 'both');
    await user.click(screen.getByRole('button', { name: '连接服务器' }));

    expect(await screen.findByRole('heading', { name: '代理已连接' })).toBeInTheDocument();
    expect(screen.getByText('真实代理已运行 · TCP/UDP')).toBeInTheDocument();
    expect(screen.getByText('127.0.0.1:47101')).toBeInTheDocument();
    expect(screen.getByText('127.0.0.1:47102')).toBeInTheDocument();
    const saveCall = fetchMock.mock.calls.find(([url, options]) => url === '/api/proxy/config' && options.method === 'PUT');
    expect(JSON.parse(saveCall[1].body)).toEqual({
      servers: [{ name: '生产节点', ip: '47.92.25.188', port: 9518 }],
      selected_endpoint: '47.92.25.188:9518',
      transport: 'both',
      udp_target: '1.1.1.1:53',
    });
  });

  it('loads saved servers and persists a different selected server', async () => {
    const user = userEvent.setup();
    const config = {
      servers: [
        { name: '杭州', ip: '47.92.25.188', port: 9518 },
        { name: '备用', ip: '198.51.100.8', port: 9519 },
      ],
      selected_endpoint: '47.92.25.188:9518',
      transport: 'tcp',
      udp_target: '1.1.1.1:53',
    };
    const fetchMock = backend((url, method, options) => {
      if (url === '/api/proxy/config' && method === 'GET') return response(config);
      if (url === '/api/proxy/status' && method === 'GET') return response({ ...disconnectedProxy, configured: true, selected_endpoint: config.selected_endpoint, servers: config.servers });
      if (url === '/api/proxy/config' && method === 'PUT') return response(JSON.parse(options.body));
      return undefined;
    }, { coreLive: false });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByLabelText('服务器 IP')).toHaveValue('47.92.25.188'));
    await user.selectOptions(screen.getByLabelText('选择服务器'), '198.51.100.8:9519');
    expect(screen.getByLabelText('服务器 IP')).toHaveValue('198.51.100.8');
    await user.click(screen.getByRole('button', { name: '保存配置' }));

    const saveCall = await waitFor(() => {
      const call = fetchMock.mock.calls.find(([url, options]) => url === '/api/proxy/config' && options.method === 'PUT');
      expect(call).toBeTruthy();
      return call;
    });
    expect(JSON.parse(saveCall[1].body).selected_endpoint).toBe('198.51.100.8:9519');
  });

  it('does not display a fake connection when the local controller rejects connect', async () => {
    const user = userEvent.setup();
    const fetchMock = backend((url, method, options) => {
      if (url === '/api/proxy/config' && method === 'PUT') return response(JSON.parse(options.body));
      if (url === '/api/proxy/connect' && method === 'POST') return response({ error: { message: '缺少服务器证书' } }, 409);
      return undefined;
    }, { coreLive: false });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    await fillServer(user);
    await user.click(screen.getByRole('button', { name: '连接服务器' }));

    expect(await screen.findByText('缺少服务器证书')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: '代理已连接' })).not.toBeInTheDocument();
    expect(screen.getAllByText('未连接').length).toBeGreaterThan(0);
  });

  it('rejects an invalid port before sending configuration', async () => {
    const user = userEvent.setup();
    const fetchMock = backend(undefined, { coreLive: false });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    await fillServer(user, '47.92.25.188', '70000');
    await user.click(screen.getByRole('button', { name: '连接服务器' }));

    expect(screen.getByRole('alert')).toHaveTextContent('端口必须是 1–65535 之间的整数');
    expect(fetchMock.mock.calls.some(([url, options]) => url === '/api/proxy/config' && options.method === 'PUT')).toBe(false);
  });

  it('keeps a manual rule target read-only and sends its revision', async () => {
    const user = userEvent.setup();
    const rule = { id: 'rule-7', target: 'api.example.com', target_type: 'DOMAIN', result: 'TUNNEL', source: 'MANUAL', revision: 9 };
    const fetchMock = backend((url, method) => {
      if (url === '/api/v1/rules' && method === 'GET') return response({ rules: [rule] });
      if (url === '/api/v1/rules' && method === 'POST') return response({ rule: { ...rule, result: 'DIRECT', revision: 10 } });
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

    const saveCall = await waitFor(() => {
      const call = fetchMock.mock.calls.find(([url, options]) => url === '/api/v1/rules' && options.method === 'POST');
      expect(call).toBeTruthy();
      return call;
    });
    expect(JSON.parse(saveCall[1].body)).toMatchObject({ id: 'rule-7', expected_revision: 9, target: 'api.example.com', result: 'DIRECT' });
  });

  it('uses validated backend data for IPv6 pairing', async () => {
    const user = userEvent.setup();
    const fetchMock = backend((url, method, options) => {
      if (url === '/api/v1/pairing/validate' && method === 'POST') {
        const body = JSON.parse(options.body);
        return response({
          valid: true,
          validation_id: 'validation-ipv6',
          server_ip: body.server_ip,
          port: 9518,
          file_name: body.file_name,
          fingerprint: 'wgs-ipv6-validated-fingerprint',
          expires_at: '2030-07-17T01:02:03Z',
        });
      }
      return undefined;
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    await screen.findByText('后台在线');
    await user.click(screen.getByRole('button', { name: '首次配对' }));
    const serverInput = screen.getByLabelText('服务器 IP');
    await user.clear(serverInput);
    await user.type(serverInput, '2001:db8::10');
    await user.click(screen.getByRole('button', { name: '确认并继续' }));
    await user.click(screen.getByRole('button', { name: '确认并继续' }));

    expect(await screen.findByText('wgs-ipv6-validated-fingerprint')).toBeInTheDocument();
    expect(screen.getByText(/\[2001:db8::10\]:9518/)).toBeInTheDocument();
  });

  it('does not report a rejected live upgrade as successful', async () => {
    const user = userEvent.setup();
    vi.stubGlobal('fetch', backend((url, method) => {
      if (url === '/api/v1/updates/check' && method === 'POST') return response({ available_version: '1.2.4', compatible: true, manifest_verified: true });
      if (url === '/api/v1/updates/upgrade' && method === 'POST') return response({ error: { message: '尚未实现' } }, 501);
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
  });
});
