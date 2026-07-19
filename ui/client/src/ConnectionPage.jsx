import { useState } from 'react';
import {
  ArrowsClockwise,
  ArrowsSplit,
  ArrowDown,
  ArrowUp,
  Clock,
  FloppyDisk,
  GlobeHemisphereWest,
  HardDrives,
  Link,
  LinkBreak,
  Plus,
  Trash,
  Warning,
} from '@phosphor-icons/react';

function endpointFor(server) {
  if (!server?.ip || !server?.port) return '';
  return (server.ip.includes(':') ? '[' + server.ip + ']' : server.ip) + ':' + server.port;
}

function emptyEditor(config) {
  return {
    endpoint: '',
    name: '',
    ip: '',
    port: '9518',
    transport: config?.transport || 'tcp',
    udpTarget: config?.udp_target || '1.1.1.1:53',
  };
}

function editorFromConfig(config) {
  const selected = config?.servers?.find((server) => endpointFor(server) === config.selected_endpoint);
  if (!selected) return emptyEditor(config);
  return {
    endpoint: config.selected_endpoint,
    name: selected.name || '',
    ip: selected.ip,
    port: String(selected.port),
    transport: config.transport || 'tcp',
    udpTarget: config.udp_target || '1.1.1.1:53',
  };
}

export function ConnectionPage({ status, proxyRuntime, proxyConfig, busy, onConnect, onSaveConfig, onDisconnect, onReconnect, onNavigate }) {
  const connected = status.connection === 'connected';
  const connecting = status.connection === 'connecting' || status.connection === 'reconnecting' || busy === 'connect';
  const [draft, setDraft] = useState(null);
  const [formError, setFormError] = useState('');
  const servers = proxyConfig?.servers || [];
  const editor = draft || editorFromConfig(proxyConfig);
  const dirty = draft !== null;

  function change(field, value) {
    setDraft({ ...editor, [field]: value });
    setFormError('');
  }

  function selectServer(endpoint) {
    if (!endpoint) {
      setDraft(emptyEditor(proxyConfig));
      setFormError('');
      return;
    }
    const selected = servers.find((server) => endpointFor(server) === endpoint);
    if (!selected) return;
    setDraft({
      endpoint,
      name: selected.name || '',
      ip: selected.ip,
      port: String(selected.port),
      transport: proxyConfig.transport || 'tcp',
      udpTarget: proxyConfig.udp_target || '1.1.1.1:53',
    });
    setFormError('');
  }

  function buildConfig() {
    const ip = editor.ip.trim();
    const port = Number(editor.port);
    if (!ip) {
      setFormError('请输入服务器 IP。');
      return null;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setFormError('端口必须是 1–65535 之间的整数。');
      return null;
    }
    const server = { name: editor.name.trim() || ip, ip, port };
    const endpoint = endpointFor(server);
    const remaining = servers.filter((item) => {
      const itemEndpoint = endpointFor(item);
      return itemEndpoint !== editor.endpoint && itemEndpoint !== endpoint;
    });
    return {
      config: {
        servers: [...remaining, server],
        selected_endpoint: endpoint,
        transport: editor.transport,
        udp_target: editor.udpTarget.trim() || '1.1.1.1:53',
      },
      endpoint,
    };
  }

  async function save(connectAfterSave = false) {
    const candidate = buildConfig();
    if (!candidate) return;
    const ok = await (connectAfterSave ? onConnect(candidate.config) : onSaveConfig(candidate.config));
    if (ok) {
      setDraft(null);
    }
  }

  async function removeServer() {
    if (!editor.endpoint || connected) return;
    const remaining = servers.filter((server) => endpointFor(server) !== editor.endpoint);
    const nextEndpoint = remaining[0] ? endpointFor(remaining[0]) : '';
    const ok = await onSaveConfig({
      servers: remaining,
      selected_endpoint: nextEndpoint,
      transport: editor.transport,
      udp_target: editor.udpTarget.trim() || '1.1.1.1:53',
    });
    if (ok) {
      setDraft(null);
    }
  }

  return (
    <section className="page connection-page" aria-labelledby="connection-title">
      <h1 id="connection-title">连接</h1>

      <div className="connection-hero" aria-live="polite">
        <span className={'connection-indicator ' + (connected ? 'connected' : '')} aria-hidden="true" />
        <div>
          <h2>{connecting ? '正在连接' : connected ? '代理已连接' : '未连接'}</h2>
          <p>{connected ? '本机代理已连接到 ' + status.endpoint : connecting ? '正在启动真实本机代理…' : '选择或填写服务器后即可连接'}</p>
        </div>
      </div>

      <section className="server-config-card" aria-labelledby="server-config-title">
        <div className="server-config-heading">
          <div>
            <span className="eyebrow">真实代理配置</span>
            <h2 id="server-config-title">服务器</h2>
            <p>配置会保存到本机；连接时使用已安装的服务器证书和令牌。</p>
          </div>
          <span className={'config-state ' + (connected ? 'connected' : '')}>{connected ? '正在使用' : servers.length + ' 台已保存'}</span>
        </div>

        <div className="server-picker-row">
          <label htmlFor="server-picker">选择服务器</label>
          <div>
            <select id="server-picker" value={editor.endpoint} onChange={(event) => selectServer(event.target.value)} disabled={Boolean(busy)}>
              <option value="">＋ 添加服务器</option>
              {servers.map((server) => {
                const endpoint = endpointFor(server);
                return <option key={endpoint} value={endpoint}>{server.name || server.ip} · {endpoint}</option>;
              })}
            </select>
            <button className="button secondary compact" type="button" onClick={() => selectServer('')} disabled={Boolean(busy)}><Plus size={18} />新增</button>
            <button className="icon-danger-button" type="button" aria-label="删除当前服务器" title={connected ? '请先断开连接' : '删除当前服务器'} onClick={removeServer} disabled={Boolean(busy) || !editor.endpoint || connected}><Trash size={20} /></button>
          </div>
        </div>

        <div className="server-config-grid">
          <label>
            <span>服务器名称</span>
            <input value={editor.name} onChange={(event) => change('name', event.target.value)} placeholder="例如：杭州节点" autoComplete="off" />
          </label>
          <label>
            <span>服务器 IP</span>
            <input value={editor.ip} onChange={(event) => change('ip', event.target.value)} placeholder="47.92.25.188" inputMode="decimal" autoComplete="off" required />
          </label>
          <label>
            <span>端口</span>
            <input value={editor.port} onChange={(event) => change('port', event.target.value)} type="number" min="1" max="65535" inputMode="numeric" required />
          </label>
          <label>
            <span>连接模式</span>
            <select value={editor.transport} onChange={(event) => change('transport', event.target.value)}>
              <option value="tcp">TCP 代理</option>
              <option value="udp">UDP 中继</option>
              <option value="both">TCP + UDP</option>
            </select>
          </label>
          {(editor.transport === 'udp' || editor.transport === 'both') && (
            <label className="udp-target-field">
              <span>UDP 目标</span>
              <input value={editor.udpTarget} onChange={(event) => change('udpTarget', event.target.value)} placeholder="1.1.1.1:53" autoComplete="off" required />
              <small>UDP 中继收到的数据会转发到此目标；默认用于 DNS 连通测试。</small>
            </label>
          )}
        </div>

        {connected && dirty && <p className="form-note" role="status">请先断开当前连接，再保存或切换服务器。</p>}
        {formError && <p className="form-error" role="alert">{formError}</p>}

        <div className="server-config-actions">
          <button className="button secondary" type="button" onClick={() => save(false)} disabled={Boolean(busy) || connected}>
            <FloppyDisk size={20} />{busy === 'save-server' ? '正在保存…' : '保存配置'}
          </button>
          <button className="button primary" type="button" onClick={() => save(true)} disabled={Boolean(busy) || connected}>
            <Link size={20} />{busy === 'connect' ? '正在连接…' : '连接服务器'}
          </button>
          {connected && (
            <>
              <button className="button secondary" type="button" onClick={onReconnect} disabled={Boolean(busy)}>
                <ArrowsClockwise className={busy === 'reconnect' ? 'spin' : ''} size={20} />{busy === 'reconnect' ? '正在重新连接…' : '重新连接'}
              </button>
              <button className="button danger" type="button" onClick={onDisconnect} disabled={Boolean(busy)}>
                <LinkBreak size={20} />{busy === 'disconnect' ? '正在断开…' : '断开连接'}
              </button>
            </>
          )}
        </div>
      </section>

      <dl className="connection-details">
        <div><dt><HardDrives size={24} />当前端点</dt><dd>{status.endpoint}</dd></div>
        <div><dt><Clock size={24} />连接时长</dt><dd>{connected ? status.duration : '—'}</dd></div>
        <div><dt><ArrowUp size={24} />本地 TCP 代理</dt><dd>{proxyRuntime?.tcp_listener ? '127.0.0.1:47101' : '未监听'}</dd></div>
        <div><dt><ArrowDown size={24} />本地 UDP 中继</dt><dd>{proxyRuntime?.udp_listener ? '127.0.0.1:47102' : '未监听'}</dd></div>
        <div>
          <dt><ArrowsSplit size={24} />智能分流</dt>
          <dd><button className="inline-link" type="button" onClick={() => onNavigate('routing')}>管理请求规则</button></dd>
        </div>
        <div><dt><GlobeHemisphereWest size={24} />系统 DNS</dt><dd>{status.dnsUnchanged ? '未修改' : '需要检查'}</dd></div>
      </dl>

      {status.dnsState === 'degraded' && (
        <div className="warning-callout" role="status">
          <Warning size={25} weight="fill" aria-hidden="true" />
          <span>代理已连接，但私有 DNS 降级</span>
          <button type="button" onClick={() => onNavigate('dns')}>查看详情</button>
        </div>
      )}
    </section>
  );
}
