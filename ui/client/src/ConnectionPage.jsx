import {
  ArrowsClockwise,
  ArrowsSplit,
  ArrowDown,
  ArrowUp,
  Clock,
  GlobeHemisphereWest,
  LinkBreak,
  HardDrives,
  Warning,
} from '@phosphor-icons/react';

export function ConnectionPage({ status, busy, onDisconnect, onReconnect, onNavigate }) {
  const connected = status.connection === 'connected';
  const connecting = status.connection === 'connecting' || status.connection === 'reconnecting';

  return (
    <section className="page connection-page" aria-labelledby="connection-title">
      <h1 id="connection-title">连接</h1>

      <div className="connection-hero" aria-live="polite">
        <span className={'connection-indicator ' + (connected ? 'connected' : '')} aria-hidden="true" />
        <div>
          <h2>{connecting ? '正在连接' : connected ? status.proxyRuntime ? '代理已运行' : '已连接' : '未连接'}</h2>
          <p>{connected ? status.proxyRuntime ? '本机 TCP 代理正在监听' : '隧道运行正常' : connecting ? '正在安全建立隧道…' : '隧道已停止'}</p>
        </div>
      </div>

      <dl className="connection-details">
        <div><dt><HardDrives size={24} />端点</dt><dd>{status.endpoint}</dd></div>
        <div><dt><Clock size={24} />连接时长</dt><dd>{connected ? status.duration : '—'}</dd></div>
        <div><dt><ArrowUp size={24} />上传总计</dt><dd>{status.uploaded}</dd></div>
        <div><dt><ArrowDown size={24} />下载总计</dt><dd>{status.downloaded}</dd></div>
        <div>
          <dt><ArrowsSplit size={24} />路由状态</dt>
          <dd>
            <button className="inline-link" type="button" onClick={() => onNavigate('routing')}>
              {status.routingMode} 智能分流
            </button>
          </dd>
        </div>
        <div><dt><GlobeHemisphereWest size={24} />DNS 状态</dt><dd>{status.dnsUnchanged ? '未修改系统 DNS' : '需要检查'}</dd></div>
      </dl>

      {status.dnsState === 'degraded' && (
        <div className="warning-callout" role="status">
          <Warning size={25} weight="fill" aria-hidden="true" />
          <span>已连接，但 DNS 降级</span>
          <button type="button" onClick={() => onNavigate('dns')}>查看详情</button>
        </div>
      )}

      <div className="connection-actions">
        <button className="button primary" type="button" onClick={onDisconnect} disabled={busy || !connected}>
          <LinkBreak size={22} aria-hidden="true" />
          {busy === 'disconnect' ? '正在断开…' : '断开连接'}
        </button>
        <button className="button secondary" type="button" onClick={onReconnect} disabled={busy}>
          <ArrowsClockwise className={busy === 'reconnect' ? 'spin' : ''} size={22} aria-hidden="true" />
          {busy === 'reconnect' ? '正在重新连接…' : '重新连接'}
        </button>
      </div>
    </section>
  );
}
