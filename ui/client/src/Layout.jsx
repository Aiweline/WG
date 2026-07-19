import {
  ArrowsSplit,
  CircleNotch,
  GlobeHemisphereWest,
  Info,
  Key,
  Link,
  Minus,
  Pulse,
  SlidersHorizontal,
  Square,
  X,
} from '@phosphor-icons/react';

const navigation = [
  { id: 'connection', label: '连接', icon: Link },
  { id: 'routing', label: '智能分流', icon: ArrowsSplit },
  { id: 'dns', label: '私有 DNS', icon: GlobeHemisphereWest },
  { id: 'health', label: '健康与更新', icon: Pulse },
];

export function Layout({ page, onNavigate, backendMode, proxyRuntime, status, versions, children }) {
  const connected = status.connection === 'connected';

  return (
    <div className="desktop-frame">
      <aside className="sidebar" aria-label="客户端导航">
        <button className="brand" type="button" onClick={() => onNavigate('connection')} aria-label="返回连接页">
          WG
        </button>
        <nav className="primary-nav" aria-label="主要页面">
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <button
                className={'nav-item ' + (page === item.id ? 'active' : '')}
                type="button"
                key={item.id}
                onClick={() => onNavigate(item.id)}
                aria-current={page === item.id ? 'page' : undefined}
              >
                <Icon size={25} weight="regular" aria-hidden="true" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <button
            className={'pairing-link ' + (page === 'pairing' ? 'active' : '')}
            type="button"
            onClick={() => onNavigate('pairing')}
            aria-current={page === 'pairing' ? 'page' : undefined}
          >
            <Key size={20} aria-hidden="true" />
            <span>首次配对</span>
          </button>
          <div className="utility-actions" aria-label="辅助操作">
            <button type="button" aria-label="设置" title="设置">
              <SlidersHorizontal size={24} aria-hidden="true" />
            </button>
            <button type="button" aria-label="关于 WG" title="关于 WG">
              <Info size={24} aria-hidden="true" />
            </button>
          </div>
        </div>
      </aside>

      <section className="app-surface">
        <header className="window-bar" aria-label="窗口栏">
          {backendMode === 'checking' ? (
            <span className="backend-chip checking"><CircleNotch className="spin" size={16} /> 正在连接后台</span>
          ) : proxyRuntime?.connected ? (
            <span className="backend-chip live" title="本机代理进程已监听">
              真实代理已运行 · {proxyRuntime.tcp_listener && proxyRuntime.udp_listener ? 'TCP/UDP' : proxyRuntime.udp_listener ? 'UDP' : 'TCP'}
            </span>
          ) : backendMode === 'live' ? (
            <span className="backend-chip live">后台在线</span>
          ) : (
            <span className="backend-chip">代理控制台 · 未连接</span>
          )}
          <div className="window-actions" aria-hidden="true">
            <Minus size={18} />
            <Square size={15} />
            <X size={18} />
          </div>
        </header>

        <main className="content" id="main-content">
          {backendMode === 'proxy' && (
            <p className="sr-only" role="status">
              管理核心未运行；连接页的服务器配置和代理控制仍然可用。
            </p>
          )}
          {children}
        </main>

        {page !== 'pairing' && (
          <footer className="status-footer">
            <span className={'footer-status ' + (connected ? 'ok' : 'muted')}>
              <span className="status-dot" aria-hidden="true" />
              状态：<strong>{connected ? '已连接' : '未连接'}</strong>
            </span>
            <span className="footer-versions">
              Bundle {versions.bundle} · UI {versions.ui}
            </span>
          </footer>
        )}
      </section>
    </div>
  );
}
