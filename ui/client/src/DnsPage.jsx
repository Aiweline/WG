import {
  CheckCircle,
  Copy,
  Globe,
  Info,
  Stethoscope,
  Warning,
  ArrowClockwise,
} from '@phosphor-icons/react';

export function DnsPage({ dns, diagnostics, busy, diagnosticsOpen, onRefresh, onDiagnose, onCloseDiagnostics, onCopy }) {
  const degraded = dns.state === 'degraded';
  const dnsCheck = diagnostics?.health?.find((item) => item.id === 'dns');

  return (
    <section className="page dns-page" aria-labelledby="dns-title">
      <h1 id="dns-title">私有 DNS</h1>

      <div className="dns-proof">
        <Info size={37} aria-hidden="true" />
        <div><h2>系统 DNS 只读副本</h2><p>WG 只读复制系统解析器配置，用于隧道域名解析与分流决策。</p></div>
        <span className="unchanged-badge"><CheckCircle size={20} />未修改系统 DNS</span>
      </div>

      <div className="dns-summary">
        <div className={'dns-state ' + (degraded ? 'degraded' : 'ready')}>
          {degraded ? <Warning size={26} weight="fill" /> : <CheckCircle size={26} weight="fill" />}
          <strong>状态：{degraded ? 'DEGRADED（降级）' : 'READY（正常）'}</strong>
        </div>
        <span>快照 ID：<code>{dns.snapshotId}</code><button type="button" aria-label="复制快照 ID" onClick={() => onCopy(dns.snapshotId)}><Copy size={17} /></button></span>
        <span>生成时间：{dns.generatedAt}</span>
      </div>
      <p className="dns-subtitle">系统 resolver 配置只读副本 · Generation {dns.generation}</p>

      <div className="dns-grid">
        <section aria-labelledby="upstream-title">
          <h2 id="upstream-title">上游服务器（共 {dns.upstreams.length} 个）</h2>
          <ul className="upstream-list">
            {dns.upstreams.map((upstream, index) => (
              <li key={upstream.address}>
                <Globe size={20} aria-hidden="true" />
                <span>{index + 1}. {upstream.address}<small>作用域：{upstream.scope}</small></span>
                <span className={'upstream-status ' + upstream.state}>{upstream.state === 'ready' ? '可用' : '不可达'}</span>
              </li>
            ))}
          </ul>
          {degraded && <div className="small-warning"><Warning size={21} weight="fill" /><div><strong>1 个上游暂时不可达</strong><p>部分解析请求可能通过其他上游完成。</p><button className="text-button" type="button" onClick={onDiagnose}>查看详情</button></div></div>}
        </section>

        <section className="dns-metrics" aria-labelledby="cache-title">
          <h2 id="cache-title">快照与私有缓存</h2>
          <dl>
            <div><dt>最后同步时间</dt><dd>{dns.lastSync}</dd></div>
            <div><dt>缓存条目数</dt><dd>{dns.cacheEntries.toLocaleString()}</dd></div>
            <div><dt>命中率</dt><dd>{dns.hitRate}</dd></div>
            <div><dt>TTL（最小 / 平均 / 最大）</dt><dd>{dns.ttl}</dd></div>
          </dl>
        </section>
      </div>

      <div className="dns-actions">
        <button className="button secondary" type="button" disabled={busy === 'refresh-dns'} onClick={onRefresh}><ArrowClockwise className={busy === 'refresh-dns' ? 'spin' : ''} size={20} />{busy === 'refresh-dns' ? '正在读取…' : '重新同步'}</button>
        <button className="button secondary" type="button" disabled={busy === 'doctor'} onClick={onDiagnose}><Stethoscope size={20} />诊断</button>
      </div>

      <div className="dns-safety-note"><Info size={19} /><span>私有 DNS 仅用于 WG 分流决策，不会修改或覆盖系统 DNS，也不会清理系统缓存。</span></div>

      {diagnosticsOpen && (
        <div className="modal-backdrop">
          <section className="diagnostic-dialog" role="dialog" aria-modal="true" aria-labelledby="dns-diagnostic-title">
            <header><div><span className="eyebrow">私有 DNS 诊断</span><h2 id="dns-diagnostic-title">后台只读诊断已完成</h2></div><button type="button" aria-label="关闭诊断结果" onClick={onCloseDiagnostics}>关闭</button></header>
            <dl><div><dt>检查时间</dt><dd>{diagnostics?.generatedAt || '—'}</dd></div><div><dt>总体状态</dt><dd>{diagnostics?.overall || 'UNKNOWN'}</dd></div><div><dt>私有 DNS</dt><dd>{dnsCheck?.detail || '后台未返回 DNS 检查项'}</dd></div><div><dt>系统 DNS</dt><dd>{dns.unchanged ? '未修改' : '状态异常'}</dd></div></dl>
            <p>{diagnostics?.summary || '诊断报告未包含附加摘要。'} WG 不会为了恢复而替换系统 DNS。</p>
            <button className="button primary" type="button" onClick={onCloseDiagnostics}>知道了</button>
          </section>
        </div>
      )}
    </section>
  );
}
