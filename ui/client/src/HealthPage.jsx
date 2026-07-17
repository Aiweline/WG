import {
  ArrowClockwise,
  ArrowCounterClockwise,
  ArrowUp,
  CheckCircle,
  Clipboard,
  DownloadSimple,
  GlobeHemisphereWest,
  Link,
  LockKey,
  Pulse,
  Stethoscope,
  TerminalWindow,
  Warning,
  ArrowsSplit,
} from '@phosphor-icons/react';

const healthIcons = {
  tunnel: Link,
  routing: ArrowsSplit,
  dns: GlobeHemisphereWest,
  scripts: TerminalWindow,
  permissions: LockKey,
};

export function HealthPage({ health, diagnostics, versions, busy, updateState, onDiagnose, onCopy, onExport, onCheckUpdate, onUpgrade, onRollback }) {
  return (
    <section className="page health-page" aria-labelledby="health-title">
      <h1 id="health-title">健康与更新</h1>

      <div className="doctor-head">
        <button className="button secondary doctor-button" type="button" disabled={busy === 'doctor'} onClick={onDiagnose}>
          <Stethoscope size={26} />{busy === 'doctor' ? '正在诊断…' : '一键诊断'}
        </button>
        <div><p>全面检查系统健康状况，包括隧道连接、分流、DNS、脚本环境与系统权限。</p><span>诊断时间：{diagnostics?.generatedAt || '尚未运行'}</span></div>
      </div>

      <section className="health-results" aria-labelledby="health-results-title">
        <h2 id="health-results-title">诊断结果</h2>
        <div className="health-table" role="table" aria-label="健康检查结果">
          <div className="health-row health-head" role="row"><span role="columnheader">项目</span><span role="columnheader">状态</span><span role="columnheader">详情</span></div>
          {health.map((item) => {
            const Icon = healthIcons[item.id] || Pulse;
            const normal = item.state === 'normal';
            return <div className="health-row" role="row" key={item.id}><span role="cell"><Icon size={21} />{item.label}</span><span role="cell" className={'health-state ' + item.state}>{normal ? <CheckCircle size={17} weight="fill" /> : <Warning size={17} weight="fill" />}{normal ? '正常' : '降级'}</span><span role="cell">{item.detail}</span></div>;
          })}
          {health.length === 0 && <div className="health-row" role="row"><span role="cell"><Pulse size={21} />尚未诊断</span><span role="cell">—</span><span role="cell">运行一键诊断后显示后台返回的只读结果。</span></div>}
        </div>
        <div className="report-actions">
          <button className="button secondary compact" type="button" onClick={onCopy}><Clipboard size={19} />复制到剪贴板</button>
          <button className="button secondary compact" type="button" onClick={onExport}><DownloadSimple size={19} />导出报告…</button>
        </div>
        <p className="privacy-caption">报告不会包含密钥、配对凭据、完整域名、DNS 响应或用户规则内容。</p>
      </section>

      <section className="update-section" aria-labelledby="update-title">
        <div className="update-heading"><div><h2 id="update-title">更新</h2><p>发布包需通过离线信任根和签名校验后才能安装。</p></div><span className={'update-state ' + updateState}>{updateState === 'available' ? '可更新' : updateState === 'complete' ? '已是最新' : updateState === 'upgrading' ? '正在升级' : updateState === 'unavailable' ? '无可用签名更新' : '尚未检查'}</span></div>
        <div className="version-layout">
          <dl className="version-list">
            <div><dt>Bundle 版本</dt><dd>{versions.bundle}</dd></div>
            <div><dt>Core 版本</dt><dd>{versions.core}</dd></div>
            <div><dt>UI 版本</dt><dd>{versions.ui}</dd></div>
            <div><dt>Scripts 版本</dt><dd>{versions.scripts}</dd></div>
            <div><dt>最新 Bundle</dt><dd>{versions.latest}（{versions.platform}）</dd></div>
          </dl>
          <div className="update-controls">
            <p>升级将原子更新 Bundle 内的客户端、Core 与脚本，并保留已验证的回滚点。</p>
            <div>
              <button className="button secondary" type="button" disabled={busy} onClick={onCheckUpdate}><ArrowClockwise className={busy === 'check-update' ? 'spin' : ''} size={20} />检查更新</button>
              <button className="button primary" type="button" disabled={busy || updateState !== 'available'} onClick={onUpgrade}><ArrowUp size={20} />{busy === 'upgrade' ? '正在升级…' : '升级'}</button>
              <button className="button secondary" type="button" disabled={busy} onClick={onRollback}><ArrowCounterClockwise size={20} />回滚</button>
            </div>
          </div>
        </div>
      </section>
    </section>
  );
}
