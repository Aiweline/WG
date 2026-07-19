import { useEffect, useState } from 'react';
import { CheckCircle, Info, Warning, X } from '@phosphor-icons/react';
import { api, ApiUnavailableError, formatDiagnosticReport } from './api.js';
import { ConnectionPage } from './ConnectionPage.jsx';
import { DnsPage } from './DnsPage.jsx';
import { HealthPage } from './HealthPage.jsx';
import { Layout } from './Layout.jsx';
import { PairingPage } from './PairingPage.jsx';
import { RoutingPage } from './RoutingPage.jsx';

const emptyStatus = {
  connection: 'disconnected',
  endpoint: '请选择服务器',
  duration: '—',
  uploaded: '—',
  downloaded: '—',
  routingMode: 'AUTO',
  dnsUnchanged: true,
  dnsState: 'ready',
  proxyRuntime: true,
};

const emptyDns = {
  state: 'ready',
  snapshotId: '—',
  generatedAt: '—',
  lastSync: '—',
  generation: 0,
  upstreams: [],
  cacheEntries: 0,
  hitRate: '—',
  ttl: '—',
  unchanged: true,
};

const localVersions = { bundle: '—', core: '—', ui: '1.0.0', scripts: '—', latest: '—', platform: 'local' };

function signedUpdateCandidate(result) {
  const latest = result?.available_version || result?.latest || result?.latest_version || result?.version;
  const declaredAvailable = result?.available === true || result?.update_available === true || Boolean(result?.available_version);
  return {
    latest,
    available: declaredAvailable && result?.compatible !== false && result?.manifest_verified === true,
  };
}

export function App() {
  const [page, setPage] = useState('connection');
  const [backendMode, setBackendMode] = useState('checking');
  const [status, setStatus] = useState(emptyStatus);
  const [rules, setRules] = useState([]);
  const [dns, setDns] = useState(emptyDns);
  const [versions, setVersions] = useState(localVersions);
  const [health, setHealth] = useState([]);
  const [diagnosticReport, setDiagnosticReport] = useState(null);
  const [proxyTests, setProxyTests] = useState(null);
  const [proxyRuntime, setProxyRuntime] = useState({ configured: false, connected: false, tcp_listener: false, udp_listener: false, servers: [], transport: 'tcp', udp_target: '1.1.1.1:53' });
  const [proxyConfig, setProxyConfig] = useState({ servers: [], selected_endpoint: '', transport: 'tcp', udp_target: '1.1.1.1:53' });
  const [busy, setBusy] = useState('');
  const [updateState, setUpdateState] = useState('idle');
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [snapshot, liveRules, liveDns] = await Promise.all([
          api.snapshot(), api.rules(), api.dns(),
        ]);
        if (!active) return;
        if (snapshot?.status) setStatus((current) => ({ ...current, ...snapshot.status }));
        if (Array.isArray(liveRules)) setRules(liveRules);
        if (liveDns && typeof liveDns === 'object') setDns((current) => ({ ...current, ...liveDns }));
        if (snapshot?.versions) setVersions((current) => ({ ...current, ...snapshot.versions }));
        setHealth([]);
        setDiagnosticReport(null);
        setBackendMode('live');
      } catch {
        if (!active) return;
        setBackendMode('proxy');
      }
    }
    load();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    function applyRuntime(runtime) {
      setProxyRuntime(runtime);
      setStatus((current) => ({
        ...current,
        connection: runtime?.connected ? 'connected' : 'disconnected',
        endpoint: runtime?.selected_endpoint || '请选择服务器',
        duration: runtime?.started_at ? '运行中' : '—',
        uploaded: '—',
        downloaded: '—',
        routingMode: String(runtime?.transport || 'tcp').toUpperCase(),
        dnsState: 'ready',
        proxyRuntime: true,
      }));
    }
    async function loadProxyRuntime() {
      try {
        const [runtime, config] = await Promise.all([api.proxyStatus(), api.proxyConfig()]);
        if (!active) return;
        applyRuntime(runtime);
        setProxyConfig(config);
      } catch {
        if (active) setToast({ tone: 'warning', message: '本机代理控制后台不可用，请重新启动 WG Web UI。' });
      }
    }
    loadProxyRuntime();
    const timer = window.setInterval(loadProxyRuntime, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = window.setTimeout(() => setToast(null), 4600);
    return () => window.clearTimeout(timer);
  }, [toast]);

  async function perform(key, apiCall, localUpdate, successMessage) {
    if (backendMode !== 'live') {
      setToast({ tone: 'warning', message: '该管理功能需要 wg-core；没有执行模拟操作。代理连接仍可在连接页使用。' });
      return false;
    }
    setBusy(key);
    try {
      const response = await apiCall();
      localUpdate(response, true);
      const resolvedMessage = typeof successMessage === 'function' ? successMessage(response, true) : successMessage;
      if (resolvedMessage) setToast({ tone: 'success', message: resolvedMessage });
      return true;
    } catch (error) {
      if (error instanceof ApiUnavailableError) {
        setBackendMode('proxy');
        setToast({ tone: 'warning', message: 'wg-core 响应中断，管理操作未执行；真实代理连接不受影响。' });
      } else {
        setToast({ tone: 'warning', message: error.status === 501 ? '后台已明确返回：此版本尚未实现该操作。没有执行升级或回滚。' : error.message });
      }
      return false;
    } finally {
      setBusy('');
    }
  }

  function applyProxyRuntime(runtime) {
    setProxyRuntime(runtime);
    setStatus((current) => ({
      ...current,
      connection: runtime?.connected ? 'connected' : 'disconnected',
      endpoint: runtime?.selected_endpoint || '请选择服务器',
      duration: runtime?.started_at ? '运行中' : '—',
      routingMode: String(runtime?.transport || 'tcp').toUpperCase(),
      dnsState: 'ready',
      proxyRuntime: true,
    }));
  }

  async function connectProxy(config) {
    setBusy('connect');
    try {
      const saved = await api.saveProxyConfig(config);
      setProxyConfig(saved);
      const runtime = await api.proxyConnect();
      applyProxyRuntime(runtime);
      setToast({ tone: 'success', message: '已连接 ' + runtime.selected_endpoint + '（' + String(runtime.transport).toUpperCase() + '）' });
      return true;
    } catch (error) {
      setToast({ tone: 'warning', message: error.message || '连接失败' });
      return false;
    } finally {
      setBusy('');
    }
  }

  async function saveProxyConfig(config) {
    setBusy('save-server');
    try {
      const saved = await api.saveProxyConfig(config);
      setProxyConfig(saved);
      const runtime = await api.proxyStatus();
      applyProxyRuntime(runtime);
      setToast({ tone: 'success', message: '服务器配置已保存' });
      return true;
    } catch (error) {
      setToast({ tone: 'warning', message: error.message || '保存失败' });
      return false;
    } finally {
      setBusy('');
    }
  }

  async function disconnect() {
    setBusy('disconnect');
    try {
      const runtime = await api.proxyDisconnect();
      applyProxyRuntime(runtime);
      setToast({ tone: 'success', message: '代理已断开，系统 DNS 保持原样' });
    } catch (error) {
      setToast({ tone: 'warning', message: error.message || '断开失败' });
    } finally {
      setBusy('');
    }
  }

  async function reconnect() {
    setBusy('reconnect');
    try {
      const runtime = await api.proxyReconnect();
      applyProxyRuntime(runtime);
      setToast({ tone: 'success', message: '已重新连接 ' + runtime.selected_endpoint });
    } catch (error) {
      setToast({ tone: 'warning', message: error.message || '重新连接失败' });
    } finally {
      setBusy('');
    }
  }

  async function saveRule(rule) {
    const isNew = !rule.id;
    return perform('save-rule', () => api.saveRule(rule), (liveRule, live) => {
      const ruleForState = { ...rule };
      delete ruleForState.replacesAutoId;
      const appliedRule = live ? liveRule : { ...ruleForState, id: rule.id || 'r-' + Date.now(), revision: rule.revision || 1 };
      if (!appliedRule) return;
      setRules((current) => {
        const withoutLearnedDecision = rule.replacesAutoId ? current.filter((item) => item.id !== rule.replacesAutoId) : current;
        return isNew ? [appliedRule, ...withoutLearnedDecision] : withoutLearnedDecision.map((item) => item.id === rule.id ? appliedRule : item);
      });
    }, isNew ? '规则已添加并原子应用' : '规则已更新并原子应用');
  }

  async function deleteRule(rule) {
    return perform('delete-rule', () => api.deleteRule(rule), (_result, live) => {
      setRules((current) => live
        ? current.filter((item) => item.id !== rule.id)
        : current.map((item) => item.id === rule.id ? { ...item, action: 'AUTO', source: '自动学习', expires: '—', note: '' } : item));
    }, rule.target + ' 已恢复 AUTO，下一次请求将重新评估');
  }

  async function refreshDns() {
    const now = new Date().toLocaleString('zh-CN', { hour12: false }).replaceAll('/', '-');
    await perform('refresh-dns', api.refreshDns, (liveDns, live) => setDns((current) => {
      if (live) return liveDns ? { ...current, ...liveDns } : current;
      return {
        ...current,
        lastSync: now,
        generatedAt: now,
        generation: current.generation + 1,
        snapshotId: 'dns-snapshot-' + Date.now(),
      };
    }), '已重新读取系统 DNS，只读快照已更新');
  }

  async function runDoctor(openDialog = false) {
    await perform('doctor', api.doctor, (liveReport, _live) => {
      setDiagnosticReport(liveReport);
      setHealth(liveReport.health);
      if (openDialog) setDiagnosticsOpen(true);
    }, '只读诊断已完成');
  }

  async function runProxyTests() {
    setBusy('proxy-test');
    try {
      const report = await api.proxyTest();
      setProxyTests(report);
      const passed = [report?.tcp, report?.udp, report?.system_dns].filter((item) => item?.state === 'passed').length;
      setToast({ tone: passed === 3 ? 'success' : 'warning', message: '真实代理测试完成：' + passed + '/3 通过' });
    } catch (error) {
      setToast({ tone: 'warning', message: error.message || '真实代理测试请求失败' });
    } finally {
      setBusy('');
    }
  }

  function copyText(text) {
    Promise.resolve(navigator.clipboard?.writeText(text)).catch(() => undefined);
    setToast({ tone: 'success', message: '已复制脱敏内容' });
  }

  function copyDiagnosticReport() {
    const content = formatDiagnosticReport(diagnosticReport, dns.unchanged);
    if (!content) {
      setToast({ tone: 'info', message: '请先运行一次只读诊断。' });
      return;
    }
    copyText(content);
  }

  function exportReport() {
    const content = formatDiagnosticReport(diagnosticReport, dns.unchanged);
    if (!content) {
      setToast({ tone: 'info', message: '请先运行一次只读诊断。' });
      return;
    }
    try {
      const url = URL.createObjectURL(new Blob([content], { type: 'text/plain;charset=utf-8' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'wg-diagnostic-redacted.txt';
      link.click();
      URL.revokeObjectURL(url);
      setToast({ tone: 'success', message: '脱敏诊断报告已导出' });
    } catch {
      setToast({ tone: 'info', message: '当前浏览器不支持下载，可使用“复制到剪贴板”。' });
    }
  }

  async function checkUpdate() {
    await perform('check-update', api.checkUpdate, (result, _live) => {
      const { latest, available } = signedUpdateCandidate(result);
      setUpdateState(available ? 'available' : 'unavailable');
      if (latest) setVersions((current) => ({ ...current, latest }));
    }, (result, _live) => {
      const { latest, available } = signedUpdateCandidate(result);
      if (available) return '签名清单验证完成，发现 Bundle ' + (latest || versions.latest);
      return result?.message || result?.reason || '未发现经过签名验证的可用更新；没有执行升级。';
    });
  }

  async function upgrade() {
    const previousState = updateState;
    setUpdateState('upgrading');
    const ok = await perform('upgrade', api.upgrade, () => {
      setVersions((current) => ({ ...current, bundle: current.latest, core: current.latest, ui: '1.0.1', scripts: current.latest }));
      setUpdateState('complete');
    }, '升级与自检完成，回滚点已保留');
    if (!ok) setUpdateState(previousState);
  }

  async function rollback() {
    await perform('rollback', api.rollback, () => {
      setVersions(localVersions);
      setUpdateState('idle');
    }, '已回滚到上一个验证版本，系统 DNS 未修改');
  }

  async function validatePairing(payload) {
    let validation = null;
    const ok = await perform('pairing', () => api.validatePairing(payload), (liveValidation, _live) => {
      const candidate = liveValidation;
      if (candidate?.valid && candidate.validationId && candidate.serverIp && candidate.port && candidate.fileName && candidate.fingerprint && candidate.expiresAt) {
        validation = { ...candidate, requestedServerIp: payload.serverIp.trim(), requestedFileName: payload.fileName };
      }
    }, () => validation ? '配对文件校验通过' : '');
    if (ok && !validation) setToast({ tone: 'warning', message: '后台返回的配对验证信息不完整，未进入指纹确认。' });
    return ok ? validation : null;
  }

  async function enroll(payload) {
    const endpoint = (payload.serverIp.includes(':') ? '[' + payload.serverIp + ']' : payload.serverIp) + ':' + payload.port;
    return perform('pairing', () => api.enroll(payload), () => setStatus((current) => ({ ...current, connection: 'disconnected', endpoint })), '客户端已激活，一次性凭据已清除');
  }

  function renderPage() {
    if (page === 'routing') return <RoutingPage rules={rules} busy={busy} onSave={saveRule} onDelete={deleteRule} />;
    if (page === 'dns') return <DnsPage dns={dns} diagnostics={diagnosticReport} busy={busy} diagnosticsOpen={diagnosticsOpen} onRefresh={refreshDns} onDiagnose={() => runDoctor(true)} onCloseDiagnostics={() => setDiagnosticsOpen(false)} onCopy={copyText} />;
    if (page === 'health') return <HealthPage health={health} diagnostics={diagnosticReport} proxyTests={proxyTests} versions={versions} busy={busy} updateState={updateState} onDiagnose={() => runDoctor(false)} onProxyTest={runProxyTests} onCopy={copyDiagnosticReport} onExport={exportReport} onCheckUpdate={checkUpdate} onUpgrade={upgrade} onRollback={rollback} />;
    if (page === 'pairing') return <PairingPage busy={busy} onValidate={validatePairing} onEnroll={enroll} onCopy={copyText} onComplete={() => setPage('connection')} />;
    return <ConnectionPage status={status} proxyRuntime={proxyRuntime} proxyConfig={proxyConfig} busy={busy} onConnect={connectProxy} onSaveConfig={saveProxyConfig} onDisconnect={disconnect} onReconnect={reconnect} onNavigate={setPage} />;
  }

  return (
    <>
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <Layout page={page} onNavigate={setPage} backendMode={backendMode} proxyRuntime={proxyRuntime} status={status} versions={versions}>
        {renderPage()}
      </Layout>
      {toast && (
        <div className={'toast ' + toast.tone} role="status">
          {toast.tone === 'success' ? <CheckCircle size={21} weight="fill" /> : toast.tone === 'warning' ? <Warning size={21} weight="fill" /> : <Info size={21} weight="fill" />}
          <span>{toast.message}</span>
          <button type="button" aria-label="关闭提示" onClick={() => setToast(null)}><X size={18} /></button>
        </div>
      )}
    </>
  );
}
