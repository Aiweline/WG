import { useEffect, useState } from 'react';
import { CheckCircle, Info, Warning, X } from '@phosphor-icons/react';
import { api, ApiUnavailableError, formatDiagnosticReport } from './api.js';
import { ConnectionPage } from './ConnectionPage.jsx';
import { DnsPage } from './DnsPage.jsx';
import { HealthPage } from './HealthPage.jsx';
import { Layout } from './Layout.jsx';
import { PairingPage } from './PairingPage.jsx';
import { RoutingPage } from './RoutingPage.jsx';
import {
  demoDns,
  demoDiagnostics,
  demoHealth,
  demoRules,
  demoStatus,
  demoVersions,
  serverFingerprint,
} from './demoData.js';

const delay = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

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
  const [status, setStatus] = useState(demoStatus);
  const [rules, setRules] = useState(demoRules);
  const [dns, setDns] = useState(demoDns);
  const [versions, setVersions] = useState(demoVersions);
  const [health, setHealth] = useState(demoHealth);
  const [diagnosticReport, setDiagnosticReport] = useState(demoDiagnostics);
  const [proxyTests, setProxyTests] = useState(null);
  const [proxyRuntime, setProxyRuntime] = useState({ tcp_listener: false, udp_listener: false });
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
        setBackendMode('demo');
        setToast({ tone: 'info', message: '后台 API 未响应，已进入安全演示模式；操作不会修改真实网络或系统 DNS。' });
      }
    }
    load();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    async function loadProxyRuntime() {
      try {
        const runtime = await api.proxyStatus();
        if (!active) return;
        setProxyRuntime(runtime);
        if (runtime?.tcp_listener) {
          setStatus((current) => ({ ...current, connection: 'connected', endpoint: '本机 TCP 代理 127.0.0.1:47101', duration: '—', uploaded: '—', downloaded: '—', dnsState: 'ready', proxyRuntime: true }));
        } else {
          setStatus((current) => ({ ...current, connection: 'disconnected', endpoint: '本机代理未启动', duration: '—', uploaded: '—', downloaded: '—', proxyRuntime: true }));
        }
      } catch {
        // The normal core UI remains available when its local host is not running.
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
    setBusy(key);
    const live = backendMode === 'live';
    try {
      let response;
      if (live) response = await apiCall();
      else await delay(520);
      localUpdate(response, live);
      const resolvedMessage = typeof successMessage === 'function' ? successMessage(response, live) : successMessage;
      if (resolvedMessage) setToast({ tone: 'success', message: resolvedMessage + (live ? '' : '（演示）') });
      return true;
    } catch (error) {
      if (error instanceof ApiUnavailableError) {
        setBackendMode('demo');
        setToast({ tone: 'warning', message: '后台响应中断，无法确认操作结果；本地状态未更新，已切换到安全演示模式。重新连接后台后请核实。' });
      } else {
        setToast({ tone: 'warning', message: error.status === 501 ? '后台已明确返回：此版本尚未实现该操作。没有执行升级或回滚。' : error.message });
      }
      return false;
    } finally {
      setBusy('');
    }
  }

  async function disconnect() {
    await perform('disconnect', api.disconnect, () => setStatus((current) => ({ ...current, connection: 'disconnected', duration: '—' })), '隧道已安全断开，系统 DNS 保持原样');
  }

  async function reconnect() {
    await perform('reconnect', api.reconnect, () => setStatus((current) => ({ ...current, connection: 'connected', duration: '00:00:01' })), '已使用新会话重新连接');
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
    await perform('doctor', api.doctor, (liveReport, live) => {
      const report = live ? liveReport : { ...demoDiagnostics, health: demoHealth.map((item) => ({ ...item })) };
      setDiagnosticReport(report);
      setHealth(report.health);
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
    await perform('check-update', api.checkUpdate, (result, live) => {
      if (!live) {
        setUpdateState('available');
        return;
      }
      const { latest, available } = signedUpdateCandidate(result);
      setUpdateState(available ? 'available' : 'unavailable');
      if (latest) setVersions((current) => ({ ...current, latest }));
    }, (result, live) => {
      if (!live) return '演示模式已模拟发现 Bundle ' + versions.latest;
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
      setVersions(demoVersions);
      setUpdateState('idle');
    }, '已回滚到上一个验证版本，系统 DNS 未修改');
  }

  async function validatePairing(payload) {
    let validation = null;
    const ok = await perform('pairing', () => api.validatePairing(payload), (liveValidation, live) => {
      const candidate = live ? liveValidation : {
        valid: true,
        validationId: 'demo-validation-' + Date.now(),
        serverIp: payload.serverIp.trim(),
        port: 9518,
        fileName: payload.fileName,
        fingerprint: serverFingerprint,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        message: '安全演示验证，不会读取真实配对文件。',
      };
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
    return <ConnectionPage status={status} busy={busy} onDisconnect={disconnect} onReconnect={reconnect} onNavigate={setPage} />;
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
