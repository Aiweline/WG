import { useRef, useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle,
  Copy,
  FileArrowUp,
  Fingerprint,
  Info,
  Key,
  LockKey,
  Network,
  HardDrives,
} from '@phosphor-icons/react';

const steps = ['服务器 IP', '配对文件', '指纹确认', '系统授权', '完成'];

export function PairingPage({ busy, onValidate, onEnroll, onCopy, onComplete }) {
  const [step, setStep] = useState(1);
  const [serverIp, setServerIp] = useState('203.0.113.10');
  const [fileName, setFileName] = useState('wg-pairing.wgp');
  const [validation, setValidation] = useState(null);
  const [fingerprintConfirmed, setFingerprintConfirmed] = useState(false);
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [error, setError] = useState('');
  const fileInput = useRef(null);
  const inputVersion = useRef(0);

  function validIp(value) {
    const trimmed = value.trim();
    const ipv4 = trimmed.split('.');
    if (ipv4.length === 4 && ipv4.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) return true;
    const [address, zone, ...extraZones] = trimmed.split('%');
    if (extraZones.length || (zone !== undefined && !/^[a-zA-Z0-9_.-]+$/.test(zone))) return false;
    if (!address.includes(':') || address.includes(':::') || !/^[0-9a-fA-F:.]+$/.test(address)) return false;
    if ((address.match(/::/g) || []).length > 1) return false;
    const parts = address.split(':').filter(Boolean);
    let units = 0;
    for (const [index, part] of parts.entries()) {
      if (part.includes('.')) {
        const tail = part.split('.');
        if (index !== parts.length - 1 || tail.length !== 4 || !tail.every((item) => /^\d{1,3}$/.test(item) && Number(item) <= 255)) return false;
        units += 2;
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
        units += 1;
      }
    }
    return address.includes('::') ? units < 8 : units === 8;
  }

  function invalidateValidation() {
    inputVersion.current += 1;
    setValidation(null);
    setFingerprintConfirmed(false);
    setAuthorizationConfirmed(false);
  }

  function changeServerIp(value) {
    if (value !== serverIp) invalidateValidation();
    setServerIp(value);
  }

  function changeFileName(value) {
    if (value !== fileName) invalidateValidation();
    setFileName(value);
  }

  function validationMatchesInputs() {
    return validation?.requestedServerIp === serverIp.trim() && validation?.requestedFileName === fileName;
  }

  function expiryLabel(value) {
    if (!value) return '未知';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('zh-CN', { hour12: false });
  }

  function endpointLabel(address, port) {
    if (!address) return '—';
    return (address.includes(':') ? '[' + address + ']' : address) + ':' + port;
  }

  async function next() {
    setError('');
    if (step === 1 && !validIp(serverIp)) {
      setError('请输入有效的服务器 IPv4 或 IPv6 字面量，不接受域名。');
      return;
    }
    if (step === 2) {
      if (fileName !== 'wg-pairing.wgp') {
        setError('配对文件名必须精确为 wg-pairing.wgp。');
        return;
      }
      const requestVersion = inputVersion.current;
      const validated = await onValidate({ serverIp: serverIp.trim(), fileName });
      if (!validated) return;
      if (requestVersion !== inputVersion.current) {
        setError('配对信息在校验期间发生变化，请重新校验。');
        return;
      }
      setValidation(validated);
      setFingerprintConfirmed(false);
      setAuthorizationConfirmed(false);
    }
    if (step === 3) {
      if (!validation || !validationMatchesInputs()) {
        setError('配对信息已变化，请返回上一步重新校验。');
        return;
      }
      if (!fingerprintConfirmed) {
        setError('请先通过独立渠道核对并确认服务器指纹。');
        return;
      }
    }
    if (step === 4) {
      if (!validation || !validationMatchesInputs()) {
        setStep(2);
        setError('配对信息已变化，请重新校验后再授权。');
        return;
      }
      const expiresAt = new Date(validation.expiresAt).getTime();
      if (!validation.expiresAt || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
        setValidation(null);
        setFingerprintConfirmed(false);
        setStep(2);
        setError('本次配对验证已过期，请重新校验配对文件。');
        return;
      }
      if (!authorizationConfirmed) {
        setError('请确认系统授权范围。');
        return;
      }
      const ok = await onEnroll({
        validationId: validation.validationId,
        serverIp: validation.serverIp,
        port: validation.port,
        fileName: validation.fileName,
        fingerprint: validation.fingerprint,
        fingerprintConfirmed,
        authorizationConfirmed,
      });
      if (!ok) return;
    }
    setStep((current) => Math.min(5, current + 1));
  }

  function previous() {
    setError('');
    setStep((current) => Math.max(1, current - 1));
  }

  function reset() {
    inputVersion.current += 1;
    setStep(1);
    setValidation(null);
    setFingerprintConfirmed(false);
    setAuthorizationConfirmed(false);
    setError('');
  }

  return (
    <section className="page pairing-page" aria-labelledby="pairing-title">
      <div className="pairing-heading"><div><span className="eyebrow">安全配对</span><h1 id="pairing-title">首次配对向导</h1><p>按照向导完成配对，成功后即可连接。</p></div><button className="text-button" type="button" onClick={reset}>从头开始</button></div>

      <ol className="stepper" aria-label="配对进度">
        {steps.map((label, index) => {
          const number = index + 1;
          const complete = number < step;
          const active = number === step;
          return <li key={label} className={complete ? 'complete' : active ? 'active' : ''}><button type="button" disabled={number > step} onClick={() => number < step && setStep(number)} aria-current={active ? 'step' : undefined}><span>{complete ? <Check size={17} weight="bold" /> : number}</span>{label}</button></li>;
        })}
      </ol>

      <div className="pairing-card">
        <aside className="pair-summary" aria-label="配对信息摘要">
          <h2>配对信息摘要</h2>
          <dl>
            <div><dt><HardDrives size={21} />服务器 IP</dt><dd>{validation?.serverIp || serverIp || '尚未填写'}{step > 1 && <CheckCircle size={17} weight="fill" />}</dd></div>
            <div><dt><Network size={21} />端口</dt><dd>{validation?.port || '待校验'}{validation && <CheckCircle size={17} weight="fill" />}</dd></div>
            <div><dt><Key size={21} />配对文件</dt><dd>{fileName || '尚未选择'}{validation && <CheckCircle size={17} weight="fill" />}</dd></div>
          </dl>
          <p><CheckCircle size={18} />以上信息仅是脱敏摘要，不包含一次性令牌。</p>
        </aside>

        <section className="pair-step-content" aria-live="polite">
          {step === 1 && (
            <div className="pair-form-step">
              <span className="step-kicker">步骤 1 / 5</span><h2>输入服务器 IP</h2><p>填写服务端安装时使用的同一个对外 IP。</p>
              <label>服务器 IP<input autoFocus value={serverIp} onChange={(event) => changeServerIp(event.target.value)} placeholder="203.0.113.10 或 2001:db8::10" /></label>
              <div className="safe-note"><LockKey size={20} /><span>仅凭 IP 不会自动信任服务器，后续仍需核对固定公钥指纹。</span></div>
            </div>
          )}

          {step === 2 && (
            <div className="pair-form-step">
              <span className="step-kicker">步骤 2 / 5</span><h2>选择一次性配对文件</h2><p>默认文件名为 <code>wg-pairing.wgp</code>，只接受安全的普通文件。</p>
              <input ref={fileInput} className="sr-only" type="file" accept=".wgp" aria-label="选择配对文件" onChange={(event) => event.target.files[0] && changeFileName(event.target.files[0].name)} />
              <button className="file-drop" type="button" onClick={() => fileInput.current?.click()}><FileArrowUp size={36} /><strong>{fileName || '选择 wg-pairing.wgp'}</strong><span>文件必须未过期，且权限符合安全要求</span></button>
            </div>
          )}

          {step === 3 && (
            <div className="fingerprint-step">
              <span className="step-kicker">当前步骤 3 / 5</span><h2>指纹确认</h2>
              <label>服务器指纹（BLAKE2s-256 · WG-FP/1）</label>
              <div className="fingerprint-value"><Fingerprint size={23} aria-hidden="true" /><code>{validation?.fingerprint}</code><button type="button" aria-label="复制服务器指纹" onClick={() => onCopy(validation?.fingerprint)}><Copy size={21} /></button></div>
              <p className="fingerprint-help"><Info size={18} />已验证端点 {endpointLabel(validation?.serverIp, validation?.port)} · 验证有效期至 {expiryLabel(validation?.expiresAt)}。请将以上 <code>wgs-</code> Base32 指纹与服务器脚本通过独立渠道输出的指纹逐字核对。</p>
              <label className="check-row"><input type="checkbox" checked={fingerprintConfirmed} onChange={(event) => setFingerprintConfirmed(event.target.checked)} /><span>我已通过独立渠道核对并确认指纹正确</span></label>
              <div className="safe-note"><LockKey size={20} /><span>WG 不会把指纹发送给任何第三方，也不会使用 SHA-256 十六进制默认格式替代它。</span></div>
            </div>
          )}

          {step === 4 && (
            <div className="authorization-step">
              <span className="step-kicker">步骤 4 / 5</span><h2>系统授权</h2><p>授权只用于安装和管理隧道、分流组件以及本地服务。</p>
              <ul><li><CheckCircle size={18} />创建隧道网络接口</li><li><CheckCircle size={18} />添加或移除 WG 路由规则</li><li><CheckCircle size={18} />启动或停止本地服务</li></ul>
              <div className="dns-boundary"><Info size={20} /><strong>不会修改系统 DNS</strong><span>WG 只读取系统 DNS 的副本，不接管系统解析器。</span></div>
              <label className="check-row"><input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} /><span>我确认以上最小授权范围</span></label>
            </div>
          )}

          {step === 5 && (
            <div className="pair-complete"><CheckCircle size={54} weight="fill" /><span className="step-kicker">步骤 5 / 5</span><h2>配对成功</h2><p>服务端已激活此客户端，临时配对凭据已清除。现在可以返回连接页建立隧道。</p><div className="completion-summary"><span>服务器</span><strong>{endpointLabel(validation?.serverIp, validation?.port)}</strong><span>系统 DNS</span><strong>未修改</strong></div><button className="button primary" type="button" onClick={onComplete}>返回连接页</button></div>
          )}

          {error && <p className="field-error pairing-error" role="alert">{error}</p>}
        </section>
      </div>

      {step < 5 && (
        <div className="wizard-actions">
          <button className="button secondary" type="button" onClick={previous} disabled={step === 1 || busy}><ArrowLeft size={19} />上一步</button>
          <button className="button primary" type="button" onClick={next} disabled={busy || (step === 3 && !fingerprintConfirmed) || (step === 4 && !authorizationConfirmed)}>{busy === 'pairing' ? '正在安全配对…' : step === 4 ? '授权并完成配对' : '确认并继续'}<ArrowRight size={19} /></button>
        </div>
      )}
    </section>
  );
}
