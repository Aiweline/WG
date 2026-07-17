import { useMemo, useState } from 'react';
import {
  ArrowsSplit,
  Globe,
  Info,
  MagnifyingGlass,
  Network,
  PencilSimple,
  Plus,
  Trash,
  X,
} from '@phosphor-icons/react';

const emptyDraft = {
  id: null,
  target: '',
  type: '域名',
  action: 'TUNNEL',
  source: '手动',
  expires: '永久',
  note: '',
};

const standardExpiries = ['永久', '1 小时', '1 天', '3 天', '7 天'];

function inferType(target) {
  if (target.includes('/')) return 'CIDR';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) return 'IP';
  return '域名';
}

function targetLooksValid(target) {
  const trimmed = target.trim();
  if (!trimmed || trimmed.includes(' ')) return false;
  return trimmed.includes('.') || trimmed.includes(':');
}

function TargetIcon({ type }) {
  return type === '域名' ? <Globe size={20} aria-hidden="true" /> : <Network size={20} aria-hidden="true" />;
}

export function RoutingPage({ rules, busy, onSave, onDelete }) {
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('全部');
  const [sourceFilter, setSourceFilter] = useState('全部');
  const [typeFilter, setTypeFilter] = useState('全部');
  const [drawer, setDrawer] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [error, setError] = useState('');

  const visibleRules = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return rules.filter((rule) => {
      if (needle && !rule.target.toLowerCase().includes(needle)) return false;
      if (actionFilter !== '全部' && rule.action !== actionFilter) return false;
      if (sourceFilter !== '全部' && rule.source !== sourceFilter) return false;
      if (typeFilter !== '全部' && rule.type !== typeFilter) return false;
      return true;
    });
  }, [rules, search, actionFilter, sourceFilter, typeFilter]);

  function openAdd() {
    setError('');
    setDrawer({ ...emptyDraft });
  }

  function openEdit(rule) {
    setError('');
    const editingLearnedDecision = rule.source === '自动学习';
    setDrawer({
      ...rule,
      id: editingLearnedDecision ? null : rule.id,
      revision: editingLearnedDecision ? undefined : rule.revision,
      source: '手动',
      note: rule.note || '',
      editingLearnedDecision,
      targetReadOnly: true,
      replacesAutoId: editingLearnedDecision ? rule.id : undefined,
    });
  }

  async function submit(event) {
    event.preventDefault();
    if (!targetLooksValid(drawer.target)) {
      setError('请输入有效的域名、IP 或 CIDR。');
      return;
    }
    const normalized = drawer.target.trim().toLowerCase();
    const ruleDraft = { ...drawer };
    delete ruleDraft.editingLearnedDecision;
    delete ruleDraft.targetReadOnly;
    const saved = await onSave({
      ...ruleDraft,
      target: normalized,
      type: inferType(normalized),
      source: '手动',
    });
    if (saved) setDrawer(null);
  }

  return (
    <section className="page routing-page" aria-labelledby="routing-title">
      <div className="page-heading">
        <div>
          <h1 id="routing-title">智能分流</h1>
          <p>根据规则将流量分流到隧道、直连或拦截，其余流量由 AUTO 智能评估。</p>
        </div>
      </div>

      <div className="rule-toolbar" aria-label="规则筛选">
        <label className="search-field">
          <span className="sr-only">搜索域名或 IP</span>
          <MagnifyingGlass size={19} aria-hidden="true" />
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索域名或 IP" />
        </label>
        <label><span className="sr-only">结果</span><select value={actionFilter} onChange={(event) => setActionFilter(event.target.value)}><option value="全部">结果：全部</option><option>TUNNEL</option><option>DIRECT</option><option>BLOCK</option><option>AUTO</option></select></label>
        <label><span className="sr-only">来源</span><select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}><option value="全部">来源：全部</option><option>手动</option><option>自动学习</option></select></label>
        <label><span className="sr-only">目标类型</span><select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}><option value="全部">目标类型：全部</option><option>域名</option><option>IP</option><option>CIDR</option></select></label>
        <button className="button primary compact" type="button" onClick={openAdd}><Plus size={19} />添加规则</button>
      </div>

      <div className="table-wrap">
        <table className="rules-table">
          <caption className="sr-only">当前智能分流规则与自动决策</caption>
          <thead><tr><th>目标</th><th>结果</th><th>来源</th><th>到期时间</th><th>操作</th></tr></thead>
          <tbody>
            {visibleRules.map((rule) => (
              <tr key={rule.id}>
                <td><span className="target-cell"><TargetIcon type={rule.type} /><span><strong>{rule.target}</strong><small>{rule.type}</small></span></span></td>
                <td><span className={'action-badge ' + rule.action.toLowerCase()}>{rule.action}</span></td>
                <td>{rule.source}</td>
                <td>{rule.expires}</td>
                <td>
                  <div className="row-actions">
                    <button type="button" aria-label={'编辑 ' + rule.target} onClick={() => openEdit(rule)} title="编辑"><PencilSimple size={19} /></button>
                    <button type="button" className="danger-icon" aria-label={'删除 ' + rule.target} onClick={() => setDeleteTarget(rule)} title="删除"><Trash size={19} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {visibleRules.length === 0 && (
          <div className="empty-state"><ArrowsSplit size={32} /><strong>没有匹配的目标</strong><span>调整搜索词或筛选条件后再试。</span></div>
        )}
      </div>
      <p className="auto-note"><Info size={17} aria-hidden="true" />删除覆盖项后恢复 AUTO 并立即重新评估；删除不等于 DIRECT。</p>

      {drawer && (
        <div className="drawer-backdrop" onMouseDown={(event) => event.target === event.currentTarget && setDrawer(null)}>
          <aside className="rule-drawer" role="dialog" aria-modal="true" aria-labelledby="rule-drawer-title">
            <header><h2 id="rule-drawer-title">{drawer.editingLearnedDecision ? '创建手动覆盖' : drawer.id ? '编辑规则' : '添加规则'}</h2><button type="button" aria-label="关闭编辑规则" onClick={() => setDrawer(null)}><X size={22} /></button></header>
            <form onSubmit={submit}>
              {drawer.editingLearnedDecision && <p className="inline-notice">自动学习来源不可修改；保存后会创建一条新的手动覆盖。</p>}
              <label>目标<input autoFocus value={drawer.target} readOnly={drawer.targetReadOnly} aria-readonly={drawer.targetReadOnly || undefined} onChange={(event) => setDrawer({ ...drawer, target: event.target.value })} placeholder="api.example.com" aria-describedby={error ? 'target-error' : undefined} /></label>
              {drawer.targetReadOnly && <small className="field-help">已有目标不可修改；如需更换目标，请删除后新增规则。</small>}
              {error && <p className="field-error" id="target-error" role="alert">{error}</p>}
              <label>结果<select value={drawer.action} onChange={(event) => setDrawer({ ...drawer, action: event.target.value })}><option>TUNNEL</option><option>DIRECT</option><option>BLOCK</option></select></label>
              <label>来源<input value="手动（由 wg-core 记录）" readOnly aria-readonly="true" /></label>
              <small className="field-help">来源由后台生成，客户端不能伪造“自动学习”。</small>
              <label>到期时间<select value={drawer.expires} onChange={(event) => setDrawer({ ...drawer, expires: event.target.value })}>{!standardExpiries.includes(drawer.expires) && <option>{drawer.expires}</option>}<option>永久</option><option>1 小时</option><option>1 天</option><option>3 天</option><option>7 天</option></select></label>
              <label>备注（可选）<textarea value={drawer.note} onChange={(event) => setDrawer({ ...drawer, note: event.target.value })} placeholder="输入备注" rows="4" /></label>
              <div className="drawer-actions"><button className="button secondary" type="button" onClick={() => setDrawer(null)}>取消</button><button className="button primary" type="submit" disabled={busy === 'save-rule'}>{busy === 'save-rule' ? '正在保存…' : '保存'}</button></div>
            </form>
          </aside>
        </div>
      )}

      {deleteTarget && (
        <div className="modal-backdrop">
          <section className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="delete-title" aria-describedby="delete-description">
            <h2 id="delete-title">删除规则？</h2>
            <p id="delete-description">删除 <strong>{deleteTarget.target}</strong> 后，它将恢复 AUTO 并重新评估，不会被强制改为直连。</p>
            <div className="dialog-actions"><button className="button secondary" type="button" onClick={() => setDeleteTarget(null)}>取消</button><button className="button danger" type="button" disabled={busy === 'delete-rule'} onClick={async () => { if (await onDelete(deleteTarget)) setDeleteTarget(null); }}>{busy === 'delete-rule' ? '正在删除…' : '删除并恢复 AUTO'}</button></div>
          </section>
        </div>
      )}
    </section>
  );
}
