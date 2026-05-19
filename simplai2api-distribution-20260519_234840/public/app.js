const state = {
  activeAccountId: null,
  settings: null,
  summary: null,
  reconcile: null,
  items: [],
};

const el = {
  body: document.getElementById('accountsBody'),
  activeBadge: document.getElementById('activeBadge'),
  form: document.getElementById('accountForm'),
  settingsForm: document.getElementById('settingsForm'),
  resetBtn: document.getElementById('resetBtn'),
  reloadBtn: document.getElementById('reloadBtn'),
  logoutBtn: document.getElementById('logoutBtn'),
  refreshBalancesBtn: document.getElementById('refreshBalancesBtn'),
  reconcileBtn: document.getElementById('reconcileBtn'),
  toast: document.getElementById('toast'),
  serviceInfo: document.getElementById('serviceInfo'),
};

function showToast(message, isError = false) {
  el.toast.textContent = message;
  el.toast.classList.remove('hidden');
  el.toast.style.borderColor = isError ? '#7a2f2f' : '#25304d';
  setTimeout(() => el.toast.classList.add('hidden'), 2800);
}

function getField(id) {
  return document.getElementById(id);
}

function resetForm() {
  getField('accountId').value = '';
  getField('label').value = '';
  getField('email').value = '';
  getField('password').value = '';
  getField('accessToken').value = '';
  getField('userId').value = '';
  getField('tenantId').value = '';
  getField('projectId').value = '';
  getField('agentName').value = '';
  getField('agentPipelineId').value = '';
  getField('versionId').value = '';
  getField('browserProfileDir').value = '';
  getField('notes').value = '';
  getField('enabled').checked = true;
}

function fillForm(item) {
  getField('accountId').value = item.id || '';
  getField('label').value = item.label || '';
  getField('email').value = item.email || '';
  getField('password').value = item.password || '';
  getField('accessToken').value = item.accessToken || '';
  getField('userId').value = item.userId || '';
  getField('tenantId').value = item.tenantId || '';
  getField('projectId').value = item.projectId || '';
  getField('agentName').value = item.agentName || '';
  getField('agentPipelineId').value = item.agentPipelineId || '';
  getField('versionId').value = item.versionId || '';
  getField('browserProfileDir').value = item.browserProfileDir || '';
  getField('notes').value = item.notes || '';
  getField('enabled').checked = item.enabled !== false;
  window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
}

function fillSettings(settings = {}) {
  getField('autoReplenishEnabled').checked = settings.autoReplenishEnabled !== false;
  getField('minAvailableAccounts').value = settings.minAvailableAccounts ?? 1;
  getField('preExhaustedCreditsThreshold').value = settings.preExhaustedCreditsThreshold ?? 20;
  getField('maxPoolSize').value = settings.maxPoolSize ?? 10;
  getField('balanceRefreshEveryCalls').value = settings.balanceRefreshEveryCalls ?? 3;
}

function formatDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('zh-CN', { hour12: false });
}

function formatBalance(value) {
  if (value === null || value === undefined || value === '') return '-';
  const num = Number(value);
  if (!Number.isFinite(num)) return String(value);
  return num.toFixed(4).replace(/\.0+$/, '').replace(/(\.\d*?)0+$/, '$1');
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function renderServiceInfo() {
  const summary = state.summary || {};
  const reconcile = state.reconcile || {};
  const template = state.items.find(item => item.id === state.activeAccountId);
  const lastSummary = reconcile.lastSummary || {};
  const info = [
    ['Base URL', window.location.origin],
    ['固定模型名', 'claude-opus-4.6-simplai'],
    ['模板账号', template ? `${template.label} (${template.email || '无邮箱'})` : '未设置'],
    ['账号总数 / 可用', `${summary.total ?? 0} / ${summary.ready ?? 0}`],
    ['预耗尽账号', String(summary.preExhausted ?? 0)],
    ['最大池 / 最低可用', `${state.settings?.maxPoolSize ?? '-'} / ${state.settings?.minAvailableAccounts ?? '-'}`],
    ['最近对账', reconcile.lastAt ? formatDate(reconcile.lastAt) : '未执行'],
    ['最近对账状态', reconcile.inProgress ? '执行中' : (lastSummary.status || '未执行')],
  ];
  el.serviceInfo.innerHTML = info.map(([label, value]) => `
    <div class="info-item">
      <div class="label">${escapeHtml(label)}</div>
      <div>${escapeHtml(value)}</div>
    </div>
  `).join('');
}

function statusClass(code) {
  if (code === 'ready') return 'ok';
  if (code === 'pre_exhausted') return 'warn';
  if (code === 'disabled') return 'off';
  return '';
}

function renderAccounts() {
  el.activeBadge.textContent = `模板账号: ${state.activeAccountId || '-'}`;
  const refreshEvery = state.settings?.balanceRefreshEveryCalls ?? '-';
  el.body.innerHTML = state.items.map(item => {
    const runtime = item.runtime || {};
    const balanceError = item.balanceRefreshError ? `<div class="muted small-text danger-text">${escapeHtml(item.balanceRefreshError)}</div>` : '';
    const templateTag = item.id === state.activeAccountId ? '<span class="tiny-badge">模板</span>' : '';
    const autoTag = item.autoRegistered ? '<span class="tiny-badge ghost-badge">自动补号</span>' : '';
    return `
      <tr>
        <td>
          <div class="row-title">${escapeHtml(item.label || '')}</div>
          <div class="inline-badges">${templateTag}${autoTag}</div>
          <div class="muted small-text">${escapeHtml(item.agentName || '-')} · v${escapeHtml(item.versionId || '-')}</div>
        </td>
        <td>
          <div>${escapeHtml(item.email || '')}</div>
          <div class="muted small-text">tenant: ${escapeHtml(item.tenantId || '-')}</div>
        </td>
        <td>
          <div>user: ${escapeHtml(item.userId || '-')}</div>
          <div class="muted small-text">project: ${escapeHtml(item.projectId || '-')}</div>
        </td>
        <td>
          <div class="balance">${escapeHtml(formatBalance(item.lastKnownUsableBalance))}</div>
          <div class="muted small-text">钱包: ${escapeHtml(formatBalance(item.lastKnownWalletBalance))}</div>
        </td>
        <td>
          <div>最近使用: ${escapeHtml(formatDate(item.lastUsedAt))}</div>
          <div class="muted small-text">累计调用: ${escapeHtml(String(item.lastRelayUseCount || 0))}</div>
          <div class="muted small-text">余额刷新: ${escapeHtml(formatDate(item.lastBalanceAt))}</div>
          <div class="muted small-text">距离下次刷新: ${escapeHtml(String(item.callsSinceBalanceRefresh || 0))} / ${escapeHtml(String(refreshEvery))}</div>
        </td>
        <td>
          <span class="status-pill ${statusClass(runtime.statusCode)}">${escapeHtml(runtime.statusLabel || '-')}</span>
          ${balanceError}
        </td>
        <td>
          <div class="actions">
            <button class="small" data-action="edit" data-id="${item.id}">编辑</button>
            <button class="small ok" data-action="select" data-id="${item.id}">设为模板</button>
            <button class="small" data-action="refreshBalance" data-id="${item.id}">刷新积分</button>
            <button class="small" data-action="refreshToken" data-id="${item.id}">刷新Token</button>
            <button class="small danger" data-action="delete" data-id="${item.id}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
  renderServiceInfo();
}

async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    credentials: 'same-origin',
    ...options,
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (response.status === 401) {
    location.href = '/login';
    throw new Error('未登录');
  }
  if (!response.ok) {
    throw new Error(data?.error || data?.detail || text || '请求失败');
  }
  return data;
}

async function loadAccounts() {
  const data = await request('/api/accounts');
  state.activeAccountId = data.activeAccountId;
  state.settings = data.settings || {};
  state.summary = data.summary || {};
  state.reconcile = data.reconcile || {};
  state.items = data.items || [];
  fillSettings(state.settings);
  renderAccounts();
}

function collectPayload() {
  const id = getField('accountId').value.trim();
  return {
    id: id || undefined,
    label: getField('label').value.trim(),
    email: getField('email').value.trim(),
    password: getField('password').value,
    accessToken: getField('accessToken').value.trim(),
    userId: getField('userId').value.trim(),
    tenantId: getField('tenantId').value.trim(),
    projectId: getField('projectId').value.trim(),
    agentName: getField('agentName').value.trim(),
    agentPipelineId: getField('agentPipelineId').value.trim(),
    versionId: getField('versionId').value.trim(),
    browserProfileDir: getField('browserProfileDir').value.trim(),
    notes: getField('notes').value.trim(),
    enabled: getField('enabled').checked,
  };
}

function collectSettingsPayload() {
  return {
    autoReplenishEnabled: getField('autoReplenishEnabled').checked,
    minAvailableAccounts: Number(getField('minAvailableAccounts').value || 0),
    preExhaustedCreditsThreshold: Number(getField('preExhaustedCreditsThreshold').value || 0),
    maxPoolSize: Number(getField('maxPoolSize').value || 1),
    balanceRefreshEveryCalls: Number(getField('balanceRefreshEveryCalls').value || 1),
  };
}

el.form.addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const payload = collectPayload();
    if (payload.id) {
      await request(`/api/accounts/${payload.id}`, { method: 'PUT', body: JSON.stringify(payload) });
      showToast('账号已更新');
    } else {
      await request('/api/accounts', { method: 'POST', body: JSON.stringify(payload) });
      showToast('账号已新增');
    }
    resetForm();
    await loadAccounts();
  } catch (error) {
    showToast(error.message, true);
  }
});

el.settingsForm.addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await request('/api/settings', { method: 'PUT', body: JSON.stringify(collectSettingsPayload()) });
    showToast('统一配置已保存');
    await loadAccounts();
  } catch (error) {
    showToast(error.message, true);
  }
});

el.body.addEventListener('click', async event => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = button.dataset.id;
  const action = button.dataset.action;
  const item = state.items.find(row => row.id === id);
  try {
    if (action === 'edit') {
      fillForm(item);
      return;
    }
    if (action === 'select') {
      await request(`/api/accounts/${id}/select`, { method: 'POST' });
      showToast('已设为模板账号');
    }
    if (action === 'refreshToken') {
      await request(`/api/accounts/${id}/refresh`, { method: 'POST' });
      showToast('Token 已刷新');
    }
    if (action === 'refreshBalance') {
      await request(`/api/accounts/${id}/balance`, { method: 'POST' });
      showToast('积分已刷新');
    }
    if (action === 'delete') {
      if (!confirm(`确认删除账号：${item?.label || id} ?`)) return;
      await request(`/api/accounts/${id}`, { method: 'DELETE' });
      showToast('账号已删除');
    }
    await loadAccounts();
  } catch (error) {
    showToast(error.message, true);
  }
});

el.resetBtn.addEventListener('click', resetForm);
el.reloadBtn.addEventListener('click', () => loadAccounts().catch(error => showToast(error.message, true)));

el.refreshBalancesBtn.addEventListener('click', async () => {
  try {
    await request('/api/accounts/refresh-balances', { method: 'POST', body: JSON.stringify({ force: true }) });
    showToast('全部积分刷新完成');
    await loadAccounts();
  } catch (error) {
    showToast(error.message, true);
  }
});

el.reconcileBtn.addEventListener('click', async () => {
  try {
    const result = await request('/api/reconcile', { method: 'POST', body: JSON.stringify({ forceBalanceRefresh: true }) });
    showToast(`对账完成: ${result.status || 'ok'}`);
    await loadAccounts();
  } catch (error) {
    showToast(error.message, true);
  }
});

el.logoutBtn?.addEventListener('click', async () => {
  try {
    await request('/auth/logout', { method: 'POST' });
  } catch {
    // ignore
  }
  location.href = '/login';
});

loadAccounts().catch(error => showToast(error.message, true));
