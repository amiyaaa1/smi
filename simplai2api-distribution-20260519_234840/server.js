const express = require('express');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { fetch, ProxyAgent } = require('undici');

const app = express();
const HOST = process.env.SIMPLAI2API_HOST || process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.SIMPLAI2API_PORT || process.env.PORT || 8031);
const ADMIN_PASSWORD = process.env.SIMPLAI2API_ADMIN_PASSWORD || 'Nishibaka114514.';
const SESSION_COOKIE_NAME = 'simplai2api_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DATA_DIR = path.join(__dirname, 'data');
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const DEFAULT_DATA_DIR = path.join(__dirname, 'default-data');
const ACCOUNTS_SEED_FILE = process.env.SIMPLAI2API_ACCOUNTS_SEED_FILE || path.join(DEFAULT_DATA_DIR, 'accounts.json');
const SEED_ACCOUNTS_IF_EMPTY = parseBoolean(process.env.SIMPLAI2API_SEED_ACCOUNTS_IF_EMPTY, true);
const PUBLIC_DIR = path.join(__dirname, 'public');
const REFRESH_HELPER = path.join(__dirname, 'scripts', 'refresh_session.py');
const REGISTER_HELPER = path.join(__dirname, 'scripts', 'register_account.py');
const ROTATE_PROJECT_HELPER = path.join(__dirname, 'scripts', 'rotate_project.py');
const FIXED_MODEL_NAME = 'claude-opus-4.6-simplai';
const DEFAULT_PROFILE_BASE_DIR = path.resolve(process.env.SIMPLAI_PROFILE_BASE_DIR || path.join(__dirname, 'profiles'));
const TOKEN_RE = /\w+|[^\w\s]/gu;
const BALANCE_STALE_MS = Number(process.env.SIMPLAI2API_BALANCE_STALE_MS || 30 * 60 * 1000);
const RECONCILE_INTERVAL_MS = Number(process.env.SIMPLAI2API_RECONCILE_INTERVAL_MS || 10 * 60 * 1000);
const RECONCILE_MIN_GAP_MS = Number(process.env.SIMPLAI2API_RECONCILE_MIN_GAP_MS || 15 * 1000);
const HELPER_TIMEOUT_MS = Number(process.env.SIMPLAI2API_HELPER_TIMEOUT_MS || 15 * 60 * 1000);
const REFRESH_HELPER_TIMEOUT_MS = Number(process.env.SIMPLAI2API_REFRESH_HELPER_TIMEOUT_MS || 3 * 60 * 1000);
const REGISTER_HELPER_TIMEOUT_MS = Number(process.env.SIMPLAI2API_REGISTER_HELPER_TIMEOUT_MS || 15 * 60 * 1000);
const ROTATE_PROJECT_HELPER_TIMEOUT_MS = Number(process.env.SIMPLAI2API_ROTATE_PROJECT_HELPER_TIMEOUT_MS || 8 * 60 * 1000);
const USE_WARP_PROXY = parseBoolean(process.env.USE_WARP_PROXY, false);
const WARP_PROXY_URL = process.env.WARP_PROXY_URL || 'http://warp:1080';
const HELPER_USE_WARP_PROXY = parseBoolean(process.env.SIMPLAI_HELPER_USE_WARP_PROXY, USE_WARP_PROXY);
const HELPER_PROXY_URL = process.env.SIMPLAI_HELPER_PROXY_URL || WARP_PROXY_URL;
const PROXY_FALLBACK_LOG_INTERVAL_MS = Math.max(
  1000,
  Number(process.env.SIMPLAI2API_PROXY_FALLBACK_LOG_INTERVAL_MS || 60 * 1000),
);
const DEFAULT_SETTINGS = Object.freeze({
  autoReplenishEnabled: true,
  minAvailableAccounts: 1,
  preExhaustedCreditsThreshold: 20,
  maxPoolSize: 10,
  balanceRefreshEveryCalls: 3,
});
const SIMPLAI_ERROR_PATTERNS = [
  /agent not found/i,
  /project run limit exhausted/i,
  /invalid session id/i,
  /access denied/i,
  /network authentication required/i,
  /unauthorized/i,
];
const proxyDispatcher = USE_WARP_PROXY && WARP_PROXY_URL ? new ProxyAgent(WARP_PROXY_URL) : null;
const inFlightAccountUsage = new Map();
let relayRoundRobin = 0;
let accountsSaveQueue = Promise.resolve();
let proxyFallbackLastLogAt = 0;
let proxyFallbackSuppressed = 0;

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

const state = {
  accounts: {
    activeAccountId: null,
    settings: { ...DEFAULT_SETTINGS },
    lastReconcileAt: null,
    lastReconcileSummary: null,
    items: [],
  },
  sessions: new Map(),
  reconcilePromise: null,
  reconcileTimer: null,
  lastReconcileStartedAt: 0,
};

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function nowIso() {
  return new Date().toISOString();
}

function parseBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === '') return defaultValue;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function randomId(prefix) {
  return `${prefix}-${crypto.randomUUID().replace(/-/g, '')}`;
}

function logProxyFallback(error) {
  const now = Date.now();
  proxyFallbackSuppressed += 1;
  if (now - proxyFallbackLastLogAt < PROXY_FALLBACK_LOG_INTERVAL_MS) return;
  const suppressed = proxyFallbackSuppressed - 1;
  proxyFallbackLastLogAt = now;
  proxyFallbackSuppressed = 0;
  const suffix = suppressed > 0 ? `; suppressed=${suppressed}` : '';
  console.warn(`[proxy] warp fallback to direct: ${error.message}${suffix}`);
}

async function fetchWithOptionalProxy(url, init = {}) {
  if (!proxyDispatcher) return fetch(url, init);
  try {
    return await fetch(url, { ...init, dispatcher: proxyDispatcher });
  } catch (error) {
    logProxyFallback(error);
    return fetch(url, init);
  }
}

function helperProxyEnv() {
  if (!HELPER_USE_WARP_PROXY || !HELPER_PROXY_URL) return {};
  const noProxy = process.env.NO_PROXY || process.env.no_proxy || '127.0.0.1,localhost,::1';
  return {
    PROXY: HELPER_PROXY_URL,
    HTTP_PROXY: HELPER_PROXY_URL,
    HTTPS_PROXY: HELPER_PROXY_URL,
    ALL_PROXY: HELPER_PROXY_URL,
    NO_PROXY: noProxy,
    no_proxy: noProxy,
  };
}

function resolveAccountProfileDir(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) return '';
  let expanded = raw
    .replace(/\$\{SIMPLAI_PROFILE_BASE_DIR\}/g, DEFAULT_PROFILE_BASE_DIR)
    .replace(/\$SIMPLAI_PROFILE_BASE_DIR\b/g, DEFAULT_PROFILE_BASE_DIR);
  if (expanded.startsWith('~/')) {
    expanded = path.join(process.env.HOME || '', expanded.slice(2));
  }
  return path.isAbsolute(expanded) ? expanded : path.resolve(__dirname, expanded);
}

function safeNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

function clampInteger(value, minimum, maximum, fallback) {
  const num = Number.parseInt(value, 10);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(maximum, Math.max(minimum, num));
}

function clampNumber(value, minimum, maximum, fallback) {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(maximum, Math.max(minimum, num));
}

function cleanupSessions() {
  const now = Date.now();
  for (const [sid, session] of state.sessions.entries()) {
    if (!session || session.expiresAt <= now) {
      state.sessions.delete(sid);
    }
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

function getSessionFromRequest(req) {
  cleanupSessions();
  const cookies = parseCookies(req);
  const sessionId = cookies[SESSION_COOKIE_NAME];
  if (!sessionId) return null;
  const session = state.sessions.get(sessionId);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    state.sessions.delete(sessionId);
    return null;
  }
  return { id: sessionId, ...session };
}

function isAuthenticated(req) {
  return !!getSessionFromRequest(req);
}

function createSession(res) {
  const sessionId = crypto.randomUUID();
  state.sessions.set(sessionId, {
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  res.cookie(SESSION_COOKIE_NAME, sessionId, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL_MS,
  });
}

function clearSession(req, res) {
  const cookies = parseCookies(req);
  if (cookies[SESSION_COOKIE_NAME]) {
    state.sessions.delete(cookies[SESSION_COOKIE_NAME]);
  }
  res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
}

function requirePageAuth(req, res, next) {
  if (isAuthenticated(req)) return next();
  return res.redirect('/login');
}

function requireApiAuth(req, res, next) {
  if (isAuthenticated(req)) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

function createError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}


async function readAccountsSeedObject() {
  if (!SEED_ACCOUNTS_IF_EMPTY || !ACCOUNTS_SEED_FILE || !fs.existsSync(ACCOUNTS_SEED_FILE)) return null;
  try {
    const raw = await fsp.readFile(ACCOUNTS_SEED_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    if (Array.isArray(parsed.items) && parsed.items.length > 0) return parsed;
  } catch (error) {
    console.warn(`[accounts] seed file ignored: ${error.message}`);
  }
  return null;
}

function shouldSeedAccountsStore(raw) {
  if (!SEED_ACCOUNTS_IF_EMPTY || !raw || typeof raw !== 'object') return false;
  const items = Array.isArray(raw.items) ? raw.items : [];
  return items.length === 0 && !raw.activeAccountId;
}

async function ensureAccountsFile() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  if (!fs.existsSync(ACCOUNTS_FILE)) {
    const seed = await readAccountsSeedObject();
    const initialStore = seed || { activeAccountId: null, settings: DEFAULT_SETTINGS, items: [] };
    await fsp.writeFile(ACCOUNTS_FILE, JSON.stringify(initialStore, null, 2));
    console.log(`[accounts] initialized ${ACCOUNTS_FILE}${seed ? ` from seed ${ACCOUNTS_SEED_FILE}` : ''}`);
  }
}

function normalizeSettings(raw = {}) {
  return {
    autoReplenishEnabled: raw.autoReplenishEnabled !== false,
    minAvailableAccounts: clampInteger(raw.minAvailableAccounts, 0, 9999, DEFAULT_SETTINGS.minAvailableAccounts),
    preExhaustedCreditsThreshold: clampNumber(
      raw.preExhaustedCreditsThreshold,
      0,
      1e12,
      DEFAULT_SETTINGS.preExhaustedCreditsThreshold,
    ),
    maxPoolSize: clampInteger(raw.maxPoolSize, 1, 9999, DEFAULT_SETTINGS.maxPoolSize),
    balanceRefreshEveryCalls: clampInteger(
      raw.balanceRefreshEveryCalls,
      1,
      9999,
      DEFAULT_SETTINGS.balanceRefreshEveryCalls,
    ),
  };
}

function normalizeAccount(item = {}, index = 0) {
  const createdAt = item.createdAt || item.created_at || nowIso();
  const updatedAt = item.updatedAt || item.updated_at || createdAt;
  const normalized = {
    ...item,
    id: String(item.id || item.email || `acct-${index + 1}`),
    label: String(item.label || item.email || `Account ${index + 1}`),
    email: String(item.email || ''),
    password: String(item.password || ''),
    accessToken: String(item.accessToken || ''),
    userId: String(item.userId || ''),
    tenantId: String(item.tenantId || ''),
    projectId: String(item.projectId || ''),
    agentName: String(item.agentName || ''),
    agentPipelineId: String(item.agentPipelineId || ''),
    versionId: String(item.versionId || 'latest'),
    browserProfileDir: String(item.browserProfileDir || ''),
    enabled: item.enabled !== false,
    notes: String(item.notes || ''),
    createdAt,
    updatedAt,
    lastUsedAt: item.lastUsedAt || null,
    lastBalanceAt: item.lastBalanceAt || null,
    callsSinceBalanceRefresh: clampInteger(item.callsSinceBalanceRefresh, 0, 1_000_000_000, 0),
    lastKnownUsableBalance: safeNumber(item.lastKnownUsableBalance),
    lastKnownWalletBalance: safeNumber(item.lastKnownWalletBalance),
    balanceRefreshError: String(item.balanceRefreshError || ''),
    lastRelayUseCount: clampInteger(item.lastRelayUseCount, 0, 1_000_000_000, 0),
    lastRelayStatus: safeNumber(item.lastRelayStatus),
    lastRelayError: String(item.lastRelayError || ''),
    lastRelayCompletedAt: item.lastRelayCompletedAt || null,
    lastRelayFailedAt: item.lastRelayFailedAt || null,
    autoRegistered: !!item.autoRegistered,
    agentRelayVerifiedAt: item.agentRelayVerifiedAt || null,
  };
  if (!normalized.id) normalized.id = randomId('acct');
  return normalized;
}

function normalizeAccountsStore(raw = {}) {
  const items = Array.isArray(raw.items) ? raw.items : [];
  const normalizedItems = items.map((item, index) => normalizeAccount(item, index));
  const activeAccountId = raw.activeAccountId || normalizedItems[0]?.id || null;
  return {
    activeAccountId,
    settings: normalizeSettings(raw.settings || {}),
    lastReconcileAt: raw.lastReconcileAt || null,
    lastReconcileSummary: raw.lastReconcileSummary || null,
    items: normalizedItems,
  };
}

async function loadAccounts() {
  await accountsSaveQueue;
  await ensureAccountsFile();
  const raw = await fsp.readFile(ACCOUNTS_FILE, 'utf8');
  let data = JSON.parse(raw || '{}');
  if (shouldSeedAccountsStore(data)) {
    const seed = await readAccountsSeedObject();
    if (seed) {
      data = seed;
      state.accounts = normalizeAccountsStore(data || {});
      await saveAccounts();
      console.log(`[accounts] seeded empty account store from ${ACCOUNTS_SEED_FILE}`);
      return state.accounts;
    }
  }
  state.accounts = normalizeAccountsStore(data || {});
  return state.accounts;
}

async function saveAccounts() {
  await ensureAccountsFile();
  const snapshot = JSON.stringify(state.accounts, null, 2);
  const tempFile = `${ACCOUNTS_FILE}.${process.pid}.${Date.now()}.${crypto.randomUUID()}.tmp`;
  const writePromise = accountsSaveQueue.catch(() => {}).then(async () => {
    try {
      await fsp.writeFile(tempFile, snapshot);
      await fsp.rename(tempFile, ACCOUNTS_FILE);
    } catch (error) {
      await fsp.unlink(tempFile).catch(() => {});
      throw error;
    }
  });
  accountsSaveQueue = writePromise.catch(() => {});
  await writePromise;
}

function getAccount(id) {
  return state.accounts.items.find(item => item.id === id);
}

function getConfiguredTemplateAccount() {
  const preferred = getAccount(state.accounts.activeAccountId);
  if (preferred && preferred.agentName && preferred.agentPipelineId) return preferred;
  return state.accounts.items.find(item => item.agentName && item.agentPipelineId) || null;
}

function isTemplateAccount(account) {
  return !!account && !!state.accounts.activeAccountId && String(account.id) === String(state.accounts.activeAccountId);
}

function relayPoolAccounts() {
  return state.accounts.items.filter(account => !isTemplateAccount(account));
}

function getBalanceValue(account) {
  return safeNumber(account?.lastKnownUsableBalance);
}

function hasRelayFields(account) {
  return !!(
    account &&
    account.accessToken &&
    account.userId &&
    account.tenantId &&
    account.projectId &&
    account.agentName &&
    account.agentPipelineId
  );
}

function hasWalletFields(account) {
  return !!(account && account.accessToken && account.userId && account.tenantId && account.projectId);
}

function isPreExhaustedAccount(account, settings = state.accounts.settings) {
  const balance = getBalanceValue(account);
  return balance !== null && balance <= Number(settings.preExhaustedCreditsThreshold || 0);
}

function shouldRefreshBalance(account, settings = state.accounts.settings, force = false) {
  if (!hasWalletFields(account)) return false;
  if (force) return true;
  if (getBalanceValue(account) === null || !account.lastBalanceAt) return true;
  const staleAt = Date.parse(account.lastBalanceAt || '') || 0;
  if (!staleAt || Date.now() - staleAt >= BALANCE_STALE_MS) return true;
  return Number(account.callsSinceBalanceRefresh || 0) >= Number(settings.balanceRefreshEveryCalls || 1);
}

function getAccountStatusCode(account, settings = state.accounts.settings) {
  if (account.enabled === false) return 'disabled';
  if (isTemplateAccount(account)) return 'template';
  if (!hasRelayFields(account)) return 'incomplete';
  if (isPreExhaustedAccount(account, settings)) return 'pre_exhausted';
  if (getBalanceValue(account) === null) {
    return account.balanceRefreshError ? 'ready_balance_error' : 'ready_balance_unknown';
  }
  if (account.balanceRefreshError) return 'ready_balance_error';
  return 'ready';
}

function getAccountStatusLabel(account, settings = state.accounts.settings) {
  const code = getAccountStatusCode(account, settings);
  const labels = {
    template: '模板(不调用)',
    disabled: '停用',
    incomplete: '资料不完整',
    pre_exhausted: '预耗尽',
    ready_balance_unknown: '可用(待查余额)',
    ready_balance_error: '可用(余额异常)',
    ready: '可用',
  };
  return labels[code] || code;
}

function buildAccountRuntime(account, settings = state.accounts.settings) {
  const balance = getBalanceValue(account);
  const template = isTemplateAccount(account);
  const configured = hasRelayFields(account);
  const preExhausted = isPreExhaustedAccount(account, settings);
  return {
    configured,
    template,
    preExhausted,
    ready: !template && account.enabled !== false && configured && !preExhausted,
    balance,
    statusCode: getAccountStatusCode(account, settings),
    statusLabel: getAccountStatusLabel(account, settings),
    needsBalanceRefresh: shouldRefreshBalance(account, settings),
  };
}

function summarizeAccounts(settings = state.accounts.settings) {
  const items = Array.isArray(state.accounts.items) ? state.accounts.items : [];
  const summary = {
    total: items.length,
    callableTotal: 0,
    enabled: 0,
    ready: 0,
    preExhausted: 0,
    incomplete: 0,
    disabled: 0,
    autoRegistered: 0,
    templateAccountId: state.accounts.activeAccountId,
    templateExcludedFromRelay: true,
    maxPoolSize: settings.maxPoolSize,
    minAvailableAccounts: settings.minAvailableAccounts,
  };
  for (const account of items) {
    const runtime = buildAccountRuntime(account, settings);
    if (!runtime.template) summary.callableTotal += 1;
    if (account.enabled === false) summary.disabled += 1;
    else summary.enabled += 1;
    if (runtime.ready) summary.ready += 1;
    if (!runtime.template && runtime.preExhausted) summary.preExhausted += 1;
    if (!runtime.template && !runtime.configured) summary.incomplete += 1;
    if (account.autoRegistered) summary.autoRegistered += 1;
  }
  return summary;
}

function publicAccountsView() {
  return {
    activeAccountId: state.accounts.activeAccountId,
    settings: state.accounts.settings,
    summary: summarizeAccounts(),
    reconcile: {
      inProgress: !!state.reconcilePromise,
      lastAt: state.accounts.lastReconcileAt || null,
      lastSummary: state.accounts.lastReconcileSummary || null,
    },
    items: state.accounts.items.map(item => ({
      ...item,
      runtime: {
        ...buildAccountRuntime(item),
        resolvedBrowserProfileDir: resolveAccountProfileDir(item.browserProfileDir),
      },
    })),
  };
}

function approxTokenCount(text) {
  return (String(text || '').match(TOKEN_RE) || []).length;
}

function extractText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map(item => {
        if (typeof item === 'string') return item;
        if (item && typeof item === 'object') {
          if (item.type === 'text' && typeof item.text === 'string') return item.text;
          if (typeof item.text === 'string') return item.text;
        }
        return '';
      })
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

function normalizeMessages(messages) {
  if (!Array.isArray(messages) || !messages.length) {
    throw createError(400, 'messages is required');
  }
  const normalized = messages
    .filter(item => item && typeof item === 'object')
    .map(item => {
      const roleRaw = String(item.role || 'user').trim().toLowerCase();
      const role = ['system', 'user', 'assistant'].includes(roleRaw) ? roleRaw : 'user';
      return { role, content: extractText(item.content) };
    })
    .filter(item => item.content);
  if (!normalized.length) throw createError(400, 'messages must contain text content');
  return normalized;
}

function buildPrompt(messages) {
  return messages
    .map(msg => `### ${msg.role.toUpperCase()}\n${msg.content}`)
    .join('\n\n\n');
}

function safeJsonParse(value) {
  if (typeof value !== 'string') return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function flattenSimplaiTexts(value, bucket = []) {
  if (value === null || value === undefined) return bucket;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed) bucket.push(trimmed);
    const parsed = safeJsonParse(trimmed);
    if (parsed && parsed !== value) flattenSimplaiTexts(parsed, bucket);
    return bucket;
  }
  if (Array.isArray(value)) {
    for (const item of value) flattenSimplaiTexts(item, bucket);
    return bucket;
  }
  if (typeof value === 'object') {
    for (const key of ['message', 'content', 'result', 'detail']) {
      if (typeof value[key] === 'string' && value[key].trim()) {
        bucket.push(value[key].trim());
      }
    }
    if (value.error) flattenSimplaiTexts(value.error, bucket);
    if (value.data) flattenSimplaiTexts(value.data, bucket);
  }
  return bucket;
}

function extractSimplaiKnownError(value) {
  for (const text of flattenSimplaiTexts(value)) {
    for (const pattern of SIMPLAI_ERROR_PATTERNS) {
      const match = text.match(pattern);
      if (match) return match[0];
    }
  }
  return '';
}

function makeSimplaiError(detail, fallbackMessage = 'SimplAI upstream error') {
  const normalized = String(detail || '').trim() || fallbackMessage;
  const status = /project run limit exhausted/i.test(normalized) ? 429 : 502;
  if (/^simplai\b/i.test(normalized)) {
    return createError(status, normalized);
  }
  return createError(status, `SimplAI agent error: ${normalized}`);
}

function isProjectRunLimitError(error) {
  return /project run limit exhausted/i.test(String(error?.message || error || ''));
}

function finalizeSimplaiMessage(message) {
  const upstreamError = extractSimplaiKnownError(message?.tool_calls || message);
  if (upstreamError) {
    throw makeSimplaiError(upstreamError);
  }
  const text = typeof message?.query_result === 'string' ? message.query_result : '';
  if (!text.trim()) {
    throw createError(502, 'SimplAI returned an empty completion');
  }
  return text;
}

function parseSimplaiStreamEventBlock(block) {
  if (!block) return null;
  const dataLines = [];
  for (const rawLine of String(block).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || !line.startsWith('data:')) continue;
    dataLines.push(line.slice(5).trim());
  }
  if (!dataLines.length) return null;
  let payload = dataLines.join('\n').trim();
  if (!payload) return null;
  if (payload.startsWith('---->') && payload.endsWith('<----')) {
    payload = payload.slice(5, -5).trim();
  }
  return safeJsonParse(payload);
}

async function* streamConversation(account, messageId, options = {}) {
  const response = await simplaiFetch(
    account,
    `https://edge-external.simplai.ai/interact/api/v1/intract/data/${messageId}/stream`,
    {
      headers: {
        accept: 'text/event-stream',
      },
      signal: options.signal,
    },
  );
  if (!response.ok) {
    const text = await response.text();
    const upstreamError = extractSimplaiKnownError(safeJsonParse(text) || text);
    if (upstreamError) throw makeSimplaiError(upstreamError);
    throw createError(502, `SimplAI stream failed: ${text.slice(0, 500)}`);
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw createError(502, 'SimplAI stream body is unavailable');
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      while (true) {
        const match = buffer.match(/\r?\n\r?\n/);
        if (!match || match.index === undefined) break;
        const block = buffer.slice(0, match.index);
        buffer = buffer.slice(match.index + match[0].length);
        const event = parseSimplaiStreamEventBlock(block);
        if (event) yield event;
      }
    }

    buffer += decoder.decode();
    const tail = parseSimplaiStreamEventBlock(buffer);
    if (tail) yield tail;
  } finally {
    try {
      await reader.cancel();
    } catch {}
  }
}

function simplaiHeaders(account) {
  return {
    accept: 'application/json, text/plain, */*',
    'content-type': 'application/json',
    referer: 'https://app.simplai.ai/',
    'x-device-id': 'simplai',
    'pim-sid': account.accessToken || '',
    'x-user-id': account.userId || '',
    'x-seller-profile-id': account.userId || '',
    'x-seller-id': account.userId || '',
    'x-client-id': account.userId || '',
    'x-tenant-id': account.tenantId || '',
    'x-project-id': account.projectId || '',
  };
}

async function runJsonHelper(command, args, extraEnv = {}, timeoutMs = HELPER_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: __dirname,
      env: { ...process.env, ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timedOut = false;
    const timeoutHandle = timeoutMs > 0 ? setTimeout(() => {
      timedOut = true;
      try {
        child.kill('SIGTERM');
      } catch {}
      setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {}
      }, 5000).unref();
    }, timeoutMs) : null;

    const finalize = callback => {
      if (settled) return;
      settled = true;
      if (timeoutHandle) clearTimeout(timeoutHandle);
      callback();
    };

    child.stdout.on('data', chunk => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', chunk => {
      stderr += chunk.toString();
    });
    child.on('error', error => finalize(() => reject(error)));
    child.on('close', code => {
      finalize(() => {
        if (timedOut) {
          reject(new Error(stderr || stdout || `${command} timed out after ${timeoutMs}ms`));
          return;
        }
        if (code !== 0) {
          reject(new Error(stderr || stdout || `${command} exited with ${code}`));
          return;
        }
        try {
          const parsed = JSON.parse(stdout.trim());
          resolve(parsed);
        } catch (error) {
          reject(new Error(`Invalid helper output: ${stdout || stderr}`));
        }
      });
    });
  });
}

async function runRefreshHelper(profileDir) {
  return runJsonHelper('python3', [REFRESH_HELPER, profileDir], helperProxyEnv(), REFRESH_HELPER_TIMEOUT_MS);
}

async function runRegisterHelper(templateAccount) {
  return runJsonHelper('python3', [REGISTER_HELPER], {
    ...helperProxyEnv(),
    SIMPLAI_TEMPLATE_ACCOUNT_JSON: JSON.stringify({
      label: templateAccount.label || '',
      accessToken: templateAccount.accessToken || '',
      userId: templateAccount.userId || '',
      tenantId: templateAccount.tenantId || '',
      projectId: templateAccount.projectId || '',
      agentName: templateAccount.agentName || '',
      agentPipelineId: templateAccount.agentPipelineId || '',
      versionId: templateAccount.versionId || 'latest',
    }),
  }, REGISTER_HELPER_TIMEOUT_MS);
}

async function runRotateProjectHelper(account, templateAccount) {
  return runJsonHelper('python3', [ROTATE_PROJECT_HELPER], {
    ...helperProxyEnv(),
    SIMPLAI_ACCOUNT_JSON: JSON.stringify({
      accessToken: account.accessToken || '',
      userId: account.userId || '',
      tenantId: account.tenantId || '',
      projectId: account.projectId || '',
    }),
    SIMPLAI_TEMPLATE_ACCOUNT_JSON: JSON.stringify({
      label: templateAccount.label || '',
      accessToken: templateAccount.accessToken || '',
      userId: templateAccount.userId || '',
      tenantId: templateAccount.tenantId || '',
      projectId: templateAccount.projectId || '',
      agentName: templateAccount.agentName || '',
      agentPipelineId: templateAccount.agentPipelineId || '',
      versionId: templateAccount.versionId || 'latest',
    }),
  }, ROTATE_PROJECT_HELPER_TIMEOUT_MS);
}

async function refreshAccountSession(accountId) {
  const account = getAccount(accountId);
  if (!account) throw createError(404, 'Account not found');
  if (!account.browserProfileDir) throw createError(400, 'browserProfileDir is required to refresh token');
  const profileDir = resolveAccountProfileDir(account.browserProfileDir);
  if (!profileDir) throw createError(400, 'browserProfileDir is empty after resolution');
  const data = await runRefreshHelper(profileDir);
  account.accessToken = data.accessToken || account.accessToken;
  account.userId = data.userId || account.userId;
  account.tenantId = data.tenantId || account.tenantId;
  account.email = data.email || account.email;
  account.updatedAt = nowIso();
  await saveAccounts();
  return account;
}

async function simplaiFetch(account, url, options = {}, retried = false) {
  const response = await fetchWithOptionalProxy(url, {
    ...options,
    headers: {
      ...simplaiHeaders(account),
      ...(options.headers || {}),
    },
  });
  if ((response.status === 401 || response.status === 511) && !retried && account.browserProfileDir) {
    await refreshAccountSession(account.id);
    return simplaiFetch(getAccount(account.id), url, options, true);
  }
  return response;
}

async function refreshAccountBalance(accountId, { force = false, silent = false } = {}) {
  const account = getAccount(accountId);
  if (!account) throw createError(404, 'Account not found');
  if (!hasWalletFields(account)) {
    throw createError(400, 'Account is missing wallet auth fields');
  }
  if (!force && !shouldRefreshBalance(account, state.accounts.settings)) {
    return account;
  }
  try {
    const response = await simplaiFetch(account, 'https://edge-service.simplai.ai/wallet/api/v1/wallet');
    const text = await response.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = {};
    }
    if (!response.ok || !data?.ok) {
      throw new Error(text.slice(0, 500) || `wallet fetch failed: ${response.status}`);
    }
    const usable = safeNumber(data?.result?.usable_balance);
    const walletBalance = safeNumber(data?.result?.wallet_balance);
    account.lastKnownUsableBalance = usable;
    account.lastKnownWalletBalance = walletBalance;
    account.lastBalanceAt = nowIso();
    account.balanceRefreshError = '';
    account.callsSinceBalanceRefresh = 0;
    account.updatedAt = nowIso();
    await saveAccounts();
    return account;
  } catch (error) {
    account.balanceRefreshError = String(error?.message || error);
    account.updatedAt = nowIso();
    await saveAccounts();
    if (!silent) throw error;
    return account;
  }
}

async function refreshBalancesForAccounts(accounts, { force = false, silent = true } = {}) {
  const results = [];
  for (const account of accounts) {
    if (!account || !hasWalletFields(account)) continue;
    if (!force && !shouldRefreshBalance(account, state.accounts.settings)) continue;
    const refreshed = await refreshAccountBalance(account.id, { force, silent }).catch(() => getAccount(account.id));
    if (refreshed) results.push(refreshed);
  }
  return results;
}

async function startConversation(account, prompt) {
  const payload = {
    model: account.agentName,
    language_code: 'EN',
    source: 'APP',
    app_id: account.agentPipelineId,
    model_id: account.agentPipelineId,
    version_id: account.versionId || 'latest',
    state_override: {
      sys: {
        user_timezone: process.env.TZ || 'Asia/Shanghai',
        language_code: 'en-US',
      },
    },
    action: 'START_SCREEN',
    query: {
      message: prompt,
      message_type: 'text',
      message_category: '',
    },
  };
  const response = await simplaiFetch(account, 'https://edge-service.simplai.ai/interact/api/v1/intract/conversation', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }
  const upstreamError = extractSimplaiKnownError(data);
  if (!response.ok) {
    if (upstreamError) throw makeSimplaiError(upstreamError);
    throw createError(502, `SimplAI start failed: ${text.slice(0, 500)}`);
  }
  const result = data.result || {};
  if (upstreamError && !result.conversation_id) {
    throw makeSimplaiError(upstreamError);
  }
  if (!result.conversation_id || !result.message_id) {
    throw createError(502, `Unexpected SimplAI start response: ${text.slice(0, 500)}`);
  }
  return { conversationId: result.conversation_id, messageId: result.message_id };
}

async function pollConversation(account, conversationId, timeoutMs = 300000, intervalMs = 1500) {
  const deadline = Date.now() + timeoutMs;
  let lastText = '';
  while (Date.now() < deadline) {
    const response = await simplaiFetch(account, `https://edge-service.simplai.ai/interact/api/v1/intract/conversation/${conversationId}`);
    const text = await response.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = {};
    }
    if (!response.ok) {
      throw createError(502, `SimplAI poll failed: ${text.slice(0, 500)}`);
    }
    const messages = data.result?.response || [];
    if (messages.length) {
      const last = messages[messages.length - 1];
      lastText = typeof last.query_result === 'string' ? last.query_result : '';
      const upstreamError = extractSimplaiKnownError(last.tool_calls || last);
      if (upstreamError) throw makeSimplaiError(upstreamError);
      if (last.message_status === 2) return finalizeSimplaiMessage(last);
    }
    await sleep(intervalMs);
  }
  throw createError(504, `Timed out waiting for SimplAI response. Last text: ${lastText.slice(0, 200)}`);
}

function makeUsage(prompt, completion) {
  const promptTokens = approxTokenCount(prompt);
  const completionTokens = approxTokenCount(completion);
  return {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: promptTokens + completionTokens,
  };
}

function compareIsoAsc(a, b) {
  const aTime = a ? Date.parse(a) || 0 : 0;
  const bTime = b ? Date.parse(b) || 0 : 0;
  if (!aTime && !bTime) return 0;
  if (!aTime) return -1;
  if (!bTime) return 1;
  return aTime - bTime;
}

function getInFlightUsage(accountId) {
  return Math.max(0, Number(inFlightAccountUsage.get(accountId) || 0));
}

function reserveAccountSelection(accountId) {
  if (!accountId) return;
  inFlightAccountUsage.set(accountId, getInFlightUsage(accountId) + 1);
}

function releaseAccountSelection(accountId) {
  if (!accountId) return;
  const next = getInFlightUsage(accountId) - 1;
  if (next > 0) inFlightAccountUsage.set(accountId, next);
  else inFlightAccountUsage.delete(accountId);
}

function sortedRelayCandidates() {
  return [...state.accounts.items]
    .filter(account => !isTemplateAccount(account) && account.enabled !== false && hasRelayFields(account))
    .sort((a, b) => {
      const active = getInFlightUsage(a.id) - getInFlightUsage(b.id);
      if (active !== 0) return active;
      const relayUses = Number(a.lastRelayUseCount || 0) - Number(b.lastRelayUseCount || 0);
      if (relayUses !== 0) return relayUses;
      const used = compareIsoAsc(a.lastUsedAt, b.lastUsedAt);
      if (used !== 0) return used;
      const created = compareIsoAsc(a.createdAt, b.createdAt);
      if (created !== 0) return created;
      const bias = relayRoundRobin % 2 === 0 ? 1 : -1;
      return bias * String(a.id).localeCompare(String(b.id));
    });
}

async function selectRelayAccount() {
  const settings = state.accounts.settings;
  const candidates = sortedRelayCandidates();
  if (!candidates.length) {
    scheduleReconcile('no-callable-account');
    throw createError(503, 'No non-template enabled and fully configured accounts available');
  }

  for (const candidate of candidates) {
    if (shouldRefreshBalance(candidate, settings)) {
      await refreshAccountBalance(candidate.id, { force: false, silent: true }).catch(() => null);
    }
    const account = getAccount(candidate.id);
    if (!account || account.enabled === false || !hasRelayFields(account)) continue;
    if (isTemplateAccount(account)) continue;
    if (isPreExhaustedAccount(account, settings)) continue;
    reserveAccountSelection(account.id);
    relayRoundRobin += 1;
    account.lastUsedAt = nowIso();
    account.updatedAt = nowIso();
    try {
      await saveAccounts();
    } catch (error) {
      releaseAccountSelection(account.id);
      throw error;
    }
    return account;
  }

  scheduleReconcile('no-ready-account');
  throw createError(503, 'No ready account available; all enabled accounts are pre-exhausted or invalid');
}

async function markRelaySuccess(accountId) {
  const account = getAccount(accountId);
  if (!account) return;
  account.lastRelayStatus = 200;
  account.lastRelayError = '';
  account.lastRelayCompletedAt = nowIso();
  account.lastRelayUseCount = Number(account.lastRelayUseCount || 0) + 1;
  account.callsSinceBalanceRefresh = Number(account.callsSinceBalanceRefresh || 0) + 1;
  account.updatedAt = nowIso();
  await saveAccounts();
}

async function markRelayFailure(accountId, error) {
  const account = getAccount(accountId);
  if (!account) return;
  account.lastRelayStatus = Number(error?.status || 500) || 500;
  account.lastRelayError = String(error?.message || error || 'Unknown relay error');
  if (/agent not found|project run limit exhausted/i.test(account.lastRelayError)) {
    account.enabled = false;
  }
  account.lastRelayFailedAt = nowIso();
  account.updatedAt = nowIso();
  await saveAccounts();
}

function removeAccountLocally(accountId) {
  const index = state.accounts.items.findIndex(item => item.id === accountId);
  if (index === -1) return null;
  const [removed] = state.accounts.items.splice(index, 1);
  if (state.accounts.activeAccountId === removed.id) {
    state.accounts.activeAccountId = state.accounts.items[0]?.id || null;
  }
  return removed;
}

function buildNewAccountFromHelperPayload(payload) {
  return normalizeAccount({
    id: payload.id || randomId('acct'),
    label: payload.label || payload.email || 'Auto Registered Account',
    email: payload.email || '',
    password: payload.password || '',
    accessToken: payload.accessToken || '',
    userId: payload.userId || '',
    tenantId: payload.tenantId || '',
    projectId: payload.projectId || '',
    agentName: payload.agentName || '',
    agentPipelineId: payload.agentPipelineId || '',
    versionId: payload.versionId || 'latest',
    browserProfileDir: payload.browserProfileDir || '',
    enabled: payload.enabled !== false,
    notes: payload.notes || 'Auto registered by replenish helper',
    createdAt: payload.createdAt || nowIso(),
    updatedAt: payload.updatedAt || nowIso(),
    lastKnownUsableBalance: payload.lastKnownUsableBalance,
    lastKnownWalletBalance: payload.lastKnownWalletBalance,
    lastBalanceAt: payload.lastBalanceAt || null,
    autoRegistered: true,
    agentRelayVerifiedAt: payload.agentRelayVerifiedAt || null,
  });
}

async function registerNewAccountFromTemplate() {
  const template = getConfiguredTemplateAccount();
  if (!template) {
    throw createError(400, 'No template account with agent configuration is available');
  }
  const payload = await runRegisterHelper(template);
  const account = buildNewAccountFromHelperPayload(payload || {});
  if (!account.id) account.id = randomId('acct');
  if (getAccount(account.id)) account.id = randomId('acct');
  if (!account.label) account.label = account.email || account.id;
  state.accounts.items.push(account);
  if (!state.accounts.activeAccountId) state.accounts.activeAccountId = account.id;
  await saveAccounts();
  return account;
}

async function rotateAccountProject(accountId) {
  const account = getAccount(accountId);
  if (!account) throw createError(404, 'Account not found');
  const template = getConfiguredTemplateAccount();
  if (!template) throw createError(400, 'No template account with agent configuration is available');
  const payload = await runRotateProjectHelper(account, template);
  account.projectId = String(payload.projectId || account.projectId || '').trim();
  account.agentName = String(payload.agentName || account.agentName || '').trim();
  account.agentPipelineId = String(payload.agentPipelineId || account.agentPipelineId || '').trim();
  account.versionId = String(payload.versionId || account.versionId || 'latest').trim() || 'latest';
  account.enabled = true;
  account.lastRelayError = '';
  account.lastRelayStatus = 200;
  account.lastRelayFailedAt = null;
  account.agentRelayVerifiedAt = nowIso();
  const recycledProjectId = String(payload.recycledProjectId || '').trim();
  const runsLimit = safeNumber(payload.projectRunsLimit);
  account.notes = [
    String(account.notes || '').trim(),
    recycledProjectId
      ? `Auto-rotated project; recycled ${recycledProjectId} -> ${account.projectId}${runsLimit ? ` (${runsLimit} runs)` : ''}`
      : `Auto-rotated project -> ${account.projectId}${runsLimit ? ` (${runsLimit} runs)` : ''}`,
  ].filter(Boolean).join(' | ');
  account.updatedAt = nowIso();
  await saveAccounts();
  return account;
}

async function reconcileAccountPool(reason = 'manual', { forceBalanceRefresh = false } = {}) {
  if (state.reconcilePromise) return state.reconcilePromise;
  if (Date.now() - state.lastReconcileStartedAt < RECONCILE_MIN_GAP_MS && !forceBalanceRefresh) {
    return state.accounts.lastReconcileSummary || { ok: true, status: 'skipped_recently_ran' };
  }

  state.lastReconcileStartedAt = Date.now();
  state.reconcilePromise = (async () => {
    console.log(`[reconcile] start reason=${reason}`);
    await loadAccounts();
    const summary = {
      ok: true,
      reason,
      startedAt: nowIso(),
      settings: { ...state.accounts.settings },
      before: summarizeAccounts(state.accounts.settings),
      removed: [],
      registered: [],
      balanceRefreshed: [],
      errors: [],
      status: 'noop',
    };

    try {
      const balanceTargets = state.accounts.items.filter(account =>
        hasWalletFields(account) && (forceBalanceRefresh || shouldRefreshBalance(account, state.accounts.settings)),
      );
      for (const account of balanceTargets) {
        const refreshed = await refreshAccountBalance(account.id, { force: forceBalanceRefresh, silent: true }).catch(error => {
          summary.errors.push({ type: 'balance_refresh', accountId: account.id, error: String(error?.message || error) });
          return null;
        });
        if (refreshed) {
          summary.balanceRefreshed.push({
            id: refreshed.id,
            email: refreshed.email,
            usableBalance: refreshed.lastKnownUsableBalance,
            lastBalanceAt: refreshed.lastBalanceAt,
          });
        }
      }

      const settings = state.accounts.settings;
      const preExhausted = [...state.accounts.items]
        .filter(account => !isTemplateAccount(account) && isPreExhaustedAccount(account, settings))
        .sort((a, b) => {
          const aBalance = getBalanceValue(a);
          const bBalance = getBalanceValue(b);
          if (aBalance !== bBalance) return (aBalance ?? Number.MAX_SAFE_INTEGER) - (bBalance ?? Number.MAX_SAFE_INTEGER);
          return compareIsoAsc(a.updatedAt, b.updatedAt);
        });

      if (relayPoolAccounts().length >= settings.maxPoolSize && preExhausted.length > 0) {
        const queue = [...preExhausted];
        while (relayPoolAccounts().length >= settings.maxPoolSize && queue.length > 0) {
          const doomed = queue.shift();
          const removed = removeAccountLocally(doomed.id);
          if (!removed) continue;
          summary.removed.push({
            id: removed.id,
            email: removed.email,
            usableBalance: removed.lastKnownUsableBalance,
            reason: 'pre_exhausted_cleanup_for_replacement',
          });
        }
        await saveAccounts();
      }

      const afterCleanupSummary = summarizeAccounts(state.accounts.settings);
      summary.afterCleanup = afterCleanupSummary;

      const relayPoolSize = relayPoolAccounts().length;
      if (relayPoolSize >= settings.maxPoolSize) {
        summary.status = relayPoolSize > settings.maxPoolSize
          ? 'paused_pool_over_max_no_deletable_pre_exhausted'
          : 'paused_pool_at_max';
      } else if (!settings.autoReplenishEnabled) {
        summary.status = 'auto_replenish_disabled';
      } else {
        const readyCount = summarizeAccounts(state.accounts.settings).ready;
        const preExhaustedCount = summarizeAccounts(state.accounts.settings).preExhausted;
        const shouldReplenish = readyCount < settings.minAvailableAccounts || preExhaustedCount > 0;
        if (!shouldReplenish) {
          summary.status = 'healthy_no_replenish_needed';
        } else {
          const freeSlots = Math.max(0, settings.maxPoolSize - relayPoolAccounts().length);
          const deficit = Math.max(0, settings.minAvailableAccounts - readyCount);
          const replacementNeed = Math.max(0, preExhaustedCount);
          const targetRegisterCount = Math.min(freeSlots, Math.max(deficit, replacementNeed));
          if (targetRegisterCount <= 0) {
            summary.status = 'no_free_slots_to_replenish';
          } else {
            for (let index = 0; index < targetRegisterCount; index += 1) {
              try {
                const account = await registerNewAccountFromTemplate();
                summary.registered.push({
                  id: account.id,
                  email: account.email,
                  usableBalance: account.lastKnownUsableBalance,
                });
              } catch (error) {
                summary.ok = false;
                summary.errors.push({ type: 'register', error: String(error?.message || error) });
                break;
              }
            }
            summary.status = summary.registered.length > 0 ? 'registered_accounts' : 'register_attempt_failed';
          }
        }
      }

      summary.after = summarizeAccounts(state.accounts.settings);
    } catch (error) {
      summary.ok = false;
      summary.status = 'reconcile_failed';
      summary.errors.push({ type: 'fatal', error: String(error?.message || error) });
    }

    summary.finishedAt = nowIso();
    state.accounts.lastReconcileAt = summary.finishedAt;
    state.accounts.lastReconcileSummary = summary;
    await saveAccounts();
    console.log(`[reconcile] finish reason=${reason} status=${summary.status} registered=${summary.registered.length} errors=${summary.errors.length}`);
    if (summary.errors.length > 0) {
      console.warn(`[reconcile] errors: ${JSON.stringify(summary.errors.slice(0, 3))}`);
    }
    return summary;
  })();

  try {
    return await state.reconcilePromise;
  } finally {
    state.reconcilePromise = null;
  }
}

function scheduleReconcile(reason = 'background', delayMs = 1000) {
  if (state.reconcileTimer) return;
  state.reconcileTimer = setTimeout(() => {
    state.reconcileTimer = null;
    reconcileAccountPool(reason).catch(error => {
      console.error('[reconcile]', error?.stack || error);
    });
  }, delayMs);
}

function assignEditableAccountFields(account, body, isCreate = false) {
  if (isCreate && !String(body.label || '').trim()) {
    throw createError(400, 'label is required');
  }
  const fields = [
    'label',
    'email',
    'password',
    'accessToken',
    'userId',
    'tenantId',
    'projectId',
    'agentName',
    'agentPipelineId',
    'versionId',
    'browserProfileDir',
    'notes',
  ];
  for (const field of fields) {
    if (Object.prototype.hasOwnProperty.call(body, field)) {
      account[field] = String(body[field] ?? '').trim();
    }
  }
  if (!account.versionId) account.versionId = 'latest';
  if (!account.label) throw createError(400, 'label is required');
  if (Object.prototype.hasOwnProperty.call(body, 'enabled')) {
    account.enabled = body.enabled !== false;
  }
  account.updatedAt = nowIso();
}

app.get('/healthz', (req, res) => {
  res.json({
    ok: true,
    host: HOST,
    port: PORT,
    model: FIXED_MODEL_NAME,
    outboundProxy: proxyDispatcher ? WARP_PROXY_URL : 'disabled',
    helperProxy: HELPER_USE_WARP_PROXY && HELPER_PROXY_URL ? HELPER_PROXY_URL : 'disabled',
    summary: summarizeAccounts(),
    templateAccountId: state.accounts.activeAccountId,
  });
});

app.get('/v1/models', (req, res) => {
  res.json({
    object: 'list',
    data: [{ id: FIXED_MODEL_NAME, object: 'model', owned_by: 'simplai' }],
  });
});

app.get('/login', (req, res) => {
  if (isAuthenticated(req)) {
    return res.redirect('/');
  }
  return res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

app.get('/auth/status', (req, res) => {
  res.json({ authenticated: isAuthenticated(req) });
});

app.post('/auth/login', (req, res) => {
  const password = String(req.body?.password || '');
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Password incorrect' });
  }
  createSession(res);
  return res.json({ ok: true });
});

app.post('/auth/logout', (req, res) => {
  clearSession(req, res);
  res.json({ ok: true });
});

app.use('/api', requireApiAuth);

app.get('/api/accounts', async (req, res, next) => {
  try {
    await loadAccounts();
    res.json(publicAccountsView());
  } catch (error) {
    next(error);
  }
});

app.put('/api/settings', async (req, res, next) => {
  try {
    await loadAccounts();
    state.accounts.settings = normalizeSettings(req.body || {});
    await saveAccounts();
    scheduleReconcile('settings-updated', 250);
    res.json(publicAccountsView());
  } catch (error) {
    next(error);
  }
});

app.post('/api/reconcile', async (req, res, next) => {
  try {
    await loadAccounts();
    const result = await reconcileAccountPool('manual-api', { forceBalanceRefresh: !!req.body?.forceBalanceRefresh });
    res.json(result);
  } catch (error) {
    next(error);
  }
});

app.post('/api/accounts/refresh-balances', async (req, res, next) => {
  try {
    await loadAccounts();
    const refreshed = await refreshBalancesForAccounts(state.accounts.items, {
      force: req.body?.force !== false,
      silent: true,
    });
    res.json({ ok: true, refreshed: refreshed.map(item => ({ id: item.id, email: item.email, usableBalance: item.lastKnownUsableBalance })) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/accounts', async (req, res, next) => {
  try {
    await loadAccounts();
    const body = req.body || {};
    const item = normalizeAccount({ id: body.id || randomId('acct') }, state.accounts.items.length);
    assignEditableAccountFields(item, body, true);
    if (state.accounts.items.some(account => account.id === item.id)) {
      throw createError(409, 'Account id already exists');
    }
    state.accounts.items.push(item);
    if (!state.accounts.activeAccountId) state.accounts.activeAccountId = item.id;
    await saveAccounts();
    scheduleReconcile('account-created', 250);
    res.json(item);
  } catch (error) {
    next(error);
  }
});

app.put('/api/accounts/:id', async (req, res, next) => {
  try {
    await loadAccounts();
    const account = getAccount(req.params.id);
    if (!account) throw createError(404, 'Account not found');
    assignEditableAccountFields(account, req.body || {}, false);
    await saveAccounts();
    scheduleReconcile('account-updated', 250);
    res.json(account);
  } catch (error) {
    next(error);
  }
});

app.delete('/api/accounts/:id', async (req, res, next) => {
  try {
    await loadAccounts();
    const removed = removeAccountLocally(req.params.id);
    if (!removed) throw createError(404, 'Account not found');
    await saveAccounts();
    scheduleReconcile('account-deleted', 250);
    res.json({ ok: true, removed });
  } catch (error) {
    next(error);
  }
});

app.post('/api/accounts/:id/select', async (req, res, next) => {
  try {
    await loadAccounts();
    const account = getAccount(req.params.id);
    if (!account) throw createError(404, 'Account not found');
    state.accounts.activeAccountId = account.id;
    await saveAccounts();
    res.json({ ok: true, activeAccountId: account.id, mode: 'template_account' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/accounts/:id/refresh', async (req, res, next) => {
  try {
    await loadAccounts();
    const account = await refreshAccountSession(req.params.id);
    res.json(account);
  } catch (error) {
    next(error);
  }
});

app.post('/api/accounts/:id/balance', async (req, res, next) => {
  try {
    await loadAccounts();
    const account = await refreshAccountBalance(req.params.id, { force: true, silent: false });
    res.json(account);
  } catch (error) {
    next(error);
  }
});

app.post('/v1/chat/completions', async (req, res, next) => {
  let selectedAccount = null;
  const releaseSelectedAccount = () => {
    if (selectedAccount?.id) releaseAccountSelection(selectedAccount.id);
    selectedAccount = null;
  };
  try {
    const messages = normalizeMessages(req.body?.messages);
    const stream = !!req.body?.stream;

    await loadAccounts();
    const prompt = buildPrompt(messages);
    let lastError = null;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      selectedAccount = await selectRelayAccount();
      const completionId = `chatcmpl-${crypto.randomUUID().replace(/-/g, '')}`;
      const created = Math.floor(Date.now() / 1000);
      try {
        const { conversationId, messageId } = await startConversation(selectedAccount, prompt);

        if (!stream) {
          const text = await pollConversation(selectedAccount, conversationId);
          await markRelaySuccess(selectedAccount.id);
          scheduleReconcile('post-relay');
          res.json({
            id: completionId,
            object: 'chat.completion',
            created,
            model: FIXED_MODEL_NAME,
            choices: [{
              index: 0,
              message: { role: 'assistant', content: text },
              finish_reason: 'stop',
            }],
            usage: makeUsage(prompt, text),
          });
          return;
        }

        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          Connection: 'keep-alive',
        });
        if (typeof res.flushHeaders === 'function') {
          res.flushHeaders();
        }

        const writeSse = payload => res.write(`data: ${JSON.stringify(payload)}\n\n`);
        const abortController = new AbortController();
        let clientClosed = false;
        const handleClientClose = () => {
          clientClosed = true;
          abortController.abort();
        };
        req.once('close', handleClientClose);
        req.once('aborted', handleClientClose);

        writeSse({
          id: completionId,
          object: 'chat.completion.chunk',
          created,
          model: FIXED_MODEL_NAME,
          choices: [{ index: 0, delta: { role: 'assistant' }, finish_reason: null }],
        });

        let emittedText = '';

        try {
          for await (const event of streamConversation(selectedAccount, messageId, { signal: abortController.signal })) {
            if (clientClosed || res.writableEnded) return;
            if (String(event?.role || '').toLowerCase() !== 'assistant') continue;
            if (typeof event?.content !== 'string' || !event.content) continue;

            emittedText += event.content;
            writeSse({
              id: completionId,
              object: 'chat.completion.chunk',
              created,
              model: FIXED_MODEL_NAME,
              choices: [{ index: 0, delta: { content: event.content }, finish_reason: null }],
            });
          }

          if (!emittedText && !clientClosed) {
            const text = await pollConversation(selectedAccount, conversationId);
            if (text) {
              emittedText = text;
              writeSse({
                id: completionId,
                object: 'chat.completion.chunk',
                created,
                model: FIXED_MODEL_NAME,
                choices: [{ index: 0, delta: { content: text }, finish_reason: null }],
              });
            }
          }

          if (clientClosed || res.writableEnded) return;

          await markRelaySuccess(selectedAccount.id);
          scheduleReconcile('post-relay');

          writeSse({
            id: completionId,
            object: 'chat.completion.chunk',
            created,
            model: FIXED_MODEL_NAME,
            choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
          });
          res.write('data: [DONE]\n\n');
          res.end();
          return;
        } finally {
          req.off('close', handleClientClose);
          req.off('aborted', handleClientClose);
        }
      } catch (error) {
        if (stream && (req.aborted || req.destroyed || res.writableEnded || error?.name === 'AbortError')) {
          return;
        }
        lastError = error;
        if (selectedAccount?.id && attempt === 0 && isProjectRunLimitError(error)) {
          try {
            await rotateAccountProject(selectedAccount.id);
            continue;
          } catch (rotateError) {
            error.message = `${error.message}; auto-rotate failed: ${rotateError.message}`;
          }
        }
        if (selectedAccount?.id) {
          await markRelayFailure(selectedAccount.id, error).catch(() => null);
          scheduleReconcile('relay-error');
        }
        throw error;
      } finally {
        releaseSelectedAccount();
      }
    }

    throw lastError || createError(500, 'Relay failed');
  } catch (error) {
    if (res.headersSent) {
      try {
        res.end();
      } catch {}
      return;
    }
    next(error);
  }
});

app.get('/', requirePageAuth, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    return res.status(404).json({ error: 'Not found' });
  }
  return next();
});

app.use(express.static(PUBLIC_DIR, { index: false }));

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((error, req, res, next) => {
  const status = error.status || 500;
  res.status(status).json({ error: error.message || 'Internal server error' });
});

(async () => {
  await loadAccounts();
  await saveAccounts();
  app.listen(PORT, HOST, () => {
    console.log(`simplai2api listening on http://${HOST}:${PORT}`);
    console.log(`simplai2api outbound proxy: ${proxyDispatcher ? WARP_PROXY_URL : 'disabled'}`);
    console.log(`simplai2api helper proxy: ${HELPER_USE_WARP_PROXY && HELPER_PROXY_URL ? HELPER_PROXY_URL : 'disabled'}`);
  });
  scheduleReconcile('startup', 1500);
  if (RECONCILE_INTERVAL_MS > 0) {
    setInterval(() => scheduleReconcile('interval'), RECONCILE_INTERVAL_MS).unref();
  }
})();
