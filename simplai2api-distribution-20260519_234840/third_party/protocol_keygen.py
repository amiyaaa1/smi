"""
OpenAI 协议注册机 (Protocol Keygen) v5 — 全流程纯 HTTP 实现
========================================================
协议注册机实现

核心架构（全流程纯 HTTP，零浏览器依赖）：

  【注册流程】全步骤纯 HTTP：
    步骤0：GET  /oauth/authorize         → 获取 login_session cookie（PKCE + screen_hint=signup）
    步骤0：POST /api/accounts/authorize/continue → 提交邮箱（需 sentinel token）
    步骤2：POST /api/accounts/user/register      → 注册用户（username+password，需 sentinel）
    步骤3：GET  /api/accounts/email-otp/send      → 触发验证码发送
    步骤4：POST /api/accounts/email-otp/validate  → 提交邮箱验证码
    步骤5：POST /api/accounts/create_account      → 提交姓名+生日完成注册

  【OAuth 登录流程】纯 HTTP（perform_codex_oauth_login_http）：
    步骤1：GET  /oauth/authorize                  → 获取 login_session
    步骤2：POST /api/accounts/authorize/continue   → 提交邮箱
    步骤3：POST /api/accounts/password/verify       → 提交密码
    步骤4：consent 多步流程 → 提取 code → POST /oauth/token 换取 tokens

  Sentinel Token PoW 生成（纯 Python，逆向 SDK JS 的 PoW 算法）：
    - FNV-1a 哈希 + xorshift 混合
    - 伪造浏览器环境数据数组
    - 暴力搜索直到哈希前缀 ≤ 难度阈值
    - t 字段传空字符串（服务端不校验），c 字段从 sentinel API 实时获取

关键协议字段（逆向还原）：
  - oai-client-auth-session: OAuth 流程中由服务端 Set-Cookie 设置的会话 cookie
  - openai-sentinel-token:   JSON 对象 {p, t, c, id, flow}
  - Cookie 链式传递:         每步 Set-Cookie 自动累积
  - oai-did:                 设备唯一标识（UUID v4）

环境依赖：
  pip install requests
"""

import json
import os
import re
import sys
import time
import ssl
import asyncio
import uuid
import math
import select
import random
import string
import secrets
import hashlib
import base64
import threading
import queue
import subprocess
from collections import deque
from http.cookies import SimpleCookie
from types import MethodType
from html import unescape
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait as futures_wait
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
try:
    import aiohttp
except Exception:
    aiohttp = None
try:
    from aiohttp_socks import ProxyConnector as AiohttpSocksProxyConnector
except Exception:
    AiohttpSocksProxyConnector = None
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_IMPORT_ERROR = None
except Exception as _playwright_exc:
    sync_playwright = None
    _PLAYWRIGHT_IMPORT_ERROR = _playwright_exc
try:
    import socks as _pysocks  # noqa: F401
    _SOCKS_IMPORT_ERROR = None
except Exception as _socks_exc:
    _pysocks = None
    _SOCKS_IMPORT_ERROR = _socks_exc

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =================== 日志系统 ===================

class _SharedLogWriter:
    """共享日志写入器：stdout/stderr 共用同一日志文件并支持自动轮转。"""
    def __init__(self, log_dir, prefix="keygen", max_bytes=20 * 1024 * 1024):
        self._log_dir = log_dir
        self._prefix = prefix
        self._max_bytes = max(1024 * 1024, int(max_bytes or 0))
        self._lock = threading.Lock()
        self._file = None
        self._current_path = ""
        self._current_size = 0
        self._cleanup_old_logs()
        self._rotate_file_unlocked()

    @property
    def current_path(self):
        return self._current_path

    def _new_log_path(self):
        while True:
            ts = datetime.now().strftime("%Y-%m-%d_%H%M%S_%f")
            path = os.path.join(self._log_dir, f"{self._prefix}_{ts}.log")
            if not os.path.exists(path):
                return path
            time.sleep(0.001)

    def _write_header(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("=== OpenAI Codex Protocol Keygen Log ===\n")
            f.write(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Python:  {sys.version}\n")
            f.write(f"Platform: {sys.platform}\n")
            f.write(f"{'=' * 50}\n\n")

    def _rotate_file_unlocked(self):
        if self._file is not None:
            try:
                self._file.flush()
            except Exception:
                pass
            try:
                self._file.close()
            except Exception:
                pass
        path = self._new_log_path()
        self._write_header(path)
        self._file = open(path, "a", encoding="utf-8", errors="replace")
        self._current_path = path
        try:
            self._current_size = os.path.getsize(path)
        except Exception:
            self._current_size = 0

    def _cleanup_old_logs(self):
        try:
            cutoff = time.time() - 7 * 86400
            for fname in os.listdir(self._log_dir):
                fpath = os.path.join(self._log_dir, fname)
                if fname.startswith(f"{self._prefix}_") and fname.endswith(".log"):
                    if os.path.getmtime(fpath) < cutoff:
                        os.remove(fpath)
        except Exception:
            pass

    def write(self, text):
        clean = re.sub(r'\[[0-9;]*m', '', text or '')
        if not clean:
            return
        encoded_len = len(clean.encode("utf-8", errors="replace"))
        with self._lock:
            if self._current_size + encoded_len > self._max_bytes:
                self._rotate_file_unlocked()
            try:
                self._file.write(clean)
                self._file.flush()
                self._current_size += encoded_len
            except Exception:
                pass

    def flush(self):
        with self._lock:
            try:
                self._file.flush()
            except Exception:
                pass

    def close(self):
        with self._lock:
            try:
                self._file.close()
            except Exception:
                pass


class _TeeLogger:
    """双写流：同时写入控制台和共享日志文件。"""
    def __init__(self, shared_writer, original_stream):
        self._original = original_stream
        self._shared_writer = shared_writer
        self._lock = threading.Lock()

    @property
    def current_log_file(self):
        return self._shared_writer.current_path

    def write(self, text):
        with self._lock:
            try:
                self._original.write(text)
            except Exception:
                pass
            try:
                self._shared_writer.write(text)
            except Exception:
                pass

    def flush(self):
        try:
            self._original.flush()
        except Exception:
            pass
        try:
            self._shared_writer.flush()
        except Exception:
            pass

    def close(self):
        try:
            self._shared_writer.close()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self._original, name)


def _setup_logging():
    """初始化日志系统：创建日志目录、启动双写、清理旧日志。"""
    if isinstance(sys.stdout, _TeeLogger) and hasattr(sys.stdout, 'current_log_file'):
        return sys.stdout.current_log_file

    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(script_dir, "output", "logs")
    os.makedirs(log_dir, exist_ok=True)

    try:
        log_max_mb = int(str(os.environ.get("LOG_MAX_MB", "20") or "20").strip())
    except Exception:
        log_max_mb = 20
    log_max_mb = max(5, log_max_mb)
    shared_writer = _SharedLogWriter(log_dir, prefix="keygen", max_bytes=log_max_mb * 1024 * 1024)

    sys.stdout = _TeeLogger(shared_writer, sys.stdout)
    sys.stderr = _TeeLogger(shared_writer, sys.stderr)

    print(f"  📝 日志文件: {shared_writer.current_path}")
    return shared_writer.current_path


# =================== 配置加载 ===================

def load_dotenv():
    """加载同目录 .env（仅在环境变量缺失时提供默认值，不覆盖外部注入值）"""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return {}

    loaded = {}
    with open(env_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if key in os.environ:
                loaded[key] = os.environ[key]
            else:
                loaded[key] = value
                os.environ[key] = value
    return loaded


def load_config():
    """加载外部配置文件"""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"config.json 未找到: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


_config = load_config()
_dotenv = load_dotenv()


def _bool_value(value, default=False):
    """兼容字符串/布尔值的配置解析"""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _float_value(value, default=0.0):
    """兼容字符串/数值的浮点配置解析"""
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _int_value(value, default=0):
    """兼容字符串/数值的整数配置解析"""
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _normalize_proxy_url(proxy_url):
    """规范化代理 URL，兼容 sock5:// 误写。"""
    value = str(proxy_url or "").strip()
    if not value:
        return ""
    if value.startswith("sock5://"):
        value = "socks5://" + value[len("sock5://"):]
    return value


def _proxy_scheme(proxy_url):
    return urlparse(_normalize_proxy_url(proxy_url)).scheme.lower()


def _is_socks_proxy(proxy_url):
    return _proxy_scheme(proxy_url).startswith("socks")


def _effective_proxy(proxy_url=None):
    if proxy_url is None:
        return PROXY if PROXY_MODE in (1, 3) else ""
    return _normalize_proxy_url(proxy_url)


def _proxy_display(proxy_url):
    proxy_url = _normalize_proxy_url(proxy_url)
    return proxy_url if proxy_url else "无 (直连)"


def _assert_proxy_supported(proxy_url):
    proxy_url = _normalize_proxy_url(proxy_url)
    if not proxy_url:
        return
    if _is_socks_proxy(proxy_url) and _SOCKS_IMPORT_ERROR is not None:
        raise RuntimeError(
            "当前环境缺少 SOCKS 依赖，请先安装 PySocks（例如: pip install pysocks）"
        )

# 基础配置
TOTAL_ACCOUNTS = _config.get("total_accounts", 30)
CONCURRENT_WORKERS = _config.get("concurrent_workers", 1)  # 并发数（默认串行）
HEADLESS = _bool_value(_config.get("headless", False), False)  # 是否无头模式运行浏览器
PROXY = _normalize_proxy_url(
    os.environ.get("SOCKS5_PROXY")
    or os.environ.get("PROXY")
    or _config.get("proxy", "")
)
_proxy_mode_raw = str(os.environ.get("PROXY_MODE", _config.get("proxy_mode", "")) or "").strip()
_proxy_mode_fallback_enabled = _bool_value(
    os.environ.get("MAIL_PROXY_ENABLED", _config.get("mail_proxy_enabled", False)),
    False,
)
if _proxy_mode_raw:
    PROXY_MODE = _int_value(_proxy_mode_raw, 1)
    if PROXY_MODE not in (1, 2, 3, 4, 5, 7):
        print(f"⚠️ 未知 PROXY_MODE={_proxy_mode_raw}，已回退到模式 1")
        PROXY_MODE = 1
else:
    PROXY_MODE = 2 if _proxy_mode_fallback_enabled else 1
MAIL_PROVIDER = str(os.environ.get("MAIL_PROVIDER", _config.get("mail_provider", "duckmail"))).strip().lower()

# DuckMail 临时邮箱配置
DUCKMAIL_API_URL = _config.get("duckmail_api_url", "https://api.duckmail.sbs")
DUCKMAIL_API_KEY = _config.get("duckmail_api_key", "")  # dk_xxx 格式，私有域名时需要
DUCKMAIL_DOMAIN = _config.get("duckmail_domain", "duckmail.sbs")

# ChatGPT 临时邮箱配置
CHATGPTMAIL_BASE_URL = str(
    os.environ.get("CHATGPTMAIL_BASE_URL", _config.get("chatgptmail_base_url", "https://mail.chatgpt.org.uk"))
).rstrip("/")
CHATGPTMAIL_LOCALE = str(
    os.environ.get("CHATGPTMAIL_LOCALE", _config.get("chatgptmail_locale", "zh"))
).strip().strip("/") or "zh"
CHATGPTMAIL_AUTH_MARKER = "provider=chatgptmail"
CHATGPTMAIL_REQUEST_INTERVAL = max(
    0.0,
    _float_value(
        os.environ.get("CHATGPTMAIL_REQUEST_INTERVAL", _config.get("chatgptmail_request_interval", 0.0)),
        0.0,
    ),
)

# DuckDuckGo Alias + Outlook 预留配置（当前默认未启用）
DDG_AUTH_MARKER_PROVIDER = "ddg"
DDG_AUTH_MARKER = "provider=ddg"
DDG_API_URL = str(
    os.environ.get("DDG_API_URL", _config.get("ddg_api_url", "https://quack.duckduckgo.com"))
).rstrip("/")
DDG_BASE_URL = str(
    os.environ.get("DDG_BASE_URL", _config.get("ddg_base_url", "https://duckduckgo.com"))
).rstrip("/")
DDG_ALIAS_DOMAIN = str(
    os.environ.get("DDG_ALIAS_DOMAIN", _config.get("ddg_alias_domain", "duck.com"))
).strip().lower() or "duck.com"
DDG_ACCESS_TOKEN = str(
    os.environ.get("DDG_ACCESS_TOKEN", _config.get("ddg_access_token", ""))
).strip()
DDG_AUTH_TOKEN = str(
    os.environ.get("DDG_AUTH_TOKEN", _config.get("ddg_auth_token", ""))
).strip()
DDG_USERNAME = str(
    os.environ.get("DDG_USERNAME", _config.get("ddg_username", ""))
).strip()
DDG_FORWARD_EMAIL = str(
    os.environ.get("DDG_FORWARD_EMAIL", _config.get("ddg_forward_email", ""))
).strip().lower()
DDG_CAPTURE_DIR = str(
    os.environ.get("DDG_CAPTURE_DIR", _config.get("ddg_capture_dir", ""))
).strip()
DDG_OUTLOOK_BASE_URL = str(
    os.environ.get("DDG_OUTLOOK_BASE_URL", _config.get("ddg_outlook_base_url", "http://127.0.0.1:3009"))
).rstrip("/")
DDG_OUTLOOK_ACCOUNT_ID = str(
    os.environ.get("DDG_OUTLOOK_ACCOUNT_ID", _config.get("ddg_outlook_account_id", ""))
).strip()
MAIL_POLL_BASE_SECONDS = max(
    0.5,
    _float_value(
        os.environ.get("MAIL_POLL_BASE_SECONDS", _config.get("mail_poll_base_seconds", 1.5)),
        1.5,
    ),
)
MAIL_POLL_MAX_SECONDS = max(
    MAIL_POLL_BASE_SECONDS,
    _float_value(
        os.environ.get("MAIL_POLL_MAX_SECONDS", _config.get("mail_poll_max_seconds", 4.0)),
        4.0,
    ),
)
MAIL_POLL_EMPTY_BACKOFF_STEP_SECONDS = max(
    0.0,
    _float_value(
        os.environ.get("MAIL_POLL_EMPTY_BACKOFF_STEP_SECONDS", _config.get("mail_poll_empty_backoff_step_seconds", 0.5)),
        0.5,
    ),
)
MAIL_POLL_JITTER_SECONDS = max(
    0.0,
    _float_value(
        os.environ.get("MAIL_POLL_JITTER_SECONDS", _config.get("mail_poll_jitter_seconds", 0.8)),
        0.8,
    ),
)
OTP_RESEND_AFTER_SECONDS = max(
    5.0,
    _float_value(
        os.environ.get("OTP_RESEND_AFTER_SECONDS", _config.get("otp_resend_after_seconds", 20.0)),
        20.0,
    ),
)
REGISTER_OTP_TIMEOUT_SECONDS = max(
    30,
    _int_value(
        os.environ.get("REGISTER_OTP_TIMEOUT_SECONDS", _config.get("register_otp_timeout_seconds", 90)),
        90,
    ),
)
OAUTH_OTP_TIMEOUT_WITH_SNAPSHOT_SECONDS = max(
    30,
    _int_value(
        os.environ.get(
            "OAUTH_OTP_TIMEOUT_WITH_SNAPSHOT_SECONDS",
            _config.get("oauth_otp_timeout_with_snapshot_seconds", 45),
        ),
        45,
    ),
)
OAUTH_OTP_TIMEOUT_NO_SNAPSHOT_SECONDS = max(
    30,
    _int_value(
        os.environ.get(
            "OAUTH_OTP_TIMEOUT_NO_SNAPSHOT_SECONDS",
            _config.get("oauth_otp_timeout_no_snapshot_seconds", 60),
        ),
        60,
    ),
)
MAIL_PROXY_ENABLED = PROXY_MODE in (2, 3, 4, 5, 7)
MAIL_PROXY_API_URL = str(
    os.environ.get("MAIL_PROXY_API_URL", _config.get("mail_proxy_api_url", "http://127.0.0.1:3017/api/node-relay"))
).strip()
MAIL_PROXY_API_KEY = str(
    os.environ.get("MAIL_PROXY_API_KEY", _config.get("mail_proxy_api_key", "Nishibaka114514."))
).strip()
_node_session_proxy_api_default = "http://127.0.0.1:3017/api/node-session-proxy"
if MAIL_PROXY_API_URL:
    _mail_proxy_api_url = MAIL_PROXY_API_URL.rstrip("/")
    if "/api/node-relay" in _mail_proxy_api_url:
        _node_session_proxy_api_default = _mail_proxy_api_url.replace("/api/node-relay", "/api/node-session-proxy")
NODE_SESSION_PROXY_API_URL = str(
    os.environ.get("NODE_SESSION_PROXY_API_URL", _config.get("node_session_proxy_api_url", _node_session_proxy_api_default))
).strip()
NODE_SESSION_PROXY_API_KEY = str(
    os.environ.get("NODE_SESSION_PROXY_API_KEY", _config.get("node_session_proxy_api_key", MAIL_PROXY_API_KEY))
).strip() or MAIL_PROXY_API_KEY
NODE_SESSION_RANDOM_TOP_N = max(
    0,
    _int_value(
        os.environ.get("NODE_SESSION_RANDOM_TOP_N", _config.get("node_session_random_top_n", 10)),
        10,
    ),
)
MAIL_PROXY_POOL = str(
    os.environ.get("MAIL_PROXY_POOL", _config.get("mail_proxy_pool", "node"))
).strip() or "node"
MAIL_PROXY_NODE_ID = str(
    os.environ.get("MAIL_PROXY_NODE_ID", _config.get("mail_proxy_node_id", ""))
).strip()
MAIL_PROXY_RANDOM_TOP_N = max(
    0,
    _int_value(
        os.environ.get("MAIL_PROXY_RANDOM_TOP_N", _config.get("mail_proxy_random_top_n", 10)),
        10,
    ),
)
MAIL_PROXY_ROTATE_ON_429 = _bool_value(
    os.environ.get("MAIL_PROXY_ROTATE_ON_429", _config.get("mail_proxy_rotate_on_429", True)),
    True,
)
MAIL_PROXY_MAX_ROTATIONS = int(
    os.environ.get("MAIL_PROXY_MAX_ROTATIONS", _config.get("mail_proxy_max_rotations", 3)) or 3
)
MAIL_PROXY_ROTATE_INTERVAL_SECONDS = max(
    0.0,
    float(
        os.environ.get(
            "MAIL_PROXY_ROTATE_INTERVAL_SECONDS",
            _config.get("mail_proxy_rotate_interval_seconds", 0.5),
        )
        or 0.5
    ),
)
MAIL_PROXY_SESSION_PREFIX = str(
    os.environ.get("MAIL_PROXY_SESSION_PREFIX", _config.get("mail_proxy_session_prefix", "codex-mail"))
).strip() or "codex-mail"
MODE4_MAIL_USE_NODE_RELAY = _bool_value(
    os.environ.get("MODE4_MAIL_USE_NODE_RELAY", _config.get("mode4_mail_use_node_relay", True)),
    True,
)
AUTO_BLACKLIST_BAD_EMAIL_DOMAINS = _bool_value(
    os.environ.get("AUTO_BLACKLIST_BAD_EMAIL_DOMAINS", _config.get("auto_blacklist_bad_email_domains", True)),
    True,
)
REGISTRATION_STICKY_DOMAIN_ENABLED = _bool_value(
    os.environ.get("REGISTRATION_STICKY_DOMAIN_ENABLED", _config.get("registration_sticky_domain_enabled", True)),
    True,
)
REGISTRATION_STICKY_DOMAIN_FAILURE_LIMIT = max(
    1,
    _int_value(
        os.environ.get(
            "REGISTRATION_STICKY_DOMAIN_FAILURE_LIMIT",
            _config.get("registration_sticky_domain_failure_limit", 5),
        ),
        5,
    ),
)
REGISTRATION_SUCCESS_PAIR_HISTORY_LIMIT = max(
    1,
    _int_value(
        os.environ.get(
            "REGISTRATION_SUCCESS_PAIR_HISTORY_LIMIT",
            _config.get("registration_success_pair_history_limit", 10),
        ),
        10,
    ),
)
RELAY_UNAVAILABLE_RETRY_LIMIT = max(
    0,
    _int_value(
        os.environ.get("RELAY_UNAVAILABLE_RETRY_LIMIT", _config.get("relay_unavailable_retry_limit", 3)),
        3,
    ),
)
BAD_EMAIL_DOMAIN_RETRY_LIMIT = max(
    0,
    _int_value(
        os.environ.get("BAD_EMAIL_DOMAIN_RETRY_LIMIT", _config.get("bad_email_domain_retry_limit", 2)),
        2,
    ),
)
BAD_EMAIL_GENERATE_MAX_ATTEMPTS = max(
    1,
    _int_value(
        os.environ.get("BAD_EMAIL_GENERATE_MAX_ATTEMPTS", _config.get("bad_email_generate_max_attempts", 8)),
        8,
    ),
)
BAD_EMAIL_DOMAIN_ERROR_CODES = {"unsupported_email"}
CREATE_ACCOUNT_SOFT_SUCCESS_ERROR_CODES = {"registration_disallowed"}
OAUTH_SOFT_RETRY_REASONS = {
    "about_you_add_phone_pending",
    "about_you_registration_disallowed",
}
OAUTH_NO_RETRY_REASONS = {"chatgptmail_unsupported_email"}
AUTO_OAUTH_RETRY_SOFT_EXTRA_ATTEMPTS = 1
AUTO_OAUTH_RETRY_IMMEDIATE_RETRY_SECONDS = max(
    0.0,
    float(
        os.environ.get(
            "AUTO_OAUTH_RETRY_IMMEDIATE_RETRY_SECONDS",
            _config.get("auto_oauth_retry_immediate_retry_seconds", 1.0),
        )
        or 1.0
    ),
)
AUTO_OAUTH_RETRY_SOFT_MIN_DELAY_SECONDS = 25.0
AUTO_OAUTH_RETRY_ENABLED = _bool_value(
    os.environ.get("AUTO_OAUTH_RETRY_ENABLED", _config.get("auto_oauth_retry_enabled", True)),
    True,
)
AUTO_OAUTH_RETRY_WORKERS = max(
    1,
    _int_value(
        os.environ.get("AUTO_OAUTH_RETRY_WORKERS", _config.get("auto_oauth_retry_workers", 1)),
        1,
    ),
)
AUTO_OAUTH_RETRY_DELAY_SECONDS = max(
    0.0,
    _float_value(
        os.environ.get("AUTO_OAUTH_RETRY_DELAY_SECONDS", _config.get("auto_oauth_retry_delay_seconds", 20.0)),
        20.0,
    ),
)
AUTO_OAUTH_RETRY_MAX_ATTEMPTS = max(
    1,
    _int_value(
        os.environ.get("AUTO_OAUTH_RETRY_MAX_ATTEMPTS", _config.get("auto_oauth_retry_max_attempts", 1)),
        1,
    ),
)
AUTO_OAUTH_RETRY_DELETE_AFTER_FAILURES = max(
    0,
    _int_value(
        os.environ.get("AUTO_OAUTH_RETRY_DELETE_AFTER_FAILURES", _config.get("auto_oauth_retry_delete_after_failures", 3)),
        3,
    ),
)

if MAIL_PROVIDER not in {"duckmail", "chatgptmail"}:
    print(f"⚠️ 未知 MAIL_PROVIDER={MAIL_PROVIDER}，已回退到 duckmail")
    MAIL_PROVIDER = "duckmail"


def _proxy_mode_label(mode=None):
    mode = PROXY_MODE if mode is None else mode
    if mode == 1:
        return "模式1（普通，CPA管理直连）" if CPA_MANAGEMENT_NO_PROXY else "模式1（普通）"
    if mode == 2:
        return "模式2（邮箱独立代理，其他直连）"
    if mode == 3:
        return (
            "模式3（邮箱独立代理 + 注册/OAuth 走全局代理，CPA管理直连）"
            if CPA_MANAGEMENT_NO_PROXY
            else "模式3（邮箱独立代理 + 注册/OAuth 走全局代理）"
        )
    if mode == 4:
        return (
            "模式4（邮箱走 node-relay；注册/OAuth 走 node-session-proxy；CPA管理直连）"
            if CPA_MANAGEMENT_NO_PROXY and MODE4_MAIL_USE_NODE_RELAY
            else "模式4（邮箱/注册/OAuth 走 node-session-proxy，CPA管理直连）"
            if CPA_MANAGEMENT_NO_PROXY
            else "模式4（邮箱走 node-relay；注册/OAuth 走 node-session-proxy）"
            if MODE4_MAIL_USE_NODE_RELAY
            else "模式4（全部请求走 node-session-proxy）"
        )
    if mode == 5:
        return (
            "模式5（邮箱走 node-relay；注册走 ChatGPT 新链路；注册/OAuth 走 node-session-proxy；CPA管理直连）"
            if CPA_MANAGEMENT_NO_PROXY
            else "模式5（邮箱走 node-relay；注册走 ChatGPT 新链路；注册/OAuth 走 node-session-proxy）"
        )
    if mode == 7:
        return (
            "模式7（邮箱走 node-relay；注册走 Camoufox OAuth 直链+Cookie；Token 走 node-session-proxy；CPA管理直连）"
            if CPA_MANAGEMENT_NO_PROXY
            else "模式7（邮箱走 node-relay；注册走 Camoufox OAuth 直链+Cookie；Token 走 node-session-proxy）"
        )
    return f"模式{mode}"


def _mail_source_display():
    """返回当前邮件 provider 的展示名称"""
    if MAIL_PROVIDER == "duckmail":
        return DUCKMAIL_DOMAIN
    if MAIL_PROVIDER == "chatgptmail":
        return CHATGPTMAIL_BASE_URL
    return DUCKMAIL_DOMAIN

# OAuth 配置
OAUTH_ISSUER = _config.get("oauth_issuer", "https://auth.openai.com")
OAUTH_CLIENT_ID = _config.get("oauth_client_id", "app_EMoamEEZ73f0CkXaXp7hrann")
OAUTH_REDIRECT_URI = _config.get("oauth_redirect_uri", "http://localhost:1455/auth/callback")

# 上传配置
UPLOAD_API_URL = _config.get("upload_api_url", "")
UPLOAD_API_TOKEN = _config.get("upload_api_token", "")

# CPA 账号清理配置（由 test/config.json.txt 合并）
CPA_BASE_URL = _config.get("base_url", "")
if (not CPA_BASE_URL) and UPLOAD_API_URL:
    _u = urlparse(UPLOAD_API_URL)
    if _u.scheme and _u.netloc:
        CPA_BASE_URL = f"{_u.scheme}://{_u.netloc}"
CPA_PASSWORD = _config.get("cpa_password", "") or _config.get("upload_api_token", "")
CPA_TARGET_TYPE = _config.get("target_type", "codex")
CPA_PROVIDER = _config.get("provider", "")
CPA_WORKERS = int(_config.get("workers", 200))
CPA_DELETE_WORKERS = int(_config.get("delete_workers", 40))
CPA_TIMEOUT = int(_config.get("timeout", 10))
CPA_RETRIES = int(_config.get("retries", 1))
CPA_USER_AGENT = _config.get(
    "user_agent",
    "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
)
CPA_CHATGPT_ACCOUNT_ID = _config.get("chatgpt_account_id", "")
CPA_OUTPUT_NAME = _config.get("output", "invalid_codex_accounts.json")
CPA_QUOTA_WORKERS = max(
    1,
    int(os.environ.get("CPA_QUOTA_WORKERS", _config.get("cpa_quota_workers", 30)) or 30),
)
CPA_QUOTA_TIMEOUT = max(
    5,
    int(os.environ.get("CPA_QUOTA_TIMEOUT", _config.get("cpa_quota_timeout", CPA_TIMEOUT)) or CPA_TIMEOUT),
)
CPA_QUOTA_RETRIES = max(
    0,
    int(os.environ.get("CPA_QUOTA_RETRIES", _config.get("cpa_quota_retries", 0)) or 0),
)
CPA_QUOTA_CACHE_SECONDS = max(
    5.0,
    float(os.environ.get("CPA_QUOTA_CACHE_SECONDS", _config.get("cpa_quota_cache_seconds", 180)) or 180),
)
CPA_QUOTA_TARGET_PARALLELISM = max(
    1,
    int(os.environ.get("CPA_QUOTA_TARGET_PARALLELISM", _config.get("cpa_quota_target_parallelism", 2)) or 2),
)
DEFAULT_CPA_QUOTA_ENABLED = _bool_value(
    os.environ.get("DEFAULT_CPA_QUOTA_ENABLED", _config.get("default_cpa_quota_enabled", True)),
    True,
)
DEFAULT_CPA_MIN_AVAILABLE = max(
    0,
    int(os.environ.get("DEFAULT_CPA_MIN_AVAILABLE", _config.get("default_cpa_min_available", 20)) or 20),
)
DEFAULT_CPA_TOPUP_MAX_PER_ROUND = max(
    0,
    int(os.environ.get("DEFAULT_CPA_TOPUP_MAX_PER_ROUND", _config.get("default_cpa_topup_max_per_round", 20)) or 20),
)
CPA_AUTO_TOPUP_ENABLED = _bool_value(
    os.environ.get("CPA_AUTO_TOPUP_ENABLED", _config.get("cpa_auto_topup_enabled", True)),
    True,
)
CPA_AUTO_TOPUP_SUCCESS_INTERVAL = max(
    1,
    int(os.environ.get("CPA_AUTO_TOPUP_SUCCESS_INTERVAL", _config.get("cpa_auto_topup_success_interval", 20)) or 20),
)
CPA_AUTO_TOPUP_MIN_INTERVAL_SECONDS = max(
    10.0,
    float(os.environ.get("CPA_AUTO_TOPUP_MIN_INTERVAL_SECONDS", _config.get("cpa_auto_topup_min_interval_seconds", 120)) or 120),
)
CPA_AUTO_TOPUP_FORCE_PROBE = _bool_value(
    os.environ.get("CPA_AUTO_TOPUP_FORCE_PROBE", _config.get("cpa_auto_topup_force_probe", False)),
    False,
)
CPA_AUTO_DELETE_401_ENABLED = _bool_value(
    os.environ.get("CPA_AUTO_DELETE_401_ENABLED", _config.get("cpa_auto_delete_401_enabled", True)),
    True,
)
CPA_AUTO_DELETE_401_THRESHOLD = max(
    1,
    int(os.environ.get("CPA_AUTO_DELETE_401_THRESHOLD", _config.get("cpa_auto_delete_401_threshold", 20)) or 20),
)
CPA_AUTO_DELETE_401_MIN_INTERVAL_SECONDS = max(
    10.0,
    float(os.environ.get("CPA_AUTO_DELETE_401_MIN_INTERVAL_SECONDS", _config.get("cpa_auto_delete_401_min_interval_seconds", 120)) or 120),
)
CPA_AUTO_DELETE_401_WORKERS = max(
    1,
    int(os.environ.get("CPA_AUTO_DELETE_401_WORKERS", _config.get("cpa_auto_delete_401_workers", min(CPA_DELETE_WORKERS, 10) or 1)) or min(CPA_DELETE_WORKERS, 10) or 1),
)
CPA_AUTO_DELETE_401_MAX_DELETE_PER_RUN = max(
    0,
    int(os.environ.get("CPA_AUTO_DELETE_401_MAX_DELETE_PER_RUN", _config.get("cpa_auto_delete_401_max_delete_per_run", 0)) or 0),
)
CPA_MANAGEMENT_NO_PROXY = _bool_value(
    os.environ.get("CPA_MANAGEMENT_NO_PROXY", _config.get("cpa_management_no_proxy", True)),
    True,
)
SAVED_AUTH_401_CHECK_WORKERS = max(
    1,
    int(os.environ.get("SAVED_AUTH_401_CHECK_WORKERS", _config.get("saved_auth_401_check_workers", 8)) or 8),
)
SAVED_AUTH_401_CHECK_TIMEOUT = max(
    3,
    int(os.environ.get("SAVED_AUTH_401_CHECK_TIMEOUT", _config.get("saved_auth_401_check_timeout", 15)) or 15),
)

# 输出目录（所有凭证文件统一存放）
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "OAuth")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 输出文件（均放入 OAuth/ 目录下）
ACCOUNTS_FILE = os.path.join(OUTPUT_DIR, _config.get("accounts_file", "accounts.txt"))
CSV_FILE = os.path.join(OUTPUT_DIR, _config.get("csv_file", "registered_accounts.csv"))
AK_FILE = os.path.join(OUTPUT_DIR, _config.get("ak_file", "ak.txt"))
RK_FILE = os.path.join(OUTPUT_DIR, _config.get("rk_file", "rk.txt"))
INVALID_CODEX_FILE = CPA_OUTPUT_NAME if os.path.isabs(CPA_OUTPUT_NAME) else os.path.join(OUTPUT_DIR, CPA_OUTPUT_NAME)
ACCOUNT_PROXY_MAP_FILE = os.path.join(OUTPUT_DIR, _config.get("account_proxy_map_file", "account_proxies.json"))
ACCOUNT_RELAY_MAP_FILE = os.path.join(OUTPUT_DIR, _config.get("account_relay_map_file", "account_relays.json"))

# 并发文件写入锁（多线程共享文件时防止数据竞争）
_file_lock = threading.Lock()
_cpa_round_robin_lock = threading.Lock()
_cpa_round_robin_index = 0

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)
CPA_TARGETS_FILE = os.path.join(DATA_DIR, _config.get("cpa_targets_file", "cpa_targets.json"))
CPA_PUSH_STATS_FILE = os.path.join(DATA_DIR, _config.get("cpa_push_stats_file", "cpa_push_stats.json"))
CPA_PUSH_RECORDS_FILE = os.path.join(DATA_DIR, _config.get("cpa_push_records_file", "cpa_push_records.json"))
BAD_EMAIL_DOMAINS_FILE = os.path.join(DATA_DIR, _config.get("bad_email_domains_file", "bad_email_domains.json"))
AUTO_OAUTH_RETRY_FAILURES_FILE = os.path.join(DATA_DIR, _config.get("auto_oauth_retry_failures_file", "auto_oauth_retry_failures.json"))
AUTH_FILE_MARKS_FILE = os.path.join(DATA_DIR, _config.get("auth_file_marks_file", "auth_file_marks.json"))
DOMAIN_STICKY_STATE_FILE = os.path.join(DATA_DIR, _config.get("domain_sticky_state_file", "domain_sticky_state.json"))

_cpa_quota_cache_lock = threading.Lock()
_cpa_quota_cache = {}
_cpa_auto_topup_lock = threading.Lock()
_cpa_auto_topup_plan = deque()
_cpa_auto_topup_last_run_ts = 0.0
_cpa_auto_topup_last_reason = ""
_cpa_auto_topup_success_since_refresh = 0
_cpa_auto_topup_inflight = False
_cpa_auto_topup_last_result = {}
_cpa_auto_delete_401_lock = threading.Lock()
_cpa_auto_delete_401_state = {}
_saved_auth_401_cleanup_lock = threading.Lock()

_auto_oauth_retry_lock = threading.Lock()
_auto_oauth_retry_queue = queue.Queue()
_auto_oauth_retry_pending = {}
_auto_oauth_retry_active = {}
_auto_oauth_retry_recent = deque(maxlen=50)
_auto_oauth_retry_worker_specs = {}
_auto_oauth_retry_next_worker_id = 1
_auto_oauth_retry_started = False
_auto_oauth_retry_runtime_enabled = AUTO_OAUTH_RETRY_ENABLED


def _extract_email_domain(value):
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "@" in raw:
        raw = raw.split("@", 1)[1]
    return raw.strip().strip(".")


_EMAIL_DOMAIN_PATTERN = re.compile(
    r"^[0-9a-z](?:[0-9a-z-]{0,61}[0-9a-z])?(?:\.[0-9a-z](?:[0-9a-z-]{0,61}[0-9a-z])?)+$"
)


def _is_valid_email_domain(value):
    domain = _extract_email_domain(value)
    if not domain or len(domain) > 253 or ".." in domain:
        return False
    return bool(_EMAIL_DOMAIN_PATTERN.fullmatch(domain))


def _normalize_email_domain_list(values):
    if isinstance(values, (list, tuple, set)):
        raw_items = list(values)
    else:
        raw_items = re.split(r"[\s,，;；]+", str(values or ""))

    result = []
    seen = set()
    for raw in raw_items:
        domain = _extract_email_domain(raw)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        result.append(domain)
    return result


def _normalize_node_id(value):
    return re.sub(r"[^0-9a-z]", "", str(value or "").strip().lower())


def _extract_relay_node_id(value):
    if isinstance(value, dict):
        return _normalize_node_id(value.get("node_id"))
    if isinstance(value, str):
        return _normalize_node_id(value)
    state = getattr(value, "_relay_state", None)
    if isinstance(state, dict):
        node_id = _normalize_node_id(state.get("node_id"))
        if node_id:
            return node_id
    return _normalize_node_id(getattr(value, "_mail_relay_node_id", ""))


def _registration_pair_key(domain, node_id):
    domain = _extract_email_domain(domain)
    node_id = _normalize_node_id(node_id)
    if not domain or not node_id:
        return ""
    return f"{domain}|{node_id}"


def _normalize_recent_registration_pair(item=None):
    payload = item if isinstance(item, dict) else {}
    domain = _extract_email_domain(payload.get("domain") or payload.get("active_domain") or payload.get("last_success_domain"))
    node_id = _normalize_node_id(payload.get("node_id") or payload.get("active_node_id") or payload.get("last_success_node_id"))
    if not domain or not node_id:
        return None
    return {
        "key": _registration_pair_key(domain, node_id),
        "domain": domain,
        "node_id": node_id,
        "last_email": str(payload.get("last_email") or "").strip().lower(),
        "last_success_at": str(payload.get("last_success_at") or payload.get("updated_at") or "").strip(),
        "success_count": max(1, _int_value(payload.get("success_count"), 1)),
        "source": str(payload.get("source") or "").strip(),
    }


def _default_domain_sticky_state():
    return {
        "selection_mode": "auto",
        "active_domain": "",
        "active_node_id": "",
        "active_failures": 0,
        "last_success_domain": "",
        "last_success_node_id": "",
        "manual_domain": "",
        "manual_domains": [],
        "manual_node_id": "",
        "recent_pairs": [],
        "mode": "random",
        "updated_at": "",
    }


def _normalize_domain_sticky_state(data=None):
    state = _default_domain_sticky_state()
    payload = data if isinstance(data, dict) else {}

    selection_mode = str(payload.get("selection_mode") or "").strip().lower()
    if selection_mode not in {"auto", "random", "manual", "manual_domain", "manual_domains"}:
        selection_mode = "auto"

    active_domain = _extract_email_domain(payload.get("active_domain"))
    active_node_id = _normalize_node_id(payload.get("active_node_id"))
    last_success_domain = _extract_email_domain(payload.get("last_success_domain"))
    last_success_node_id = _normalize_node_id(payload.get("last_success_node_id"))
    manual_domain = _extract_email_domain(payload.get("manual_domain"))
    manual_domains = _normalize_email_domain_list(payload.get("manual_domains"))
    if manual_domain and manual_domain not in manual_domains:
        manual_domains.insert(0, manual_domain)
    if not manual_domain and manual_domains:
        manual_domain = manual_domains[0]
    manual_node_id = _normalize_node_id(payload.get("manual_node_id"))
    active_failures = max(0, _int_value(payload.get("active_failures"), 0))
    updated_at = str(payload.get("updated_at") or "").strip()

    if not active_domain:
        active_failures = 0

    recent_pairs = []
    seen_domains = set()
    for raw_item in list(payload.get("recent_pairs") or []):
        item = _normalize_recent_registration_pair(raw_item)
        if not isinstance(item, dict):
            continue
        domain_key = _extract_email_domain(item.get("domain"))
        key = str(item.get("key") or "").strip()
        if not key or not domain_key or domain_key in seen_domains:
            continue
        seen_domains.add(domain_key)
        recent_pairs.append(item)

    last_success_key = _registration_pair_key(last_success_domain, last_success_node_id)
    if last_success_key and last_success_domain:
        existing_last = None
        filtered_pairs = []
        for item in recent_pairs:
            if _extract_email_domain(item.get("domain")) == last_success_domain:
                if existing_last is None:
                    existing_last = dict(item)
                continue
            filtered_pairs.append(item)

        merged_last = dict(existing_last or {})
        merged_last.update({
            "key": last_success_key,
            "domain": last_success_domain,
            "node_id": last_success_node_id,
            "last_success_at": updated_at or str(merged_last.get("last_success_at") or "").strip(),
        })
        merged_last["last_email"] = str(merged_last.get("last_email") or "").strip().lower()
        merged_last["success_count"] = max(1, _int_value(merged_last.get("success_count"), 1))
        merged_last["source"] = str(merged_last.get("source") or "").strip()
        recent_pairs = [merged_last] + filtered_pairs

    recent_pairs = recent_pairs[:max(1, int(REGISTRATION_SUCCESS_PAIR_HISTORY_LIMIT or 10))]

    if selection_mode == "manual" and manual_domain and manual_node_id:
        mode = "manual"
    elif selection_mode == "manual_domains" and manual_domains:
        mode = "manual_domains"
    elif selection_mode == "manual_domain" and manual_domain:
        mode = "manual_domain"
    elif selection_mode == "auto" and active_domain and active_node_id:
        mode = "sticky"
    else:
        mode = "random"

    state.update({
        "selection_mode": selection_mode,
        "active_domain": active_domain,
        "active_node_id": active_node_id,
        "active_failures": active_failures,
        "last_success_domain": last_success_domain,
        "last_success_node_id": last_success_node_id,
        "manual_domain": manual_domain,
        "manual_domains": manual_domains,
        "manual_node_id": manual_node_id,
        "recent_pairs": recent_pairs,
        "mode": mode,
        "updated_at": updated_at,
    })
    return state


def _load_domain_sticky_state_unlocked():
    if not os.path.exists(DOMAIN_STICKY_STATE_FILE):
        return _default_domain_sticky_state()
    try:
        with open(DOMAIN_STICKY_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return _default_domain_sticky_state()
    return _normalize_domain_sticky_state(data)


def _save_domain_sticky_state_unlocked(data):
    with open(DOMAIN_STICKY_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(_normalize_domain_sticky_state(data), f, ensure_ascii=False, indent=2)


def load_domain_sticky_state():
    with _file_lock:
        return _load_domain_sticky_state_unlocked()


def get_registration_pair_state(limit=10):
    limit = max(1, _int_value(limit, REGISTRATION_SUCCESS_PAIR_HISTORY_LIMIT or 10))
    with _file_lock:
        state = _load_domain_sticky_state_unlocked()

    selection_mode = str(state.get("selection_mode") or "auto")
    active_domain = _extract_email_domain(state.get("active_domain"))
    active_node_id = _normalize_node_id(state.get("active_node_id"))
    manual_domain = _extract_email_domain(state.get("manual_domain"))
    manual_domains = _normalize_email_domain_list(state.get("manual_domains"))
    if manual_domain and manual_domain not in manual_domains:
        manual_domains.insert(0, manual_domain)
    if not manual_domain and manual_domains:
        manual_domain = manual_domains[0]
    manual_node_id = _normalize_node_id(state.get("manual_node_id"))
    last_success_domain = _extract_email_domain(state.get("last_success_domain"))
    last_success_node_id = _normalize_node_id(state.get("last_success_node_id"))

    effective_mode = "random"
    if selection_mode == "manual" and manual_domain and manual_node_id:
        effective_mode = "manual"
    elif selection_mode == "manual_domains" and manual_domains:
        effective_mode = "manual_domains"
    elif selection_mode == "manual_domain" and manual_domain:
        effective_mode = "manual_domain"
    elif selection_mode == "auto" and active_domain and active_node_id:
        effective_mode = "auto"

    recent_pairs = []
    active_key = _registration_pair_key(active_domain, active_node_id)
    manual_key = _registration_pair_key(manual_domain, manual_node_id)
    last_success_key = _registration_pair_key(last_success_domain, last_success_node_id)
    manual_domain_set = set(manual_domains)
    for item in list(state.get("recent_pairs") or [])[:limit]:
        pair = dict(item) if isinstance(item, dict) else {}
        key = str(pair.get("key") or _registration_pair_key(pair.get("domain"), pair.get("node_id"))).strip()
        if not key:
            continue
        pair["key"] = key
        pair["is_auto_active"] = bool(selection_mode == "auto" and active_key and key == active_key)
        pair["is_manual_selected"] = bool(selection_mode == "manual" and manual_key and key == manual_key)
        pair["is_manual_domain_selected"] = bool(
            selection_mode in {"manual_domain", "manual_domains"}
            and manual_domain_set
            and _extract_email_domain(pair.get("domain")) in manual_domain_set
        )
        pair["is_last_success"] = bool(last_success_key and key == last_success_key)
        recent_pairs.append(pair)

    return {
        "enabled": bool(REGISTRATION_STICKY_DOMAIN_ENABLED and MAIL_PROVIDER == "chatgptmail"),
        "selection_mode": selection_mode,
        "effective_mode": effective_mode,
        "failure_limit": max(1, int(REGISTRATION_STICKY_DOMAIN_FAILURE_LIMIT or 5)),
        "active_pair": {
            "domain": active_domain,
            "node_id": active_node_id,
            "failures": max(0, _int_value(state.get("active_failures"), 0)),
            "key": active_key,
        },
        "manual_pair": {
            "domain": manual_domain,
            "node_id": manual_node_id,
            "key": manual_key,
        },
        "manual_domains": manual_domains,
        "last_success_pair": {
            "domain": last_success_domain,
            "node_id": last_success_node_id,
            "key": last_success_key,
        },
        "recent_pairs": recent_pairs,
        "updated_at": str(state.get("updated_at") or "").strip(),
    }


def backfill_registration_pairs_from_logs(limit=5, scan_files=20):
    limit = max(1, _int_value(limit, 5))
    scan_files = max(limit, _int_value(scan_files, max(limit * 4, 20)))
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "logs")
    if not os.path.isdir(log_dir):
        return {"added": 0, "items": [], "message": "log dir missing"}

    success_pattern = re.compile(r"^\[(?:W|AR)\d+\] ✅ (?P<email>\S+) \| (?P<tail>.*)$")
    log_files = []
    try:
        for name in os.listdir(log_dir):
            if not str(name).startswith("keygen_") or not str(name).endswith(".log"):
                continue
            path = os.path.join(log_dir, name)
            if os.path.isfile(path):
                log_files.append(path)
    except Exception:
        log_files = []
    log_files.sort(key=lambda path: os.path.getmtime(path), reverse=True)

    pair_items = []
    pair_index = {}
    for path in log_files[:scan_files]:
        try:
            lines = open(path, "r", encoding="utf-8", errors="ignore").read().splitlines()
        except Exception:
            continue
        file_time = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
        for line in reversed(lines):
            matched = success_pattern.match(str(line or "").strip())
            if not matched:
                continue
            email = str(matched.group("email") or "").strip().lower()
            domain = _extract_email_domain(email)
            relay_state = load_account_relay(email)
            node_id = _extract_relay_node_id(relay_state)
            pair_key = _registration_pair_key(domain, node_id)
            if not pair_key:
                continue
            if domain in pair_index:
                pair_items[pair_index[domain]]["success_count"] = max(
                    1,
                    _int_value(pair_items[pair_index[domain]].get("success_count"), 1) + 1,
                )
                continue
            pair_index[domain] = len(pair_items)
            pair_items.append({
                "key": pair_key,
                "domain": domain,
                "node_id": node_id,
                "last_email": email,
                "last_success_at": file_time,
                "success_count": 1,
                "source": "log_backfill",
            })
            if len(pair_items) >= limit:
                break
        if len(pair_items) >= limit:
            break

    if not pair_items:
        return {"added": 0, "items": [], "message": "no log success pairs found"}

    with _file_lock:
        state = _load_domain_sticky_state_unlocked()
        existing_items = []
        existing_map = {}
        for raw_item in list(state.get("recent_pairs") or []):
            item = _normalize_recent_registration_pair(raw_item)
            if not isinstance(item, dict):
                continue
            item_domain = _extract_email_domain(item.get("domain"))
            if not item_domain or item_domain in existing_map:
                continue
            existing_map[item_domain] = item
            existing_items.append(item)

        merged = []
        seen = set()
        for item in pair_items + existing_items:
            item_domain = _extract_email_domain((item or {}).get("domain"))
            if not item_domain or item_domain in seen:
                continue
            seen.add(item_domain)
            if item_domain in existing_map:
                base = dict(existing_map[item_domain])
                base_source = str(base.get("source") or "").strip()
                item_source = str((item or {}).get("source") or "").strip()
                if base_source and base_source != "log_backfill" and item_source == "log_backfill":
                    merged.append(base)
                    continue
                if base_source == "log_backfill":
                    if item.get("key"):
                        base["key"] = str(item.get("key") or "").strip()
                    if item.get("node_id"):
                        base["node_id"] = _normalize_node_id(item.get("node_id"))
                    base["success_count"] = max(
                        _int_value(base.get("success_count"), 1),
                        _int_value(item.get("success_count"), 1),
                    )
                    if item.get("last_success_at"):
                        base["last_success_at"] = str(item.get("last_success_at") or "")
                    if item.get("last_email"):
                        base["last_email"] = str(item.get("last_email") or "").strip().lower()
                    merged.append(base)
                    continue
            merged.append(dict(item))

        state["recent_pairs"] = merged[:max(1, int(REGISTRATION_SUCCESS_PAIR_HISTORY_LIMIT or 10))]
        state["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _save_domain_sticky_state_unlocked(state)

    return {"added": len(pair_items), "items": pair_items, "message": "ok"}


def set_registration_pair_selection(mode="auto", domain="", node_id="", domains=None):
    selection_mode = str(mode or "").strip().lower()
    if selection_mode not in {"auto", "random", "manual", "manual_domain", "manual_domains"}:
        raise ValueError("invalid selection mode")

    domain = _extract_email_domain(domain)
    manual_domains = _normalize_email_domain_list(domains)
    if domain and domain not in manual_domains:
        manual_domains.insert(0, domain)
    node_id = _normalize_node_id(node_id)
    if selection_mode in {"manual", "manual_domain"} and domain and not _is_valid_email_domain(domain):
        raise ValueError("域名格式不正确")
    if selection_mode == "manual_domains":
        if not manual_domains:
            raise ValueError("manual_domains mode requires domains")
        invalid_domains = [item for item in manual_domains if not _is_valid_email_domain(item)]
        if invalid_domains:
            raise ValueError(f"域名格式不正确: {', '.join(invalid_domains[:5])}")
    if selection_mode == "manual" and (not domain or not node_id):
        raise ValueError("manual mode requires domain and node_id")
    if selection_mode == "manual_domain" and not domain:
        raise ValueError("manual_domain mode requires domain")

    with _file_lock:
        state = _load_domain_sticky_state_unlocked()
        state["selection_mode"] = selection_mode
        if selection_mode == "manual":
            state["manual_domain"] = domain
            state["manual_domains"] = [domain]
            state["manual_node_id"] = node_id
        elif selection_mode == "manual_domain":
            state["manual_domain"] = domain
            state["manual_domains"] = [domain]
            state["manual_node_id"] = ""
        elif selection_mode == "manual_domains":
            state["manual_domain"] = manual_domains[0]
            state["manual_domains"] = manual_domains
            state["manual_node_id"] = ""
        state["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _save_domain_sticky_state_unlocked(state)

    return get_registration_pair_state(limit=REGISTRATION_SUCCESS_PAIR_HISTORY_LIMIT)


def get_preferred_registration_pair():
    result = {
        "enabled": False,
        "selection_mode": "random",
        "effective_mode": "random",
        "domain": "",
        "node_id": "",
        "strict_node_id": False,
        "manual_domains": [],
        "domain_pool": [],
        "state": {},
    }
    if not REGISTRATION_STICKY_DOMAIN_ENABLED or MAIL_PROVIDER != "chatgptmail":
        return result

    with _file_lock:
        state = _load_domain_sticky_state_unlocked()
        selection_mode = str(state.get("selection_mode") or "auto")
        result["enabled"] = True
        result["selection_mode"] = selection_mode

        if selection_mode == "auto":
            domain = _extract_email_domain(state.get("active_domain"))
            if domain and AUTO_BLACKLIST_BAD_EMAIL_DOMAINS:
                blocked = _load_bad_email_domains_unlocked()
                if domain in blocked:
                    state["active_domain"] = ""
                    state["active_node_id"] = ""
                    state["active_failures"] = 0
                    state["selection_mode"] = "random"
                    state["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    _save_domain_sticky_state_unlocked(state)
                    reason = str((blocked.get(domain) or {}).get("last_code") or (blocked.get(domain) or {}).get("last_message") or "blocked").strip()
                    print(f"⚠️ 固定域名+节点命中黑名单，已切回随机: {domain} ({reason})")
                    state = _load_domain_sticky_state_unlocked()

    state_payload = get_registration_pair_state(limit=REGISTRATION_SUCCESS_PAIR_HISTORY_LIMIT)
    result["state"] = state_payload
    result["selection_mode"] = str(state_payload.get("selection_mode") or "auto")
    result["effective_mode"] = str(state_payload.get("effective_mode") or "random")
    result["manual_domains"] = _normalize_email_domain_list(state_payload.get("manual_domains"))

    if result["effective_mode"] == "manual":
        pair = state_payload.get("manual_pair") or {}
        result["domain"] = _extract_email_domain(pair.get("domain"))
        result["node_id"] = _normalize_node_id(pair.get("node_id"))
        result["strict_node_id"] = bool(result["domain"] and result["node_id"])
        return result

    if result["effective_mode"] == "manual_domains":
        available_domains = list(result["manual_domains"])
        result["domain_pool"] = list(available_domains)
        if AUTO_BLACKLIST_BAD_EMAIL_DOMAINS and available_domains:
            blocked = load_bad_email_domains()
            filtered_domains = [item for item in available_domains if item not in blocked]
            if filtered_domains:
                available_domains = filtered_domains
        if available_domains:
            result["domain"] = random.choice(available_domains)
        result["node_id"] = ""
        result["strict_node_id"] = False
        return result

    if result["effective_mode"] == "manual_domain":
        pair = state_payload.get("manual_pair") or {}
        result["domain"] = _extract_email_domain(pair.get("domain"))
        result["node_id"] = ""
        result["strict_node_id"] = False
        return result

    if result["effective_mode"] == "auto":
        pair = state_payload.get("active_pair") or {}
        result["domain"] = _extract_email_domain(pair.get("domain"))
        result["node_id"] = _normalize_node_id(pair.get("node_id"))
        result["strict_node_id"] = bool(result["domain"] and result["node_id"])
        return result

    return result


def mark_registration_pair_success(email, relay_state=None, source=""):
    domain = _extract_email_domain(email)
    node_id = _extract_relay_node_id(relay_state)
    result = {
        "domain": domain,
        "node_id": node_id,
        "previous_active_domain": "",
        "previous_active_node_id": "",
        "active_domain": "",
        "active_node_id": "",
        "active_failures": 0,
        "mode": "random",
        "selection_mode": "auto",
        "changed": False,
        "recent_pairs": [],
    }
    if not REGISTRATION_STICKY_DOMAIN_ENABLED or not domain or not node_id:
        return result

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pair_key = _registration_pair_key(domain, node_id)
    with _file_lock:
        state = _load_domain_sticky_state_unlocked()
        previous_active_domain = _extract_email_domain(state.get("active_domain"))
        previous_active_node_id = _normalize_node_id(state.get("active_node_id"))
        previous_failures = max(0, _int_value(state.get("active_failures"), 0))
        previous_selection_mode = str(state.get("selection_mode") or "auto")

        recent_pairs = []
        found_item = None
        domain_success_count = 0
        for raw_item in list(state.get("recent_pairs") or []):
            item = _normalize_recent_registration_pair(raw_item)
            if not isinstance(item, dict):
                continue
            if _extract_email_domain(item.get("domain")) == domain:
                if found_item is None:
                    found_item = dict(item)
                domain_success_count += max(1, _int_value(item.get("success_count"), 1))
                continue
            recent_pairs.append(item)

        success_count = 1
        if isinstance(found_item, dict):
            success_count = max(1, domain_success_count) + 1

        recent_pairs.insert(0, {
            "key": pair_key,
            "domain": domain,
            "node_id": node_id,
            "last_email": str(email or "").strip().lower(),
            "last_success_at": timestamp,
            "success_count": success_count,
            "source": str(source or "").strip(),
        })
        state["recent_pairs"] = recent_pairs[:max(1, int(REGISTRATION_SUCCESS_PAIR_HISTORY_LIMIT or 10))]
        state["last_success_domain"] = domain
        state["last_success_node_id"] = node_id
        state["active_domain"] = domain
        state["active_node_id"] = node_id
        state["active_failures"] = 0
        if previous_selection_mode == "random":
            state["selection_mode"] = "auto"
        state["updated_at"] = timestamp
        _save_domain_sticky_state_unlocked(state)

    result.update({
        "previous_active_domain": previous_active_domain,
        "previous_active_node_id": previous_active_node_id,
        "active_domain": domain,
        "active_node_id": node_id,
        "active_failures": 0,
        "mode": "sticky",
        "selection_mode": str(state.get("selection_mode") or "auto"),
        "changed": previous_active_domain != domain or previous_active_node_id != node_id or previous_failures > 0,
        "recent_pairs": list(state.get("recent_pairs") or []),
    })
    return result


def mark_registration_pair_failure(value, node_id="", mode_hint="auto"):
    domain = _extract_email_domain(value)
    node_id = _normalize_node_id(node_id)
    result = {
        "domain": domain,
        "node_id": node_id,
        "tracked": False,
        "failure_count": 0,
        "threshold": max(1, int(REGISTRATION_STICKY_DOMAIN_FAILURE_LIMIT or 5)),
        "switched_to_random": False,
        "active_domain": "",
        "active_node_id": "",
        "mode": "random",
        "selection_mode": "auto",
    }
    if not REGISTRATION_STICKY_DOMAIN_ENABLED or not domain:
        return result

    with _file_lock:
        state = _load_domain_sticky_state_unlocked()
        selection_mode = str(state.get("selection_mode") or "auto")
        active_domain = _extract_email_domain(state.get("active_domain"))
        active_node_id = _normalize_node_id(state.get("active_node_id"))
        result["active_domain"] = active_domain
        result["active_node_id"] = active_node_id
        result["selection_mode"] = selection_mode
        result["mode"] = str(state.get("mode") or "random")

        if str(mode_hint or "").strip().lower() != "auto":
            return result
        if selection_mode != "auto":
            return result
        if not active_domain or active_domain != domain:
            return result
        if active_node_id and node_id and active_node_id != node_id:
            return result

        failure_count = max(0, _int_value(state.get("active_failures"), 0)) + 1
        state["active_failures"] = failure_count
        state["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        switched_to_random = failure_count >= result["threshold"]
        if switched_to_random:
            state["active_domain"] = ""
            state["active_node_id"] = ""
            state["active_failures"] = 0
            state["selection_mode"] = "random"

        _save_domain_sticky_state_unlocked(state)

    result.update({
        "tracked": True,
        "failure_count": failure_count,
        "switched_to_random": switched_to_random,
        "active_domain": _extract_email_domain(state.get("active_domain")),
        "active_node_id": _normalize_node_id(state.get("active_node_id")),
        "mode": "random" if switched_to_random else "sticky",
        "selection_mode": str(state.get("selection_mode") or "auto"),
    })
    return result


def get_preferred_registration_domain():
    return str(get_preferred_registration_pair().get("domain") or "").strip().lower()


def mark_registration_domain_success(value):
    return mark_registration_pair_success(value, relay_state=None)


def mark_registration_domain_failure(value):
    return mark_registration_pair_failure(value, node_id="", mode_hint="auto")


def _load_bad_email_domains_unlocked():
    if not os.path.exists(BAD_EMAIL_DOMAINS_FILE):
        return {}
    try:
        with open(BAD_EMAIL_DOMAINS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    result = {}
    if isinstance(data, list):
        for item in data:
            domain = _extract_email_domain(item)
            if domain:
                result[domain] = {}
        return result

    if not isinstance(data, dict):
        return {}

    for key, value in data.items():
        domain = _extract_email_domain(key)
        if not domain:
            continue
        item = dict(value) if isinstance(value, dict) else {"count": _int_value(value, 0)}
        item["count"] = max(1, _int_value(item.get("count", 1), 1))
        item["last_code"] = str(item.get("last_code") or "").strip()
        item["last_message"] = str(item.get("last_message") or "").strip()
        item["last_email"] = str(item.get("last_email") or "").strip().lower()
        item["updated_at"] = str(item.get("updated_at") or "").strip()
        result[domain] = item
    return result


def load_bad_email_domains():
    with _file_lock:
        return _load_bad_email_domains_unlocked()


def is_bad_email_domain(value, data=None):
    domain = _extract_email_domain(value)
    if not domain:
        return False
    if data is None:
        data = load_bad_email_domains()
    return domain in data


def remember_bad_email_domain(value, error_code="", error_message="", email=""):
    domain = _extract_email_domain(value)
    if not domain:
        return None
    with _file_lock:
        data = _load_bad_email_domains_unlocked()
        item = data.get(domain, {})
        if not isinstance(item, dict):
            item = {}
        item["count"] = max(0, _int_value(item.get("count"), 0)) + 1
        item["last_code"] = str(error_code or item.get("last_code") or "").strip()
        item["last_message"] = str(error_message or item.get("last_message") or "").strip()
        item["last_email"] = str(email or item.get("last_email") or "").strip().lower()
        item["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data[domain] = item
        with open(BAD_EMAIL_DOMAINS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    return domain


def list_bad_email_domains(page=1, limit=0):
    data = load_bad_email_domains()
    items = []
    for domain, meta in data.items():
        meta = meta if isinstance(meta, dict) else {}
        items.append({
            "domain": domain,
            "count": max(1, _int_value(meta.get("count"), 1)),
            "last_code": str(meta.get("last_code") or "").strip(),
            "last_message": str(meta.get("last_message") or "").strip(),
            "last_email": str(meta.get("last_email") or "").strip().lower(),
            "updated_at": str(meta.get("updated_at") or "").strip(),
        })
    items.sort(
        key=lambda item: (
            item.get("count") or 0,
            str(item.get("updated_at") or ""),
            str(item.get("domain") or ""),
        ),
        reverse=True,
    )

    total = len(items)
    limit = max(0, _int_value(limit, 0))
    if limit <= 0:
        return {
            "count": total,
            "page": 1,
            "limit": total,
            "total_pages": 1 if total > 0 else 0,
            "items": items,
        }

    total_pages = max(1, (total + limit - 1) // limit) if total > 0 else 1
    page = max(1, _int_value(page, 1))
    page = min(page, total_pages)
    start = (page - 1) * limit
    end = start + limit
    return {
        "count": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
        "items": items[start:end],
    }


def delete_bad_email_domain(value):
    domain = _extract_email_domain(value)
    if not domain:
        return False
    removed = False
    with _file_lock:
        data = _load_bad_email_domains_unlocked()
        if domain in data:
            data.pop(domain, None)
            removed = True
            with open(BAD_EMAIL_DOMAINS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
    return removed


def clear_bad_email_domains():
    with _file_lock:
        with open(BAD_EMAIL_DOMAINS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)
    return True


def _normalize_cpa_push_limit(value):
    try:
        limit = int(str(value).strip())
    except Exception:
        limit = 0
    return max(0, limit)


def _normalize_cpa_quota_int(value, default=0):
    try:
        parsed = int(str(value).strip())
    except Exception:
        parsed = default
    return max(0, parsed)


def _cpa_target_quota_config(target):
    target = target if isinstance(target, dict) else {}
    quota_enabled = _bool_value(
        target.get("quota_enabled") if "quota_enabled" in target else DEFAULT_CPA_QUOTA_ENABLED,
        DEFAULT_CPA_QUOTA_ENABLED,
    )
    min_available = _normalize_cpa_quota_int(target.get("min_available"), DEFAULT_CPA_MIN_AVAILABLE)
    topup_max_per_round = _normalize_cpa_quota_int(
        target.get("topup_max_per_round"),
        DEFAULT_CPA_TOPUP_MAX_PER_ROUND,
    )
    return {
        "quota_enabled": bool(quota_enabled),
        "min_available": min_available,
        "topup_max_per_round": topup_max_per_round,
    }


def _cpa_auto_delete_401_default_state():
    return {
        "inflight": False,
        "last_invalid": 0,
        "last_deleted": 0,
        "last_failed": 0,
        "last_run_ts": 0.0,
        "last_run_at": "",
        "last_status": "idle",
        "last_message": "",
        "last_reason": "",
        "last_duration_seconds": 0.0,
    }


def _get_cpa_auto_delete_401_state(target_id=None):
    state = _cpa_auto_delete_401_default_state()
    target_id = str(target_id or "").strip()
    if not target_id:
        return state
    with _cpa_auto_delete_401_lock:
        existing = _cpa_auto_delete_401_state.get(target_id)
    if isinstance(existing, dict):
        state.update(existing)
    return state


def _cpa_auto_delete_401_public_fields(entry=None):
    entry = entry if isinstance(entry, dict) else {}
    return {
        "auto_delete_401_enabled": bool(CPA_AUTO_DELETE_401_ENABLED),
        "auto_delete_401_threshold": max(1, int(CPA_AUTO_DELETE_401_THRESHOLD or 1)),
        "auto_delete_401_running": bool(entry.get("inflight")),
        "auto_delete_401_last_invalid": max(0, _int_value(entry.get("last_invalid"), 0)),
        "auto_delete_401_last_deleted": max(0, _int_value(entry.get("last_deleted"), 0)),
        "auto_delete_401_last_failed": max(0, _int_value(entry.get("last_failed"), 0)),
        "auto_delete_401_last_run_at": str(entry.get("last_run_at") or ""),
        "auto_delete_401_last_status": str(entry.get("last_status") or "idle"),
        "auto_delete_401_last_message": str(entry.get("last_message") or "")[:300],
        "auto_delete_401_last_reason": str(entry.get("last_reason") or ""),
        "auto_delete_401_last_duration_seconds": round(max(0.0, _float_value(entry.get("last_duration_seconds"), 0.0)), 1),
    }


def _normalize_cpa_target(entry):
    if not isinstance(entry, dict):
        return None

    raw_upload = str(entry.get("upload_api_url") or entry.get("upload_url") or "").strip()
    raw_base = str(entry.get("base_url") or entry.get("url") or "").strip()
    token = str(entry.get("upload_api_token") or entry.get("token") or entry.get("cpa_password") or "").strip()

    source = raw_upload or raw_base
    if not source:
        return None
    if "://" not in source:
        source = f"http://{source}"

    parsed = urlparse(source)
    if not parsed.scheme or not parsed.netloc:
        return None

    base_url = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    if raw_upload:
        upload_api_url = source.rstrip("/")
    elif parsed.path and parsed.path not in ("", "/"):
        upload_api_url = source.rstrip("/")
    else:
        upload_api_url = f"{base_url}/v0/management/auth-files"

    label = str(entry.get("label") or entry.get("name") or base_url).strip() or base_url
    target_id = str(entry.get("id") or "").strip()
    if not target_id:
        digest = hashlib.sha1(f"{upload_api_url}|{token}".encode("utf-8", errors="ignore")).hexdigest()
        target_id = digest[:12]

    push_limit = _normalize_cpa_push_limit(
        entry.get("push_limit") if isinstance(entry, dict) else 0
    )
    if not push_limit:
        push_limit = _normalize_cpa_push_limit(
            (entry or {}).get("limit") if isinstance(entry, dict) else 0
        )

    quota_config = _cpa_target_quota_config(entry)

    return {
        "id": target_id,
        "label": label,
        "base_url": base_url,
        "upload_api_url": upload_api_url,
        "upload_api_token": token,
        "push_limit": push_limit,
        **quota_config,
    }


def _default_cpa_target():
    if not UPLOAD_API_URL:
        return None
    return _normalize_cpa_target({
        "id": "default",
        "label": CPA_BASE_URL or UPLOAD_API_URL,
        "base_url": CPA_BASE_URL,
        "upload_api_url": UPLOAD_API_URL,
        "upload_api_token": UPLOAD_API_TOKEN,
    })


def load_cpa_targets():
    data = None
    with _file_lock:
        if os.path.exists(CPA_TARGETS_FILE):
            try:
                with open(CPA_TARGETS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = []
    if data is None:
        default_target = _default_cpa_target()
        return [default_target] if default_target else []

    targets = []
    if isinstance(data, list):
        for item in data:
            target = _normalize_cpa_target(item)
            if target:
                targets.append(target)
    return targets


def save_cpa_targets(targets):
    normalized = []
    seen = set()
    for item in list(targets or []):
        target = _normalize_cpa_target(item)
        if not target:
            continue
        if target["id"] in seen:
            continue
        seen.add(target["id"])
        normalized.append(target)
    with _file_lock:
        with open(CPA_TARGETS_FILE, "w", encoding="utf-8") as f:
            json.dump(normalized, f, ensure_ascii=False, indent=2)
    clear_cpa_quota_cache()
    _reset_cpa_auto_topup_runtime(reset_last_run=True)
    return normalized


def _find_cpa_target_by_id(target_id, targets=None):
    target_id = str(target_id or "").strip()
    if not target_id:
        return None
    for item in list(targets or load_cpa_targets()):
        if str((item or {}).get("id") or "").strip() == target_id:
            return item
    return None


def _load_cpa_push_stats_unlocked():
    if not os.path.exists(CPA_PUSH_STATS_FILE):
        return {}
    try:
        with open(CPA_PUSH_STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def get_cpa_push_stats():
    with _file_lock:
        return _load_cpa_push_stats_unlocked()


def _cpa_target_push_count(target, stats=None):
    if stats is None:
        stats = get_cpa_push_stats()
    target_id = str((target or {}).get("id") or "").strip()
    if not target_id or not isinstance(stats, dict):
        return 0
    stat = stats.get(target_id, {})
    if not isinstance(stat, dict):
        return 0
    return int(stat.get("count") or 0)


def _cpa_target_remaining_capacity(target, stats=None):
    push_limit = _normalize_cpa_push_limit((target or {}).get("push_limit") or 0)
    if push_limit <= 0:
        return None
    used = _cpa_target_push_count(target, stats=stats)
    used -= _count_used_auth_file_marks_for_target((target or {}).get("id"))
    return max(0, push_limit - used)


def _cpa_target_is_full(target, stats=None):
    remaining = _cpa_target_remaining_capacity(target, stats=stats)
    return remaining is not None and remaining <= 0


def _load_cpa_push_records_unlocked():
    if not os.path.exists(CPA_PUSH_RECORDS_FILE):
        return {}
    try:
        with open(CPA_PUSH_RECORDS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def get_cpa_push_records():
    with _file_lock:
        return _load_cpa_push_records_unlocked()


def _token_push_record_key(filename):
    return os.path.basename(str(filename or "").strip())


def _token_file_fingerprint(filename):
    try:
        stat = os.stat(filename)
        return f"{int(stat.st_size)}:{int(getattr(stat, 'st_mtime_ns', int(stat.st_mtime * 1_000_000_000)))}"
    except Exception:
        return ""


def _mark_token_push_success(filename, target):
    key = _token_push_record_key(filename)
    if not key:
        return
    fingerprint = _token_file_fingerprint(filename)
    record = {
        "filename": key,
        "email": key[:-5] if key.endswith('.json') else key,
        "fingerprint": fingerprint,
        "target_id": str((target or {}).get("id") or ""),
        "target_label": str((target or {}).get("label") or (target or {}).get("base_url") or ""),
        "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "success",
    }
    with _file_lock:
        data = _load_cpa_push_records_unlocked()
        data[key] = record
        with open(CPA_PUSH_RECORDS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


def _token_json_candidate_paths():
    if not os.path.isdir(OUTPUT_DIR):
        return []
    paths = []
    for fn in sorted(os.listdir(OUTPUT_DIR)):
        if not fn.endswith('.json'):
            continue
        if '@' not in fn:
            continue
        full_path = os.path.join(OUTPUT_DIR, fn)
        if os.path.isfile(full_path):
            paths.append(full_path)
    return paths


def is_token_json_pending_push(filename, records=None):
    key = _token_push_record_key(filename)
    if not key or not os.path.isfile(filename):
        return False
    if records is None:
        records = get_cpa_push_records()
    record = records.get(key, {}) if isinstance(records, dict) else {}
    current_fingerprint = _token_file_fingerprint(filename)
    if not current_fingerprint:
        return False
    return str(record.get("fingerprint") or "") != current_fingerprint or str(record.get("status") or "") != "success"


def list_pending_token_pushes(limit=100):
    records = get_cpa_push_records()
    items = []
    total = 0
    for filename in _token_json_candidate_paths():
        if not is_token_json_pending_push(filename, records=records):
            continue
        total += 1
        if limit and len(items) >= limit:
            continue
        try:
            stat = os.stat(filename)
            modified_at = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            size = int(stat.st_size)
        except Exception:
            modified_at = ""
            size = 0
        key = _token_push_record_key(filename)
        items.append({
            "filename": key,
            "email": key[:-5] if key.endswith('.json') else key,
            "modified_at": modified_at,
            "size": size,
        })
    return {"count": total, "items": items}


def list_saved_auth_files(limit=0):
    """列出本地已保存的成功凭证文件（OAuth 目录下的邮箱 JSON）。"""
    try:
        limit = max(0, int(limit or 0))
    except Exception:
        limit = 0

    marks = load_auth_file_marks()
    entries = []
    for filename in _token_json_candidate_paths():
        try:
            stat = os.stat(filename)
            modified_ts = float(stat.st_mtime)
            modified_at = datetime.fromtimestamp(modified_ts).strftime("%Y-%m-%d %H:%M:%S")
            size = int(stat.st_size)
        except Exception:
            modified_ts = 0.0
            modified_at = ""
            size = 0
        key = _token_push_record_key(filename)
        entries.append({
            "filename": key,
            "email": key[:-5] if key.endswith('.json') else key,
            "modified_at": modified_at,
            "modified_ts": modified_ts,
            "size": size,
            "used": bool((marks.get(key) or {}).get("used")),
            "used_at": str((marks.get(key) or {}).get("used_at") or ""),
        })

    entries.sort(key=lambda item: (float(item.get("modified_ts") or 0.0), str(item.get("filename") or "")), reverse=True)
    if limit > 0:
        entries = entries[:limit]
    for item in entries:
        item.pop("modified_ts", None)
    return {"count": len(entries), "items": entries}


def _format_saved_auth_file_content(content_json):
    if not isinstance(content_json, dict):
        return content_json

    access_token = str(content_json.get("access_token") or "")
    refresh_token = str(content_json.get("refresh_token") or "")
    id_token = str(content_json.get("id_token") or "")
    account_id = str(content_json.get("account_id") or "")
    last_refresh = str(content_json.get("last_refresh") or "")

    if not any([access_token, refresh_token, id_token, account_id, last_refresh]):
        return content_json

    return {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": id_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "account_id": account_id,
        },
        "last_refresh": last_refresh,
    }


def _load_auth_file_marks_unlocked():
    if not os.path.exists(AUTH_FILE_MARKS_FILE):
        return {}
    try:
        with open(AUTH_FILE_MARKS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}

    result = {}
    for key, value in data.items():
        filename = os.path.basename(str(key or "").strip())
        if not filename or filename in (".", "..") or "@" not in filename or not filename.endswith(".json"):
            continue
        item = value if isinstance(value, dict) else {}
        result[filename] = {
            "used": bool(item.get("used")),
            "used_at": str(item.get("used_at") or "").strip(),
        }
    return result


def load_auth_file_marks():
    with _file_lock:
        return _load_auth_file_marks_unlocked()


def set_auth_file_used_status(filename, used):
    key = os.path.basename(str(filename or "").strip())
    if not key or key in (".", "..") or "/" in key or "\\" in key or "@" not in key or not key.endswith(".json"):
        return None
    full_path = os.path.join(OUTPUT_DIR, key)
    if not os.path.isfile(full_path):
        return None

    with _file_lock:
        data = _load_auth_file_marks_unlocked()
        if used:
            data[key] = {
                "used": True,
                "used_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        else:
            data.pop(key, None)
        with open(AUTH_FILE_MARKS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        item = data.get(key, {})
        return {
            "filename": key,
            "used": bool(item.get("used")),
            "used_at": str(item.get("used_at") or ""),
        }


def _summarize_used_auth_file_marks(targets=None, marks=None, records=None):
    target_ids = None
    if isinstance(targets, (list, tuple, set)):
        target_ids = {
            str((item or {}).get("id") or "").strip()
            for item in list(targets or [])
            if str((item or {}).get("id") or "").strip()
        }

    if marks is None:
        marks = load_auth_file_marks()
    if records is None:
        records = get_cpa_push_records()

    by_target = {}
    unassigned = 0
    total = 0

    for filename, item in (marks or {}).items():
        if not bool((item or {}).get("used")):
            continue
        key = os.path.basename(str(filename or "").strip())
        if not key or "@" not in key or not key.endswith(".json"):
            continue
        full_path = os.path.join(OUTPUT_DIR, key)
        if not os.path.isfile(full_path):
            continue
        total += 1
        record = (records or {}).get(key) if isinstance(records, dict) else {}
        target_id = str((record or {}).get("target_id") or "").strip()
        if target_id and (target_ids is None or target_id in target_ids):
            by_target[target_id] = int(by_target.get(target_id) or 0) + 1
        else:
            unassigned += 1

    return {
        "total": total,
        "by_target": by_target,
        "unassigned": unassigned,
    }


def _count_used_auth_file_marks_for_target(target_id):
    target_id = str(target_id or "").strip()
    if not target_id:
        return 0
    summary = _summarize_used_auth_file_marks(targets=[{"id": target_id}])
    return max(0, int((summary or {}).get("by_target", {}).get(target_id) or 0))


def _apply_used_auth_file_marks_to_quota_items(items, targets=None):
    items = [dict(item) for item in list(items or []) if isinstance(item, dict)]
    if not items:
        return items

    target_list = list(targets or load_cpa_targets() or [])
    target_map = {
        str((target or {}).get("id") or "").strip(): (target if isinstance(target, dict) else {})
        for target in target_list
        if str((target or {}).get("id") or "").strip()
    }
    mark_summary = _summarize_used_auth_file_marks(targets=target_list)
    assigned_by_target = dict((mark_summary or {}).get("by_target") or {})
    unassigned = max(0, int((mark_summary or {}).get("unassigned") or 0))
    stats = get_cpa_push_stats()

    working = []
    for idx, item in enumerate(items, start=1):
        target_id = str(item.get("id") or "").strip()
        target = target_map.get(target_id, {})
        assigned = max(0, int(assigned_by_target.get(target_id) or 0))
        order = _normalize_cpa_quota_int((target or {}).get("order"), idx)
        working.append({
            "summary": item,
            "target": target,
            "assigned_used": assigned,
            "used_count": assigned,
            "order": order,
        })

    while unassigned > 0:
        candidates = [entry for entry in working if _cpa_target_quota_config(entry.get("target") or {}).get("quota_enabled")]
        if not candidates:
            break
        candidates.sort(
            key=lambda entry: (
                10 ** 9 if (entry["summary"].get("available") in (None, "")) else max(0, _normalize_cpa_quota_int(entry["summary"].get("available"), 0) - int(entry.get("used_count") or 0)),
                -(_normalize_cpa_quota_int(entry["summary"].get("need_topup"), 0) + int(entry.get("used_count") or 0)),
                _normalize_cpa_quota_int(entry.get("order"), 10 ** 6),
                str((entry.get("summary") or {}).get("id") or ""),
            )
        )
        candidates[0]["used_count"] = int(candidates[0].get("used_count") or 0) + 1
        unassigned -= 1

    adjusted = []
    for entry in working:
        item = dict(entry.get("summary") or {})
        target = entry.get("target") or {}
        used_count = max(0, int(entry.get("used_count") or 0))
        assigned_used = max(0, int(entry.get("assigned_used") or 0))
        extra_used = max(0, used_count - assigned_used)
        item["marked_used_count"] = used_count
        if used_count > 0:
            available = item.get("available")
            if available not in (None, ""):
                available = max(0, _normalize_cpa_quota_int(available, 0) - used_count)
                item["available"] = available

                quota = _cpa_target_quota_config(target)
                need_topup = 0
                if quota["quota_enabled"] and available < quota["min_available"]:
                    need_topup = max(0, quota["min_available"] - available)
                remaining_capacity = _cpa_target_remaining_capacity(target, stats=stats)
                if remaining_capacity is not None and extra_used > 0:
                    remaining_capacity = max(0, int(remaining_capacity) + extra_used)
                plan_topup = need_topup
                topup_max_per_round = max(0, _normalize_cpa_quota_int(quota.get("topup_max_per_round"), DEFAULT_CPA_TOPUP_MAX_PER_ROUND))
                if topup_max_per_round > 0:
                    plan_topup = min(plan_topup, topup_max_per_round)
                if remaining_capacity is not None:
                    plan_topup = min(plan_topup, remaining_capacity)
                item["need_topup"] = need_topup
                item["plan_topup"] = max(0, plan_topup)
                item["remaining_capacity"] = remaining_capacity
                item["quota_estimated"] = True
                if str(item.get("quota_state") or "") in ("", "idle"):
                    item["quota_state"] = "estimated"

            if "remaining" in item and item.get("remaining") is not None:
                item["remaining"] = max(0, _normalize_cpa_quota_int(item.get("remaining"), 0) + used_count)
                item["is_full"] = bool(item["remaining"] <= 0)
        adjusted.append(item)

    return adjusted


def read_saved_auth_file(filename):
    """读取单个本地成功凭证文件内容。"""
    key = os.path.basename(str(filename or "").strip())
    if not key or key in (".", "..") or "/" in key or "\\" in key or not key.endswith(".json") or "@" not in key:
        return None

    full_path = os.path.join(OUTPUT_DIR, key)
    if not os.path.isfile(full_path):
        return None

    try:
        stat = os.stat(full_path)
        modified_at = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        size = int(stat.st_size)
    except Exception:
        modified_at = ""
        size = 0

    try:
        with open(full_path, "r", encoding="utf-8") as f:
            content_text = f.read()
    except Exception:
        return None

    content_json = None
    try:
        content_json = json.loads(content_text)
    except Exception:
        content_json = None

    display_content = _format_saved_auth_file_content(content_json) if content_json is not None else content_text
    mark_record = (load_auth_file_marks() or {}).get(key) or {}

    return {
        "filename": key,
        "email": key[:-5],
        "modified_at": modified_at,
        "size": size,
        "used": bool(mark_record.get("used")),
        "used_at": str(mark_record.get("used_at") or ""),
        "content": display_content,
        "is_json": content_json is not None,
    }


def _remove_saved_auth_file_metadata_unlocked(filename):
    key = os.path.basename(str(filename or "").strip())
    if not key:
        return {"mark_removed": False, "push_record_removed": False}

    mark_removed = False
    push_record_removed = False

    marks = _load_auth_file_marks_unlocked()
    if key in marks:
        marks.pop(key, None)
        with open(AUTH_FILE_MARKS_FILE, "w", encoding="utf-8") as f:
            json.dump(marks, f, ensure_ascii=False, indent=2)
        mark_removed = True

    records = _load_cpa_push_records_unlocked()
    if key in records:
        records.pop(key, None)
        with open(CPA_PUSH_RECORDS_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        push_record_removed = True

    return {
        "mark_removed": mark_removed,
        "push_record_removed": push_record_removed,
    }


def delete_saved_auth_file(filename):
    """删除本地成功凭证文件，并清理对应的本地标记/推送记录。"""
    key = os.path.basename(str(filename or "").strip())
    if not key or key in (".", "..") or "/" in key or "\\" in key or "@" not in key or not key.endswith(".json"):
        return {
            "filename": key,
            "deleted": False,
            "file_existed": False,
            "mark_removed": False,
            "push_record_removed": False,
            "error": "invalid filename",
        }

    full_path = os.path.join(OUTPUT_DIR, key)
    deleted = False
    file_existed = False
    error = ""
    metadata = {"mark_removed": False, "push_record_removed": False}

    with _file_lock:
        file_existed = os.path.exists(full_path)
        if file_existed:
            try:
                os.remove(full_path)
                deleted = True
            except Exception as e:
                error = str(e)
        if deleted or not file_existed:
            metadata = _remove_saved_auth_file_metadata_unlocked(key)

    return {
        "filename": key,
        "deleted": deleted,
        "file_existed": file_existed,
        "mark_removed": bool(metadata.get("mark_removed")),
        "push_record_removed": bool(metadata.get("push_record_removed")),
        "error": error[:300],
    }


def _probe_saved_auth_file_401(filename, timeout=None, user_agent=None):
    key = os.path.basename(str(filename or "").strip())
    result = {
        "filename": key,
        "email": key[:-5] if key.endswith(".json") else key,
        "status_code": None,
        "usage_state": "unknown",
        "detail": "",
        "invalid_401": False,
        "error": None,
    }

    full_path = os.path.join(OUTPUT_DIR, key)
    if not key or not os.path.isfile(full_path):
        result["error"] = "file not found"
        return result

    try:
        with open(full_path, "r", encoding="utf-8") as f:
            token_data = json.load(f)
    except Exception as e:
        result["error"] = f"load json failed: {e}"
        return result

    if not isinstance(token_data, dict):
        result["error"] = "invalid json payload"
        return result

    email = str(token_data.get("email") or result.get("email") or "").strip().lower()
    access_token = str(token_data.get("access_token") or "").strip()
    account_id = str(token_data.get("account_id") or "").strip()
    if not access_token:
        result["email"] = email or result["email"]
        result["error"] = "missing access_token"
        return result

    timeout = max(3, int(timeout or SAVED_AUTH_401_CHECK_TIMEOUT or 15))
    request_user_agent = str(user_agent or CPA_USER_AGENT or USER_AGENT or "").strip() or USER_AGENT
    default_proxy = token_data.get("proxy")
    proxy_url = load_account_proxy(email, default=default_proxy)
    relay_state = load_account_relay(email)

    session = None
    try:
        session = create_session(proxy_url=proxy_url, relay_state=relay_state)
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": request_user_agent,
        }
        if account_id:
            headers["Chatgpt-Account-Id"] = account_id

        resp = session.get(
            "https://chatgpt.com/backend-api/wham/usage",
            headers=headers,
            verify=False,
            timeout=timeout,
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text[:500]
        parsed = _cpa_parse_usage_probe_response({
            "status_code": resp.status_code,
            "body": body,
        })
        result.update({
            "email": email or result["email"],
            "status_code": parsed.get("status_code"),
            "usage_state": parsed.get("usage_state") or "unknown",
            "detail": str(parsed.get("detail") or "")[:300],
            "invalid_401": parsed.get("status_code") == 401,
            "error": None,
        })
    except Exception as e:
        result.update({
            "email": email or result["email"],
            "error": str(e)[:300],
        })
    finally:
        _close_session(session)

    return result


def cleanup_saved_auth_files_invalid_401(limit=0, workers=None, timeout=None, user_agent=None):
    """检测本地成功凭证，遇到 401 则删除本地 JSON 与关联标记。"""
    try:
        limit = max(0, int(limit or 0))
    except Exception:
        limit = 0
    workers = max(1, int(workers or SAVED_AUTH_401_CHECK_WORKERS or 1))
    timeout = max(3, int(timeout or SAVED_AUTH_401_CHECK_TIMEOUT or 15))
    request_user_agent = str(user_agent or CPA_USER_AGENT or USER_AGENT or "").strip() or USER_AGENT

    if not _saved_auth_401_cleanup_lock.acquire(blocking=False):
        return {
            "ok": False,
            "busy": True,
            "message": "401 检测清理正在进行中",
            "scanned": 0,
            "invalid_401": 0,
            "deleted": 0,
            "delete_failed": 0,
            "error_count": 0,
            "kept": 0,
            "items": [],
        }

    try:
        paths = _token_json_candidate_paths()
        if limit > 0:
            paths = paths[:limit]
        if not paths:
            return {
                "ok": True,
                "busy": False,
                "message": "暂无成功凭证",
                "scanned": 0,
                "invalid_401": 0,
                "deleted": 0,
                "delete_failed": 0,
                "error_count": 0,
                "kept": 0,
                "items": [],
            }

        probe_results = []
        pool_size = min(max(1, workers), max(1, len(paths)))
        with ThreadPoolExecutor(max_workers=pool_size) as executor:
            futures = [
                executor.submit(
                    _probe_saved_auth_file_401,
                    path,
                    timeout,
                    request_user_agent,
                )
                for path in paths
            ]
            for future in futures:
                try:
                    probe_results.append(future.result())
                except Exception as e:
                    probe_results.append({
                        "filename": "",
                        "email": "",
                        "status_code": None,
                        "usage_state": "unknown",
                        "detail": "",
                        "invalid_401": False,
                        "error": str(e)[:300],
                    })

        deleted_count = 0
        delete_failed = 0
        error_count = 0
        invalid_count = 0

        for row in probe_results:
            if row.get("error"):
                error_count += 1
            if not bool(row.get("invalid_401")):
                continue

            invalid_count += 1
            deleted = delete_saved_auth_file(row.get("filename"))
            row.update({
                "deleted": bool(deleted.get("deleted")),
                "mark_removed": bool(deleted.get("mark_removed")),
                "push_record_removed": bool(deleted.get("push_record_removed")),
                "delete_error": str(deleted.get("error") or "")[:300],
            })
            if row.get("deleted"):
                deleted_count += 1
            else:
                delete_failed += 1

        kept = max(0, len(paths) - deleted_count)
        message = f"扫描 {len(paths)} 个，本地401 {invalid_count} 个，已删 {deleted_count} 个"
        if delete_failed > 0:
            message += f"，删除失败 {delete_failed} 个"
        if error_count > 0:
            message += f"，检测异常 {error_count} 个"

        probe_results.sort(key=lambda item: (str(item.get("filename") or ""), str(item.get("email") or "")))
        return {
            "ok": True,
            "busy": False,
            "message": message,
            "scanned": len(paths),
            "invalid_401": invalid_count,
            "deleted": deleted_count,
            "delete_failed": delete_failed,
            "error_count": error_count,
            "kept": kept,
            "items": probe_results,
        }
    finally:
        _saved_auth_401_cleanup_lock.release()


def _list_pending_token_json_files():
    records = get_cpa_push_records()
    return [
        filename
        for filename in _token_json_candidate_paths()
        if is_token_json_pending_push(filename, records=records)
    ]


def _increment_cpa_push_count(target):
    target_id = str((target or {}).get("id") or "").strip()
    if not target_id:
        return
    with _file_lock:
        data = _load_cpa_push_stats_unlocked()
        item = data.get(target_id, {})
        if not isinstance(item, dict):
            item = {}
        item["label"] = str((target or {}).get("label") or item.get("label") or "")
        item["upload_api_url"] = str((target or {}).get("upload_api_url") or item.get("upload_api_url") or "")
        item["count"] = int(item.get("count") or 0) + 1
        item["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data[target_id] = item
        with open(CPA_PUSH_STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


def _plan_cpa_topup_for_available_count(target, available_count, stats=None):
    quota = _cpa_target_quota_config(target)
    available_count = max(0, _normalize_cpa_quota_int(available_count, 0))
    need_topup = 0
    if quota["quota_enabled"] and available_count < quota["min_available"]:
        need_topup = max(0, quota["min_available"] - available_count)
    remaining_capacity = _cpa_target_remaining_capacity(target, stats=stats)
    plan_topup = need_topup
    topup_max_per_round = max(0, _normalize_cpa_quota_int(quota.get("topup_max_per_round"), DEFAULT_CPA_TOPUP_MAX_PER_ROUND))
    if topup_max_per_round > 0:
        plan_topup = min(plan_topup, topup_max_per_round)
    if remaining_capacity is not None:
        plan_topup = min(plan_topup, remaining_capacity)
    return {
        **quota,
        "need_topup": need_topup,
        "plan_topup": max(0, plan_topup),
        "remaining_capacity": remaining_capacity,
    }


def clear_cpa_quota_cache(target_ids=None):
    with _cpa_quota_cache_lock:
        if target_ids is None:
            _cpa_quota_cache.clear()
            return
        if isinstance(target_ids, (str, bytes)):
            target_ids = [target_ids]
        for target_id in list(target_ids or []):
            _cpa_quota_cache.pop(str(target_id or "").strip(), None)


def _store_cpa_quota_cache(summary):
    target_id = str((summary or {}).get("id") or "").strip()
    if not target_id:
        return
    with _cpa_quota_cache_lock:
        _cpa_quota_cache[target_id] = {
            "ts": time.time(),
            "data": dict(summary or {}),
        }


def _get_cpa_quota_cache_snapshot():
    now_ts = time.time()
    snapshot = {}
    with _cpa_quota_cache_lock:
        for target_id, entry in _cpa_quota_cache.items():
            if not isinstance(entry, dict):
                continue
            data = entry.get("data")
            if not isinstance(data, dict):
                continue
            item = dict(data)
            item["quota_cache_age_seconds"] = round(max(0.0, now_ts - float(entry.get("ts") or 0.0)), 1)
            snapshot[target_id] = item
    return snapshot


def _cpa_public_quota_fields(entry=None):
    if not isinstance(entry, dict):
        return {
            "total_accounts": None,
            "available": None,
            "exhausted": None,
            "invalid": None,
            "unknown": None,
            "recover_lt_6h": None,
            "recover_lt_24h": None,
            "need_topup": None,
            "plan_topup": None,
            "quota_updated_at": "",
            "quota_cache_age_seconds": None,
            "quota_state": "idle",
            "quota_error": "",
            "quota_estimated": False,
            "marked_used_count": 0,
            "sample_errors": [],
            **_cpa_auto_delete_401_public_fields(),
        }
    auto_delete_state = {
        "inflight": entry.get("auto_delete_401_running"),
        "last_invalid": entry.get("auto_delete_401_last_invalid"),
        "last_deleted": entry.get("auto_delete_401_last_deleted"),
        "last_failed": entry.get("auto_delete_401_last_failed"),
        "last_run_at": entry.get("auto_delete_401_last_run_at"),
        "last_status": entry.get("auto_delete_401_last_status"),
        "last_message": entry.get("auto_delete_401_last_message"),
        "last_reason": entry.get("auto_delete_401_last_reason"),
        "last_duration_seconds": entry.get("auto_delete_401_last_duration_seconds"),
    }
    return {
        "total_accounts": entry.get("total_accounts"),
        "available": entry.get("available"),
        "exhausted": entry.get("exhausted"),
        "invalid": entry.get("invalid"),
        "unknown": entry.get("unknown"),
        "recover_lt_6h": entry.get("recover_lt_6h"),
        "recover_lt_24h": entry.get("recover_lt_24h"),
        "need_topup": entry.get("need_topup"),
        "plan_topup": entry.get("plan_topup"),
        "quota_updated_at": str(entry.get("quota_updated_at") or ""),
        "quota_cache_age_seconds": entry.get("quota_cache_age_seconds"),
        "quota_state": str(entry.get("quota_state") or "idle"),
        "quota_error": str(entry.get("quota_error") or ""),
        "quota_estimated": bool(entry.get("quota_estimated")),
        "marked_used_count": _normalize_cpa_quota_int(entry.get("marked_used_count"), 0),
        "sample_errors": list(entry.get("sample_errors") or []),
        **_cpa_auto_delete_401_public_fields(auto_delete_state),
    }


def _bump_cpa_quota_cache_after_push(target, success_count):
    success_count = max(0, int(success_count or 0))
    if success_count <= 0:
        return
    target_id = str((target or {}).get("id") or "").strip()
    if not target_id:
        return
    with _cpa_quota_cache_lock:
        entry = _cpa_quota_cache.get(target_id)
        cached = dict((entry or {}).get("data") or {}) if isinstance(entry, dict) else None
    if not cached:
        return
    available_before = _normalize_cpa_quota_int(cached.get("available"), 0)
    total_before = _normalize_cpa_quota_int(cached.get("total_accounts"), 0)
    stats = get_cpa_push_stats()
    plan = _plan_cpa_topup_for_available_count(target, available_before + success_count, stats=stats)
    cached.update(plan)
    cached["total_accounts"] = total_before + success_count
    cached["available"] = available_before + success_count
    cached["quota_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cached["quota_estimated"] = True
    if str(cached.get("quota_state") or "") in ("", "error"):
        cached["quota_state"] = "estimated"
        cached["quota_error"] = ""
    _store_cpa_quota_cache(cached)


def _reset_cpa_auto_topup_runtime(reset_last_run=True):
    global _cpa_auto_topup_last_run_ts, _cpa_auto_topup_last_reason, _cpa_auto_topup_success_since_refresh
    global _cpa_auto_topup_inflight, _cpa_auto_topup_last_result
    with _cpa_auto_topup_lock:
        _cpa_auto_topup_plan.clear()
        _cpa_auto_topup_success_since_refresh = 0
        _cpa_auto_topup_inflight = False
        _cpa_auto_topup_last_reason = ""
        _cpa_auto_topup_last_result = {}
        if reset_last_run:
            _cpa_auto_topup_last_run_ts = 0.0


def _cpa_topup_priority_key(item):
    item = item if isinstance(item, dict) else {}
    available = item.get("available")
    available_sort = 10 ** 9 if available in (None, "") else _normalize_cpa_quota_int(available, 10 ** 9)
    need_topup = _normalize_cpa_quota_int(item.get("need_topup"), 0)
    planned = _normalize_cpa_quota_int(item.get("count") if item.get("count") is not None else item.get("plan_topup"), 0)
    order = _normalize_cpa_quota_int(item.get("order"), 10 ** 6)
    ident = str(item.get("target_id") or item.get("id") or "")
    return (available_sort, -need_topup, -planned, order, ident)


def _build_priority_cpa_target_plan(plan_counts):
    queue_ids = []
    states = []
    for item in list(plan_counts or []):
        target_id = str((item or {}).get("target_id") or "").strip()
        count = max(0, int((item or {}).get("count") or 0))
        if not target_id or count <= 0:
            continue
        available = (item or {}).get("available")
        available_sort = 10 ** 9 if available in (None, "") else _normalize_cpa_quota_int(available, 10 ** 9)
        states.append({
            "target_id": target_id,
            "remaining": count,
            "available_sort": available_sort,
            "need_topup": _normalize_cpa_quota_int((item or {}).get("need_topup"), 0),
            "order": _normalize_cpa_quota_int((item or {}).get("order"), 10 ** 6),
        })

    while True:
        candidates = [item for item in states if int(item.get("remaining") or 0) > 0]
        if not candidates:
            break
        candidates.sort(
            key=lambda item: (
                _normalize_cpa_quota_int(item.get("available_sort"), 10 ** 9),
                -_normalize_cpa_quota_int(item.get("need_topup"), 0),
                _normalize_cpa_quota_int(item.get("order"), 10 ** 6),
                str(item.get("target_id") or ""),
            )
        )
        chosen = candidates[0]
        queue_ids.append(str(chosen.get("target_id") or ""))
        chosen["remaining"] = max(0, int(chosen.get("remaining") or 0) - 1)
        if _normalize_cpa_quota_int(chosen.get("available_sort"), 10 ** 9) < 10 ** 9:
            chosen["available_sort"] = _normalize_cpa_quota_int(chosen.get("available_sort"), 10 ** 9) + 1
    return queue_ids


def _pick_cpa_target_by_lowest_available(available_targets):
    quota_cache = _get_cpa_quota_cache_snapshot()
    candidates = []
    for order, target in enumerate(list(available_targets or []), start=1):
        target_id = str((target or {}).get("id") or "").strip()
        if not target_id:
            continue
        summary = quota_cache.get(target_id)
        if not isinstance(summary, dict):
            continue
        if str(summary.get("quota_state") or "") == "error":
            continue
        available = summary.get("available")
        if available in (None, ""):
            continue
        quota_cfg = _cpa_target_quota_config(target)
        if not quota_cfg.get("quota_enabled"):
            continue
        plan_topup = _normalize_cpa_quota_int(summary.get("plan_topup"), 0)
        if plan_topup <= 0:
            continue
        candidates.append({
            "target": target,
            "target_id": target_id,
            "available": _normalize_cpa_quota_int(available, 10 ** 9),
            "need_topup": _normalize_cpa_quota_int(summary.get("need_topup"), 0),
            "plan_topup": plan_topup,
            "order": _normalize_cpa_quota_int((target or {}).get("order"), order),
        })
    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (
            _normalize_cpa_quota_int(item.get("available"), 10 ** 9),
            -_normalize_cpa_quota_int(item.get("plan_topup"), 0),
            -_normalize_cpa_quota_int(item.get("need_topup"), 0),
            _normalize_cpa_quota_int(item.get("order"), 10 ** 6),
            str(item.get("target_id") or ""),
        )
    )
    return candidates[0].get("target")


def _run_cpa_auto_topup_refresh(reason="auto"):
    global _cpa_auto_topup_last_run_ts, _cpa_auto_topup_last_reason, _cpa_auto_topup_success_since_refresh
    global _cpa_auto_topup_inflight, _cpa_auto_topup_last_result, _cpa_auto_topup_plan

    started_at = time.time()
    try:
        quota_result = probe_all_cpa_usage(force=CPA_AUTO_TOPUP_FORCE_PROBE, use_cache=True)
        quota_map = {
            str((item or {}).get("id") or "").strip(): item
            for item in quota_result.get("items", [])
            if isinstance(item, dict)
        }
        targets = load_cpa_targets()
        plan_counts = []
        for order, target in enumerate(targets, start=1):
            target_id = str((target or {}).get("id") or "").strip()
            summary = quota_map.get(target_id, {})
            if str(summary.get("quota_state") or "") == "error":
                continue
            if not _cpa_target_quota_config(target).get("quota_enabled"):
                continue
            planned = max(0, int(summary.get("plan_topup") or 0))
            if planned <= 0:
                continue
            plan_counts.append({
                "target_id": target_id,
                "count": planned,
                "label": str((target or {}).get("label") or (target or {}).get("base_url") or ""),
                "available": summary.get("available"),
                "need_topup": summary.get("need_topup"),
                "order": order,
            })
        queue_ids = _build_priority_cpa_target_plan(plan_counts)
        with _cpa_auto_topup_lock:
            _cpa_auto_topup_plan = deque(queue_ids)
            _cpa_auto_topup_last_run_ts = time.time()
            _cpa_auto_topup_last_reason = str(reason or "auto")
            _cpa_auto_topup_success_since_refresh = 0
            _cpa_auto_topup_inflight = False
            _cpa_auto_topup_last_result = {
                "ok": True,
                "reason": str(reason or "auto"),
                "planned_uploads": len(queue_ids),
                "target_count": len(plan_counts),
                "planned_targets": plan_counts,
                "duration_seconds": round(max(0.0, time.time() - started_at), 1),
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        if queue_ids:
            print(f"  ℹ️ CPA 自动校正已刷新: 目标 {len(plan_counts)} 个 / 预留上传 {len(queue_ids)} 个 / 原因={reason}")
        else:
            print(f"  ℹ️ CPA 自动校正已刷新: 当前无缺口 / 原因={reason}")
    except Exception as e:
        with _cpa_auto_topup_lock:
            _cpa_auto_topup_last_run_ts = time.time()
            _cpa_auto_topup_last_reason = str(reason or "auto")
            _cpa_auto_topup_success_since_refresh = 0
            _cpa_auto_topup_inflight = False
            _cpa_auto_topup_last_result = {
                "ok": False,
                "reason": str(reason or "auto"),
                "error": str(e),
                "duration_seconds": round(max(0.0, time.time() - started_at), 1),
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        print(f"  ⚠️ CPA 自动校正刷新失败: {e}")


def maybe_schedule_cpa_auto_topup_refresh(reason="upload_success", success_count=0, immediate=False):
    global _cpa_auto_topup_success_since_refresh, _cpa_auto_topup_inflight
    if not CPA_AUTO_TOPUP_ENABLED:
        return False
    targets = load_cpa_targets()
    if len(targets) <= 1:
        return False

    now_ts = time.time()
    with _cpa_auto_topup_lock:
        if success_count:
            _cpa_auto_topup_success_since_refresh += max(0, int(success_count or 0))
        need_by_count = _cpa_auto_topup_success_since_refresh >= max(1, int(CPA_AUTO_TOPUP_SUCCESS_INTERVAL or 1))
        need_by_time = (_cpa_auto_topup_last_run_ts <= 0) or ((now_ts - _cpa_auto_topup_last_run_ts) >= float(CPA_AUTO_TOPUP_MIN_INTERVAL_SECONDS or 0.0))
        if (not immediate) and (not need_by_count) and (not need_by_time):
            return False
        if _cpa_auto_topup_inflight:
            return False
        _cpa_auto_topup_inflight = True

    thread = threading.Thread(
        target=_run_cpa_auto_topup_refresh,
        args=(str(reason or "upload_success"),),
        daemon=True,
    )
    thread.start()
    return True


def _pick_cpa_target_from_auto_topup_plan(available_targets):
    if not CPA_AUTO_TOPUP_ENABLED:
        return None
    available_map = {
        str((target or {}).get("id") or "").strip(): target
        for target in list(available_targets or [])
        if str((target or {}).get("id") or "").strip()
    }
    with _cpa_auto_topup_lock:
        while _cpa_auto_topup_plan:
            target_id = str(_cpa_auto_topup_plan.popleft() or "").strip()
            target = available_map.get(target_id)
            if target is not None:
                return target
    return None


def list_cpa_targets_with_stats(include_quota=True):
    targets = load_cpa_targets()
    stats = get_cpa_push_stats()
    quota_cache = _get_cpa_quota_cache_snapshot() if include_quota else {}
    result = []
    for idx, target in enumerate(targets, start=1):
        target = target if isinstance(target, dict) else {}
        target_id = str(target.get("id") or "").strip()
        stat = stats.get(target_id, {}) if isinstance(stats, dict) else {}
        count = int(stat.get("count") or 0)
        push_limit = _normalize_cpa_push_limit(target.get("push_limit") or 0)
        remaining = None if push_limit <= 0 else max(0, push_limit - count)
        quota_config = _cpa_target_quota_config(target)
        item = {
            "id": target_id,
            "label": str(target.get("label") or target.get("base_url") or "").strip(),
            "base_url": str(target.get("base_url") or "").strip(),
            "upload_api_url": str(target.get("upload_api_url") or "").strip(),
            "push_limit": push_limit,
            "quota_enabled": quota_config["quota_enabled"],
            "min_available": quota_config["min_available"],
            "topup_max_per_round": quota_config["topup_max_per_round"],
            "order": idx,
            "count": count,
            "remaining": remaining,
            "is_full": bool(push_limit > 0 and count >= push_limit),
            "updated_at": stat.get("updated_at", ""),
        }
        if include_quota:
            item.update(_cpa_public_quota_fields(quota_cache.get(target_id)))
        result.append(item)
    if include_quota and result:
        result = _apply_used_auth_file_marks_to_quota_items(result, targets=targets)
    return result


def has_cpa_upload_target():
    return bool(load_cpa_targets())


def _pick_cpa_target_for_upload():
    global _cpa_round_robin_index
    targets = load_cpa_targets()
    if not targets:
        return None
    stats = get_cpa_push_stats()
    available = [target for target in targets if not _cpa_target_is_full(target, stats=stats)]
    if not available:
        return None

    preferred_target = _pick_cpa_target_from_auto_topup_plan(available)
    if preferred_target is not None:
        return preferred_target

    lowest_available_target = _pick_cpa_target_by_lowest_available(available)
    if lowest_available_target is not None:
        return lowest_available_target

    with _cpa_round_robin_lock:
        index = _cpa_round_robin_index % len(available)
        target = available[index]
        _cpa_round_robin_index = (_cpa_round_robin_index + 1) % max(1, len(available))
        return target


# OpenAI 认证域名
OPENAI_AUTH_BASE = "https://auth.openai.com"

# ChatGPT 域名（用于 OAuth 登录获取 Token）
CHATGPT_BASE = "https://chatgpt.com"
MODE5_CHATGPT_CLIENT_ID = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
MODE5_CHATGPT_REDIRECT_URI = f"{CHATGPT_BASE}/api/auth/callback/openai"
MODE5_CHATGPT_SCOPE = (
    "openid email profile offline_access "
    "model.request model.read organization.read organization.write"
)
MODE5_CHATGPT_AUDIENCE = "https://api.openai.com/v1"
MODE5_EXT_PASSKEY_CLIENT_CAPABILITIES = "1111"


# =================== HTTP 会话管理 ===================

def _build_chrome_like_ssl_context():
    ctx = ssl.create_default_context()
    try:
        ctx.check_hostname = False
    except Exception:
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    try:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        pass
    try:
        ctx.set_ciphers(
            ":".join([
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-ECDSA-CHACHA20-POLY1305",
                "ECDHE-RSA-CHACHA20-POLY1305",
            ])
        )
    except Exception:
        pass
    if hasattr(ctx, "set_ciphersuites"):
        try:
            ctx.set_ciphersuites(
                ":".join([
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ])
            )
        except Exception:
            pass
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    try:
        ctx.options |= ssl.OP_NO_COMPRESSION
    except Exception:
        pass
    return ctx


class _TLSProfileAdapter(HTTPAdapter):
    def __init__(self, *args, ssl_context=None, **kwargs):
        self._ssl_context = ssl_context or _build_chrome_like_ssl_context()
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self._ssl_context
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = self._ssl_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)

def _create_plain_session(proxy_url=None):
    proxy_url = _effective_proxy(proxy_url)
    _assert_proxy_supported(proxy_url)

    session = requests.Session()
    session.trust_env = False
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    if TLS_CHROME_LIKE_ENABLED:
        adapter = _TLSProfileAdapter(max_retries=retry)
        session._tls_profile = "chrome_like"
    else:
        adapter = HTTPAdapter(max_retries=retry)
        session._tls_profile = ""
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
    session._proxy_url = proxy_url
    session._relay_enabled = False
    session._relay_state = None
    session._strict_node_id = False
    return session


def create_session(proxy_url=None, relay_state=None, force_relay=None, internal_plain=False):
    """创建 HTTP 会话；模式4/5/7走 node-session-proxy，force_relay 仅供邮箱 relay 使用。"""
    if internal_plain:
        return _create_plain_session(proxy_url)

    if force_relay:
        session = _create_plain_session("")
        return _attach_relay_to_session(session, relay_state=relay_state)
    if PROXY_MODE in (4, 5, 7):
        session = _create_plain_session("")
        return _attach_node_session_proxy_to_session(session, relay_state=relay_state)
    return _create_plain_session(proxy_url)


def create_cpa_management_session(proxy_url=None, relay_state=None):
    """创建 CPA 管理请求专用会话；可按配置强制直连。"""
    if CPA_MANAGEMENT_NO_PROXY:
        return _create_plain_session("")
    return create_session(proxy_url, relay_state=relay_state)


def _new_mail_proxy_session_id():
    return f"{MAIL_PROXY_SESSION_PREFIX}-{uuid.uuid4().hex[:16]}"


def _relay_request_bound(session, method, url, **kwargs):
    return _mail_relay_request(session, method, url, **kwargs)


def _attach_relay_to_session(session, relay_state=None):
    state = relay_state if isinstance(relay_state, dict) else {}
    session._relay_enabled = True
    session._node_session_proxy_enabled = False
    session._relay_state = state
    if not state.get("session_id"):
        state["session_id"] = _new_mail_proxy_session_id()
    state["node_id"] = str(state.get("node_id") or MAIL_PROXY_NODE_ID or "").strip()
    state["strict_node_id"] = bool(state.get("strict_node_id"))
    session._mail_relay_enabled = True
    session._mail_relay_session_id = str(state.get("session_id") or "")
    session._mail_relay_node_id = str(state.get("node_id") or "")
    session._strict_node_id = bool(state.get("strict_node_id"))
    session._mail_relay_rotation_count = int(getattr(session, "_mail_relay_rotation_count", 0) or 0)
    relay_client = getattr(session, "_mail_relay_client", None)
    if relay_client is None:
        relay_client = create_session("", internal_plain=True)
    session._mail_relay_client = relay_client
    session.request = MethodType(_relay_request_bound, session)
    return session


def _node_session_proxy_enabled_for_session(session):
    return bool(getattr(session, "_node_session_proxy_enabled", False))


def _mail_proxy_rotation_enabled_for_session(session):
    return bool(_mail_relay_enabled_for_session(session) or _node_session_proxy_enabled_for_session(session))


def _ensure_node_session_proxy(session, relay_state=None, force_refresh=False):
    state = relay_state if isinstance(relay_state, dict) else getattr(session, "_relay_state", None)
    if not isinstance(state, dict):
        state = {}
    if not state.get("session_id"):
        state["session_id"] = _new_mail_proxy_session_id()
    state["node_id"] = str(state.get("node_id") or MAIL_PROXY_NODE_ID or "").strip()
    state["strict_node_id"] = bool(state.get("strict_node_id"))

    session._relay_enabled = False
    session._node_session_proxy_enabled = True
    session._mail_relay_enabled = False
    session._relay_state = state
    session._mail_relay_session_id = str(state.get("session_id") or "")
    session._mail_relay_node_id = str(state.get("node_id") or "")
    session._strict_node_id = bool(state.get("strict_node_id"))
    session._mail_relay_rotation_count = int(getattr(session, "_mail_relay_rotation_count", 0) or 0)

    cached_proxy = ""
    if not force_refresh:
        cached_proxy = _normalize_proxy_url(str(state.get("proxy_url") or getattr(session, "_proxy_url", "") or ""))
    if cached_proxy:
        session.proxies = {"http": cached_proxy, "https": cached_proxy}
        session._proxy_url = cached_proxy
        return cached_proxy

    proxy_client = getattr(session, "_node_session_proxy_client", None)
    if proxy_client is None:
        proxy_client = create_session("", internal_plain=True)
        session._node_session_proxy_client = proxy_client

    payload = {
        "pool": MAIL_PROXY_POOL,
        "session_id": str(state.get("session_id") or "").strip() or _new_mail_proxy_session_id(),
        "url": "https://auth.openai.com/",
        "method": "GET",
    }
    node_id = str(state.get("node_id") or "").strip()
    if node_id:
        payload["node_id"] = node_id
    elif NODE_SESSION_RANDOM_TOP_N > 0:
        payload["random_top_n"] = NODE_SESSION_RANDOM_TOP_N

    max_attempts = max(1, 1 + int(RELAY_UNAVAILABLE_RETRY_LIMIT or 0))
    for attempt in range(max_attempts):
        try:
            relay_resp = proxy_client.post(
                NODE_SESSION_PROXY_API_URL,
                headers={
                    "X-API-Key": NODE_SESSION_PROXY_API_KEY,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=20,
                verify=False,
            )
        except Exception as e:
            raise RuntimeError(f"session 代理请求异常: {e}") from e

        if relay_resp.status_code == 200:
            break

        text = relay_resp.text[:200] if relay_resp is not None else ""
        retry_reason = _relay_error_retry_reason(relay_resp.status_code, text)
        if retry_reason and attempt + 1 < max_attempts:
            was_strict = bool(state.get("strict_node_id"))
            state = _reset_relay_state_for_retry(state, session=session)
            payload["session_id"] = str(state.get("session_id") or "").strip() or _new_mail_proxy_session_id()
            payload.pop("node_id", None)
            if NODE_SESSION_RANDOM_TOP_N > 0:
                payload["random_top_n"] = NODE_SESSION_RANDOM_TOP_N
            reason_text = "冷却中" if retry_reason == "cooling_down" else "已失活"
            if was_strict:
                print(f"  🔁 session 代理固定节点{reason_text}，改用随机节点重试 ({attempt + 1}/{max_attempts - 1})")
            else:
                print(f"  🔁 session 代理节点{reason_text}，重置账号会话后重试 ({attempt + 1}/{max_attempts - 1})")
            continue

        raise RuntimeError(f"session 代理调用失败: {relay_resp.status_code} {text}")
    else:
        raise RuntimeError("session 代理调用失败: 重试后仍未获得可用节点")

    try:
        relay_data = relay_resp.json()
    except Exception as e:
        raise RuntimeError(f"session 代理响应解析失败: {e}") from e

    proxy_url = _normalize_proxy_url(str((relay_data or {}).get("proxy_url") or ""))
    if not proxy_url:
        raise RuntimeError(f"session 代理响应缺少 proxy_url: {str(relay_data)[:200]}")
    _assert_proxy_supported(proxy_url)

    if isinstance(relay_data, dict):
        if relay_data.get("session_id"):
            state["session_id"] = str(relay_data.get("session_id"))
            session._mail_relay_session_id = str(relay_data.get("session_id"))
        if relay_data.get("node_id"):
            state["node_id"] = str(relay_data.get("node_id"))
            session._mail_relay_node_id = str(relay_data.get("node_id"))
    state["proxy_url"] = proxy_url
    session.proxies = {"http": proxy_url, "https": proxy_url}
    session._proxy_url = proxy_url
    return proxy_url


def _attach_node_session_proxy_to_session(session, relay_state=None):
    _ensure_node_session_proxy(session, relay_state=relay_state, force_refresh=False)
    return session



def _reset_chatgptmail_session_state(session):
    try:
        session.cookies.clear()
    except Exception:
        pass
    session._chatgptmail_auth_token = ""
    session._chatgptmail_auth_email = ""
    session._chatgptmail_auth_expires_at = 0
    session._chatgptmail_bootstrapped = False
    session._chatgptmail_bound_email = ""
    session._chatgptmail_last_error_code = ""
    session._chatgptmail_last_error_message = ""
    session._chatgptmail_last_error_email = ""


def _chatgptmail_set_last_error(session, code="", message="", email=""):
    if session is None:
        return
    session._chatgptmail_last_error_code = str(code or "").strip()
    session._chatgptmail_last_error_message = str(message or "").strip()
    session._chatgptmail_last_error_email = str(email or "").strip().lower()


def _chatgptmail_get_last_error(session):
    if session is None:
        return "", "", ""
    return (
        str(getattr(session, "_chatgptmail_last_error_code", "") or "").strip(),
        str(getattr(session, "_chatgptmail_last_error_message", "") or "").strip(),
        str(getattr(session, "_chatgptmail_last_error_email", "") or "").strip().lower(),
    )

def create_mail_session(proxy_url=None, relay_state=None):
    """创建邮件专用 session；模式2/3走 relay，模式4可按配置让邮箱走 relay，模式5/7固定走旧 relay。"""
    if PROXY_MODE in (5, 7):
        session = create_session("", relay_state=relay_state, force_relay=True)
        _reset_chatgptmail_session_state(session)
        return session

    if PROXY_MODE == 4:
        if MODE4_MAIL_USE_NODE_RELAY:
            session = create_session("", relay_state=relay_state, force_relay=True)
        else:
            session = create_session("", relay_state=relay_state)
        _reset_chatgptmail_session_state(session)
        return session

    if not MAIL_PROXY_ENABLED:
        return create_session(proxy_url)

    session = create_session("", relay_state=relay_state, force_relay=True)
    _reset_chatgptmail_session_state(session)
    return session


def _close_session(session_obj):
    """安全关闭 requests session，并递归关闭内部 relay client。"""
    if session_obj is None:
        return
    nested_sessions = []
    for attr in ("_mail_relay_client", "_node_session_proxy_client"):
        nested = getattr(session_obj, attr, None)
        if nested is None or nested is session_obj or any(nested is item for item in nested_sessions):
            continue
        try:
            setattr(session_obj, attr, None)
        except Exception:
            pass
        nested_sessions.append(nested)
    for nested in nested_sessions:
        _close_session(nested)
    try:
        session_obj.close()
    except Exception:
        pass


def _session_proxy_url(session_obj):
    return _normalize_proxy_url(getattr(session_obj, "_proxy_url", "") or "")


def _load_account_proxy_map_unlocked():
    if not os.path.exists(ACCOUNT_PROXY_MAP_FILE):
        return {}
    try:
        with open(ACCOUNT_PROXY_MAP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def remember_account_proxy(email, proxy_url):
    """记住单个账号绑定的代理链；空字符串表示直连。"""
    key = str(email or "").strip().lower()
    if not key:
        return

    proxy_url = _normalize_proxy_url(proxy_url)
    with _file_lock:
        data = _load_account_proxy_map_unlocked()
        data[key] = proxy_url
        with open(ACCOUNT_PROXY_MAP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


def forget_account_proxy(email):
    key = str(email or "").strip().lower()
    if not key:
        return
    with _file_lock:
        data = _load_account_proxy_map_unlocked()
        if key not in data:
            return
        data.pop(key, None)
        with open(ACCOUNT_PROXY_MAP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


def load_account_proxy(email, default=None):
    """读取账号绑定代理；若无记录则回退到 default/当前默认代理。"""
    key = str(email or "").strip().lower()
    fallback = _effective_proxy() if default is None else _normalize_proxy_url(default)
    if not key:
        return fallback

    with _file_lock:
        data = _load_account_proxy_map_unlocked()
    if key in data:
        return _normalize_proxy_url(data.get(key, ""))
    return fallback


def _new_relay_state(session_id="", node_id="", strict_node_id=False):
    return {
        "session_id": str(session_id or "").strip() or _new_mail_proxy_session_id(),
        "node_id": str(node_id or MAIL_PROXY_NODE_ID or "").strip(),
        "strict_node_id": bool(strict_node_id),
    }


def _new_oai_registration_relay_state(node_id="", strict_node_id=False):
    if PROXY_MODE not in (4, 5, 7):
        return None
    clean_node_id = str(node_id or "").strip()
    if clean_node_id:
        return _new_relay_state(node_id=clean_node_id, strict_node_id=bool(strict_node_id))
    return _new_relay_state()


def _new_random_mail_relay_state():
    if PROXY_MODE in (4, 5, 7) or MAIL_PROXY_ENABLED:
        return _new_relay_state()
    return None


def _relay_error_retry_reason(status_code, text=""):
    try:
        code = int(status_code or 0)
    except Exception:
        code = 0
    if code != 400:
        return ""
    text_lower = str(text or "").strip().lower()
    if "node " not in text_lower:
        return ""
    if "cooling down" in text_lower or "cooldown" in text_lower:
        return "cooling_down"
    if "inactive" in text_lower:
        return "inactive"
    return ""


def _reset_relay_state_for_retry(state, session=None):
    new_state = _new_relay_state()
    if isinstance(state, dict):
        state.clear()
        state.update(new_state)
        target_state = state
    else:
        target_state = dict(new_state)
    if session is not None:
        session._relay_state = target_state
        session._mail_relay_session_id = str(target_state.get("session_id") or "")
        session._mail_relay_node_id = str(target_state.get("node_id") or "")
        session._strict_node_id = bool(target_state.get("strict_node_id"))
        session._proxy_url = ""
        try:
            session.proxies = {}
        except Exception:
            pass
    return target_state


def _relay_state_from_session(session):
    state = getattr(session, "_relay_state", None)
    if not isinstance(state, dict):
        state = {}
    session_id = str(state.get("session_id") or getattr(session, "_mail_relay_session_id", "") or "").strip()
    node_id = str(state.get("node_id") or getattr(session, "_mail_relay_node_id", "") or "").strip()
    strict_node_id = bool(state.get("strict_node_id") or getattr(session, "_strict_node_id", False))
    if not session_id and not node_id:
        return None
    relay_state = _new_relay_state(session_id=session_id, node_id=node_id)
    relay_state["strict_node_id"] = strict_node_id
    return relay_state


def _load_account_relay_map_unlocked():
    if not os.path.exists(ACCOUNT_RELAY_MAP_FILE):
        return {}
    try:
        with open(ACCOUNT_RELAY_MAP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def remember_account_relay(email, relay_state):
    key = str(email or "").strip().lower()
    state = relay_state if isinstance(relay_state, dict) else _relay_state_from_session(relay_state)
    if not key or not isinstance(state, dict):
        return
    session_id = str(state.get("session_id") or "").strip()
    node_id = str(state.get("node_id") or "").strip()
    if not session_id and not node_id:
        return
    with _file_lock:
        data = _load_account_relay_map_unlocked()
        data[key] = {
            "session_id": session_id,
            "node_id": node_id,
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(ACCOUNT_RELAY_MAP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


def load_account_relay(email):
    key = str(email or "").strip().lower()
    if not key:
        return None
    with _file_lock:
        data = _load_account_relay_map_unlocked()
    item = data.get(key, {}) if isinstance(data, dict) else {}
    if not isinstance(item, dict):
        return None
    session_id = str(item.get("session_id") or "").strip()
    node_id = str(item.get("node_id") or "").strip()
    if not session_id and not node_id:
        return None
    return _new_relay_state(session_id=session_id, node_id=node_id)


def forget_account_relay(email):
    key = str(email or "").strip().lower()
    if not key:
        return
    with _file_lock:
        data = _load_account_relay_map_unlocked()
        if key not in data:
            return
        data.pop(key, None)
        with open(ACCOUNT_RELAY_MAP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


def _mail_relay_enabled_for_session(session):
    return bool(getattr(session, "_relay_enabled", False) or (MAIL_PROXY_ENABLED and getattr(session, "_mail_relay_enabled", False)))


def _split_set_cookie_header_value(value):
    raw = str(value or "").strip()
    if not raw:
        return []
    parts = []
    buf = []
    i = 0
    in_expires = False
    lower = raw.lower()
    while i < len(raw):
        if lower.startswith("expires=", i):
            in_expires = True
            buf.append(raw[i:i + 8])
            i += 8
            continue
        ch = raw[i]
        if ch == ";" and in_expires:
            in_expires = False
        if ch == "," and not in_expires:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            i += 1
            while i < len(raw) and raw[i].isspace():
                i += 1
            continue
        buf.append(ch)
        i += 1
    part = "".join(buf).strip()
    if part:
        parts.append(part)
    return parts


def _mail_relay_header_values(headers, name):
    if not isinstance(headers, dict):
        return []
    values = []
    name = str(name or "").lower()
    for key, val in headers.items():
        if str(key or "").lower() != name:
            continue
        if isinstance(val, list):
            for item in val:
                if item is None:
                    continue
                item = str(item)
                if name == "set-cookie":
                    values.extend(_split_set_cookie_header_value(item))
                else:
                    values.append(item)
        elif val is not None:
            item = str(val)
            if name == "set-cookie":
                values.extend(_split_set_cookie_header_value(item))
            else:
                values.append(item)
    return values


def _mail_relay_flat_headers(headers):
    if not isinstance(headers, dict):
        return {}
    flat = {}
    for key, val in headers.items():
        if val is None:
            continue
        if isinstance(val, list):
            flat[str(key)] = ", ".join(str(x) for x in val if x is not None)
        else:
            flat[str(key)] = str(val)
    return flat


def _mail_relay_apply_cookies(session, url, relay_headers):
    host = urlparse(url).hostname or ""
    for cookie_line in _mail_relay_header_values(relay_headers, "set-cookie"):
        parsed = None
        try:
            parsed = SimpleCookie()
            parsed.load(cookie_line)
        except Exception:
            parsed = None
        if parsed:
            for name, morsel in parsed.items():
                domain = morsel["domain"] or host
                path = morsel["path"] or "/"
                try:
                    session.cookies.set(name, morsel.value, domain=domain, path=path)
                except Exception:
                    try:
                        session.cookies.set(name, morsel.value)
                    except Exception:
                        pass
            continue
        pair = str(cookie_line or "").split(";", 1)[0].strip()
        if not pair or "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        name = name.strip()
        if not name:
            continue
        try:
            session.cookies.set(name, value.strip(), domain=host or None, path="/")
        except Exception:
            try:
                session.cookies.set(name, value.strip())
            except Exception:
                pass


def _mail_relay_build_response(url, relay_data):
    relay_headers = relay_data.get("headers", {}) if isinstance(relay_data, dict) else {}
    body_b64 = relay_data.get("body_base64", "") if isinstance(relay_data, dict) else ""
    try:
        body = base64.b64decode(body_b64 or "")
    except Exception:
        body = b""
    resp = requests.Response()
    resp.status_code = int((relay_data or {}).get("status_code") or 0)
    resp._content = body
    resp.headers = requests.structures.CaseInsensitiveDict(_mail_relay_flat_headers(relay_headers))
    resp.url = url
    resp.encoding = requests.utils.get_encoding_from_headers(resp.headers) or "utf-8"
    return resp


def _mail_relay_request(session, method, url, **kwargs):
    relay_client = getattr(session, "_mail_relay_client", None) or create_session("", internal_plain=True)
    session._mail_relay_client = relay_client
    relay_state = getattr(session, "_relay_state", None)
    if not isinstance(relay_state, dict):
        relay_state = _new_relay_state(
            session_id=getattr(session, "_mail_relay_session_id", ""),
            node_id=getattr(session, "_mail_relay_node_id", ""),
        )
        session._relay_state = relay_state

    params = kwargs.pop("params", None)
    headers = dict(kwargs.pop("headers", {}) or {})
    json_payload = kwargs.pop("json", None)
    data_payload = kwargs.pop("data", None)
    timeout = kwargs.pop("timeout", 30)
    kwargs.pop("verify", None)
    kwargs.pop("allow_redirects", None)

    prepared = requests.Request(method.upper(), url, params=params).prepare()
    target_url = prepared.url

    prepared_for_session = session.prepare_request(
        requests.Request(method.upper(), target_url, headers=headers)
    )
    cookie_header = str(prepared_for_session.headers.get("Cookie", "") or "").strip()
    if cookie_header:
        headers.setdefault("Cookie", cookie_header)

    payload = {
        "pool": MAIL_PROXY_POOL,
        "session_id": str(relay_state.get("session_id") or "").strip() or _new_mail_proxy_session_id(),
        "url": target_url,
        "method": method.upper(),
        "return_node_id": True,
    }
    node_id = str(relay_state.get("node_id") or getattr(session, "_mail_relay_node_id", "") or "").strip()
    if node_id:
        payload["node_id"] = node_id
    elif MAIL_PROXY_RANDOM_TOP_N > 0:
        payload["random_top_n"] = MAIL_PROXY_RANDOM_TOP_N
    if headers:
        payload["headers"] = headers
    if json_payload is not None:
        payload["body"] = json.dumps(json_payload, ensure_ascii=False)
        payload.setdefault("headers", {})
        payload["headers"].setdefault("Content-Type", "application/json")
    elif data_payload is not None:
        if isinstance(data_payload, (dict, list, tuple)):
            payload["body"] = urlencode(data_payload, doseq=True)
        elif isinstance(data_payload, bytes):
            payload["body"] = data_payload.decode("utf-8", "replace")
        else:
            payload["body"] = str(data_payload)

    max_attempts = max(1, 1 + int(RELAY_UNAVAILABLE_RETRY_LIMIT or 0))
    for attempt in range(max_attempts):
        try:
            relay_resp = relay_client.post(
                MAIL_PROXY_API_URL,
                headers={
                    "X-API-Key": MAIL_PROXY_API_KEY,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=max(15, int(timeout) + 10),
                verify=False,
            )
        except Exception as e:
            print(f"    ❌ relay 请求异常: {e}")
            return None

        if relay_resp.status_code == 200:
            break

        text = relay_resp.text[:200] if relay_resp is not None else ""
        retry_reason = _relay_error_retry_reason(relay_resp.status_code, text)
        if retry_reason and attempt + 1 < max_attempts:
            was_strict = bool(relay_state.get("strict_node_id"))
            relay_state = _reset_relay_state_for_retry(relay_state, session=session)
            payload["session_id"] = str(relay_state.get("session_id") or "").strip() or _new_mail_proxy_session_id()
            payload.pop("node_id", None)
            if MAIL_PROXY_RANDOM_TOP_N > 0:
                payload["random_top_n"] = MAIL_PROXY_RANDOM_TOP_N
            reason_text = "冷却中" if retry_reason == "cooling_down" else "已失活"
            if was_strict:
                print(f"    🔁 relay 固定节点{reason_text}，改用随机节点重试 ({attempt + 1}/{max_attempts - 1})")
            else:
                print(f"    🔁 relay 节点{reason_text}，重置邮箱会话后重试 ({attempt + 1}/{max_attempts - 1})")
            continue

        print(f"    ❌ relay 调用失败: {relay_resp.status_code} {text}")
        return None
    else:
        return None

    try:
        relay_data = relay_resp.json()
    except Exception as e:
        print(f"    ❌ relay 响应解析失败: {e}")
        return None

    if isinstance(relay_data, dict):
        if relay_data.get("session_id"):
            relay_state["session_id"] = str(relay_data.get("session_id"))
            session._mail_relay_session_id = str(relay_data.get("session_id"))
        if relay_data.get("node_id"):
            relay_state["node_id"] = str(relay_data.get("node_id"))
            session._mail_relay_node_id = str(relay_data.get("node_id"))
        relay_state["strict_node_id"] = bool(relay_state.get("strict_node_id"))
        session._strict_node_id = bool(relay_state.get("strict_node_id"))

    resp = _mail_relay_build_response(target_url, relay_data)
    _mail_relay_apply_cookies(session, target_url, (relay_data or {}).get("headers", {}))
    return resp


def _mail_request(session, method, url, **kwargs):
    if _mail_relay_enabled_for_session(session):
        return _mail_relay_request(session, method, url, **kwargs)
    return session.request(method, url, **kwargs)


_mail_proxy_rotate_lock = threading.Lock()
_mail_proxy_last_rotate_at = 0.0


def _mail_proxy_wait_rotate_interval():
    global _mail_proxy_last_rotate_at
    interval = max(0.0, float(MAIL_PROXY_ROTATE_INTERVAL_SECONDS or 0.0))
    if interval <= 0:
        return
    with _mail_proxy_rotate_lock:
        now = time.time()
        wait_sec = max(0.0, interval - max(0.0, now - _mail_proxy_last_rotate_at))
        if wait_sec > 0:
            time.sleep(wait_sec)
        _mail_proxy_last_rotate_at = time.time()


def rotate_mail_proxy(session, reason=""):
    _mail_proxy_wait_rotate_interval()
    if _node_session_proxy_enabled_for_session(session):
        session._mail_relay_rotation_count = int(getattr(session, "_mail_relay_rotation_count", 0) or 0) + 1
        keep_node = bool(getattr(session, "_strict_node_id", False))
        new_state = _new_relay_state(
            node_id=getattr(session, "_mail_relay_node_id", "") if keep_node else "",
        )
        new_state["strict_node_id"] = keep_node
        session._mail_relay_session_id = new_state["session_id"]
        session._mail_relay_node_id = new_state["node_id"]
        session._strict_node_id = keep_node
        if isinstance(getattr(session, "_relay_state", None), dict):
            session._relay_state.clear()
            session._relay_state.update(new_state)
        else:
            session._relay_state = dict(new_state)
        try:
            session.proxies = {}
        except Exception:
            pass
        session._proxy_url = ""
        _reset_chatgptmail_session_state(session)
        try:
            _ensure_node_session_proxy(session, relay_state=getattr(session, "_relay_state", None), force_refresh=True)
        except Exception as e:
            print(f"  ❌ session 代理切换失败: {e}")
            return False
        if reason:
            print(f"  🔁 session 代理切换: {reason}")
        return True

    if not _mail_relay_enabled_for_session(session):
        return False
    session._mail_relay_rotation_count = int(getattr(session, "_mail_relay_rotation_count", 0) or 0) + 1
    keep_node = bool(getattr(session, "_strict_node_id", False))
    new_state = _new_relay_state(
        node_id=getattr(session, "_mail_relay_node_id", "") if keep_node else "",
    )
    new_state["strict_node_id"] = keep_node
    session._mail_relay_session_id = new_state["session_id"]
    session._mail_relay_node_id = new_state["node_id"]
    session._strict_node_id = keep_node
    if isinstance(getattr(session, "_relay_state", None), dict):
        session._relay_state.clear()
        session._relay_state.update(new_state)
    _reset_chatgptmail_session_state(session)
    if reason:
        print(f"  🔁 relay 会话切换: {reason}")
    return True


def _sentinel_proxy_retry_enabled_for_session(session):
    return bool(_node_session_proxy_enabled_for_session(session) or _mail_relay_enabled_for_session(session))


def _is_retryable_sentinel_proxy_error(exc):
    if isinstance(exc, requests.exceptions.ProxyError):
        return True
    if isinstance(exc, requests.exceptions.ConnectionError):
        text = str(exc).lower()
        markers = (
            "cannot connect to proxy",
            "connection refused",
            "failed to establish a new connection",
            "max retries exceeded",
        )
        return any(marker in text for marker in markers)
    return False


# 使用普通 session（全流程纯 HTTP，无需浏览器）


# =================== 工具函数 ===================

# 浏览器 UA（需与 sec-ch-ua 版本一致）
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
MODE5_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/143.0.0.0 Safari/537.36"
)
DEFAULT_SENTINEL_SDK_URL = "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js"
DEFAULT_SENTINEL_FRAME_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
DEFAULT_SENTINEL_SEC_CH_UA = '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"'
MODE5_SEC_CH_UA = '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"'
MODE5_SENTINEL_VERSION = "20260219f9f6"
MODE5_SENTINEL_SDK_URL = f"https://sentinel.openai.com/sentinel/{MODE5_SENTINEL_VERSION}/sdk.js"
MODE5_SENTINEL_FRAME_URL = f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={MODE5_SENTINEL_VERSION}"
TLS_CHROME_LIKE_ENABLED = _bool_value(
    os.environ.get("TLS_CHROME_LIKE_ENABLED", _config.get("tls_chrome_like_enabled", False)),
    False,
)
# mode5 线上默认启用：
# 1) 给 chatgpt.com 也同步 oai-did cookie
# 2) 若 signin/openai 返回新的 device_id，则同步回本地 device_id / sentinel
# 如需回退，可通过环境变量或配置显式关闭。
MODE5_TEST_CHATGPT_OAI_DID_COOKIE = _bool_value(
    os.environ.get("MODE5_TEST_CHATGPT_OAI_DID_COOKIE", _config.get("mode5_test_chatgpt_oai_did_cookie", True)),
    True,
)
MODE5_TEST_SYNC_SIGNIN_DEVICE_ID = _bool_value(
    os.environ.get("MODE5_TEST_SYNC_SIGNIN_DEVICE_ID", _config.get("mode5_test_sync_signin_device_id", True)),
    True,
)
BROWSER_CREATE_ACCOUNT_ENABLED = _bool_value(
    os.environ.get("BROWSER_CREATE_ACCOUNT_ENABLED", _config.get("browser_create_account_enabled", True)),
    True,
)
BROWSER_CREATE_ACCOUNT_WAIT_MS = max(
    1000,
    _int_value(
        os.environ.get("BROWSER_CREATE_ACCOUNT_WAIT_MS", _config.get("browser_create_account_wait_ms", 8000)),
        8000,
    ),
)
BROWSER_CREATE_ACCOUNT_SDK_TIMEOUT_MS = max(
    5000,
    _int_value(
        os.environ.get(
            "BROWSER_CREATE_ACCOUNT_SDK_TIMEOUT_MS",
            _config.get("browser_create_account_sdk_timeout_ms", 30000),
        ),
        30000,
    ),
)
BROWSER_CREATE_ACCOUNT_IMMEDIATE_RETRY = _bool_value(
    os.environ.get(
        "BROWSER_CREATE_ACCOUNT_IMMEDIATE_RETRY",
        _config.get("browser_create_account_immediate_retry", True),
    ),
    True,
)
MODE7_COOKIE_FILE = str(
    os.environ.get("MODE7_COOKIE_FILE", _config.get("mode7_cookie_file", "/root/codex-register/cookie.txt")) or ""
).strip()
MODE7_ENGINE = str(os.environ.get("MODE7_ENGINE", _config.get("mode7_engine", "camoufox")) or "camoufox").strip().lower()
if MODE7_ENGINE not in {"camoufox", "chromium"}:
    MODE7_ENGINE = "camoufox"
MODE7_PROFILE = str(os.environ.get("MODE7_PROFILE", _config.get("mode7_profile", "default")) or "default").strip()
MODE7_SCRIPT_TIMEOUT_SECONDS = max(
    60,
    _int_value(
        os.environ.get("MODE7_SCRIPT_TIMEOUT_SECONDS", _config.get("mode7_script_timeout_seconds", 420)),
        420,
    ),
)
MODE7_SLEEP_AFTER_MS = max(
    0,
    _int_value(
        os.environ.get("MODE7_SLEEP_AFTER_MS", _config.get("mode7_sleep_after_ms", 1200)),
        1200,
    ),
)

# API 请求头模板（从 cURL 逆向提取）
COMMON_HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": OPENAI_AUTH_BASE,
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

# 页面导航请求头（用于 GET 类请求）
NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}


def generate_device_id():
    """生成设备唯一标识（oai-did），UUID v4 格式"""
    return str(uuid.uuid4())


def generate_random_password(length=16):
    """生成符合 OpenAI 要求的随机密码"""
    chars = string.ascii_letters + string.digits + "!@#$%"
    pwd = list(
        random.choice(string.ascii_uppercase)
        + random.choice(string.ascii_lowercase)
        + random.choice(string.digits)
        + random.choice("!@#$%")
        + "".join(random.choice(chars) for _ in range(length - 4))
    )
    random.shuffle(pwd)
    return "".join(pwd)


def generate_random_name():
    """随机生成自然的英文姓名"""
    first = [
        "James", "Robert", "John", "Michael", "David", "William", "Richard",
        "Mary", "Jennifer", "Linda", "Elizabeth", "Susan", "Jessica", "Sarah",
        "Emily", "Emma", "Olivia", "Sophia", "Liam", "Noah", "Oliver", "Ethan",
    ]
    last = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
        "Davis", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Martin",
    ]
    return random.choice(first), random.choice(last)


def generate_random_birthday():
    """生成随机生日字符串，格式 YYYY-MM-DD（20~30岁）"""
    year = random.randint(1996, 2006)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


def generate_datadog_trace():
    """生成 Datadog APM 追踪头（从 cURL 中逆向提取的格式）"""
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), '016x')
    parent_hex = format(int(parent_id), '016x')
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def generate_pkce():
    """生成 PKCE code_verifier 和 code_challenge"""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


# =================== Sentinel Token 逆向生成 ===================
# 
# 以下代码基于对 sentinel.openai.com 的 SDK JS 代码的逆向分析：
#   https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js
#
# 核心算法：
#   1. _getConfig() → 收集浏览器环境数据（18个元素的数组）
#   2. _runCheck(startTime, seed, difficulty, config, nonce) → PoW 计算
#      a) config[3] = nonce（第4个元素设为当前尝试次数）
#      b) config[9] = performance.now() - startTime（耗时）
#      c) data = base64(JSON.stringify(config))  
#      d) hash = fnv1a_32(seed + data)
#      e) 若 hash 的 hex 前缀 ≤ difficulty → 返回 data + "~S"
#   3. 最终 token = "gAAAAAB" + answer
#
# FNV-1a 32位哈希：
#   offset_basis = 2166136261
#   prime = 16777619
#   for each byte: hash ^= byte; hash = (hash * prime) >>> 0
#   然后做 xorshift 混合 + 转 8 位 hex
#

class SentinelTokenGenerator:
    """
    Sentinel Token 纯 Python 生成器
    
    通过逆向 sentinel SDK 的 PoW 算法，
    纯 Python 构造合法的 openai-sentinel-token。
    """

    MAX_ATTEMPTS = 500000  # 最大 PoW 尝试次数
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"  # SDK 中的错误前缀常量

    def __init__(
        self,
        device_id=None,
        user_agent=None,
        script_src=None,
        frame_url=None,
        sec_ch_ua=None,
        language="en-US",
        languages="en-US,en",
    ):
        self.device_id = device_id or generate_device_id()
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())
        self.user_agent = str(user_agent or USER_AGENT)
        self.script_src = str(script_src or DEFAULT_SENTINEL_SDK_URL)
        self.frame_url = str(frame_url or DEFAULT_SENTINEL_FRAME_URL)
        self.sec_ch_ua = str(sec_ch_ua or DEFAULT_SENTINEL_SEC_CH_UA)
        self.language = str(language or "en-US")
        self.languages = str(languages or "en-US,en")

    @staticmethod
    def _fnv1a_32(text):
        """
        FNV-1a 32位哈希算法（从 SDK JS 逆向还原）
        
        逆向来源：SDK 中的匿名函数，特征码：
          e = 2166136261  (FNV offset basis)
          e ^= t.charCodeAt(r)
          e = Math.imul(e, 16777619) >>> 0  (FNV prime)
          
        最后做 xorshift 混合（murmurhash3 风格的 finalizer）：
          e ^= e >>> 16
          e = Math.imul(e, 2246822507) >>> 0
          e ^= e >>> 13
          e = Math.imul(e, 3266489909) >>> 0
          e ^= e >>> 16
        """
        h = 2166136261  # FNV offset basis
        for ch in text:
            code = ord(ch)
            h ^= code
            # Math.imul(h, 16777619) >>> 0 模拟无符号32位乘法
            h = ((h * 16777619) & 0xFFFFFFFF)

        # xorshift 混合（murmurhash3 finalizer）
        h ^= (h >> 16)
        h = ((h * 2246822507) & 0xFFFFFFFF)
        h ^= (h >> 13)
        h = ((h * 3266489909) & 0xFFFFFFFF)
        h ^= (h >> 16)
        h = h & 0xFFFFFFFF

        # 转为8位 hex 字符串，左补零
        return format(h, '08x')

    def _get_config(self):
        """
        构造浏览器环境数据数组（_getConfig 方法逆向还原）
        
        SDK 中的元素对应关系（按索引）：
          [0]  screen.width + screen.height     → "1920x1080" 格式
          [1]  new Date().toString()             → 时间字符串
          [2]  performance.memory.jsHeapSizeLimit → 内存限制
          [3]  Math.random()                      → 随机数（后被 nonce 覆盖）
          [4]  navigator.userAgent                → UA
          [5]  随机 script src                    → 随机选一个页面 script 的 src
          [6]  脚本版本匹配                       → script src 匹配 c/[^/]*/_
          [7]  document.documentElement.data-build → 构建版本
          [8]  navigator.language                  → 语言
          [9]  navigator.languages.join(',')       → 语言列表（后被耗时覆盖）
          [10] Math.random()                       → 随机数
          [11] 随机 navigator 属性                 → 随机取 navigator 原型链上的一个属性
          [12] Object.keys(document) 随机一个       → document 属性
          [13] Object.keys(window) 随机一个         → window 属性
          [14] performance.now()                    → 高精度时间
          [15] self.sid                             → 会话标识 UUID
          [16] URLSearchParams 参数                 → URL 搜索参数
          [17] navigator.hardwareConcurrency        → CPU 核心数
          [18] performance.timeOrigin               → 时间起点
        """
        # 模拟真实的浏览器环境数据
        screen_info = f"1920x1080"
        now = datetime.now(timezone.utc)
        # 格式化为 JS Date.toString() 格式
        date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        js_heap_limit = 4294705152  # Chrome 典型值
        nav_random1 = random.random()
        ua = self.user_agent
        # 模拟 sentinel SDK 的 script src
        script_src = self.script_src
        # 匹配 c/[^/]*/_
        script_version = None
        data_build = None
        language = self.language
        languages = self.languages
        nav_random2 = random.random()
        # 模拟随机 navigator 属性
        nav_props = [
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "webkitTemporaryStorage", "webkitPersistentStorage",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ]
        nav_prop = random.choice(nav_props)
        # 模拟属性值
        nav_val = f"{nav_prop}−undefined"  # SDK 用 − (U+2212) 而非 - (U+002D)
        doc_key = random.choice(["location", "implementation", "URL", "documentURI", "compatMode"])
        win_key = random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"])
        perf_now = random.uniform(1000, 50000)
        hardware_concurrency = random.choice([4, 8, 12, 16])
        # 模拟 performance.timeOrigin（毫秒级 Unix 时间戳）
        time_origin = time.time() * 1000 - perf_now

        config = [
            screen_info,           # [0] 屏幕尺寸
            date_str,              # [1] 时间
            js_heap_limit,         # [2] 内存限制
            nav_random1,           # [3] 占位，后被 nonce 替换
            ua,                    # [4] UserAgent
            script_src,            # [5] script src
            script_version,        # [6] 脚本版本
            data_build,            # [7] 构建版本
            language,              # [8] 语言
            languages,             # [9] 占位，后被耗时替换
            nav_random2,           # [10] 随机数
            nav_val,               # [11] navigator 属性
            doc_key,               # [12] document key
            win_key,               # [13] window key
            perf_now,              # [14] performance.now
            self.sid,              # [15] 会话 UUID
            "",                    # [16] URL 参数
            hardware_concurrency,  # [17] CPU 核心数
            time_origin,           # [18] 时间起点
        ]
        return config

    @staticmethod
    def _base64_encode(data):
        """
        模拟 SDK 的 E() 函数：JSON.stringify → TextEncoder.encode → btoa
        """
        json_str = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        encoded = json_str.encode('utf-8')
        return base64.b64encode(encoded).decode('ascii')

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        """
        单次 PoW 检查（_runCheck 方法逆向还原）
        
        参数:
            start_time: 起始时间（秒）
            seed: PoW 种子字符串
            difficulty: 难度字符串（hex 前缀阈值）
            config: 环境配置数组
            nonce: 当前尝试序号
            
        返回:
            成功时返回 base64(config) + "~S"
            失败时返回 None
        """
        # 设置 nonce 和耗时
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)  # 毫秒

        # base64 编码环境数据
        data = self._base64_encode(config)

        # 计算 FNV-1a 哈希：hash(seed + data)
        hash_input = seed + data
        hash_hex = self._fnv1a_32(hash_input)

        # 难度校验：哈希前缀 ≤ 难度值
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"

        return None

    def generate_token(self, seed=None, difficulty=None):
        """
        生成 sentinel token（完整 PoW 流程）
        
        参数:
            seed: PoW 种子（来自服务端的 proofofwork.seed）
            difficulty: 难度值（来自服务端的 proofofwork.difficulty）
            
        返回:
            格式为 "gAAAAAB..." 的 sentinel token 字符串
        """
        if seed is None:
            seed = self.requirements_seed
            difficulty = difficulty or "0"

        start_time = time.time()
        config = self._get_config()
        diff_len = len(difficulty)

        # 预计算 seed 部分的 FNV-1a 哈希中间值（seed 在所有迭代中不变）
        seed_hash = 2166136261
        for ch in seed:
            seed_hash ^= ord(ch)
            seed_hash = ((seed_hash * 16777619) & 0xFFFFFFFF)

        for i in range(self.MAX_ATTEMPTS):
            # 设置 nonce 和耗时
            config[3] = i
            config[9] = round((time.time() - start_time) * 1000)

            # base64 编码环境数据
            data = self._base64_encode(config)

            # 增量计算：从 seed 的中间哈希值继续对 data 部分计算
            h = seed_hash
            for ch in data:
                h ^= ord(ch)
                h = ((h * 16777619) & 0xFFFFFFFF)
            # xorshift finalizer
            h ^= (h >> 16)
            h = ((h * 2246822507) & 0xFFFFFFFF)
            h ^= (h >> 13)
            h = ((h * 3266489909) & 0xFFFFFFFF)
            h ^= (h >> 16)
            hash_hex = format(h & 0xFFFFFFFF, '08x')

            if hash_hex[:diff_len] <= difficulty:
                elapsed = time.time() - start_time
                print(f"  ✅ PoW 完成: {i+1} 次迭代, 耗时 {elapsed:.2f}s")
                return "gAAAAAB" + data + "~S"

        print(f"  ⚠️ PoW 超过最大尝试次数 ({self.MAX_ATTEMPTS})")
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        """
        生成 requirements token（不需要服务端参数）
        
        这是 SDK 中 getRequirementsToken() 的还原。
        用于不需要服务端 seed 的场景（如注册页面初始化）。
        """
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))  # 模拟小延迟
        data = self._base64_encode(config)
        return "gAAAAAC" + data  # 注意前缀是 C 不是 B


# =================== DuckMail API 限速器 ===================

class _DuckMailRateLimiter:
    """滑动窗口限速器（线程安全）

    维护最近 1 秒内的请求时间戳列表，精确控制 QPS 不超过 max_qps。
    相比简单的最小间隔机制，在高并发下更精确。
    """
    def __init__(self, max_qps=5):
        self._max_qps = max_qps
        self._lock = threading.Lock()
        self._timestamps = []  # 最近 1 秒内的请求时间戳

    def acquire(self):
        """获取一个调用配额，必要时阻塞等待"""
        while True:
            with self._lock:
                now = time.time()
                # 清理超过 1 秒的旧时间戳
                cutoff = now - 1.0
                self._timestamps = [t for t in self._timestamps if t > cutoff]

                if len(self._timestamps) < self._max_qps:
                    self._timestamps.append(now)
                    return  # 成功获取配额

                # 窗口已满，计算需要等多久才能腾出一个位置
                oldest = self._timestamps[0]
                wait = oldest + 1.0 - now + 0.01  # +10ms 安全余量

            # 在锁外等待，不阻塞其他线程判断
            time.sleep(max(0.01, wait))

    def penalize(self, seconds=2.0):
        """收到 429 后惩罚冷却：人为占满窗口，强制所有线程减速"""
        with self._lock:
            now = time.time()
            # 填入 max_qps 个虚拟时间戳，使窗口在 seconds 秒后才释放
            self._timestamps = [now + seconds - 1.0] * self._max_qps


_duckmail_limiter = _DuckMailRateLimiter(max_qps=5)


class _MinIntervalLimiter:
    """最小调用间隔限速器（线程安全）"""

    def __init__(self, interval_seconds=0.0):
        self._interval = max(0.0, float(interval_seconds or 0.0))
        self._lock = threading.Lock()
        self._next_allowed_at = 0.0

    def acquire(self):
        interval = self._interval
        if interval <= 0:
            return

        while True:
            with self._lock:
                now = time.time()
                if now >= self._next_allowed_at:
                    self._next_allowed_at = now + interval
                    return
                wait = self._next_allowed_at - now
            time.sleep(max(0.01, wait))


def _chatgptmail_get_limiter(session):
    """ChatGPTMail 限速器按 session 独立，避免多账号共享一个全局间隔。"""
    interval = max(0.0, float(CHATGPTMAIL_REQUEST_INTERVAL or 0.0))
    limiter = getattr(session, "_chatgptmail_limiter", None)
    current_interval = max(0.0, float(getattr(limiter, "_interval", 0.0) or 0.0)) if limiter is not None else -1.0
    if limiter is None or abs(current_interval - interval) > 1e-9:
        limiter = _MinIntervalLimiter(interval)
        session._chatgptmail_limiter = limiter
    return limiter


def _duckmail_request(session, method, path, max_retries=5, **kwargs):
    """统一的 DuckMail API 请求封装（滑动窗口限速 + 429 自动退避重试）

    参数:
        session:     requests.Session
        method:      "GET" 或 "POST"
        path:        API 路径，如 "/accounts" 或 "/messages"
        max_retries: 重试次数（默认 5）
        **kwargs:    传递给 session.request 的其他参数
    返回:
        requests.Response 或 None（全部重试失败）
    """
    url = f"{DUCKMAIL_API_URL}{path}"
    kwargs.setdefault("verify", False)
    kwargs.setdefault("timeout", 30)

    for attempt in range(max_retries):
        _duckmail_limiter.acquire()
        try:
            resp = _mail_request(session, method, url, **kwargs)
            if resp.status_code == 429:
                # 惩罚冷却：通知所有线程减速
                backoff = min(2 ** attempt, 8) + random.uniform(0.5, 2.0)
                _duckmail_limiter.penalize(backoff)
                print(f"    ⚠️ DuckMail 429, 冷却 {backoff:.1f}s ({attempt+1}/{max_retries})")
                time.sleep(backoff)
                continue
            return resp
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"    ❌ DuckMail 请求异常: {e}")
                return None
            time.sleep(1 + random.uniform(0, 1))
    return None


# =================== 邮件 Provider 实现 ===================

def _duckmail_create_temp_email(session):
    """通过 DuckMail API 创建临时邮箱并获取 Bearer Token

    流程：
      1. POST /accounts  创建邮箱账号（address + password）
      2. POST /token      获取 Bearer Token

    返回:
      (address, token, mail_auth)  成功时返回邮箱地址、Bearer Token 和邮箱认证信息
      (None, None, None)           失败
    """
    print("📧 创建临时邮箱 (DuckMail)...")

    # 生成随机用户名（10~14 位字母 + 1~2 位数字）
    name_len = random.randint(10, 14)
    name_chars = list(random.choices(string.ascii_lowercase, k=name_len))
    for _ in range(random.choice([1, 2])):
        pos = random.randint(2, len(name_chars) - 1)
        name_chars.insert(pos, random.choice(string.digits))
    name = "".join(name_chars)
    address = f"{name}@{DUCKMAIL_DOMAIN}"

    # 为 DuckMail 账号生成一个随机密码（>= 6 字符）
    mail_password = "".join(random.choices(string.ascii_letters + string.digits, k=12))

    # 步骤1：创建账号（私有域名需要 API Key 认证）
    create_headers = {"Content-Type": "application/json"}
    if DUCKMAIL_API_KEY:
        create_headers["Authorization"] = f"Bearer {DUCKMAIL_API_KEY}"
    res = _duckmail_request(
        session, "POST", "/accounts",
        json={"address": address, "password": mail_password},
        headers=create_headers,
        timeout=15,
    )
    if res is None or res.status_code not in (200, 201):
        status = res.status_code if res is not None else "N/A"
        text = res.text[:200] if res is not None else ""
        print(f"  ❌ 创建失败: {status} {text}")
        return None, None, None

    # 步骤2：获取 Token
    res = _duckmail_request(
        session, "POST", "/token",
        json={"address": address, "password": mail_password},
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    if res is None or res.status_code != 200:
        status = res.status_code if res is not None else "N/A"
        text = res.text[:200] if res is not None else ""
        print(f"  ❌ 获取 Token 失败: {status} {text}")
        return None, None, None
    data = res.json()
    token = data.get("token", "")
    if not token:
        print(f"  ❌ 响应中无 token 字段")
        return None, None, None
    print(f"  ✅ 邮箱: {address}")
    return address, token, mail_password


def _duckmail_fetch_emails(session, email, mail_token, skip_ids=None, include_body=True, max_messages=40):
    """通过 DuckMail API 获取邮箱中的邮件列表（可选邮件详情）

    DuckMail 的列表接口 (GET /messages) 不含正文，因此详情需要额外请求
    GET /messages/{id}。本函数支持按需拉取，减少不必要 API 开销。

    参数:
        skip_ids:    已知旧邮件 ID 集合（这些邮件不会请求详情）
        include_body:是否拉取正文详情
        max_messages:最多处理最近 N 封邮件，避免历史邮件过多导致轮询变慢
    """
    if skip_ids is None:
        skip_ids = set()
    try:
        headers = {"Authorization": f"Bearer {mail_token}"}

        # 获取邮件列表
        res = _duckmail_request(
            session, "GET", "/messages",
            headers=headers,
        )
        if res is None or res.status_code != 200:
            status = res.status_code if res is not None else "None"
            print(f"    [fetch] GET /messages 失败: {status}")
            return []

        data = res.json()
        messages = data.get("hydra:member", [])
        if not isinstance(messages, list):
            return []

        # 按时间字段倒序（字段缺失时回退到 id）
        def _sort_key(msg):
            if not isinstance(msg, dict):
                return ""
            for key in ("createdAt", "created_at", "updatedAt", "updated_at", "date"):
                val = msg.get(key)
                if isinstance(val, str):
                    return val
            return str(msg.get("id", ""))

        messages = sorted(messages, key=_sort_key, reverse=True)
        if isinstance(max_messages, int) and max_messages > 0:
            messages = messages[:max_messages]

        results = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue

            msg_id = msg.get("id", "")
            from_info = msg.get("from", {})
            from_addr = from_info.get("address", "") if isinstance(from_info, dict) else ""
            subject = msg.get("subject", "")
            created_at = (
                msg.get("createdAt")
                or msg.get("created_at")
                or msg.get("updatedAt")
                or msg.get("updated_at")
                or msg.get("date")
                or ""
            )

            raw_content = ""
            detail_loaded = False

            # 仅在需要时拉取详情；skip_ids 内邮件不请求正文
            if not include_body or (msg_id and msg_id in skip_ids):
                detail_loaded = True
            elif msg_id:
                detail_res = _duckmail_request(
                    session, "GET", f"/messages/{msg_id}",
                    headers=headers,
                )
                if detail_res is not None and detail_res.status_code == 200:
                    detail = detail_res.json()
                    html_parts = detail.get("html", [])
                    if isinstance(html_parts, list):
                        raw_content = "".join(str(x) for x in html_parts if x)
                    if not raw_content:
                        raw_content = detail.get("text", "") or ""
                    detail_loaded = True

            # 统一字段名，兼容 wait_for_verification_code / extract_verification_code
            item = {
                "id": msg_id,
                "raw": raw_content,
                "source": from_addr,
                "subject": subject,
                "created_at": created_at,
                "detail_loaded": detail_loaded,
            }
            results.append(item)

        return results
    except Exception as e:
        print(f"    [fetch] 异常: {e}")
    return []


_ddg_capture_state_cache = None


def _ddgmail_parse_auth_marker(raw):
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        parsed = parse_qs(text, keep_blank_values=True)
    except Exception:
        return {}
    provider = str((parsed.get("provider") or [""])[0] or "").strip().lower()
    if provider not in {"ddg", "ddgmail", "duckduckgo"}:
        return {}
    return {
        "provider": DDG_AUTH_MARKER_PROVIDER,
        "account_id": str((parsed.get("account_id") or [""])[0] or "").strip(),
        "forward_email": str((parsed.get("forward_email") or [""])[0] or "").strip().lower(),
        "username": str((parsed.get("username") or [""])[0] or "").strip(),
    }


def _ddgmail_is_auth_marker(raw):
    return bool(_ddgmail_parse_auth_marker(raw))


def _ddgmail_build_auth_marker(account_id="", forward_email="", username=""):
    pairs = [("provider", DDG_AUTH_MARKER_PROVIDER)]
    if account_id:
        pairs.append(("account_id", str(account_id).strip()))
    if forward_email:
        pairs.append(("forward_email", str(forward_email).strip().lower()))
    if username:
        pairs.append(("username", str(username).strip()))
    return urlencode(pairs)


def _ddgmail_load_capture_state():
    global _ddg_capture_state_cache
    if isinstance(_ddg_capture_state_cache, dict):
        return dict(_ddg_capture_state_cache)

    candidates = []
    if DDG_CAPTURE_DIR:
        candidates.append(os.path.abspath(DDG_CAPTURE_DIR))

    base_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        auto_dirs = []
        for name in os.listdir(base_dir):
            full = os.path.join(base_dir, name)
            dashboard_path = os.path.join(full, "bodies", "response", "146.json")
            if not os.path.isdir(full) or not os.path.isfile(dashboard_path):
                continue
            if not re.match(r"^20\d{6}-\d{6}-[0-9a-f]{8}$", name):
                continue
            auto_dirs.append(full)
        auto_dirs.sort(key=lambda item: os.path.getmtime(item), reverse=True)
        for full in auto_dirs:
            if full not in candidates:
                candidates.append(full)
    except Exception:
        pass

    for directory in candidates:
        dashboard_path = os.path.join(directory, "bodies", "response", "146.json")
        verify_path = os.path.join(directory, "bodies", "response", "145.json")
        if not os.path.isfile(dashboard_path):
            continue
        try:
            with open(dashboard_path, "r", encoding="utf-8") as f:
                dashboard_payload = json.load(f)
        except Exception:
            continue
        user = dashboard_payload.get("user", {}) if isinstance(dashboard_payload, dict) else {}
        access_token = str(user.get("access_token", "") or "").strip()
        if not access_token:
            continue
        state = {
            "access_token": access_token,
            "auth_token": "",
            "username": str(user.get("username", "") or "").strip(),
            "forward_email": str(user.get("email", "") or "").strip().lower(),
            "capture_dir": directory,
        }
        try:
            if os.path.isfile(verify_path):
                with open(verify_path, "r", encoding="utf-8") as f:
                    verify_payload = json.load(f)
                state["auth_token"] = str(verify_payload.get("token", "") or "").strip()
        except Exception:
            pass
        _ddg_capture_state_cache = dict(state)
        return state

    _ddg_capture_state_cache = {}
    return {}


def _ddgmail_resolve_state():
    capture_state = _ddgmail_load_capture_state()
    return {
        "access_token": DDG_ACCESS_TOKEN or str(capture_state.get("access_token", "") or "").strip(),
        "auth_token": DDG_AUTH_TOKEN or str(capture_state.get("auth_token", "") or "").strip(),
        "username": DDG_USERNAME or str(capture_state.get("username", "") or "").strip(),
        "forward_email": DDG_FORWARD_EMAIL or str(capture_state.get("forward_email", "") or "").strip().lower(),
        "capture_dir": str(capture_state.get("capture_dir", "") or "").strip(),
    }


def _ddgmail_get_outlook_client(session):
    client = getattr(session, "_ddg_outlook_client", None)
    if client is None:
        client = create_session("", internal_plain=True)
        session._ddg_outlook_client = client
    return client


def _ddgmail_outlook_request(session, method, path, **kwargs):
    client = _ddgmail_get_outlook_client(session)
    url = f"{DDG_OUTLOOK_BASE_URL}{path}"
    kwargs.setdefault("timeout", 30)
    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("accept", "application/json")
    headers.setdefault("user-agent", USER_AGENT)
    return client.request(method, url, headers=headers, **kwargs)


def _ddgmail_request(session, method, path, **kwargs):
    url = f"{DDG_API_URL}{path}"
    kwargs.setdefault("verify", False)
    kwargs.setdefault("timeout", 30)
    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("accept", "application/json")
    headers.setdefault("referer", f"{DDG_BASE_URL}/")
    headers.setdefault("origin", DDG_BASE_URL)
    headers.setdefault("user-agent", USER_AGENT)
    return _mail_request(session, method, url, headers=headers, **kwargs)


def _ddgmail_refresh_access_token_from_dashboard(session):
    auth_token = str(getattr(session, "_ddg_auth_token", "") or "").strip()
    if not auth_token:
        return ""
    try:
        res = _ddgmail_request(
            session,
            "GET",
            "/api/email/dashboard",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        if res is None or res.status_code != 200:
            return ""
        payload = res.json() if res is not None else {}
        user = payload.get("user", {}) if isinstance(payload, dict) else {}
        access_token = str(user.get("access_token", "") or "").strip()
        if access_token:
            session._ddg_access_token = access_token
        if user.get("username"):
            session._ddg_username = str(user.get("username") or "").strip()
        if user.get("email"):
            session._ddg_forward_email = str(user.get("email") or "").strip().lower()
        return access_token
    except Exception:
        return ""


def _ddgmail_bootstrap_state(session):
    if not str(getattr(session, "_ddg_access_token", "") or "").strip():
        resolved = _ddgmail_resolve_state()
        session._ddg_access_token = str(resolved.get("access_token", "") or "").strip()
        session._ddg_auth_token = str(resolved.get("auth_token", "") or "").strip()
        session._ddg_username = str(resolved.get("username", "") or "").strip()
        session._ddg_forward_email = str(resolved.get("forward_email", "") or "").strip().lower()
        session._ddg_capture_dir = str(resolved.get("capture_dir", "") or "").strip()
    if not str(getattr(session, "_ddg_access_token", "") or "").strip():
        _ddgmail_refresh_access_token_from_dashboard(session)
    return {
        "access_token": str(getattr(session, "_ddg_access_token", "") or "").strip(),
        "auth_token": str(getattr(session, "_ddg_auth_token", "") or "").strip(),
        "username": str(getattr(session, "_ddg_username", "") or "").strip(),
        "forward_email": str(getattr(session, "_ddg_forward_email", "") or "").strip().lower(),
        "capture_dir": str(getattr(session, "_ddg_capture_dir", "") or "").strip(),
    }


def _ddgmail_resolve_outlook_account(session, preferred_account_id="", forward_email=""):
    account_id = str(preferred_account_id or getattr(session, "_ddg_outlook_account_id", "") or DDG_OUTLOOK_ACCOUNT_ID or "").strip()
    clean_forward_email = str(forward_email or getattr(session, "_ddg_forward_email", "") or "").strip().lower()
    if account_id:
        return {"account_id": account_id, "forward_email": clean_forward_email}

    try:
        res = _ddgmail_outlook_request(session, "GET", "/accounts")
        if res is None or res.status_code != 200:
            return {"account_id": "", "forward_email": clean_forward_email}
        payload = res.json()
    except Exception:
        return {"account_id": "", "forward_email": clean_forward_email}

    accounts = payload.get("accounts", []) if isinstance(payload, dict) else payload
    if not isinstance(accounts, list):
        return {"account_id": "", "forward_email": clean_forward_email}

    selected = None
    for account in accounts:
        if not isinstance(account, dict):
            continue
        username = str(account.get("username", "") or account.get("label", "") or "").strip().lower()
        if clean_forward_email and username == clean_forward_email:
            selected = account
            break

    if selected is None:
        ordered = sorted(
            [item for item in accounts if isinstance(item, dict)],
            key=lambda item: str(item.get("lastUsedAt") or item.get("updatedAt") or ""),
            reverse=True,
        )
        if ordered:
            selected = ordered[0]

    if not isinstance(selected, dict):
        return {"account_id": "", "forward_email": clean_forward_email}

    account_id = str(selected.get("id", "") or "").strip()
    username = str(selected.get("username", "") or selected.get("label", "") or "").strip().lower()
    if account_id:
        session._ddg_outlook_account_id = account_id
    if username:
        session._ddg_forward_email = username
    return {"account_id": account_id, "forward_email": username or clean_forward_email}


def _ddgmail_message_targets_alias(message, alias_email):
    target = str(alias_email or "").strip().lower()
    if not target or not isinstance(message, dict):
        return False
    for field in ("toRecipients", "ccRecipients", "bccRecipients"):
        recipients = message.get(field, [])
        if not isinstance(recipients, list):
            continue
        for item in recipients:
            address = ""
            if isinstance(item, dict):
                address = str(((item.get("emailAddress") or {}).get("address")) or "").strip().lower()
            if address == target:
                return True
    subject = str(message.get("subject", "") or "").strip().lower()
    preview = str(message.get("bodyPreview", "") or "").strip().lower()
    return target in subject or target in preview


def _ddgmail_create_temp_email(session, preferred_domain=""):
    preferred_domain = _extract_email_domain(preferred_domain)
    if preferred_domain and preferred_domain != DDG_ALIAS_DOMAIN:
        print(f"  ⚠️ DDG alias 仅支持 @{DDG_ALIAS_DOMAIN}，当前请求域名={preferred_domain}")
        return None, None, None

    print("📧 创建临时邮箱 (DuckDuckGo Alias)...")
    state = _ddgmail_bootstrap_state(session)
    access_token = str(state.get("access_token", "") or "").strip()
    if not access_token:
        print("  ❌ 未找到 DDG access_token（可通过 DDG_ACCESS_TOKEN 或抓包 146.json 自动发现）")
        return None, None, None

    resolved_outlook = _ddgmail_resolve_outlook_account(
        session,
        preferred_account_id=DDG_OUTLOOK_ACCOUNT_ID,
        forward_email=state.get("forward_email", ""),
    )
    outlook_account_id = str(resolved_outlook.get("account_id", "") or "").strip()
    forward_email = str(resolved_outlook.get("forward_email", "") or state.get("forward_email", "") or "").strip().lower()
    if not outlook_account_id:
        print("  ❌ 未找到 Outlook accountId（可通过 DDG_OUTLOOK_ACCOUNT_ID 指定）")
        return None, None, None

    def _do_create(current_access_token):
        return _ddgmail_request(
            session,
            "POST",
            "/api/email/addresses",
            headers={"Authorization": f"Bearer {current_access_token}"},
            json={},
        )

    res = _do_create(access_token)
    if res is not None and res.status_code in (401, 403):
        refreshed = _ddgmail_refresh_access_token_from_dashboard(session)
        if refreshed:
            access_token = refreshed
            res = _do_create(access_token)
    if res is None or res.status_code not in (200, 201):
        status = res.status_code if res is not None else "N/A"
        text = res.text[:200] if res is not None else ""
        print(f"  ❌ DDG alias 生成失败: {status} {text}")
        return None, None, None

    try:
        payload = res.json()
    except Exception:
        payload = {}
    local_part = str(payload.get("address", "") or "").strip()
    if not local_part:
        print("  ❌ DDG 响应中无 address 字段")
        return None, None, None

    address = local_part if "@" in local_part else f"{local_part}@{DDG_ALIAS_DOMAIN}"
    marker = _ddgmail_build_auth_marker(
        account_id=outlook_account_id,
        forward_email=forward_email,
        username=state.get("username", ""),
    )
    print(f"  ✅ 邮箱: {address}")
    return address, marker, marker


def _ddgmail_fetch_emails(session, email, mail_token, skip_ids=None, include_body=True, max_messages=40):
    if skip_ids is None:
        skip_ids = set()
    marker = _ddgmail_parse_auth_marker(mail_token)
    bootstrap_state = _ddgmail_bootstrap_state(session)
    resolved_outlook = _ddgmail_resolve_outlook_account(
        session,
        preferred_account_id=marker.get("account_id", ""),
        forward_email=marker.get("forward_email", "") or bootstrap_state.get("forward_email", ""),
    )
    account_id = str(resolved_outlook.get("account_id", "") or "").strip()
    if not account_id:
        print("    [fetch] DDG Outlook accountId 缺失")
        return []

    try:
        top = 50 if not isinstance(max_messages, int) or max_messages <= 0 else min(50, max(10, max_messages))
        res = _ddgmail_outlook_request(
            session,
            "GET",
            "/messages",
            params={"accountId": account_id, "top": top},
        )
        if res is None or res.status_code != 200:
            status = res.status_code if res is not None else "None"
            print(f"    [fetch] GET /messages 失败: {status}")
            return []

        payload = res.json()
        messages = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(messages, list):
            return []

        alias_email = str(email or "").strip().lower()
        filtered = [msg for msg in messages if _ddgmail_message_targets_alias(msg, alias_email)]
        filtered = sorted(filtered, key=lambda item: str(item.get("receivedDateTime") or ""), reverse=True)
        if isinstance(max_messages, int) and max_messages > 0:
            filtered = filtered[:max_messages]

        results = []
        for msg in filtered:
            if not isinstance(msg, dict):
                continue
            msg_id = str(msg.get("id", "") or "").strip()
            from_info = msg.get("from", {}) if isinstance(msg.get("from"), dict) else {}
            email_address = from_info.get("emailAddress", {}) if isinstance(from_info, dict) else {}
            source = str(email_address.get("address") or email_address.get("name") or "").strip()
            subject = str(msg.get("subject", "") or "").strip()
            created_at = str(msg.get("receivedDateTime", "") or "").strip()
            raw_content = str(msg.get("bodyPreview", "") or "").strip()
            detail_loaded = bool(raw_content) if not include_body else False

            if not include_body or (msg_id and msg_id in skip_ids):
                detail_loaded = True
            elif msg_id:
                detail_res = _ddgmail_outlook_request(
                    session,
                    "GET",
                    f"/messages/{quote(msg_id, safe='')}",
                    params={"accountId": account_id},
                )
                if detail_res is not None and detail_res.status_code == 200:
                    detail_payload = detail_res.json()
                    detail = detail_payload.get("data", {}) if isinstance(detail_payload, dict) else {}
                    body = detail.get("body", {}) if isinstance(detail, dict) else {}
                    if isinstance(body, dict):
                        raw_content = str(body.get("content", "") or raw_content)
                    else:
                        raw_content = str(body or raw_content)
                    if detail.get("subject"):
                        subject = str(detail.get("subject") or "").strip()
                    if detail.get("receivedDateTime"):
                        created_at = str(detail.get("receivedDateTime") or "").strip()
                    detail_loaded = True

            results.append({
                "id": msg_id,
                "raw": raw_content,
                "source": source,
                "subject": subject,
                "created_at": created_at,
                "detail_loaded": detail_loaded,
            })

        return results
    except Exception as e:
        print(f"    [fetch] DDG 异常: {e}")
    return []


def _chatgptmail_entry_path(email=""):
    """返回 ChatGPTMail 页面路径"""
    if email:
        return f"/{CHATGPTMAIL_LOCALE}/{quote(email, safe='')}"
    return f"/{CHATGPTMAIL_LOCALE}/"


def _chatgptmail_request(session, method, path, **kwargs):
    """统一的 ChatGPTMail 请求封装"""
    url = f"{CHATGPTMAIL_BASE_URL}{path}"
    kwargs.setdefault("verify", False)
    kwargs.setdefault("timeout", 30)
    retry_bootstrap = kwargs.pop("_retry_bootstrap", True)

    headers = kwargs.pop("headers", {}) or {}
    default_headers = {
        "user-agent": USER_AGENT,
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    if path.startswith("/api/"):
        default_headers.setdefault("accept", "application/json")
        auth_token = str(getattr(session, "_chatgptmail_auth_token", "") or "").strip()
        if auth_token and path != "/api/inbox-token":
            default_headers.setdefault("X-Inbox-Token", auth_token)
    merged_headers = {**default_headers, **headers}
    kwargs["headers"] = merged_headers

    try:
        _chatgptmail_get_limiter(session).acquire()
        resp = _mail_request(session, method, url, **kwargs)
        if (
            retry_bootstrap
            and path.startswith("/api/")
            and path != "/api/inbox-token"
            and resp is not None
            and resp.status_code == 401
        ):
            text = ""
            try:
                text = resp.text[:200]
            except Exception:
                pass
            if "Browser session required" in text and _chatgptmail_bootstrap_session(session, force=True):
                retry_headers = dict(merged_headers)
                auth_token = str(getattr(session, "_chatgptmail_auth_token", "") or "").strip()
                if auth_token:
                    retry_headers["X-Inbox-Token"] = auth_token
                retry_kwargs = dict(kwargs)
                retry_kwargs["headers"] = retry_headers
                return _chatgptmail_request(session, method, path, _retry_bootstrap=False, **retry_kwargs)
        return resp
    except Exception as e:
        print(f"    ❌ ChatGPTMail 请求异常: {e}")
        return None


def _chatgptmail_normalize_auth(auth):
    """标准化 ChatGPTMail auth 结构"""
    if not isinstance(auth, dict):
        return {"token": "", "email": "", "expires_at": 0}
    token = str(auth.get("token", "") or "").strip()
    email = str(auth.get("email", "") or "").strip().lower()
    expires_at = auth.get("expires_at", auth.get("expiresAt", 0))
    try:
        expires_at = int(expires_at or 0)
    except Exception:
        expires_at = 0
    return {"token": token, "email": email, "expires_at": expires_at}


def _chatgptmail_set_auth(session, auth):
    """把 auth 状态写回 session"""
    normalized = _chatgptmail_normalize_auth(auth)
    session._chatgptmail_auth_token = normalized["token"]
    session._chatgptmail_auth_email = normalized["email"]
    session._chatgptmail_auth_expires_at = normalized["expires_at"]
    return normalized


def _chatgptmail_sync_auth_from_payload(session, payload):
    """从 JSON 响应中同步 auth"""
    if isinstance(payload, dict) and isinstance(payload.get("auth"), dict):
        return _chatgptmail_set_auth(session, payload.get("auth"))
    return _chatgptmail_normalize_auth({})


def _chatgptmail_extract_bootstrap_auth(html_text):
    """从首页 HTML 中提取 window.__BROWSER_AUTH"""
    if not html_text:
        return {"token": "", "email": "", "expires_at": 0}
    match = re.search(r"window\.__BROWSER_AUTH\s*=\s*(\{.*?\})\s*;", html_text, re.S)
    if not match:
        return {"token": "", "email": "", "expires_at": 0}
    raw = match.group(1)
    try:
        return _chatgptmail_normalize_auth(json.loads(raw))
    except Exception:
        return {"token": "", "email": "", "expires_at": 0}


def _chatgptmail_bootstrap_session(session, force=False):
    """访问首页拿 gm_sid cookie"""
    if (
        not force
        and getattr(session, "_chatgptmail_bootstrapped", False)
        and session.cookies.get("gm_sid")
        and str(getattr(session, "_chatgptmail_auth_token", "") or "").strip()
    ):
        return True

    max_attempts = max(1, MAIL_PROXY_MAX_ROTATIONS + 1) if _mail_proxy_rotation_enabled_for_session(session) else 1

    for attempt in range(max_attempts):
        res = _chatgptmail_request(
            session,
            "GET",
            _chatgptmail_entry_path(),
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "upgrade-insecure-requests": "1",
            },
            allow_redirects=True,
        )

        if res is not None and res.status_code < 400:
            bootstrap_auth = _chatgptmail_extract_bootstrap_auth(getattr(res, "text", ""))
            _chatgptmail_set_auth(session, bootstrap_auth)
            session._chatgptmail_bootstrapped = True
            if not session.cookies.get("gm_sid"):
                print("  ⚠️ ChatGPTMail 初始化未拿到 gm_sid")
            if not bootstrap_auth.get("token"):
                print("  ⚠️ ChatGPTMail 初始化未提取到 browser auth token")
            return True

        status = res.status_code if res is not None else "N/A"
        should_rotate = (
            _mail_proxy_rotation_enabled_for_session(session)
            and attempt + 1 < max_attempts
        )
        if should_rotate:
            rotated = rotate_mail_proxy(
                session,
                reason=f"ChatGPTMail 初始化失败({status})，切换邮箱代理重试 ({attempt + 1}/{max_attempts - 1})",
            )
            if rotated:
                continue

        print(f"  ❌ ChatGPTMail 初始化失败: {status}")
        return False

    return False



def _chatgptmail_bind_inbox(session, email):
    """绑定当前会话到指定邮箱"""
    target_email = str(email or "").strip().lower()
    bound_email = str(getattr(session, "_chatgptmail_bound_email", "") or "").strip().lower()
    if bound_email == target_email and session.cookies.get("gm_sid"):
        _chatgptmail_set_last_error(session)
        return True

    _chatgptmail_set_last_error(session)

    max_attempts = 1
    if _mail_proxy_rotation_enabled_for_session(session) and MAIL_PROXY_ROTATE_ON_429:
        max_attempts = max(1, MAIL_PROXY_MAX_ROTATIONS + 1)

    for attempt in range(max_attempts):
        if not _chatgptmail_bootstrap_session(session):
            return False

        referer = f"{CHATGPTMAIL_BASE_URL}{_chatgptmail_entry_path(email)}"
        res = _chatgptmail_request(
            session,
            "POST",
            "/api/inbox-token",
            headers={
                "content-type": "application/json",
                "origin": CHATGPTMAIL_BASE_URL,
                "referer": referer,
            },
            json={"email": email},
        )
        if res is not None and res.status_code == 200:
            try:
                payload = res.json()
            except Exception:
                payload = {}
            auth = _chatgptmail_sync_auth_from_payload(session, payload)
            session._chatgptmail_bound_email = email
            if auth.get("email"):
                session._chatgptmail_bound_email = auth.get("email")
            _chatgptmail_set_last_error(session)
            return True

        status = res.status_code if res is not None else "N/A"
        text = res.text[:200] if res is not None else ""
        text_lower = text.lower()
        should_rotate = (
            _mail_proxy_rotation_enabled_for_session(session)
            and status == 429
            and "too many requests" in text_lower
            and attempt + 1 < max_attempts
        )
        if should_rotate:
            rotate_mail_proxy(session, reason=f"ChatGPTMail 429，切换邮箱代理重试 ({attempt + 1}/{max_attempts - 1})")
            continue

        if status == 400 and "unsupported email address" in text_lower:
            _chatgptmail_set_last_error(
                session,
                code="unsupported_email",
                message=text or "Unsupported email address",
                email=target_email,
            )

        print(f"  ❌ ChatGPTMail 绑定收件箱失败: {status} {text}")
        return False

    return False

def _chatgptmail_create_temp_email(session, preferred_domain=""):
    """通过 ChatGPTMail 生成临时邮箱并绑定当前收件箱"""
    preferred_domain = _extract_email_domain(preferred_domain)
    print("📧 创建临时邮箱 (ChatGPTMail)...")

    if not _chatgptmail_bootstrap_session(session):
        return None, None, None

    if preferred_domain:
        address = f"probe{secrets.token_hex(4)}@{preferred_domain}"
        if not _chatgptmail_bind_inbox(session, address):
            return None, None, None
        print(f"  ✅ 邮箱: {address} (固定域名)")
        return address, CHATGPTMAIL_AUTH_MARKER, CHATGPTMAIL_AUTH_MARKER

    res = _chatgptmail_request(
        session,
        "GET",
        "/api/generate-email",
        headers={
            "content-type": "application/json",
            "referer": f"{CHATGPTMAIL_BASE_URL}{_chatgptmail_entry_path()}",
        },
    )
    if res is None or res.status_code != 200:
        status = res.status_code if res is not None else "N/A"
        text = res.text[:200] if res is not None else ""
        print(f"  ❌ ChatGPTMail 生成邮箱失败: {status} {text}")
        return None, None, None

    try:
        payload = res.json()
    except Exception:
        payload = {}

    _chatgptmail_sync_auth_from_payload(session, payload)
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    auth = payload.get("auth", {}) if isinstance(payload, dict) else {}
    address = data.get("email") or auth.get("email") or ""
    if not address:
        print("  ❌ ChatGPTMail 响应中无 email 字段")
        return None, None, None

    if not _chatgptmail_bind_inbox(session, address):
        return None, None, None

    print(f"  ✅ 邮箱: {address}")
    return address, CHATGPTMAIL_AUTH_MARKER, CHATGPTMAIL_AUTH_MARKER


def _chatgptmail_fetch_emails(session, email, mail_token, skip_ids=None, include_body=True, max_messages=40):
    """通过 ChatGPTMail API 获取邮件列表并按需打开邮件详情"""
    del mail_token
    if skip_ids is None:
        skip_ids = set()

    try:
        if not _chatgptmail_bind_inbox(session, email):
            return []

        referer = f"{CHATGPTMAIL_BASE_URL}{_chatgptmail_entry_path(email)}"
        res = _chatgptmail_request(
            session,
            "GET",
            "/api/emails",
            params={"email": email},
            headers={"referer": referer},
        )
        if res is None or res.status_code != 200:
            status = res.status_code if res is not None else "None"
            print(f"    [fetch] GET /api/emails 失败: {status}")
            return []

        payload = res.json()
        _chatgptmail_sync_auth_from_payload(session, payload)
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        messages = data.get("emails", [])
        if not isinstance(messages, list):
            return []

        def _sort_key(msg):
            if not isinstance(msg, dict):
                return 0
            ts = msg.get("timestamp")
            if isinstance(ts, (int, float)):
                return ts
            created_at = msg.get("created_at") or msg.get("createdAt") or ""
            return str(created_at)

        messages = sorted(messages, key=_sort_key, reverse=True)
        if isinstance(max_messages, int) and max_messages > 0:
            messages = messages[:max_messages]

        results = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue

            msg_id = msg.get("id", "")
            from_addr = msg.get("from_address", "")
            subject = msg.get("subject", "")
            created_at = msg.get("created_at") or msg.get("createdAt") or msg.get("timestamp") or ""
            raw_content = msg.get("html_content") or msg.get("content") or ""
            detail_loaded = bool(raw_content)

            if not include_body or (msg_id and msg_id in skip_ids):
                detail_loaded = True
            elif msg_id:
                detail_res = _chatgptmail_request(
                    session,
                    "GET",
                    f"/api/email/{msg_id}",
                    headers={"referer": referer},
                )
                if detail_res is not None and detail_res.status_code == 200:
                    detail_payload = detail_res.json()
                    _chatgptmail_sync_auth_from_payload(session, detail_payload)
                    detail = detail_payload.get("data", {}) if isinstance(detail_payload, dict) else {}
                    raw_content = detail.get("html_content") or detail.get("content") or raw_content
                    from_addr = detail.get("from_address") or from_addr
                    subject = detail.get("subject") or subject
                    created_at = detail.get("created_at") or detail.get("createdAt") or created_at
                    detail_loaded = True

            item = {
                "id": msg_id,
                "raw": raw_content,
                "source": from_addr,
                "subject": subject,
                "created_at": created_at,
                "detail_loaded": detail_loaded,
            }
            results.append(item)

        return results
    except Exception as e:
        print(f"    [fetch] ChatGPTMail 异常: {e}")
    return []


def create_temp_email(session, preferred_domain=""):
    """按配置的 provider 创建临时邮箱，并跳过已拉黑域名。"""
    preferred_domain = _extract_email_domain(preferred_domain)
    if MAIL_PROVIDER == "chatgptmail":
        provider_fn = lambda current_session: _chatgptmail_create_temp_email(
            current_session,
            preferred_domain=preferred_domain,
        )
    elif MAIL_PROVIDER == "ddg":
        provider_fn = lambda current_session: _ddgmail_create_temp_email(
            current_session,
            preferred_domain=preferred_domain,
        )
    else:
        provider_fn = _duckmail_create_temp_email
    blocked_domains = load_bad_email_domains() if AUTO_BLACKLIST_BAD_EMAIL_DOMAINS else {}
    max_attempts = BAD_EMAIL_GENERATE_MAX_ATTEMPTS if AUTO_BLACKLIST_BAD_EMAIL_DOMAINS else 1

    for attempt in range(max_attempts):
        email, email_id, mail_auth = provider_fn(session)
        if not email:
            return None, None, None

        domain = _extract_email_domain(email)
        meta = blocked_domains.get(domain, {}) if domain else {}
        if domain and meta:
            reason = str(meta.get("last_code") or meta.get("last_message") or "blocked").strip()
            print(f"  ⚠️ 命中已拉黑邮箱域名，丢弃重开: {email} ({reason})")
            if attempt + 1 >= max_attempts:
                print("  ❌ 连续命中黑名单域名，放弃本轮邮箱创建")
                return None, None, None
            continue

        return email, email_id, mail_auth

    return None, None, None


def fetch_emails(session, email, mail_token, skip_ids=None, include_body=True, max_messages=40):
    """按 provider 拉取邮件列表"""
    token_text = str(mail_token or "").strip().lower()
    if token_text == CHATGPTMAIL_AUTH_MARKER:
        return _chatgptmail_fetch_emails(
            session, email, mail_token,
            skip_ids=skip_ids,
            include_body=include_body,
            max_messages=max_messages,
        )
    if _ddgmail_is_auth_marker(mail_token):
        return _ddgmail_fetch_emails(
            session, email, mail_token,
            skip_ids=skip_ids,
            include_body=include_body,
            max_messages=max_messages,
        )
    return _duckmail_fetch_emails(
        session, email, mail_token,
        skip_ids=skip_ids,
        include_body=include_body,
        max_messages=max_messages,
    )


def _normalize_mail_text(text):
    """将邮件 HTML/纯文本统一清洗为可检索文本"""
    if not text:
        return ""
    txt = unescape(str(text))
    txt = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", txt)
    txt = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", txt)
    txt = re.sub(r"(?i)<br\s*/?>", "\n", txt)
    txt = re.sub(r"(?i)</p\s*>", "\n", txt)
    txt = re.sub(r"(?is)<[^>]+>", " ", txt)
    txt = txt.replace("\xa0", " ")
    txt = re.sub(r"[ \t\r\f\v]+", " ", txt)
    txt = re.sub(r"\n+", "\n", txt)
    return txt.strip()


def _extract_openai_error_details(resp):
    code = ""
    message = ""
    if resp is None:
        return code, message

    try:
        payload = resp.json()
    except Exception:
        payload = None

    if isinstance(payload, dict):
        error = payload.get("error") if isinstance(payload.get("error"), dict) else payload
        if isinstance(error, dict):
            code = str(error.get("code") or "").strip()
            message = str(error.get("message") or "").strip()

    if code or message:
        return code, message

    text = str(getattr(resp, "text", "") or "")
    match = re.search(r'"code"\s*:\s*"([^"]+)"', text)
    if match:
        code = match.group(1).strip()
    match = re.search(r'"message"\s*:\s*"([^"]+)"', text)
    if match:
        message = match.group(1).strip()
    return code, message


def _collect_candidate_codes(text):
    """提取候选验证码，支持 123456 / 123-456 / 123 456"""
    if not text:
        return []

    candidates = []

    # 6 位连续数字
    for m in re.finditer(r"(?<!\d)(\d{6})(?!\d)", text):
        candidates.append((m.group(1), m.start(1)))

    # 3-3 分组数字
    for m in re.finditer(r"(?<!\d)(\d{3})[\s\-](\d{3})(?!\d)", text):
        code = f"{m.group(1)}{m.group(2)}"
        candidates.append((code, m.start(1)))

    return candidates


def extract_verification_code(content, subject=""):
    """从邮件正文/主题提取 6 位验证码（带关键词上下文识别）"""
    subject_text = _normalize_mail_text(subject)
    body_text = _normalize_mail_text(content)

    occurrences = []
    for code, pos in _collect_candidate_codes(subject_text):
        occurrences.append((code, pos, "subject", subject_text))
    for code, pos in _collect_candidate_codes(body_text):
        occurrences.append((code, pos, "body", body_text))

    if not occurrences:
        return None

    blocked_codes = {"177010"}
    hint_words = (
        "verification", "verify", "code", "otp", "passcode", "one-time",
        "验证码", "校验码", "动态码", "登录", "验证",
    )

    best_by_code = {}
    for code, pos, src, src_text in occurrences:
        if code in blocked_codes:
            continue

        left = max(0, pos - 48)
        right = min(len(src_text), pos + 48)
        window = src_text[left:right]
        window_lower = window.lower()

        score = 3 if src == "subject" else 0
        if any(word in window_lower for word in hint_words):
            score += 3
        if re.search(rf"(verification|verify|code|otp|passcode|验证码)[^0-9]{{0,18}}{code}", window, re.I):
            score += 4
        if re.search(rf"{code}[^0-9]{{0,18}}(verification|verify|code|otp|passcode|验证码)", window, re.I):
            score += 3
        if "openai" in window_lower or "chatgpt" in window_lower:
            score += 1

        prev = best_by_code.get(code, -999)
        if score > prev:
            best_by_code[code] = score

    if best_by_code:
        code, score = max(best_by_code.items(), key=lambda kv: (kv[1], kv[0]))
        if score > 0:
            return code

    # 回退策略：如果全局仅出现一个候选码，直接返回
    uniq_codes = []
    for code, _, _, _ in occurrences:
        if code in blocked_codes:
            continue
        if code not in uniq_codes:
            uniq_codes.append(code)
    if len(uniq_codes) == 1:
        return uniq_codes[0]

    return None


def capture_mail_snapshot(email, email_id, proxy_url=None, session=None):
    """捕获当前邮箱中所有邮件的 ID 集合（用于区分新旧邮件）

    必须在 OTP 发送前调用，这样 OTP 邮件的 ID 不会出现在返回的集合中。
    """
    if not email_id:
        return set()
    created_session = None
    try:
        s = session
        if s is None:
            s = create_mail_session(proxy_url)
            created_session = s
        # 快照只需要 ID，不拉正文详情，降低请求量
        emails = fetch_emails(s, email, email_id, include_body=False, max_messages=100)
        if emails:
            return {e.get("id") for e in emails if isinstance(e, dict) and e.get("id")}
    except Exception:
        pass
    finally:
        if created_session is not None:
            _close_session(created_session)
    return set()




def wait_for_verification_code(
    session,
    email,
    mail_token,
    timeout=REGISTER_OTP_TIMEOUT_SECONDS,
    pre_otp_ids=None,
    resend_fn=None,
):
    """等待验证邮件并提取验证码（DuckMail）

    参数:
        pre_otp_ids: OTP 发送前捕获的旧邮件 ID 集合。如果提供，直接使用；
                     如果不提供，函数内部 fetch（但可能因时序问题误含 OTP 邮件）。
        resend_fn:   可选回调函数，无新邮件超过阈值时自动调用一次以重发 OTP。
    """
    print(f"  ⏳ 等待验证码 (最大 {timeout}s)...")

    def _abort_on_unsupported_email():
        err_code, err_msg, err_email = _chatgptmail_get_last_error(session)
        if err_code != "unsupported_email":
            return False
        detail = err_msg or err_email or email
        print(f"  ⚠️ ChatGPTMail 不支持该邮箱地址，停止等待验证码: {err_email or email}")
        if detail:
            print(f"    详情: {detail[:200]}")
        return True

    if _abort_on_unsupported_email():
        return None

    if pre_otp_ids is not None:
        old_ids = {x for x in pre_otp_ids if x}
        print(f"    使用预捕获快照: {len(old_ids)} 封旧邮件")
    else:
        old_ids = set()
        # 初始化阶段只需旧邮件 ID，无需拉正文
        old = fetch_emails(session, email, mail_token, include_body=False, max_messages=100)
        if _abort_on_unsupported_email():
            return None
        if old:
            old_ids = {e.get("id") for e in old if isinstance(e, dict) and e.get("id")}
            print(f"    已有 {len(old_ids)} 封旧邮件")

    base_poll = max(0.5, float(MAIL_POLL_BASE_SECONDS or 1.5))
    max_poll = max(base_poll, float(MAIL_POLL_MAX_SECONDS or base_poll))
    empty_backoff_step = max(0.0, float(MAIL_POLL_EMPTY_BACKOFF_STEP_SECONDS or 0.0))
    poll_jitter = max(0.0, float(MAIL_POLL_JITTER_SECONDS or 0.0))
    resend_after = max(5.0, float(OTP_RESEND_AFTER_SECONDS or 20.0))
    start = time.time()
    poll_count = 0
    last_status_time = start
    last_new_mail_elapsed = 0.0
    no_new_rounds = 0
    resent = False  # 是否已重发

    while time.time() - start < timeout:
        poll_count += 1
        elapsed = time.time() - start

        # 中途重发：连续一段时间无新邮件才重发，避免过早触发
        if not resent and resend_fn and (elapsed - last_new_mail_elapsed) >= resend_after:
            print(f"    🔄 {resend_after:.0f}s 无新邮件，触发 OTP 重发...")
            try:
                resend_fn()
                resent = True
            except Exception as e:
                print(f"    ⚠️ OTP 重发异常: {e}")
                resent = True  # 不再重试

        emails = fetch_emails(
            session, email, mail_token,
            skip_ids=old_ids,
            include_body=True,
            max_messages=60,
        )
        if _abort_on_unsupported_email():
            return None

        if not emails:
            no_new_rounds += 1
            if time.time() - last_status_time >= 15:
                print(f"    ... 第{poll_count}轮, 已等 {elapsed:.0f}s, 邮件列表为空")
                last_status_time = time.time()
            sleep_for = min(max_poll, base_poll + no_new_rounds * empty_backoff_step) + random.uniform(0, poll_jitter)
            time.sleep(sleep_for)
            continue

        # 过滤出新邮件
        new_items = [e for e in emails if isinstance(e, dict) and e.get("id") not in old_ids]

        if not new_items:
            no_new_rounds += 1
            if time.time() - last_status_time >= 15:
                print(f"    ... 第{poll_count}轮, {elapsed:.0f}s, 共{len(emails)}封/新0封, 无可用验证码")
                last_status_time = time.time()
            sleep_for = min(max_poll, base_poll + no_new_rounds * empty_backoff_step) + random.uniform(0, poll_jitter)
            time.sleep(sleep_for)
            continue

        # 有新邮件：优先处理看起来像 OpenAI/验证码通知的邮件
        def _priority(item):
            src = str(item.get("source", "")).lower()
            sub = str(item.get("subject", "")).lower()
            likely_otp = any(k in src or k in sub for k in ("openai", "chatgpt", "noreply", "verification", "otp"))
            detail_loaded = bool(item.get("detail_loaded"))
            return (1 if likely_otp else 0, 1 if detail_loaded else 0)

        new_items.sort(key=_priority, reverse=True)
        last_new_mail_elapsed = elapsed
        no_new_rounds = 0
        pending_retry = 0

        # 找到新邮件，检查验证码
        for item in new_items:
            raw = item.get("raw", "")
            source = item.get("source", "未知")
            subject = item.get("subject", "无标题")
            mid = item.get("id")
            detail_loaded = bool(item.get("detail_loaded"))
            print(f"    📩 新邮件: from={source[:40]}, subject={subject[:40]}")
            code = extract_verification_code(raw, subject=subject)
            if code:
                print(f"  ✅ 验证码: {code}")
                return code

            # 详情没拉到时，不立刻丢弃该邮件，下一轮重试详情
            if not detail_loaded and not raw:
                pending_retry += 1
                print(f"    ⏳ 邮件详情暂不可用，下一轮重试")
                continue

            print(f"    ⚠️ 未从此邮件中提取到验证码")
            if raw:
                print(f"    raw预览: {raw[:200]}")

            # 只有已完整处理过的邮件才加入 old_ids，防止漏码
            if mid:
                old_ids.add(mid)

        if pending_retry and time.time() - last_status_time >= 10:
            print(f"    ... {pending_retry} 封新邮件详情未就绪，将继续重试")
            last_status_time = time.time()

        time.sleep(base_poll + random.uniform(0, poll_jitter))
    print(f"  ⏰ 等待验证码超时 (共轮询 {poll_count} 次, 耗时 {time.time()-start:.0f}s)")
    return None

class ProtocolRegistrar:
    """
    协议注册机核心类 v3 — 纯 HTTP 实现

    架构：
      全部步骤均通过 requests 构造 HTTP 请求完成。
      Sentinel token 通过逆向的 PoW 算法纯 Python 生成。
      
    流程（基于浏览器抓包验证的真实 API 链）：
      步骤0:   OAuth 会话初始化 → 获取 login_session cookie（纯 HTTP 302 跟随）
      步骤1+2: 注册账号         → POST /api/accounts/user/register {username, password}
      步骤3:   触发验证码       → GET  /api/accounts/email-otp/send
      步骤4:   验证邮箱         → POST /api/accounts/email-otp/validate
      步骤5:   创建账号         → POST /api/accounts/create_account
    """

    def __init__(self, proxy_url=None, mail_session=None, relay_state=None):
        # HTTP 会话（全流程纯 HTTP，cookies 通过 302 跟随自动累积）
        self.proxy_url = _effective_proxy(proxy_url)
        self.relay_state = relay_state if isinstance(relay_state, dict) else None
        self.session = create_session(self.proxy_url, relay_state=self.relay_state)
        self.mail_session = mail_session or create_mail_session(self.proxy_url, relay_state=self.relay_state)
        self.device_id = generate_device_id()
        self.use_mode5 = PROXY_MODE == 5
        if self.use_mode5:
            self.sentinel_gen = SentinelTokenGenerator(
                device_id=self.device_id,
                user_agent=MODE5_USER_AGENT,
                script_src=MODE5_SENTINEL_SDK_URL,
                frame_url=MODE5_SENTINEL_FRAME_URL,
                sec_ch_ua=MODE5_SEC_CH_UA,
            )
        else:
            self.sentinel_gen = SentinelTokenGenerator(device_id=self.device_id)
        self.code_verifier = None
        self.state = None
        self.last_create_account_error_code = ""
        self.last_create_account_error_message = ""
        self.last_create_account_continue_url = ""
        self.last_create_account_page_type = ""
        self.last_create_account_retry_reason = ""
        self.last_create_account_used_browser = False
        self.mode5_auth_session_logging_id = ""
        self.mode5_state = ""
        self.mode5_last_continue_url = ""
        self.mode5_last_page_type = ""
        self.mode5_email_verification_ready = False

    def _build_headers(self, referer, with_sentinel=False):
        """
        构造完整的 API 请求头
        
        参数:
            referer: 页面来源 URL
            with_sentinel: 是否附加 sentinel token
        """
        headers = dict(COMMON_HEADERS)
        headers["referer"] = referer
        headers["oai-device-id"] = self.device_id
        headers.update(generate_datadog_trace())

        if with_sentinel:
            token = self.sentinel_gen.generate_token()
            headers["openai-sentinel-token"] = token

        return headers

    def _reset_create_account_state(self):
        self.last_create_account_error_code = ""
        self.last_create_account_error_message = ""
        self.last_create_account_continue_url = ""
        self.last_create_account_page_type = ""
        self.last_create_account_retry_reason = ""
        self.last_create_account_used_browser = False
        self.mode5_last_continue_url = ""
        self.mode5_last_page_type = ""

    def _remember_create_account_response_meta(self, resp_obj):
        continue_url = ""
        page_type = ""
        try:
            payload_obj = resp_obj.json() or {}
        except Exception:
            payload_obj = {}
        if isinstance(payload_obj, dict):
            continue_url = str(
                payload_obj.get("continue_url")
                or ((payload_obj.get("page") or {}).get("payload") or {}).get("url")
                or ""
            ).strip()
            page_type = str((payload_obj.get("page") or {}).get("type") or "").strip()
        if not continue_url:
            continue_url = str((getattr(resp_obj, "headers", {}) or {}).get("Location") or "").strip()
        if continue_url.startswith("/"):
            continue_url = f"{OPENAI_AUTH_BASE}{continue_url}"

        self.last_create_account_continue_url = continue_url
        self.last_create_account_page_type = page_type
        self.mode5_last_continue_url = continue_url
        self.mode5_last_page_type = page_type

        meta_text = f"{continue_url} {page_type}".lower()
        if "add-phone" in meta_text or page_type == "add_phone":
            self.last_create_account_retry_reason = "about_you_add_phone_pending"
        else:
            self.last_create_account_retry_reason = ""

    def _browser_create_account_token(self, flow="oauth_create_account"):
        proxy_server = _session_proxy_url(self.session) or self.proxy_url
        token_json, browser_data = _browser_sentinel_token_json(
            proxy_server=proxy_server,
            flow=flow,
            device_id=self.device_id,
            user_agent=MODE5_USER_AGENT if self.use_mode5 else USER_AGENT,
            frame_url=MODE5_SENTINEL_FRAME_URL,
        )
        return token_json, browser_data, proxy_server

    def _mode5_origin(self, url):
        parsed = urlparse(str(url or ""))
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return OPENAI_AUTH_BASE

    def _mode5_nav_headers(self, referer, accept=None):
        headers = {
            "accept": accept or NAVIGATE_HEADERS["accept"],
            "accept-language": "en-US,en;q=0.9",
            "referer": referer,
            "upgrade-insecure-requests": "1",
            "user-agent": MODE5_USER_AGENT,
            "sec-ch-ua": MODE5_SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        return headers

    def _mode5_fetch_headers(self, referer, content_type="application/json", accept="application/json", origin=None):
        headers = {
            "accept": accept,
            "accept-language": "en-US,en;q=0.9",
            "origin": origin or self._mode5_origin(referer),
            "referer": referer,
            "user-agent": MODE5_USER_AGENT,
            "sec-ch-ua": MODE5_SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        if content_type:
            headers["content-type"] = content_type
        return headers

    def _mode5_oai_did_cookie_domains(self):
        domains = [".openai.com", ".auth.openai.com", "auth.openai.com"]
        if MODE5_TEST_CHATGPT_OAI_DID_COOKIE:
            domains.extend([".chatgpt.com", "chatgpt.com"])
        return tuple(domains)

    def _mode5_seed_oai_did_cookies(self):
        for domain in self._mode5_oai_did_cookie_domains():
            try:
                self.session.cookies.set("oai-did", self.device_id, domain=domain)
            except Exception:
                pass

    def _mode5_sync_device_id(self, new_device_id, reason=""):
        new_device_id = str(new_device_id or "").strip()
        if not new_device_id:
            return False
        if new_device_id == self.device_id:
            self._mode5_seed_oai_did_cookies()
            return False

        old_device_id = self.device_id
        self.device_id = new_device_id
        try:
            self.sentinel_gen.device_id = new_device_id
        except Exception:
            pass
        self._mode5_seed_oai_did_cookies()
        print(f"  🔄 device_id 已同步: {old_device_id} -> {new_device_id}" + (f" ({reason})" if reason else ""))
        return True

    def _mode5_manual_authorize_url(self, email):
        if not self.mode5_auth_session_logging_id:
            self.mode5_auth_session_logging_id = str(uuid.uuid4())
        if not self.mode5_state:
            self.mode5_state = secrets.token_urlsafe(32)
        params = {
            "client_id": MODE5_CHATGPT_CLIENT_ID,
            "scope": MODE5_CHATGPT_SCOPE,
            "response_type": "code",
            "redirect_uri": MODE5_CHATGPT_REDIRECT_URI,
            "audience": MODE5_CHATGPT_AUDIENCE,
            "device_id": self.device_id,
            "prompt": "login",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": self.mode5_auth_session_logging_id,
            "screen_hint": "login_or_signup",
            "state": self.mode5_state,
        }
        return f"{OPENAI_AUTH_BASE}/api/accounts/authorize?{urlencode(params)}"

    def step0_init_oauth_session_mode5(self, email):
        print("\n🔗 [步骤0-M5] ChatGPT 成功包链路初始化")

        self.mode5_auth_session_logging_id = str(uuid.uuid4())
        self.mode5_state = secrets.token_urlsafe(32)
        self.mode5_email_verification_ready = False

        self._mode5_seed_oai_did_cookies()

        login_referer = f"{CHATGPT_BASE}/auth/login?next=%2F%3Fopenaicom_referred%3Dtrue"
        callback_url = "/?openaicom_referred=true"
        chatgpt_root = f"{CHATGPT_BASE}/?openaicom_referred=true"

        try:
            self.session.get(
                chatgpt_root,
                headers=self._mode5_nav_headers(login_referer),
                allow_redirects=True,
                verify=False,
                timeout=30,
            )
        except Exception:
            pass

        csrf_url = f"{CHATGPT_BASE}/api/auth/csrf"
        base_headers = self._mode5_fetch_headers(login_referer, content_type="application/json", origin=CHATGPT_BASE)

        try:
            resp = self.session.get(csrf_url, headers=base_headers, verify=False, timeout=30)
            print(f"  csrf: {resp.status_code}")
        except Exception as e:
            print(f"  ❌ 获取 csrf 失败: {e}")
            return False
        if resp.status_code != 200:
            print(f"  ❌ csrf 返回异常: {resp.status_code}")
            return False

        try:
            csrf_token = str((resp.json() or {}).get("csrfToken") or "").strip()
        except Exception:
            csrf_token = ""
        if not csrf_token:
            print("  ❌ csrfToken 为空")
            return False

        signin_params = {
            "prompt": "login",
            "screen_hint": "login_or_signup",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": self.mode5_auth_session_logging_id,
        }
        signin_url = f"{CHATGPT_BASE}/api/auth/signin/openai?{urlencode(signin_params)}"
        signin_headers = self._mode5_fetch_headers(
            login_referer,
            content_type="application/x-www-form-urlencoded",
            origin=CHATGPT_BASE,
        )
        signin_body = {
            "callbackUrl": callback_url,
            "csrfToken": csrf_token,
            "json": "true",
        }

        try:
            resp = self.session.post(
                signin_url,
                data=signin_body,
                headers=signin_headers,
                verify=False,
                timeout=30,
            )
            print(f"  signin/openai: {resp.status_code}")
        except Exception as e:
            print(f"  ❌ signin/openai 失败: {e}")
            return False
        if resp.status_code != 200:
            print(f"  ❌ signin/openai 返回异常: {resp.status_code} | {resp.text[:200]}")
            return False

        auth_url = ""
        try:
            payload = resp.json() or {}
            auth_url = str(payload.get("url") or "").strip()
        except Exception:
            auth_url = ""
        if auth_url.startswith("/"):
            auth_url = f"{OPENAI_AUTH_BASE}{auth_url}"
        if auth_url:
            try:
                auth_query = parse_qs(urlparse(auth_url).query)
                parsed_state = auth_query.get("state", [""])[0]
                if parsed_state:
                    self.mode5_state = parsed_state
                if MODE5_TEST_SYNC_SIGNIN_DEVICE_ID:
                    auth_device_id = str(auth_query.get("device_id", [""])[0] or "").strip()
                    if auth_device_id:
                        synced = self._mode5_sync_device_id(auth_device_id, reason="signin/openai auth_url")
                        if synced:
                            parsed_auth_url = urlparse(auth_url)
                            auth_query["device_id"] = [self.device_id]
                            auth_query["ext-oai-did"] = [self.device_id]
                            auth_url = parsed_auth_url._replace(query=urlencode(auth_query, doseq=True)).geturl()
                            print("  🔄 authorize URL 中的 device_id / ext-oai-did 已同步为同一值")
            except Exception:
                pass
        if not auth_url:
            auth_url = self._mode5_manual_authorize_url(email)
            print("  ⚠️ 未从 signin/openai 拿到 url，已回退手工拼 authorize")

        try:
            resp = self.session.get(
                auth_url,
                headers=self._mode5_nav_headers(login_referer),
                allow_redirects=True,
                verify=False,
                timeout=30,
            )
            print(f"  authorize: {resp.status_code} -> {resp.url[:120]}")
        except Exception as e:
            print(f"  ❌ authorize 失败: {e}")
            return False

        login_or_create_url = f"{OPENAI_AUTH_BASE}/log-in-or-create-account"
        try:
            page_resp = self.session.get(
                login_or_create_url,
                headers=self._mode5_nav_headers(auth_url),
                allow_redirects=True,
                verify=False,
                timeout=30,
            )
            print(f"  log-in-or-create-account: {page_resp.status_code}")
        except Exception as e:
            print(f"  ❌ log-in-or-create-account 失败: {e}")
            return False
        if page_resp.status_code != 200:
            return False

        headers = self._mode5_fetch_headers(
            referer=login_or_create_url,
            origin=OPENAI_AUTH_BASE,
        )
        headers.update(generate_datadog_trace())

        sentinel_token = build_sentinel_token(
            self.session,
            self.device_id,
            flow="authorize_continue",
            sentinel_gen=self.sentinel_gen,
        )
        if not sentinel_token:
            print("  ❌ 无法获取 authorize_continue 的 sentinel token")
            return False
        headers["openai-sentinel-token"] = sentinel_token

        try:
            resp = self.session.post(
                f"{OPENAI_AUTH_BASE}/api/accounts/authorize/continue",
                json={
                    "username": {"kind": "email", "value": email},
                    "screen_hint": "login_or_signup",
                },
                headers=headers,
                verify=False,
                timeout=30,
            )
            print(f"  authorize/continue: {resp.status_code}")
        except Exception as e:
            print(f"  ❌ authorize/continue 失败: {e}")
            return False
        if resp.status_code != 200:
            print(f"  ❌ authorize/continue 返回异常: {resp.status_code} | {resp.text[:200]}")
            return False

        try:
            payload = resp.json() or {}
        except Exception:
            payload = {}
        page_type = str((payload.get("page") or {}).get("type") or "").strip()
        continue_url = str(payload.get("continue_url") or "").strip()
        self.mode5_last_continue_url = continue_url
        self.mode5_last_page_type = page_type
        print(f"  page={page_type or '-'} continue={continue_url[:120] if continue_url else '-'}")

        return bool(
            page_type == "create_account_password"
            or "/create-account/password" in continue_url
        )

    def step2_register_user_mode5(self, email, password):
        print(f"\n🔑 [步骤2-M5] 注册用户: {email}")
        url = f"{OPENAI_AUTH_BASE}/api/accounts/user/register"
        headers = self._mode5_fetch_headers(
            referer=f"{OPENAI_AUTH_BASE}/create-account/password",
            origin=OPENAI_AUTH_BASE,
        )
        headers.update(generate_datadog_trace())
        sentinel_token = build_sentinel_token(
            self.session,
            self.device_id,
            flow="username_password_create",
            sentinel_gen=self.sentinel_gen,
        )
        if not sentinel_token:
            print("  ❌ 无法获取 username_password_create 的 sentinel token")
            return False
        headers["openai-sentinel-token"] = sentinel_token
        payload = {
            "username": email,
            "password": password,
        }

        try:
            resp = self.session.post(url, json=payload, headers=headers, verify=False, timeout=30)
        except Exception as e:
            print(f"  ❌ 注册请求失败: {e}")
            return False

        print(f"  状态码: {resp.status_code}")
        if resp.status_code == 200:
            print("  ✅ 注册成功")
            return True
        if resp.status_code in (301, 302):
            print(f"  ℹ️ 重定向到: {resp.headers.get('Location', '')[:120]}")
            return True

        err_code, err_message = _extract_openai_error_details(resp)
        if err_code:
            print(f"  ⚠️ register 错误码: {err_code}")
        if err_message:
            print(f"  ⚠️ register 错误: {err_message[:200]}")
        print(f"  ❌ 失败: {resp.text[:300]}")
        return False

    def step3_send_otp_mode5(self):
        print("\n📬 [步骤3-M5] 触发验证码发送")
        if self.mode5_email_verification_ready:
            resend_url = f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/resend"
            resend_headers = self._mode5_fetch_headers(
                referer=f"{OPENAI_AUTH_BASE}/email-verification",
                content_type=None,
                origin=OPENAI_AUTH_BASE,
            )
            try:
                resp_resend = self.session.post(
                    resend_url,
                    headers=resend_headers,
                    verify=False,
                    timeout=30,
                )
                print(f"  resend 状态码: {resp_resend.status_code}")
                if 200 <= resp_resend.status_code < 300:
                    return True
                print(f"  ⚠️ resend 失败，回退 send: {resp_resend.text[:200]}")
            except Exception as e:
                print(f"  ⚠️ email-otp/resend 失败，回退 send: {e}")

        send_url = f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/send"
        send_headers = self._mode5_nav_headers(f"{OPENAI_AUTH_BASE}/create-account/password")

        try:
            resp = self.session.get(
                send_url,
                headers=send_headers,
                verify=False,
                timeout=30,
                allow_redirects=False,
            )
        except Exception as e:
            print(f"  ❌ email-otp/send 失败: {e}")
            return False

        print(f"  send 状态码: {resp.status_code}")
        verify_url = resp.headers.get("Location") or f"{OPENAI_AUTH_BASE}/email-verification"
        if verify_url.startswith("/"):
            verify_url = f"{OPENAI_AUTH_BASE}{verify_url}"

        try:
            resp_verify = self.session.get(
                verify_url,
                headers=self._mode5_nav_headers(f"{OPENAI_AUTH_BASE}/create-account/password"),
                verify=False,
                timeout=30,
                allow_redirects=True,
            )
        except Exception as e:
            print(f"  ❌ email-verification 失败: {e}")
            return False

        print(f"  email-verification 状态码: {resp_verify.status_code}")
        ok_send = 200 <= resp.status_code < 400
        ok_verify = 200 <= resp_verify.status_code < 400
        if ok_send and ok_verify:
            self.mode5_email_verification_ready = True
            print("  ✅ 验证码发送触发完成")
            return True
        print("  ❌ 验证码发送触发失败")
        return False

    def step4_validate_otp_mode5(self, code):
        print(f"\n🔢 [步骤4-M5] 验证邮箱 OTP: {code}")
        url = f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/validate"
        headers = self._mode5_fetch_headers(
            referer=f"{OPENAI_AUTH_BASE}/email-verification",
            origin=OPENAI_AUTH_BASE,
        )
        payload = {"code": code}

        try:
            resp = self.session.post(url, json=payload, headers=headers, verify=False, timeout=30)
        except Exception as e:
            print(f"  ❌ OTP 校验失败: {e}")
            return False

        print(f"  状态码: {resp.status_code}")
        if resp.status_code == 200:
            print("  ✅ 邮箱验证成功")
            return True
        print(f"  ❌ 失败: {resp.text[:300]}")
        return False

    def step5_create_account_mode5(self, first_name, last_name, birthdate):
        self._reset_create_account_state()
        print(f"\n📝 [步骤5-M5] 创建账号（{first_name} {last_name}, {birthdate}）")
        url = f"{OPENAI_AUTH_BASE}/api/accounts/create_account"
        headers = self._mode5_fetch_headers(
            referer=f"{OPENAI_AUTH_BASE}/about-you",
            origin=OPENAI_AUTH_BASE,
        )
        headers.update(generate_datadog_trace())
        payload = {
            "name": f"{first_name} {last_name}".strip(),
            "birthdate": birthdate,
        }

        def _finalize_response(resp_obj, success_text="✅ 账号创建完成！"):
            self._remember_create_account_response_meta(resp_obj)
            print(f"  状态码: {resp_obj.status_code}")
            if self.last_create_account_page_type or self.last_create_account_continue_url:
                print(
                    f"  page={self.last_create_account_page_type or '-'} continue={self.last_create_account_continue_url[:160] if self.last_create_account_continue_url else '-'}"
                )
            if resp_obj.status_code == 200:
                self.last_create_account_error_code = ""
                self.last_create_account_error_message = ""
                if self.last_create_account_retry_reason == "about_you_add_phone_pending":
                    print("  ℹ️ create_account 已推进到 add-phone，适合立即接补登")
                print(f"  {success_text}")
                return True
            if resp_obj.status_code in (301, 302):
                self.last_create_account_error_code = ""
                self.last_create_account_error_message = ""
                print("  ℹ️ 收到重定向，按成功处理")
                return True

            self.last_create_account_error_code, self.last_create_account_error_message = _extract_openai_error_details(resp_obj)
            if self.last_create_account_error_code:
                print(f"  ⚠️ create_account 错误码: {self.last_create_account_error_code}")
            if self.last_create_account_error_message:
                print(f"  ⚠️ create_account 错误: {self.last_create_account_error_message[:200]}")
            if self.last_create_account_error_code in CREATE_ACCOUNT_SOFT_SUCCESS_ERROR_CODES:
                self.last_create_account_retry_reason = "about_you_registration_disallowed"
                print("  ℹ️ registration_disallowed，按已注册处理，保留账号用于补登/OAuth")
                return True
            print(f"  ❌ 失败: {resp_obj.text[:300]}")
            return False

        browser_token = ""
        browser_proxy = ""
        browser_data = None
        try:
            browser_token, browser_data, browser_proxy = self._browser_create_account_token(flow="oauth_create_account")
        except Exception as e:
            print(f"  ⚠️ Playwright create_account token 异常: {e}")
            browser_token = ""
            browser_data = None

        if browser_token:
            self.last_create_account_used_browser = True
            browser_headers = dict(headers)
            browser_headers["openai-sentinel-token"] = browser_token
            browser_so_token = _browser_sentinel_so_token_json(browser_data)
            if browser_so_token:
                browser_headers["openai-sentinel-so-token"] = browser_so_token
            try:
                resp = self.session.post(url, json=payload, headers=browser_headers, verify=False, timeout=30)
                print(f"  🌐 Playwright Sentinel 已就绪: proxy={browser_proxy or '-'} flow=oauth_create_account soToken={'Y' if bool((browser_data or {}).get('soToken')) else 'N'}")
                if _finalize_response(resp, success_text="✅ 账号创建完成（Playwright Sentinel）！"):
                    return True
            except Exception as e:
                print(f"  ⚠️ Playwright create_account 请求失败，回退纯 HTTP: {e}")
            self.last_create_account_used_browser = False
        elif BROWSER_CREATE_ACCOUNT_ENABLED:
            detail = str(_PLAYWRIGHT_IMPORT_ERROR or "browser token empty")
            print(f"  ⚠️ Playwright create_account token 不可用，回退纯 HTTP: {detail[:200]}")

        sentinel_token = build_sentinel_token(
            self.session,
            self.device_id,
            flow="oauth_create_account",
            sentinel_gen=self.sentinel_gen,
        )
        if not sentinel_token:
            print("  ❌ 无法获取 oauth_create_account 的 sentinel token")
            return False
        headers["openai-sentinel-token"] = sentinel_token

        try:
            resp = self.session.post(url, json=payload, headers=headers, verify=False, timeout=30)
        except Exception as e:
            print(f"  ❌ create_account 请求失败: {e}")
            return False

        if _finalize_response(resp):
            return True

        if resp.status_code == 403:
            print("  ⚠️ create_account 首次失败，刷新 sentinel 后重试一次...")
            retry_token = build_sentinel_token(
                self.session,
                self.device_id,
                flow="oauth_create_account",
                sentinel_gen=self.sentinel_gen,
            )
            if retry_token:
                headers["openai-sentinel-token"] = retry_token
                try:
                    retry_resp = self.session.post(url, json=payload, headers=headers, verify=False, timeout=30)
                    if _finalize_response(retry_resp, success_text="✅ 账号创建完成（重试成功）！"):
                        return True
                except Exception as e:
                    print(f"  ❌ create_account 重试异常: {e}")
                    return False
        return False

    def register_mode5(self, email, email_id, password):
        first_name, last_name = generate_random_name()
        birthdate = generate_random_birthday()

        print(f"\n🚀 注册(M5): {email}")

        try:
            if not self.step0_init_oauth_session_mode5(email):
                print("❌ 步骤0失败：ChatGPT 新链路初始化失败")
                return False, email, password

            time.sleep(random.uniform(0.2, 0.5))

            if not self.step2_register_user_mode5(email, password):
                print("❌ 步骤2失败：用户注册失败")
                return False, email, password

            time.sleep(random.uniform(0.2, 0.5))

            pre_otp_ids = capture_mail_snapshot(
                email, email_id,
                proxy_url=self.proxy_url,
                session=self.mail_session,
            )

            if not self.step3_send_otp_mode5():
                print("❌ 步骤3失败：验证码发送失败")
                return False, email, password

            code = wait_for_verification_code(
                self.mail_session, email, email_id,
                timeout=REGISTER_OTP_TIMEOUT_SECONDS,
                pre_otp_ids=pre_otp_ids,
                resend_fn=self.step3_send_otp_mode5,
            )
            if not code:
                print("❌ 未收到验证码")
                return False, email, password

            if not self.step4_validate_otp_mode5(code):
                return False, email, password

            time.sleep(random.uniform(0.2, 0.5))

            if not self.step5_create_account_mode5(first_name, last_name, birthdate):
                return False, email, password

            print("\n🎉 注册成功！")
            return True, email, password

        except Exception as e:
            print(f"\n❌ 注册异常(M5): {e}")
            import traceback
            traceback.print_exc()
            return False, email, password

    def step0_init_oauth_session(self, email):
        """
        步骤0：OAuth 会话初始化 + 邮箱提交（纯 HTTP）

        已验证核心结论：auth.openai.com 的 API 端点不需要通过 Cloudflare Challenge，
        perform_codex_oauth_login_http() 已证明 GET /oauth/authorize → POST authorize/continue
        全链路纯 HTTP 可行。

        流程（2 步替代原浏览器 7 步）：
          1. GET /oauth/authorize?...&screen_hint=signup → 302 跟随获取 session cookies
          2. POST /api/accounts/authorize/continue       → 提交邮箱

        与 OAuth 登录的差异：
          - authorize URL 含 screen_hint=signup 和 prompt=login
          - authorize/continue body 含 screen_hint=signup（关键！指示注册流程）
          - referer: /create-account（而非 /log-in）
          - 后续步骤走 user/register 而非 password/verify

        参数:
            email: 注册用的邮箱地址
        返回:
            bool: 是否成功提交邮箱并建立 session
        """
        print("\n🔗 [步骤0] OAuth 会话初始化 + 邮箱提交（纯 HTTP，零浏览器）")

        # ===== 设置 oai-did cookie（两种 domain 格式兼容） =====
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")

        # ===== 生成 PKCE 参数 =====
        # 注意：ChatGPT Web client_id (DRivsnm2Mu42T3KOpqdtwB3NYviHYzwD) 在纯 HTTP 调用
        # /oauth/authorize 时被服务端拒绝（返回 AuthApiFailure），必须使用 Codex client_id。
        # screen_hint=signup 在 authorize/continue body 中指示注册流程。
        code_verifier, code_challenge = generate_pkce()
        self.code_verifier = code_verifier
        self.state = secrets.token_urlsafe(32)

        # authorize 参数（使用 Codex client_id + screen_hint=signup）
        authorize_params = {
            "response_type": "code",
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": self.state,
            "screen_hint": "signup",
            "prompt": "login",
        }

        authorize_url = f"{OPENAI_AUTH_BASE}/oauth/authorize?{urlencode(authorize_params)}"

        # ===== 步骤0a: GET /oauth/authorize → 获取 login_session cookie =====
        print("\n  --- [步骤0a] GET /oauth/authorize ---")
        try:
            resp = self.session.get(
                authorize_url,
                headers=NAVIGATE_HEADERS,
                allow_redirects=True,
                verify=False,
                timeout=30,
            )
            print(f"  步骤0a: {resp.status_code}")
        except Exception as e:
            print(f"  ❌ OAuth 授权请求失败: {e}")
            return False

        # 检查是否获取到 login_session cookie
        has_login_session = any(c.name == "login_session" for c in self.session.cookies)
        print(f"  login_session: {'✅ 已获取' if has_login_session else '❌ 未获取'}")
        if not has_login_session:
            print("  ⚠️ 未获得 login_session cookie，后续步骤可能失败")
            # 打印响应内容片段用于诊断
            print(f"  响应预览: {resp.text[:300]}")
            if not _mail_relay_enabled_for_session(self.session):
                return False
            print("  ℹ️ 当前为 relay 模式，继续沿用 relay session 尝试步骤0b")



        # ===== 步骤0b: POST /api/accounts/authorize/continue → 提交邮箱 =====
        print("\n  --- [步骤0b] POST /api/accounts/authorize/continue ---")

        # 构造请求头（参考 perform_codex_oauth_login_http 的步骤2）
        headers = dict(COMMON_HEADERS)
        headers["referer"] = f"{OPENAI_AUTH_BASE}/create-account"  # 注册流程用 /create-account
        headers["oai-device-id"] = self.device_id
        headers.update(generate_datadog_trace())

        # 获取 authorize_continue 的 sentinel token
        sentinel_token = build_sentinel_token(self.session, self.device_id, flow="authorize_continue", sentinel_gen=self.sentinel_gen)
        if not sentinel_token:
            print("  ❌ 无法获取 authorize_continue 的 sentinel token")
            return False
        headers["openai-sentinel-token"] = sentinel_token

        try:
            resp = self.session.post(
                f"{OPENAI_AUTH_BASE}/api/accounts/authorize/continue",
                json={
                    "username": {"kind": "email", "value": email},
                    "screen_hint": "signup",
                },
                headers=headers,
                verify=False,
                timeout=30,
            )
        except Exception as e:
            print(f"  ❌ 邮箱提交失败: {e}")
            return False

        if resp.status_code != 200:
            print(f"  ❌ 邮箱提交失败: HTTP {resp.status_code}")
            return False

        try:
            data = resp.json()
            page_type = data.get("page", {}).get("type", "")
        except Exception:
            page_type = "?"
        print(f"  步骤0b: {resp.status_code} → {page_type}")

        return True

    def step1_visit_create_account(self):
        """步骤1：访问注册页面（建立前端路由状态）"""
        url = f"{OPENAI_AUTH_BASE}/create-account"
        headers = dict(NAVIGATE_HEADERS)
        headers["referer"] = f"{OPENAI_AUTH_BASE}/authorize"
        resp = self.session.get(url, headers=headers, verify=False,
                                timeout=30, allow_redirects=True)
        return resp.status_code == 200

    def step2_register_user(self, email, password):
        """
        步骤2：注册用户（邮箱+密码一次性提交）
        
        POST /api/accounts/user/register
        
        基于浏览器抓包确认的真实请求格式：
        请求体：{"username": "xxx@xxx.com", "password": "xxx"}
        
        注意：
        - 邮箱字段名是 'username' 而非 'email'（已通过抓包验证）
        - 此端点可能需要 sentinel token（通过请求头传递）
        """
        print(f"\n🔑 [步骤2-HTTP] 注册用户: {email}")
        
        url = f"{OPENAI_AUTH_BASE}/api/accounts/user/register"
        headers = self._build_headers(
            referer=f"{OPENAI_AUTH_BASE}/create-account/password",
            with_sentinel=True,
        )
        # 浏览器抓包确认的请求格式：username + password
        payload = {
            "username": email,
            "password": password,
        }
        resp = self.session.post(url, json=payload, headers=headers, verify=False, timeout=30)

        if resp.status_code == 200:
            print("  ✅ 注册成功")
            return True
        else:
            print(f"  ❌ 失败: {resp.text[:300]}")
            # 某些 302 重定向也算成功
            if resp.status_code in (301, 302):
                redirect_url = resp.headers.get('Location', '')
                print(f"  ℹ️ 重定向到: {redirect_url[:100]}")
                if 'email-otp' in redirect_url or 'email-verification' in redirect_url:
                    return True
            return False

    def step3_send_otp(self):
        """
        步骤3：触发验证码发送（HTTP GET 页面导航请求）
        GET /api/accounts/email-otp/send
        GET /email-verification
        
        这两个都是 GET 请求，不需要 sentinel token。
        """
        print("\n📬 [步骤3-HTTP] 触发验证码发送")

        # 3a: 请求 send 端点（触发邮件发送）
        url_send = f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/send"
        headers = dict(NAVIGATE_HEADERS)
        headers["referer"] = f"{OPENAI_AUTH_BASE}/create-account/password"

        resp = self.session.get(
            url_send, headers=headers, verify=False,
            timeout=30, allow_redirects=True
        )
        send_status = resp.status_code
        send_ok = 200 <= send_status < 400
        print(f"  send 状态码: {send_status}")

        # 3b: 请求 email-verification 页面（获取后续 cookie）
        url_verify = f"{OPENAI_AUTH_BASE}/email-verification"
        headers["referer"] = f"{OPENAI_AUTH_BASE}/create-account/password"

        resp = self.session.get(
            url_verify, headers=headers, verify=False,
            timeout=30, allow_redirects=True
        )
        verify_status = resp.status_code
        verify_ok = 200 <= verify_status < 400
        print(f"  email-verification 状态码: {verify_status}")

        if send_ok and verify_ok:
            print("  ✅ 验证码发送触发完成")
            return True

        print("  ❌ 验证码发送触发失败")
        return False

    def step4_validate_otp(self, code):
        """
        步骤4：提交邮箱验证码（HTTP POST）
        POST /api/accounts/email-otp/validate
        
        从 cURL 分析确认：此步骤不需要 sentinel token。
        """
        print(f"\n🔢 [步骤4-HTTP] 验证邮箱 OTP: {code}")
        url = f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/validate"
        headers = self._build_headers(
            referer=f"{OPENAI_AUTH_BASE}/email-verification",
        )
        payload = {"code": code}

        resp = self.session.post(url, json=payload, headers=headers, verify=False, timeout=30)
        print(f"  状态码: {resp.status_code}")

        if resp.status_code == 200:
            print("  ✅ 邮箱验证成功")
            return True
        else:
            print(f"  ❌ 失败: {resp.text[:300]}")
            return False

    def step5_create_account(self, first_name, last_name, birthdate):
        """
        步骤5：提交姓名 + 生日完成注册（HTTP POST）
        POST /api/accounts/create_account
        """
        self._reset_create_account_state()
        print(f"\n📝 [步骤5-HTTP] 创建账号（{first_name} {last_name}, {birthdate}）")
        url = f"{OPENAI_AUTH_BASE}/api/accounts/create_account"
        headers = self._build_headers(
            referer=f"{OPENAI_AUTH_BASE}/about-you",
        )
        payload = {
            "name": f"{first_name} {last_name}",
            "birthdate": birthdate,
        }

        def _finalize_response(resp_obj, success_text="✅ 账号创建完成！"):
            self._remember_create_account_response_meta(resp_obj)
            print(f"  状态码: {resp_obj.status_code}")
            if resp_obj.status_code == 200:
                self.last_create_account_error_code = ""
                self.last_create_account_error_message = ""
                if self.last_create_account_retry_reason == "about_you_add_phone_pending":
                    print("  ℹ️ create_account 已推进到 add-phone，适合立即接补登")
                print(f"  {success_text}")
                return True
            if resp_obj.status_code in (301, 302):
                self.last_create_account_error_code = ""
                self.last_create_account_error_message = ""
                print("  ℹ️ 收到重定向，可能已成功")
                return True

            self.last_create_account_error_code, self.last_create_account_error_message = _extract_openai_error_details(resp_obj)
            if self.last_create_account_error_code:
                print(f"  ⚠️ create_account 错误码: {self.last_create_account_error_code}")
            if self.last_create_account_error_message:
                print(f"  ⚠️ create_account 错误: {self.last_create_account_error_message[:200]}")
            if self.last_create_account_error_code in CREATE_ACCOUNT_SOFT_SUCCESS_ERROR_CODES:
                self.last_create_account_retry_reason = "about_you_registration_disallowed"
                print("  ℹ️ registration_disallowed，按已注册处理，保留账号用于补登/OAuth")
                return True
            print(f"  ❌ 失败: {resp_obj.text[:300]}")
            return False

        browser_token = ""
        browser_proxy = ""
        browser_data = None
        try:
            browser_token, browser_data, browser_proxy = self._browser_create_account_token(flow="oauth_create_account")
        except Exception as e:
            print(f"  ⚠️ Playwright create_account token 异常: {e}")
            browser_token = ""
            browser_data = None

        if browser_token:
            self.last_create_account_used_browser = True
            browser_headers = dict(headers)
            browser_headers["openai-sentinel-token"] = browser_token
            browser_so_token = _browser_sentinel_so_token_json(browser_data)
            if browser_so_token:
                browser_headers["openai-sentinel-so-token"] = browser_so_token
            try:
                resp = self.session.post(url, json=payload, headers=browser_headers, verify=False, timeout=30)
                print(f"  🌐 Playwright Sentinel 已就绪: proxy={browser_proxy or '-'} flow=oauth_create_account soToken={'Y' if bool((browser_data or {}).get('soToken')) else 'N'}")
                if _finalize_response(resp, success_text="✅ 账号创建完成（Playwright Sentinel）！"):
                    return True
            except Exception as e:
                print(f"  ⚠️ Playwright create_account 请求失败，回退纯 HTTP: {e}")
            self.last_create_account_used_browser = False
        elif BROWSER_CREATE_ACCOUNT_ENABLED:
            detail = str(_PLAYWRIGHT_IMPORT_ERROR or "browser token empty")
            print(f"  ⚠️ Playwright create_account token 不可用，回退纯 HTTP: {detail[:200]}")

        resp = self.session.post(url, json=payload, headers=headers, verify=False, timeout=30)
        if _finalize_response(resp):
            return True

        if resp.status_code == 403 and "sentinel" in resp.text.lower():
            print("  ⚠️ 需要 sentinel token，重试...")
            flow_token = build_sentinel_token(
                self.session,
                self.device_id,
                flow="oauth_create_account",
                sentinel_gen=self.sentinel_gen,
            )
            if flow_token:
                headers["openai-sentinel-token"] = flow_token
            else:
                headers["openai-sentinel-token"] = self.sentinel_gen.generate_token()
            resp = self.session.post(url, json=payload, headers=headers, verify=False, timeout=30)
            if _finalize_response(resp, success_text="✅ 账号创建完成（带 sentinel 重试成功）！"):
                self.last_create_account_error_code = ""
                self.last_create_account_error_message = ""
                return True
            return False

        return False

    def register(self, email, email_id, password):
        """
        执行完整的注册流程（全 6 步纯 HTTP）
        """
        if self.use_mode5:
            return self.register_mode5(email, email_id, password)

        first_name, last_name = generate_random_name()
        birthdate = generate_random_birthday()

        print(f"\n� 注册: {email}")

        try:
            # ===== 步骤0：OAuth 会话初始化 + 邮箱提交（纯 HTTP）=====
            if not self.step0_init_oauth_session(email):
                print("❌ 步骤0失败：OAuth 会话初始化失败")
                return False, email, password

            time.sleep(random.uniform(0.2, 0.5))

            # 注意：邮箱已在步骤0中通过 POST authorize/continue 提交完成
            # 步骤2提交用户名（邮箱）+ 密码完成注册
            if not self.step2_register_user(email, password):
                print("❌ 步骤2失败：用户注册失败")
                return False, email, password

            time.sleep(random.uniform(0.2, 0.5))

            # ===== 步骤3前：捕获邮件快照 =====
            pre_otp_ids = capture_mail_snapshot(
                email, email_id,
                proxy_url=self.proxy_url,
                session=self.mail_session,
            )

            # ===== 步骤3：触发验证码发送 =====
            if not self.step3_send_otp():
                print("❌ 步骤3失败：验证码发送失败")
                return False, email, password

            # 等待验证码（可配置阈值，无新邮件则自动重发）
            code = wait_for_verification_code(
                self.mail_session, email, email_id,
                timeout=REGISTER_OTP_TIMEOUT_SECONDS,
                pre_otp_ids=pre_otp_ids,
                resend_fn=self.step3_send_otp,
            )
            if not code:
                print("❌ 未收到验证码")
                return False, email, password

            # ===== 步骤4：验证 OTP =====
            if not self.step4_validate_otp(code):
                return False, email, password

            time.sleep(random.uniform(0.2, 0.5))

            # ===== 步骤5：创建账号 =====
            if not self.step5_create_account(first_name, last_name, birthdate):
                return False, email, password

            print("\n🎉 注册成功！")
            return True, email, password

        except Exception as e:
            print(f"\n❌ 注册异常: {e}")
            import traceback
            traceback.print_exc()
            return False, email, password


# =================== Sentinel API（纯 HTTP 获取 c 字段） ===================


def fetch_sentinel_challenge(session, device_id, flow="authorize_continue", sentinel_gen=None):
    """
    调用 sentinel 后端 API 获取 challenge 数据（c 字段 + PoW 参数）

    请求目标：POST https://sentinel.openai.com/backend-api/sentinel/req
    该端点不需要任何 cookies，直接用 requests 调用即可。

    参数:
        session: requests.Session 实例
        device_id: 设备 ID（UUID v4）
        flow: 业务流类型（"authorize_continue" 或 "password_verify"）
        sentinel_gen: 可复用的 SentinelTokenGenerator 实例
    返回:
        dict: 包含 token(c), proofofwork.seed/difficulty；失败返回 None
    """
    # 复用或创建 generator
    gen = sentinel_gen or SentinelTokenGenerator(device_id=device_id)
    p_token = gen.generate_requirements_token()

    req_body = {
        "p": p_token,
        "id": device_id,
        "flow": flow,
    }

    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": str(getattr(gen, "frame_url", DEFAULT_SENTINEL_FRAME_URL) or DEFAULT_SENTINEL_FRAME_URL),
        "User-Agent": str(getattr(gen, "user_agent", USER_AGENT) or USER_AGENT),
        "Origin": "https://sentinel.openai.com",
        "sec-ch-ua": str(getattr(gen, "sec_ch_ua", DEFAULT_SENTINEL_SEC_CH_UA) or DEFAULT_SENTINEL_SEC_CH_UA),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }

    max_attempts = 3 if _sentinel_proxy_retry_enabled_for_session(session) else 1
    for attempt in range(1, max_attempts + 1):
        try:
            resp = session.post(
                "https://sentinel.openai.com/backend-api/sentinel/req",
                data=json.dumps(req_body),
                headers=headers,
                timeout=15,
                verify=False,
            )
            if resp.status_code == 200:
                return resp.json()

            preview = resp.text[:200] if resp is not None else ""
            retryable_status = resp.status_code in (502, 503, 504)
            if retryable_status and attempt < max_attempts:
                rotated = rotate_mail_proxy(session, reason=f"sentinel {flow} 返回 {resp.status_code}，切换代理重试 ({attempt}/{max_attempts - 1})")
                if rotated:
                    time.sleep(0.3)
                    continue
            print(f"  ❌ sentinel API 返回 {resp.status_code}: {preview}")
            return None
        except Exception as e:
            if attempt < max_attempts and _is_retryable_sentinel_proxy_error(e):
                rotated = rotate_mail_proxy(session, reason=f"sentinel {flow} 代理异常，切换代理重试 ({attempt}/{max_attempts - 1})")
                if rotated:
                    time.sleep(0.3)
                    continue
            print(f"  ❌ sentinel API 调用异常: {e}")
            return None
    return None


def build_sentinel_token_payload(session, device_id, flow="authorize_continue", sentinel_gen=None):
    """
    构建完整的 openai-sentinel-token payload（纯 Python，零浏览器）

    核心结论（已验证）：
      - t 字段传空字符串即可（服务端不校验）
      - c 字段从 POST /backend-api/sentinel/req 实时获取
      - p 字段用服务端返回的 seed/difficulty 重新计算 PoW

    参数:
        session: requests.Session 实例
        device_id: 设备 ID
        flow: 业务流类型
        sentinel_gen: 可复用的 SentinelTokenGenerator 实例
    返回:
        dict: sentinel token payload；失败返回 None
    """
    # 复用或创建 generator
    gen = sentinel_gen or SentinelTokenGenerator(device_id=device_id)
    challenge = fetch_sentinel_challenge(session, device_id, flow, sentinel_gen=gen)
    if not challenge:
        return None

    c_value = challenge.get("token", "")
    pow_data = challenge.get("proofofwork", {})

    if pow_data.get("required") and pow_data.get("seed"):
        p_value = gen.generate_token(
            seed=pow_data["seed"],
            difficulty=pow_data.get("difficulty", "0")
        )
    else:
        p_value = gen.generate_requirements_token()

    return {
        "p": p_value,
        "t": "",
        "c": c_value,
        "id": device_id,
        "flow": flow,
    }


def build_sentinel_token(session, device_id, flow="authorize_continue", sentinel_gen=None):
    """
    构建完整的 openai-sentinel-token JSON 字符串（纯 Python，零浏览器）
    """
    payload = build_sentinel_token_payload(session, device_id, flow=flow, sentinel_gen=sentinel_gen)
    if not payload:
        return None
    return json.dumps(payload, separators=(",", ":"))


def _playwright_browser_sentinel_token(proxy_server="", flow="oauth_create_account", device_id="", user_agent="", frame_url=""):
    """仅在 create_account 场景启用 Playwright，向 SentinelSDK 原生取完整 token。"""
    if not BROWSER_CREATE_ACCOUNT_ENABLED:
        return None
    if sync_playwright is None:
        return None

    proxy_server = _normalize_proxy_url(proxy_server)
    user_agent = str(user_agent or USER_AGENT or "").strip() or USER_AGENT
    frame_url = str(frame_url or MODE5_SENTINEL_FRAME_URL or "").strip() or MODE5_SENTINEL_FRAME_URL
    flow = str(flow or "oauth_create_account").strip() or "oauth_create_account"
    device_id = str(device_id or "").strip()

    launch_kwargs = {
        "headless": True,
        "args": ["--no-sandbox", "--disable-dev-shm-usage"],
    }
    if proxy_server:
        launch_kwargs["proxy"] = {"server": proxy_server}

    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context(
            user_agent=user_agent,
            locale="en-US",
            viewport={"width": 1280, "height": 800},
        )
        try:
            if device_id:
                cookies = []
                for domain in ("sentinel.openai.com", "auth.openai.com"):
                    cookies.append(
                        {
                            "name": "oai-did",
                            "value": device_id,
                            "domain": domain,
                            "path": "/",
                            "httpOnly": False,
                            "secure": True,
                            "sameSite": "Lax",
                        }
                    )
                if cookies:
                    context.add_cookies(cookies)

            page = context.new_page()
            page.goto(frame_url, wait_until="load", timeout=120000)
            page.wait_for_timeout(BROWSER_CREATE_ACCOUNT_WAIT_MS)
            page.wait_for_function("() => !!window.SentinelSDK", timeout=BROWSER_CREATE_ACCOUNT_SDK_TIMEOUT_MS)
            return page.evaluate(
                """async ({flow}) => {
                    const out = {
                        flow,
                        frameUrl: location.href,
                        userAgent: navigator.userAgent,
                        cookieBefore: document.cookie,
                    };
                    if (!window.SentinelSDK) throw new Error('SentinelSDK missing');
                    await window.SentinelSDK.init(flow);
                    const tok = await window.SentinelSDK.token(flow);
                    let soTok = null;
                    try {
                        if (window.SentinelSDK.sessionObserverToken) {
                            soTok = await window.SentinelSDK.sessionObserverToken(flow);
                        }
                    } catch (e) {
                        soTok = null;
                    }
                    out.token = tok ? JSON.parse(tok) : null;
                    out.soToken = soTok ? JSON.parse(soTok) : null;
                    out.cookieAfter = document.cookie;
                    return out;
                }""",
                {"flow": flow},
            )
        finally:
            try:
                context.close()
            except Exception:
                pass
            browser.close()


def _browser_sentinel_token_json(proxy_server="", flow="oauth_create_account", device_id="", user_agent="", frame_url=""):
    data = _playwright_browser_sentinel_token(
        proxy_server=proxy_server,
        flow=flow,
        device_id=device_id,
        user_agent=user_agent,
        frame_url=frame_url,
    )
    token_obj = (data or {}).get("token") if isinstance(data, dict) else None
    if not isinstance(token_obj, dict) or not token_obj:
        return "", data
    return json.dumps(token_obj, ensure_ascii=False, separators=(",", ":")), data


def _browser_sentinel_so_token_json(browser_data):
    if not isinstance(browser_data, dict):
        return ""
    so_token_obj = browser_data.get("soToken")
    if not isinstance(so_token_obj, dict) or not so_token_obj:
        return ""
    return json.dumps(so_token_obj, ensure_ascii=False, separators=(",", ":"))


def _mode5_origin_from_url(url):
    parsed = urlparse(str(url or ""))
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return OPENAI_AUTH_BASE


def _mode5_nav_headers_static(referer, accept=None):
    return {
        "accept": accept or NAVIGATE_HEADERS["accept"],
        "accept-language": "en-US,en;q=0.9",
        "referer": referer,
        "upgrade-insecure-requests": "1",
        "user-agent": MODE5_USER_AGENT,
        "sec-ch-ua": MODE5_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }


def _mode5_fetch_headers_static(referer, content_type="application/json", accept="application/json", origin=None):
    headers = {
        "accept": accept,
        "accept-language": "en-US,en;q=0.9",
        "origin": origin or _mode5_origin_from_url(referer),
        "referer": referer,
        "user-agent": MODE5_USER_AGENT,
        "sec-ch-ua": MODE5_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    if content_type:
        headers["content-type"] = content_type
    return headers


def _is_mode5_callback_url(url):
    value = str(url or "").strip().lower()
    if not value:
        return False
    if MODE5_CHATGPT_REDIRECT_URI.lower() in value:
        return True
    return "chatgpt.com/api/auth/callback/openai" in value


def _oauth_extract_code_from_url(url):
    if not url or "code=" not in str(url):
        return None
    try:
        return parse_qs(urlparse(str(url)).query).get("code", [None])[0]
    except Exception:
        return None


def _oauth_absolute_url(url):
    value = str(url or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if value.startswith("/"):
        return f"{OAUTH_ISSUER}{value}"
    return value


def _oauth_extract_code_from_connection_error(exc):
    match = re.search(r'(https?://localhost[^\s\'"]+)', str(exc or ""))
    if not match:
        return None
    return _oauth_extract_code_from_url(match.group(1))


def _oauth_decode_auth_session(session_obj):
    for c in getattr(session_obj, "cookies", []):
        if c.name != "oai-client-auth-session":
            continue
        value = c.value or ""
        if not value:
            continue

        compressed = value.startswith(".")
        parts = value.split(".")
        if compressed:
            if len(parts) < 2 or not parts[1]:
                continue
            payload_part = parts[1]
        else:
            payload_part = parts[0]

        pad = (4 - len(payload_part) % 4) % 4
        if pad:
            payload_part += "=" * pad
        try:
            raw = base64.urlsafe_b64decode(payload_part.encode("ascii"))
            if compressed:
                import zlib
                raw = zlib.decompress(raw)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            continue
    return None


def _oauth_extract_workspace_from_session_data(session_data_obj):
    def _walk(node):
        if isinstance(node, dict):
            ws_list = node.get("workspaces")
            if isinstance(ws_list, list):
                for ws in ws_list:
                    if isinstance(ws, dict):
                        ws_id = ws.get("id")
                        if ws_id:
                            return ws_id, ws.get("kind", "?")
            for value in node.values():
                found = _walk(value)
                if found:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = _walk(item)
                if found:
                    return found
        return None

    return _walk(session_data_obj)


def _oauth_extract_workspace_from_html(html_text):
    if not html_text:
        return None, "?"

    patterns = [
        r'"workspaces"\s*:\s*\[\s*\{[^{}]*?"id"\s*:\s*"([^"]+)"[^{}]*?(?:"kind"\s*:\s*"([^"]+)")?',
        r'\\"workspaces\\"\s*:\s*\[\s*\{[^{}]*?\\"id\\"\s*:\s*\\"([^\\"]+)\\"[^{}]*?(?:\\"kind\\"\s*:\s*\\"([^\\"]+)\\")?',
        r'"workspace_id"\s*:\s*"([^"]+)"',
        r'\\"workspace_id\\"\s*:\s*\\"([^\\"]+)\\"',
    ]
    for pattern in patterns:
        match = re.search(pattern, html_text, re.S)
        if match:
            ws_id = match.group(1)
            ws_kind = match.group(2) if match.lastindex and match.lastindex >= 2 and match.group(2) else "?"
            if ws_id:
                return ws_id, ws_kind
    return None, "?"


def _oauth_read_workspace_context(session_obj, html_text=""):
    session_data_obj = _oauth_decode_auth_session(session_obj)
    workspace_id_val = None
    workspace_kind_val = "?"
    if session_data_obj:
        found = _oauth_extract_workspace_from_session_data(session_data_obj)
        if found:
            workspace_id_val, workspace_kind_val = found
    if not workspace_id_val and html_text:
        workspace_id_val, workspace_kind_val = _oauth_extract_workspace_from_html(html_text)
    return session_data_obj, workspace_id_val, workspace_kind_val


def _oauth_follow_and_extract_code(session_obj, url, headers, max_depth=10):
    if not url or max_depth <= 0:
        return None
    url = _oauth_absolute_url(url)
    try:
        resp = session_obj.get(url, headers=headers, verify=False, timeout=20, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            code = _oauth_extract_code_from_url(location)
            if code:
                return code
            location = _oauth_absolute_url(location)
            if not location:
                return None
            return _oauth_follow_and_extract_code(session_obj, location, headers, max_depth - 1)
        return _oauth_extract_code_from_url(resp.url)
    except requests.exceptions.ConnectionError as e:
        return _oauth_extract_code_from_connection_error(e)
    except Exception:
        return None


def _session_cookie_value(session_obj, cookie_name):
    for cookie in getattr(session_obj, "cookies", []):
        if cookie.name == cookie_name:
            return str(cookie.value or "").strip()
    return ""


def _extract_email_from_auth_session(session_obj):
    session_data = _oauth_decode_auth_session(session_obj)
    if not isinstance(session_data, dict):
        return ""
    email = str(session_data.get("email") or "").strip().lower()
    if email:
        return email
    username = session_data.get("username") or {}
    if isinstance(username, dict):
        value = str(username.get("value") or "").strip().lower()
        if value:
            return value
    return ""


def _new_mode5_sentinel_generator(device_id):
    return SentinelTokenGenerator(
        device_id=device_id,
        user_agent=MODE5_USER_AGENT,
        script_src=MODE5_SENTINEL_SDK_URL,
        frame_url=MODE5_SENTINEL_FRAME_URL,
        sec_ch_ua=MODE5_SEC_CH_UA,
    )


def _perform_codex_oauth_login_mode5_http(
    email,
    password,
    registrar_session=None,
    email_id=None,
    error_holder=None,
    proxy_url=None,
    mail_session=None,
    relay_state=None,
    device_id=None,
    sentinel_gen=None,
    mode5_callback_url=None,
):
    """
    Mode5 专用 OAuth 链：
      /api/accounts/authorize
        -> /log-in/password
        -> /api/accounts/password/verify
        -> /api/accounts/email-otp/validate（如触发）
        -> /sign-in-with-chatgpt/codex/consent
        -> /api/accounts/workspace/select
        -> localhost callback code
        -> /oauth/token
    """
    print("\n🔐 执行 Codex OAuth 登录（Mode5 专用链）...")

    if isinstance(error_holder, dict):
        error_holder.clear()

    def _set_error(reason, detail=""):
        if isinstance(error_holder, dict):
            error_holder["reason"] = reason
            if detail:
                error_holder["detail"] = detail

    def _abort_if_chatgptmail_unsupported():
        err_code, err_msg, err_email = _chatgptmail_get_last_error(mail_session)
        if err_code != "unsupported_email":
            return False
        detail = err_msg or err_email or email
        _set_error("chatgptmail_unsupported_email", detail)
        print(f"  ⚠️ ChatGPTMail 不支持该邮箱地址，停止当前 OAuth: {err_email or email}")
        return True

    if proxy_url is None and registrar_session is not None:
        account_proxy = _session_proxy_url(registrar_session)
    else:
        account_proxy = _effective_proxy(proxy_url)

    if relay_state is None and registrar_session is not None:
        relay_state = _relay_state_from_session(registrar_session)
    if relay_state is None and mail_session is not None:
        relay_state = _relay_state_from_session(mail_session)

    created_mail_session = None
    if mail_session is None:
        mail_session = create_mail_session(account_proxy, relay_state=_new_random_mail_relay_state())
        created_mail_session = mail_session

    borrowed_session = registrar_session is not None
    session = registrar_session if borrowed_session else create_session(account_proxy, relay_state=relay_state)

    try:
        device_id = str(device_id or _session_cookie_value(session, "oai-did") or generate_device_id()).strip()
        sentinel_gen = sentinel_gen or _new_mode5_sentinel_generator(device_id)

        mode5_cookie_domains = [".openai.com", ".auth.openai.com", "auth.openai.com"]
        if MODE5_TEST_CHATGPT_OAI_DID_COOKIE:
            mode5_cookie_domains.extend([".chatgpt.com", "chatgpt.com"])
        for domain in mode5_cookie_domains:
            try:
                session.cookies.set("oai-did", device_id, domain=domain)
            except Exception:
                pass

        if borrowed_session and mode5_callback_url:
            try:
                resp_cb = session.get(
                    mode5_callback_url,
                    headers=_mode5_nav_headers_static(f"{OPENAI_AUTH_BASE}/"),
                    allow_redirects=True,
                    verify=False,
                    timeout=30,
                )
                print(f"  callback/openai: {resp_cb.status_code} -> {resp_cb.url[:160]}")
            except Exception as e:
                print(f"  ⚠️ callback/openai 异常: {e}")

        pre_oauth_mail_ids = capture_mail_snapshot(
            email,
            email_id,
            proxy_url=account_proxy,
            session=mail_session,
        ) if email_id else set()
        if email_id:
            print(f"  预捕获 OAuth 邮件快照: {len(pre_oauth_mail_ids)} 封")

        code_verifier, code_challenge = generate_pkce()
        state = secrets.token_urlsafe(32)
        login_hint = _extract_email_from_auth_session(session) or str(email or "").strip().lower()
        about_you_state = {"error_code": "", "error_message": "", "continue_url": ""}
        about_you_processed = False
        authorize_params = {
            "client_id": OAUTH_CLIENT_ID,
            "scope": "openid profile email offline_access api.connectors.read api.connectors.invoke",
            "response_type": "code",
            "redirect_uri": OAUTH_REDIRECT_URI,
            "device_id": device_id,
            "prompt": "login",
            "ext-oai-did": device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "ext-passkey-client-capabilities": MODE5_EXT_PASSKEY_CLIENT_CAPABILITIES,
            "screen_hint": "login_or_signup",
            "state": state,
            "originator": "codex_cli_rs",
            "codex_cli_simplified_flow": "true",
            "id_token_add_organizations": "true",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if login_hint:
            authorize_params["login_hint"] = login_hint
        authorize_url = f"{OPENAI_AUTH_BASE}/api/accounts/authorize?{urlencode(authorize_params)}"
        nav_headers = _mode5_nav_headers_static(f"{CHATGPT_BASE}/")

        def _advance_about_you_flow(current_continue_url, referer_url):
            about_you_url = _oauth_absolute_url(current_continue_url)
            if not about_you_url or "about-you" not in about_you_url:
                return current_continue_url

            print("  📝 处理 OAuth about-you 步骤...")
            h_about = _mode5_nav_headers_static(referer_url)

            try:
                resp_about = session.get(
                    about_you_url,
                    headers=h_about,
                    verify=False,
                    timeout=30,
                    allow_redirects=True,
                )
                print(f"  GET about-you: {resp_about.status_code}, URL: {resp_about.url[:120]}")
                if "consent" in resp_about.url or "organization" in resp_about.url:
                    next_url = resp_about.url
                    about_you_state["continue_url"] = str(next_url or "").strip()
                    print(f"  ✅ about-you 已跳转到后续页面: {next_url}")
                    return next_url
            except Exception as e:
                print(f"  ⚠️ GET about-you 异常: {e}")

            first_names = ["James", "Mary", "John", "Linda", "Robert", "Sarah"]
            last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Wilson"]
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            year = random.randint(1995, 2002)
            month = random.randint(1, 12)
            day = random.randint(1, 28)
            birthdate = f"{year}-{month:02d}-{day:02d}"

            def _extract_continue_url_from_resp(resp_obj):
                if resp_obj is None:
                    return ""
                location = str((getattr(resp_obj, "headers", {}) or {}).get("Location") or "").strip()
                if location:
                    return location
                try:
                    payload = resp_obj.json()
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    cont = str(payload.get("continue_url") or "").strip()
                    if cont:
                        return cont
                    for k in ("data", "error", "details", "context"):
                        sub = payload.get(k, {})
                        if isinstance(sub, dict) and sub.get("continue_url"):
                            return str(sub.get("continue_url") or "").strip()
                raw = str(getattr(resp_obj, "text", "") or "")
                match = re.search(r'"continue_url"\s*:\s*"([^"]+)"', raw)
                if not match:
                    match = re.search(r'\\"continue_url\\"\s*:\s*\\"([^\\"]+)\\"', raw)
                if match:
                    return match.group(1).replace("\\/", "/").strip()
                return ""

            def _log_create_account_resp(label, resp_obj):
                if resp_obj is None:
                    print(f"  ⚠️ {label} 无响应")
                    return
                err_code, err_message = _extract_openai_error_details(resp_obj)
                about_you_state["error_code"] = str(err_code or "").strip()
                about_you_state["error_message"] = str(err_message or "").strip()
                location = str((getattr(resp_obj, "headers", {}) or {}).get("Location") or "").strip()
                preview = str(getattr(resp_obj, "text", "") or "")[:300].replace("\n", " ")
                print(
                    f"  {label}: status={resp_obj.status_code}, code={err_code or '-'}, "
                    f"message={err_message or '-'}, location={location[:120] if location else '-'}"
                )
                if preview:
                    print(f"  {label} body: {preview}")

            def _post_about_you_create(extra_headers=None, label="create_account"):
                h_create = _mode5_fetch_headers_static(about_you_url, origin=OPENAI_AUTH_BASE)
                h_create["oai-device-id"] = device_id
                h_create.update(generate_datadog_trace())
                if extra_headers:
                    h_create.update(extra_headers)
                resp_obj = session.post(
                    f"{OAUTH_ISSUER}/api/accounts/create_account",
                    json={"name": name, "birthdate": birthdate},
                    headers=h_create,
                    verify=False,
                    timeout=30,
                    allow_redirects=False,
                )
                print(f"  {label}: {resp_obj.status_code}")
                return resp_obj

            next_url = about_you_url
            resp_create = _post_about_you_create()
            create_responses = [("create_account", resp_create)]

            first_continue = _extract_continue_url_from_resp(resp_create)
            if first_continue:
                next_url = first_continue

            if resp_create.status_code in (400, 401, 403) and not first_continue:
                _log_create_account_resp("create_account", resp_create)
                sentinel_token = build_sentinel_token(
                    session,
                    device_id,
                    flow="password_verify",
                    sentinel_gen=sentinel_gen,
                )
                if sentinel_token:
                    resp_retry = _post_about_you_create(
                        {"openai-sentinel-token": sentinel_token},
                        label="create_account retry(password_verify sentinel)",
                    )
                    create_responses.append(("create_account retry(password_verify sentinel)", resp_retry))
                    retry_continue = _extract_continue_url_from_resp(resp_retry)
                    if retry_continue:
                        next_url = retry_continue
                        resp_create = resp_retry
                else:
                    print("  ⚠️ 无法获取 create_account 的 sentinel token（password_verify flow）")

            if next_url == about_you_url and resp_create.status_code in (400, 401, 403):
                raw_sentinel = None
                try:
                    raw_sentinel = (sentinel_gen or SentinelTokenGenerator(device_id=device_id)).generate_token()
                except Exception:
                    raw_sentinel = None
                if raw_sentinel:
                    resp_retry2 = _post_about_you_create(
                        {"openai-sentinel-token": raw_sentinel},
                        label="create_account retry(raw sentinel)",
                    )
                    create_responses.append(("create_account retry(raw sentinel)", resp_retry2))
                    retry_continue2 = _extract_continue_url_from_resp(resp_retry2)
                    if retry_continue2:
                        next_url = retry_continue2
                        resp_create = resp_retry2

            about_you_state["continue_url"] = str(next_url or "").strip()
            if next_url != about_you_url:
                print(f"  ✅ about-you 后续 continue_url: {next_url}")
            else:
                last_label, last_resp = create_responses[-1]
                _log_create_account_resp(last_label, last_resp)
                print("  ⚠️ create_account 未返回可用 continue_url，重新探测 about-you 跳转...")
                try:
                    probe = session.get(
                        about_you_url,
                        headers=h_about,
                        verify=False,
                        timeout=30,
                        allow_redirects=True,
                    )
                    if "consent" in probe.url or "organization" in probe.url:
                        next_url = probe.url
                        about_you_state["continue_url"] = str(next_url or "").strip()
                        print(f"  ✅ probe 跳转到后续页面: {next_url}")
                except Exception:
                    pass
            return next_url

        try:
            resp = session.get(
                authorize_url,
                headers=nav_headers,
                verify=False,
                timeout=30,
                allow_redirects=True,
            )
            print(f"  api/accounts/authorize: {resp.status_code} -> {resp.url[:160]}")
        except requests.exceptions.ConnectionError as e:
            auth_code = _oauth_extract_code_from_connection_error(e)
            if auth_code:
                print(f"  ✅ authorize ConnectionError 中提取到 code（长度: {len(auth_code)}）")
                return codex_exchange_code(
                    auth_code,
                    code_verifier,
                    proxy_url=account_proxy,
                    relay_state=_relay_state_from_session(session) or relay_state,
                )
            _set_error("mode5_authorize_connection_error", str(e))
            print(f"  ❌ authorize 异常: {e}")
            return None
        except Exception as e:
            _set_error("mode5_authorize_exception", str(e))
            print(f"  ❌ authorize 异常: {e}")
            return None

        auth_code = _oauth_extract_code_from_url(resp.url)
        if not auth_code and resp.history:
            for hop in resp.history:
                auth_code = _oauth_extract_code_from_url(hop.headers.get("Location", ""))
                if auth_code:
                    break
        if auth_code:
            print(f"  ✅ authorize 直接获取到 code（长度: {len(auth_code)}）")
            return codex_exchange_code(
                auth_code,
                code_verifier,
                proxy_url=account_proxy,
                relay_state=_relay_state_from_session(session) or relay_state,
            )

        final_url = str(getattr(resp, "url", "") or "")
        if "add-phone" in final_url:
            _set_error("mode5_authorize_add_phone", final_url)
            print("  ⚠️ authorize 阶段直接进入 add-phone")
            return None
        if "/log-in/password" not in final_url:
            _set_error("mode5_authorize_login_redirect", final_url or "unexpected_final_url")
            print(f"  ❌ authorize 未落到 password 页面: {final_url[:160]}")
            return None

        headers = _mode5_fetch_headers_static(final_url, origin=OPENAI_AUTH_BASE)
        headers["oai-device-id"] = device_id
        headers.update(generate_datadog_trace())
        sentinel_pwd = build_sentinel_token(session, device_id, flow="password_verify", sentinel_gen=sentinel_gen)
        if not sentinel_pwd:
            _set_error("mode5_password_verify_sentinel_missing", "password_verify")
            print("  ❌ 无法获取 password_verify 的 sentinel token")
            return None
        headers["openai-sentinel-token"] = sentinel_pwd

        try:
            resp = session.post(
                f"{OPENAI_AUTH_BASE}/api/accounts/password/verify",
                json={"password": password},
                headers=headers,
                verify=False,
                timeout=30,
                allow_redirects=False,
            )
            print(f"  password/verify: {resp.status_code}")
        except Exception as e:
            _set_error("mode5_password_verify_exception", str(e))
            print(f"  ❌ password/verify 异常: {e}")
            return None

        try:
            data = resp.json() or {}
        except Exception:
            data = {}
        continue_url = str(data.get("continue_url") or "").strip()
        page_type = str((data.get("page") or {}).get("type") or "").strip()
        if page_type == "about_you" and not continue_url:
            continue_url = f"{OAUTH_ISSUER}/about-you"
        elif page_type == "add_phone" and not continue_url:
            continue_url = f"{OAUTH_ISSUER}/add-phone"
        print(f"  password_verify page={page_type or '-'} continue={continue_url[:160] if continue_url else '-'}")

        if resp.status_code != 200:
            err_code, err_message = _extract_openai_error_details(resp)
            detail = err_message or err_code or f"status={resp.status_code},page={page_type}"
            if resp.status_code == 401 and page_type == "login_password":
                _set_error("password_verify_401_login_password", detail)
            elif resp.status_code == 401:
                _set_error("password_verify_401", detail)
            else:
                _set_error("mode5_password_verify_failed", detail)
            print(f"  ❌ password/verify 失败: {detail}")
            return None

        if page_type == "email_otp_verification" or "email-verification" in continue_url:
            print("  🔐 进入 OAuth 邮箱二次验证...")
            if not email_id:
                _set_error("mode5_oauth_email_id_missing", "missing email_id for oauth email verification")
                print("  ❌ 无 email_id，无法接收 OAuth 验证码")
                return None

            def _trigger_otp_resend():
                try:
                    resend_resp = session.get(
                        f"{OAUTH_ISSUER}/api/accounts/email-otp/send",
                        headers=_mode5_nav_headers_static(f"{OAUTH_ISSUER}/log-in/password"),
                        verify=False,
                        timeout=30,
                        allow_redirects=False,
                    )
                    print(f"  📬 OAuth OTP 重发触发: {resend_resp.status_code}")
                except Exception as e:
                    print(f"  ⚠️ OAuth OTP 重发异常: {e}")

            otp_timeout = (
                OAUTH_OTP_TIMEOUT_WITH_SNAPSHOT_SECONDS
                if len(pre_oauth_mail_ids) > 0
                else OAUTH_OTP_TIMEOUT_NO_SNAPSHOT_SECONDS
            )
            code = wait_for_verification_code(
                mail_session,
                email,
                email_id,
                timeout=otp_timeout,
                pre_otp_ids=pre_oauth_mail_ids,
                resend_fn=_trigger_otp_resend,
            )
            if _abort_if_chatgptmail_unsupported():
                return None
            if not code:
                _set_error("mode5_oauth_email_otp_timeout", f"timeout={otp_timeout}")
                return None

            h_val = _mode5_fetch_headers_static(f"{OAUTH_ISSUER}/email-verification", origin=OPENAI_AUTH_BASE)
            h_val["oai-device-id"] = device_id
            h_val.update(generate_datadog_trace())
            print(f"  🔢 提交 OAuth 验证码: {code}")
            resp = session.post(
                f"{OAUTH_ISSUER}/api/accounts/email-otp/validate",
                json={"code": code},
                headers=h_val,
                verify=False,
                timeout=30,
                allow_redirects=False,
            )
            if resp.status_code != 200:
                err_code, err_message = _extract_openai_error_details(resp)
                detail = err_message or err_code or f"status={resp.status_code}"
                _set_error("mode5_oauth_email_validate_failed", detail)
                print(f"  ❌ OAuth 验证码提交失败: {detail}")
                return None
            print("  ✅ OAuth 邮箱验证码通过")
            try:
                data = resp.json() or {}
            except Exception:
                data = {}
            continue_url = str(data.get("continue_url") or "").strip()
            page_type = str((data.get("page") or {}).get("type") or "").strip()
            if page_type == "about_you" and not continue_url:
                continue_url = f"{OAUTH_ISSUER}/about-you"
            elif page_type == "add_phone" and not continue_url:
                continue_url = f"{OAUTH_ISSUER}/add-phone"
            print(f"  validate 后 page={page_type or '-'} continue={continue_url[:160] if continue_url else '-'}")

            if "about-you" in continue_url or "about_you" in page_type:
                about_you_processed = True
                continue_url = _advance_about_you_flow(continue_url or f"{OAUTH_ISSUER}/about-you", f"{OAUTH_ISSUER}/email-verification")
                continue_url = str(continue_url or "").strip()
                if continue_url and "consent" in continue_url:
                    page_type = "sign_in_with_chatgpt_codex_consent"
                elif continue_url and "organization" in continue_url:
                    page_type = "sign_in_with_chatgpt_codex_org"
                elif continue_url and "add-phone" in continue_url:
                    page_type = "add_phone"
                elif continue_url and "about-you" in continue_url:
                    page_type = "about_you"

        if not about_you_processed and ("about-you" in continue_url or "about_you" in page_type):
            continue_url = _advance_about_you_flow(continue_url or f"{OAUTH_ISSUER}/about-you", f"{OAUTH_ISSUER}/log-in/password")
            continue_url = str(continue_url or "").strip()
            if continue_url and "consent" in continue_url:
                page_type = "sign_in_with_chatgpt_codex_consent"
            elif continue_url and "organization" in continue_url:
                page_type = "sign_in_with_chatgpt_codex_org"
            elif continue_url and "add-phone" in continue_url:
                page_type = "add_phone"
            elif continue_url and "about-you" in continue_url:
                page_type = "about_you"

        if "add-phone" in continue_url or page_type == "add_phone":
            _set_error("mode5_post_email_add_phone", continue_url or page_type)
            print("  ℹ️ OAuth 邮箱验证后进入 add-phone，等待下一轮补登")
            return None

        if about_you_state.get("error_code") in CREATE_ACCOUNT_SOFT_SUCCESS_ERROR_CODES and (not continue_url or "about-you" in continue_url):
            _set_error("mode5_post_email_about_you_registration_disallowed", about_you_state.get("error_code") or "registration_disallowed")
            print("  ℹ️ about-you create_account 返回 registration_disallowed，等待下一轮补登")
            return None

        if "about-you" in continue_url or "about_you" in page_type:
            print("  ⚠️ continue_url 仍为 about-you，切换到标准 consent 入口继续推进会话")
            continue_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
            page_type = "sign_in_with_chatgpt_codex_consent"

        if "consent" in page_type and not continue_url:
            continue_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
        if not continue_url or "email-verification" in continue_url:
            print("  ⚠️ 未拿到有效 consent URL，回退标准 consent 入口")
            continue_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"

        consent_url = _oauth_absolute_url(continue_url)
        html = ""
        try:
            resp = session.get(
                consent_url,
                headers=nav_headers,
                verify=False,
                timeout=30,
                allow_redirects=False,
            )
            print(
                f"  consent GET: {resp.status_code} -> "
                f"{resp.headers.get('Location', '')[:120] if resp.status_code in (301, 302, 303, 307, 308) else resp.url[:120]}"
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                auth_code = _oauth_extract_code_from_url(location) or _oauth_follow_and_extract_code(session, location, nav_headers)
                if auth_code:
                    print(f"  ✅ consent 直接拿到 code（长度: {len(auth_code)}）")
                    return codex_exchange_code(
                        auth_code,
                        code_verifier,
                        proxy_url=account_proxy,
                        relay_state=_relay_state_from_session(session) or relay_state,
                    )
            elif resp.status_code == 200:
                html = resp.text
        except requests.exceptions.ConnectionError as e:
            auth_code = _oauth_extract_code_from_connection_error(e)
            if auth_code:
                print(f"  ✅ consent ConnectionError 中拿到 code（长度: {len(auth_code)}）")
                return codex_exchange_code(
                    auth_code,
                    code_verifier,
                    proxy_url=account_proxy,
                    relay_state=_relay_state_from_session(session) or relay_state,
                )
        except Exception as e:
            print(f"  ⚠️ consent 请求异常: {e}")

        session_data, workspace_id, ws_kind = _oauth_read_workspace_context(session, html)
        if workspace_id:
            print(f"  ✅ workspace_id: {workspace_id} (kind: {ws_kind})")
        elif session_data:
            print("  ⚠️ 已解码 auth session，但暂未找到 workspace")
        else:
            print("  ⚠️ 暂未解码出 auth session / workspace")

        if not workspace_id:
            auth_code = _oauth_follow_and_extract_code(session, consent_url, nav_headers)
            if auth_code:
                print(f"  ✅ consent 跟踪获取到 code（长度: {len(auth_code)}）")
                return codex_exchange_code(
                    auth_code,
                    code_verifier,
                    proxy_url=account_proxy,
                    relay_state=_relay_state_from_session(session) or relay_state,
                )
            _set_error("mode5_code_missing_after_consent", consent_url)
            print("  ❌ consent 阶段未获取到 authorization code")
            return None

        h_consent = _mode5_fetch_headers_static(consent_url, origin=OPENAI_AUTH_BASE)
        h_consent["oai-device-id"] = device_id
        h_consent.update(generate_datadog_trace())
        try:
            resp = session.post(
                f"{OAUTH_ISSUER}/api/accounts/workspace/select",
                json={"workspace_id": workspace_id},
                headers=h_consent,
                verify=False,
                timeout=30,
                allow_redirects=False,
            )
            print(f"  workspace/select: {resp.status_code}")
        except Exception as e:
            _set_error("mode5_workspace_select_exception", str(e))
            print(f"  ❌ workspace/select 异常: {e}")
            return None

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            auth_code = _oauth_extract_code_from_url(location) or _oauth_follow_and_extract_code(session, location, nav_headers)
            if auth_code:
                print(f"  ✅ workspace/select 拿到 code（长度: {len(auth_code)}）")
                return codex_exchange_code(
                    auth_code,
                    code_verifier,
                    proxy_url=account_proxy,
                    relay_state=_relay_state_from_session(session) or relay_state,
                )

        try:
            ws_data = resp.json() if resp.status_code == 200 else {}
        except Exception:
            ws_data = {}

        ws_next = str(ws_data.get("continue_url") or "").strip()
        ws_page = str((ws_data.get("page") or {}).get("type") or "").strip()
        auth_code = _oauth_extract_code_from_url(ws_next) or _oauth_follow_and_extract_code(session, ws_next, nav_headers)
        if auth_code:
            print(f"  ✅ workspace/select 后续拿到 code（长度: {len(auth_code)}）")
            return codex_exchange_code(
                auth_code,
                code_verifier,
                proxy_url=account_proxy,
                relay_state=_relay_state_from_session(session) or relay_state,
            )

        if "organization" in ws_next or "organization" in ws_page:
            org_id = None
            project_id = None
            orgs = ((ws_data.get("data") or {}).get("orgs") or []) if isinstance(ws_data, dict) else []
            if orgs and isinstance(orgs[0], dict):
                org_id = orgs[0].get("id")
                projects = orgs[0].get("projects") or []
                if projects and isinstance(projects[0], dict):
                    project_id = projects[0].get("id")
            if org_id:
                org_url = _oauth_absolute_url(ws_next) or consent_url
                h_org = _mode5_fetch_headers_static(org_url, origin=OPENAI_AUTH_BASE)
                h_org["oai-device-id"] = device_id
                h_org.update(generate_datadog_trace())
                body = {"org_id": org_id}
                if project_id:
                    body["project_id"] = project_id
                try:
                    resp = session.post(
                        f"{OAUTH_ISSUER}/api/accounts/organization/select",
                        json=body,
                        headers=h_org,
                        verify=False,
                        timeout=30,
                        allow_redirects=False,
                    )
                    print(f"  organization/select: {resp.status_code}")
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        auth_code = _oauth_extract_code_from_url(location) or _oauth_follow_and_extract_code(session, location, nav_headers)
                    elif resp.status_code == 200:
                        try:
                            org_data = resp.json() or {}
                        except Exception:
                            org_data = {}
                        org_next = str(org_data.get("continue_url") or "").strip()
                        auth_code = _oauth_extract_code_from_url(org_next) or _oauth_follow_and_extract_code(session, org_next, nav_headers)
                    if auth_code:
                        print(f"  ✅ organization/select 拿到 code（长度: {len(auth_code)}）")
                        return codex_exchange_code(
                            auth_code,
                            code_verifier,
                            proxy_url=account_proxy,
                            relay_state=_relay_state_from_session(session) or relay_state,
                        )
                except Exception as e:
                    print(f"  ⚠️ organization/select 异常: {e}")

        _set_error("mode5_code_missing_after_workspace", ws_next or consent_url)
        print("  ❌ workspace/select 后仍未获取到 authorization code")
        return None

    finally:
        if not borrowed_session:
            _close_session(session)
        if created_mail_session is not None:
            _close_session(created_mail_session)


def perform_codex_oauth_login_http(email, password, registrar_session=None, email_id=None, error_holder=None, proxy_url=None, mail_session=None, relay_state=None, device_id=None, sentinel_gen=None, mode5_callback_url=None):
    """
    纯 HTTP 方式执行 Codex OAuth 登录获取 Token（零浏览器）。

    已验证的纯 HTTP OAuth 流程（4~5 步）：
      步骤1: GET  /oauth/authorize       → 获取 login_session cookie
      步骤2: POST /api/accounts/authorize/continue  → 提交邮箱
      步骤3: POST /api/accounts/password/verify      → 提交密码
      步骤3.5: （可选）邮箱验证 — 新注册账号首次登录时触发
      步骤4: GET  consent URL → 302 重定向提取 code → POST /oauth/token 换取 tokens

    参数:
        email: 登录邮箱
        password: 登录密码
        registrar_session: 注册时的 session（可选；若提供且未显式指定 proxy_url，则复用其代理）
        email_id: DuckMail Bearer Token（用于接收 OTP 验证码，新注册账号首次登录时需要）
        proxy_url: 当前账号绑定代理；None 时优先沿用 registrar_session 里的代理
    返回:
        dict: tokens 字典（含 access_token/refresh_token/id_token），失败返回 None
    """
    mode5_callback_url = str(mode5_callback_url or "").strip()
    if PROXY_MODE == 5 or _is_mode5_callback_url(mode5_callback_url):
        return _perform_codex_oauth_login_mode5_http(
            email,
            password,
            registrar_session=registrar_session,
            email_id=email_id,
            error_holder=error_holder,
            proxy_url=proxy_url,
            mail_session=mail_session,
            relay_state=relay_state,
            device_id=device_id,
            sentinel_gen=sentinel_gen,
            mode5_callback_url=mode5_callback_url,
        )

    print("\n🔐 执行 Codex OAuth 登录（纯 HTTP 模式）...")

    # 可选错误回传容器（用于补登检测）
    if isinstance(error_holder, dict):
        error_holder.clear()

    def _set_error(reason, detail=""):
        if isinstance(error_holder, dict):
            error_holder["reason"] = reason
            if detail:
                error_holder["detail"] = detail

    def _abort_if_chatgptmail_unsupported():
        err_code, err_msg, err_email = _chatgptmail_get_last_error(mail_session)
        if err_code != "unsupported_email":
            return False
        detail = err_msg or err_email or email
        _set_error("chatgptmail_unsupported_email", detail)
        print(f"  ⚠️ ChatGPTMail 不支持该邮箱地址，停止当前 OAuth: {err_email or email}")
        return True

    about_you_state = {"error_code": "", "error_message": "", "continue_url": ""}

    if proxy_url is None and registrar_session is not None:
        account_proxy = _session_proxy_url(registrar_session)
    else:
        account_proxy = _effective_proxy(proxy_url)

    if relay_state is None and registrar_session is not None:
        relay_state = _relay_state_from_session(registrar_session)
    if relay_state is None and mail_session is not None:
        relay_state = _relay_state_from_session(mail_session)

    if mail_session is None:
        mail_session = create_mail_session(account_proxy, relay_state=_new_random_mail_relay_state())

    session = create_session(account_proxy, relay_state=relay_state)
    try:
        device_id = generate_device_id()
    
        # 在 session 中设置 oai-did cookie（两种 domain 格式兼容）
        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
        session.cookies.set("oai-did", device_id, domain="auth.openai.com")
    
        # 生成 PKCE 参数和 state
        code_verifier, code_challenge = generate_pkce()
        state = secrets.token_urlsafe(32)
    
        authorize_params = {
            "response_type": "code",
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        authorize_url = f"{OAUTH_ISSUER}/oauth/authorize?{urlencode(authorize_params)}"
    
        # ===== 步骤1: GET /oauth/authorize =====
        try:
            resp = session.get(
                authorize_url,
                headers=NAVIGATE_HEADERS,
                allow_redirects=True,
                verify=False,
                timeout=30,
            )
            print(f"  状态码: {resp.status_code}")
            print(f"  最终URL: {resp.url[:120]}")
        except Exception as e:
            _set_error("oauth_authorize_exception", str(e))
            print(f"  ❌ OAuth 授权请求失败: {e}")
            return None
    
        has_login_session = any(c.name == "login_session" for c in session.cookies)
        if not has_login_session:
            print("  ⚠️ 未获得 login_session")
    
        # ===== 步骤2: POST authorize/continue =====
    
        # 构造请求头（参考 test_oauth_quick.py）
        headers = dict(COMMON_HEADERS)
        headers["referer"] = f"{OAUTH_ISSUER}/log-in"
        headers["oai-device-id"] = device_id
        headers.update(generate_datadog_trace())
    
        # 获取 authorize_continue 的 sentinel token
        sentinel_email = build_sentinel_token(session, device_id, flow="authorize_continue")
        if not sentinel_email:
            _set_error("authorize_continue_sentinel_missing", f"{OAUTH_ISSUER}/log-in")
            print("  ❌ 无法获取 authorize_continue 的 sentinel token")
            return None
        headers["openai-sentinel-token"] = sentinel_email
    
        try:
            resp = session.post(
                f"{OAUTH_ISSUER}/api/accounts/authorize/continue",
                json={"username": {"kind": "email", "value": email}},
                headers=headers,
                verify=False,
                timeout=30,
            )
            print(f"  步骤2: {resp.status_code}")
        except Exception as e:
            _set_error("authorize_continue_exception", str(e))
            print(f"  ❌ 邮箱提交失败: {e}")
            return None

        if resp.status_code != 200:
            err_code, err_message = _extract_openai_error_details(resp)
            _set_error("authorize_continue_failed", err_message or err_code or f"status={resp.status_code}")
            print("  ❌ 邮箱提交失败")
            return None
    
        page_type = ""
        try:
            data = resp.json()
            page_type = data.get("page", {}).get("type", "")
        except Exception:
            page_type = ""
    
        # ===== 步骤3前: 捕获邮件快照（用于步骤3.5区分新旧邮件） =====
        pre_step3_mail_ids = capture_mail_snapshot(
            email, email_id,
            proxy_url=account_proxy,
            session=mail_session,
        )
        if _abort_if_chatgptmail_unsupported():
            return None
    
        # ===== 步骤3: POST password/verify =====
    
        headers["referer"] = f"{OAUTH_ISSUER}/log-in/password"
        headers.update(generate_datadog_trace())
    
        # 获取 password_verify 的 sentinel token（每个 flow 需要独立的 token）
        sentinel_pwd = build_sentinel_token(session, device_id, flow="password_verify")
        if not sentinel_pwd:
            _set_error("password_verify_sentinel_missing", f"{OAUTH_ISSUER}/log-in/password")
            print("  ❌ 无法获取 password_verify 的 sentinel token")
            return None
        headers["openai-sentinel-token"] = sentinel_pwd
    
        try:
            resp = session.post(
                f"{OAUTH_ISSUER}/api/accounts/password/verify",
                json={"password": password},
                headers=headers,
                verify=False,
                timeout=30,
                allow_redirects=False,
            )
            print(f"  步骤3: {resp.status_code} → {page_type}")
        except Exception as e:
            _set_error("password_verify_exception", str(e))
            print(f"  ❌ 密码提交失败: {e}")
            return None
    
        if resp.status_code != 200:
            if resp.status_code == 401:
                if page_type == "login_password":
                    _set_error("password_verify_401_login_password", f"status=401,page={page_type}")
                else:
                    _set_error("password_verify_401", f"status=401,page={page_type}")
            else:
                _set_error("password_verify_failed", f"status={resp.status_code},page={page_type}")
            print("  ❌ 密码验证失败")
            return None
    
        continue_url = None
        try:
            data = resp.json()
            continue_url = data.get("continue_url", "")
            page_type = data.get("page", {}).get("type", "")
        except Exception:
            page_type = ""
    
        if not continue_url:
            _set_error("password_verify_continue_missing", f"{OAUTH_ISSUER}/log-in/password")
            print("  ❌ 未获取到 continue_url")
            return None

        print(f"  password_verify continue_url: {continue_url[:120]}")
        print(f"  password_verify page.type: {page_type or '?' }")

        def _advance_about_you_flow(current_continue_url, referer_url):
            if not current_continue_url or "about-you" not in current_continue_url:
                return current_continue_url
            print("  📝 处理 about-you 步骤...")
            about_you_url = current_continue_url if current_continue_url.startswith("http") else f"{OAUTH_ISSUER}{current_continue_url}"

            h_about = dict(NAVIGATE_HEADERS)
            h_about["referer"] = referer_url
            resp_about = session.get(
                about_you_url,
                headers=h_about, verify=False, timeout=30, allow_redirects=True,
            )
            print(f"  GET about-you: {resp_about.status_code}, URL: {resp_about.url[:80]}")

            if "consent" in resp_about.url or "organization" in resp_about.url:
                next_url = resp_about.url
                print(f"  ✅ 已跳转到 consent: {next_url}")
                return next_url

            first_names = ["James", "Mary", "John", "Linda", "Robert", "Sarah"]
            last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Wilson"]
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            year = random.randint(1995, 2002)
            month = random.randint(1, 12)
            day = random.randint(1, 28)
            birthdate = f"{year}-{month:02d}-{day:02d}"

            def _extract_continue_url_from_resp(resp_obj):
                if resp_obj is None:
                    return ""
                location = str((getattr(resp_obj, "headers", {}) or {}).get("Location") or "").strip()
                if location:
                    return location
                try:
                    payload = resp_obj.json()
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    cont = str(payload.get("continue_url") or "").strip()
                    if cont:
                        return cont
                    for k in ("data", "error", "details", "context"):
                        sub = payload.get(k, {})
                        if isinstance(sub, dict) and sub.get("continue_url"):
                            return str(sub.get("continue_url") or "").strip()
                raw = str(getattr(resp_obj, "text", "") or "")
                match = re.search(r'"continue_url"\s*:\s*"([^"]+)"', raw)
                if not match:
                    match = re.search(r'\\"continue_url\\"\s*:\s*\\"([^\\"]+)\\"', raw)
                if match:
                    return match.group(1).replace("\/", "/").strip()
                return ""

            def _log_create_account_resp(label, resp_obj):
                if resp_obj is None:
                    print(f"  ⚠️ {label} 无响应")
                    return
                err_code, err_message = _extract_openai_error_details(resp_obj)
                about_you_state["error_code"] = str(err_code or "").strip()
                about_you_state["error_message"] = str(err_message or "").strip()
                location = str((getattr(resp_obj, "headers", {}) or {}).get("Location") or "").strip()
                preview = str(getattr(resp_obj, "text", "") or "")[:300].replace("\n", " ")
                print(f"  {label}: status={resp_obj.status_code}, code={err_code or '-'}, message={err_message or '-'}, location={location[:120] if location else '-'}")
                if preview:
                    print(f"  {label} body: {preview}")

            def _post_about_you_create(extra_headers=None, label="create_account"):
                h_create = dict(COMMON_HEADERS)
                h_create["referer"] = about_you_url
                h_create["oai-device-id"] = device_id
                h_create.update(generate_datadog_trace())
                if extra_headers:
                    h_create.update(extra_headers)
                resp_obj = session.post(
                    f"{OAUTH_ISSUER}/api/accounts/create_account",
                    json={"name": name, "birthdate": birthdate},
                    headers=h_create, verify=False, timeout=30, allow_redirects=False,
                )
                print(f"  {label}: {resp_obj.status_code}")
                return resp_obj

            next_url = current_continue_url
            resp_create = _post_about_you_create()
            create_responses = [("create_account", resp_create)]

            first_continue = _extract_continue_url_from_resp(resp_create)
            if first_continue:
                next_url = first_continue

            if resp_create.status_code in (400, 403) and not first_continue:
                _log_create_account_resp("create_account", resp_create)
                sentinel_token = build_sentinel_token(session, device_id, flow="password_verify")
                if sentinel_token:
                    resp_retry = _post_about_you_create({"openai-sentinel-token": sentinel_token}, label="create_account retry(password_verify sentinel)")
                    create_responses.append(("create_account retry(password_verify sentinel)", resp_retry))
                    retry_continue = _extract_continue_url_from_resp(resp_retry)
                    if retry_continue:
                        next_url = retry_continue
                        resp_create = resp_retry
                else:
                    print("  ⚠️ 无法获取 create_account 的 sentinel token（password_verify flow）")

            if next_url == current_continue_url and resp_create.status_code in (400, 403):
                raw_sentinel = SentinelTokenGenerator(device_id=device_id).generate_token()
                if raw_sentinel:
                    resp_retry2 = _post_about_you_create({"openai-sentinel-token": raw_sentinel}, label="create_account retry(raw sentinel)")
                    create_responses.append(("create_account retry(raw sentinel)", resp_retry2))
                    retry_continue2 = _extract_continue_url_from_resp(resp_retry2)
                    if retry_continue2:
                        next_url = retry_continue2
                        resp_create = resp_retry2

            about_you_state["continue_url"] = str(next_url or "").strip()
            if next_url != current_continue_url:
                print(f"  ✅ about-you 后续 continue_url: {next_url}")
            else:
                last_label, last_resp = create_responses[-1]
                _log_create_account_resp(last_label, last_resp)
                print("  ⚠️ create_account 未返回可用 continue_url，重新探测 about-you 跳转...")
                try:
                    probe = session.get(
                        about_you_url,
                        headers=h_about,
                        verify=False,
                        timeout=30,
                        allow_redirects=True,
                    )
                    if "consent" in probe.url or "organization" in probe.url:
                        next_url = probe.url
                        about_you_state["continue_url"] = str(next_url or "").strip()
                        print(f"  ✅ probe 跳转到 consent: {next_url}")
                except Exception:
                    pass
            return next_url

    
        # ===== 步骤3.5: 邮箱验证（新注册账号首次登录时可能触发） =====
        if page_type == "email_otp_verification" or "email-verification" in continue_url:
            print("\n  --- [步骤3.5] 邮箱验证（新注册账号首次登录） ---")
    
            if not email_id:
                _set_error("oauth_email_id_missing", f"{OAUTH_ISSUER}/email-verification")
                print("  ❌ 无 email_id，无法接收验证码")
                return None
    
            # OTP 重发函数（仅在 30s 超时后作为 resend 使用）
            # 注意：password/verify 返回 email_otp_verification 时服务端已自动发送 OTP
            # 主动调用 email-otp/send 会干扰 session → 导致 validate 401 或 consent 无 workspaces
            def _trigger_otp_resend():
                try:
                    _h = dict(COMMON_HEADERS)
                    _h["referer"] = f"{OAUTH_ISSUER}/log-in/password"
                    r1 = session.get(
                        f"{OAUTH_ISSUER}/api/accounts/email-otp/send",
                        headers=_h, verify=False, timeout=30, allow_redirects=False,
                    )
                    print(f"  📬 OTP 重发触发: {r1.status_code}")
                except Exception as e:
                    print(f"  ⚠️ OTP 重发异常: {e}")
    
            # 不主动触发 — 等待服务端自动发送的 OTP
            # 分级超时：有旧邮件 = 通道正常；0 封 = 通道可疑（均可在 .env 调整）
            otp_timeout = (
                OAUTH_OTP_TIMEOUT_WITH_SNAPSHOT_SECONDS
                if len(pre_step3_mail_ids) > 0
                else OAUTH_OTP_TIMEOUT_NO_SNAPSHOT_SECONDS
            )

            # 复用统一的验证码等待逻辑（无新邮件超过阈值才触发重发）
            code = wait_for_verification_code(
                mail_session, email, email_id,
                timeout=otp_timeout,
                pre_otp_ids=pre_step3_mail_ids,
                resend_fn=_trigger_otp_resend,
            )
            if _abort_if_chatgptmail_unsupported():
                return None
    
            if not code:
                _set_error("oauth_email_otp_timeout", f"{OAUTH_ISSUER}/email-verification")
                return None
    
            # 提交验证码
            h_val = dict(COMMON_HEADERS)
            h_val["referer"] = f"{OAUTH_ISSUER}/email-verification"
            h_val["oai-device-id"] = device_id
            h_val.update(generate_datadog_trace())
    
            print(f"  🔢 提交验证码: {code}")
            resp = session.post(
                f"{OAUTH_ISSUER}/api/accounts/email-otp/validate",
                json={"code": code},
                headers=h_val, verify=False, timeout=30,
            )
            if resp.status_code == 200:
                print(f"  ✅ 验证码 {code} 验证通过！")
                try:
                    data = resp.json()
                    continue_url = data.get("continue_url", "")
                    page_type = data.get("page", {}).get("type", "")
                except Exception:
                    pass
            else:
                _set_error("oauth_email_validate_failed", f"{OAUTH_ISSUER}/email-verification")
                print(f"  ❌ 验证码 {code} 提交失败: {resp.status_code}")
                return None
    
            # 如果验证后进入 about-you（填写姓名生日），需要处理
            if "about-you" in continue_url:
                continue_url = _advance_about_you_flow(continue_url, f"{OAUTH_ISSUER}/email-verification")

            # consent 直接返回的情况（page.type 已经是 consent）
            if "consent" in page_type and not continue_url:
                continue_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"

        if continue_url and "about-you" in continue_url:
            continue_url = _advance_about_you_flow(continue_url, f"{OAUTH_ISSUER}/log-in/password")

        if continue_url and "add-phone" in continue_url:
            print("  ℹ️ about-you 已推进到 add-phone，当前账号通常已落库；等待下一轮补登进入 email-verification")
            _set_error("about_you_add_phone_pending", continue_url)
            return None

        if about_you_state.get("error_code") in CREATE_ACCOUNT_SOFT_SUCCESS_ERROR_CODES and (not continue_url or "about-you" in continue_url):
            print("  ℹ️ about-you create_account 返回 registration_disallowed，按已注册处理，等待下一轮补登")
            _set_error("about_you_registration_disallowed", about_you_state.get("error_code") or "registration_disallowed")
            return None

        # 仍停在 about-you 说明会话尚未推进到 consent，改用标准 consent 路径继续推进
        if continue_url and "about-you" in continue_url:
            print("  ⚠️ continue_url 仍为 about-you，切换到标准 consent 入口继续推进会话")
            continue_url = "/sign-in-with-chatgpt/codex/consent"

        if not continue_url or "email-verification" in continue_url:
            print("  ⚠️ 邮箱验证后未获取到有效 consent URL，后续使用兜底路径并尝试会话自恢复")
            continue_url = "/sign-in-with-chatgpt/codex/consent"
    
        # ===== 步骤4: consent 多步流程 → 提取 authorization code → 换 token =====
        #
        # 逆向分析结果（consent 页面的 React Router route-D83ftS1Y.js）：
        #   clientLoader: 从 oai-client-auth-session cookie 中读取 workspaces
        #   clientAction: POST /api/accounts/workspace/select → {"workspace_id": "..."}
        #   然后从响应的 data.orgs 中提取 org，POST organization/select
        #   最终通过重定向链获取 authorization code
        #
        print("\n  --- [步骤4] consent 多步流程 → 提取 code ---")
    
        # ----- 辅助：统一 URL（处理相对路径） -----
        def _to_absolute_url(url):
            if not url:
                return ""
            if url.startswith("/"):
                return f"{OAUTH_ISSUER}{url}"
            return url
    
        # consent URL 可能是相对路径，拼接完整 URL
        consent_url = _to_absolute_url(continue_url)
        print(f"  consent URL: {consent_url}")
    
        # ----- 辅助：从 URL 提取 code -----
        def _extract_code_from_url(url):
            if not url or "code=" not in url:
                return None
            try:
                return parse_qs(urlparse(url).query).get("code", [None])[0]
            except Exception:
                return None
    
        # ----- 辅助：从 oai-client-auth-session cookie 解码 JSON -----
        def _decode_auth_session(session_obj):
            """
            oai-client-auth-session 是 Flask/itsdangerous 格式：
            1) base64(json).timestamp.signature
            2) .base64(zlib(json)).timestamp.signature  （前导 '.' 表示压缩）
    
            解码后 JSON 中包含 workspaces/orgs/projects 等核心数据。
            """
            for c in session_obj.cookies:
                if c.name == "oai-client-auth-session":
                    val = c.value or ""
                    if not val:
                        continue
    
                    compressed = val.startswith(".")
                    parts = val.split(".")
                    if compressed:
                        if len(parts) < 2 or not parts[1]:
                            continue
                        payload_part = parts[1]
                    else:
                        payload_part = parts[0]
    
                    # 补齐 base64 padding
                    pad = (4 - len(payload_part) % 4) % 4
                    if pad:
                        payload_part += "=" * pad
                    try:
                        raw = base64.urlsafe_b64decode(payload_part.encode("ascii"))
                        if compressed:
                            import zlib
                            raw = zlib.decompress(raw)
                        return json.loads(raw.decode("utf-8"))
                    except Exception:
                        continue
            return None
    
        def _extract_workspace_from_session_data(session_data_obj):
            """
            在 session JSON 中递归查找 workspaces，兼容不同版本字段结构。
            返回: (workspace_id, workspace_kind)
            """
            def _walk(node):
                if isinstance(node, dict):
                    ws_list = node.get("workspaces")
                    if isinstance(ws_list, list):
                        for ws in ws_list:
                            if isinstance(ws, dict):
                                ws_id = ws.get("id")
                                if ws_id:
                                    return ws_id, ws.get("kind", "?")
                    for v in node.values():
                        found = _walk(v)
                        if found:
                            return found
                elif isinstance(node, list):
                    for item in node:
                        found = _walk(item)
                        if found:
                            return found
                return None
    
            found = _walk(session_data_obj)
            if found:
                return found
            return None, "?"
    
        def _extract_workspace_from_html(html_text):
            """
            consent HTML 兜底提取 workspace_id（用于 cookie 尚未完整同步时）。
            返回: (workspace_id, workspace_kind)
            """
            if not html_text:
                return None, "?"
    
            patterns = [
                r'"workspaces"\s*:\s*\[\s*\{[^{}]*?"id"\s*:\s*"([^"]+)"[^{}]*?(?:"kind"\s*:\s*"([^"]+)")?',
                r'\\"workspaces\\"\s*:\s*\[\s*\{[^{}]*?\\"id\\"\s*:\s*\\"([^\\"]+)\\"[^{}]*?(?:\\"kind\\"\s*:\s*\\"([^\\"]+)\\")?',
                r'"workspace_id"\s*:\s*"([^"]+)"',
                r'\\"workspace_id\\"\s*:\s*\\"([^\\"]+)\\"',
            ]
            for pat in patterns:
                m = re.search(pat, html_text, re.S)
                if m:
                    ws_id = m.group(1)
                    ws_kind = m.group(2) if m.lastindex and m.lastindex >= 2 and m.group(2) else "?"
                    if ws_id:
                        return ws_id, ws_kind
            return None, "?"
    
        def _read_workspace_context(session_obj, html_text=""):
            session_data_obj = _decode_auth_session(session_obj)
            workspace_id_val = None
            workspace_kind_val = "?"
            if session_data_obj:
                workspace_id_val, workspace_kind_val = _extract_workspace_from_session_data(session_data_obj)
            if not workspace_id_val and html_text:
                workspace_id_val, workspace_kind_val = _extract_workspace_from_html(html_text)
            return session_data_obj, workspace_id_val, workspace_kind_val
    
        # ----- 辅助：从 302 Location 或 ConnectionError 中提取 code -----
        def _follow_and_extract_code(session_obj, url, max_depth=10):
            """跟随 URL，从 302 Location 或 ConnectionError 中提取 code"""
            if not url or max_depth <= 0:
                return None
            url = _to_absolute_url(url)
            try:
                r = session_obj.get(url, headers=NAVIGATE_HEADERS, verify=False,
                                   timeout=15, allow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    code = _extract_code_from_url(loc)
                    if code:
                        return code
                    # 不包含 code，继续跟踪
                    loc = _to_absolute_url(loc)
                    if not loc:
                        return None
                    return _follow_and_extract_code(session_obj, loc, max_depth - 1)
                elif r.status_code == 200:
                    return _extract_code_from_url(r.url)
            except requests.exceptions.ConnectionError as e:
                # 预期：localhost 连接失败，从错误信息中提取回调 URL
                url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                if url_match:
                    return _extract_code_from_url(url_match.group(1))
            except Exception:
                pass
            return None
    
        auth_code = None
    
        # ----- 步骤4a: GET consent 页面（设置 cookies + 触发服务端状态更新） -----
        print("  [4a] GET consent 页面...")
        consent_html = ""
        try:
            resp = session.get(consent_url, headers=NAVIGATE_HEADERS,
                              verify=False, timeout=30, allow_redirects=False)
    
            # 如果直接 302 带 code（少数情况）
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                auth_code = _extract_code_from_url(loc)
                if auth_code:
                    print(f"  ✅ consent 直接 302 获取到 code（长度: {len(auth_code)}）")
                else:
                    # 继续跟踪重定向
                    auth_code = _follow_and_extract_code(session, loc)
                    if auth_code:
                        print(f"  ✅ consent 302 跟踪获取到 code（长度: {len(auth_code)}）")
            elif resp.status_code == 200:
                consent_html = resp.text
                print(f"  ✅ consent 页面已加载（HTML {len(consent_html)} 字节）")
        except requests.exceptions.ConnectionError as e:
            # 可能直接被重定向到 localhost
            url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
            if url_match:
                auth_code = _extract_code_from_url(url_match.group(1))
                if auth_code:
                    print(f"  ✅ consent ConnectionError 中获取到 code")
        except Exception as e:
            print(f"  ⚠️ consent 请求异常: {e}")
    
        # ----- 步骤4b: 提取 workspace_id（必要时先推进 consent 会话状态） -----
        if not auth_code:
            print("  [4b] 解码/补齐 session → 提取 workspace_id...")
            session_data, workspace_id, ws_kind = _read_workspace_context(session, consent_html)
    
            if session_data:
                try:
                    print(f"  session keys: {list(session_data.keys())}")
                except Exception:
                    pass
            else:
                print("  ⚠️ 首次解码 oai-client-auth-session 失败，尝试通过 consent 导航推进状态")
    
            # 核心修复：若会话里尚无 workspace，上下文可能还没推进到 consent 完整态
            if not workspace_id:
                for attempt in range(1, 4):
                    print(f"  [4b-bootstrap] 会话上下文推进 {attempt}/3 ...")
                    try:
                        resp_boot = session.get(
                            consent_url,
                            headers=NAVIGATE_HEADERS,
                            verify=False,
                            timeout=30,
                            allow_redirects=True,
                        )
    
                        # 先尝试直接从最终 URL / 重定向链提取 code
                        auth_code = _extract_code_from_url(resp_boot.url)
                        if not auth_code and resp_boot.history:
                            for hop in resp_boot.history:
                                loc = hop.headers.get("Location", "")
                                auth_code = _extract_code_from_url(loc)
                                if auth_code:
                                    break
                        if auth_code:
                            print(f"  ✅ bootstrap 导航获取到 code（长度: {len(auth_code)}）")
                            break
    
                        # 刷新 consent URL（避免后续 referer 落后于真实路由）
                        if resp_boot.url:
                            consent_url = _to_absolute_url(resp_boot.url)
    
                        if resp_boot.status_code == 200 and resp_boot.text:
                            consent_html = resp_boot.text
                    except requests.exceptions.ConnectionError as e:
                        url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                        if url_match:
                            auth_code = _extract_code_from_url(url_match.group(1))
                            if auth_code:
                                print(f"  ✅ bootstrap ConnectionError 中获取到 code")
                                break
                    except Exception as e:
                        print(f"  ⚠️ bootstrap 导航异常: {e}")
    
                    session_data, workspace_id, ws_kind = _read_workspace_context(session, consent_html)
                    if workspace_id:
                        print(f"  ✅ workspace_id: {workspace_id} (kind: {ws_kind})")
                        break
    
            if not auth_code and not workspace_id:
                if session_data:
                    print("  ⚠️ session 中仍无 workspaces 数据")
                    try:
                        print(f"  session keys: {list(session_data.keys())}")
                    except Exception:
                        pass
                else:
                    print("  ⚠️ 仍无法解码 oai-client-auth-session cookie")
    
                # 尝试直接跟踪 consent URL 获取 code（绕过 workspace/select）
                print("  [4b-fallback] 尝试直接跟踪 consent URL...")
                auth_code = _follow_and_extract_code(session, consent_url)
                if auth_code:
                    print(f"  ✅ 直接跟踪获取到 code（长度: {len(auth_code)}）")
    
            if workspace_id and not auth_code:
                print(f"  ✅ workspace_id: {workspace_id} (kind: {ws_kind})")
    
            if workspace_id and not auth_code:
                print(f"  [4b] POST workspace/select...")
                h_consent = dict(COMMON_HEADERS)
                h_consent["referer"] = consent_url
                h_consent["oai-device-id"] = device_id
                h_consent.update(generate_datadog_trace())
    
                try:
                    resp = session.post(
                        f"{OAUTH_ISSUER}/api/accounts/workspace/select",
                        json={"workspace_id": workspace_id},
                        headers=h_consent, verify=False, timeout=30, allow_redirects=False,
                    )
                    print(f"  状态码: {resp.status_code}")
    
                    if resp.status_code in (301, 302, 303, 307, 308):
                        auth_code = _extract_code_from_url(resp.headers.get("Location", ""))
                        if auth_code:
                            print(f"  ✅ workspace/select 302 获取到 code（长度: {len(auth_code)}）")
                    elif resp.status_code == 200:
                        ws_data = resp.json()
                        ws_next = ws_data.get("continue_url", "")
                        ws_page = ws_data.get("page", {}).get("type", "")
                        print(f"  continue_url: {ws_next}")
                        print(f"  page.type: {ws_page}")
    
                        # ----- 步骤4c: organization/select -----
                        if "organization" in ws_next or "organization" in ws_page:
                            org_url = ws_next if ws_next.startswith("http") else f"{OAUTH_ISSUER}{ws_next}"
                            print(f"  [4c] 准备 organization/select...")
    
                            # org_id 和 project_id 在 workspace/select 响应的 data.orgs 中
                            org_id = None
                            project_id = None
                            ws_orgs = ws_data.get("data", {}).get("orgs", [])
                            if ws_orgs and len(ws_orgs) > 0:
                                org_id = ws_orgs[0].get("id")
                                projects = ws_orgs[0].get("projects", [])
                                if projects:
                                    project_id = projects[0].get("id")
                                print(f"  ✅ org_id: {org_id}")
                                print(f"  ✅ project_id: {project_id}")
    
                            if org_id:
                                print(f"  [4c] POST organization/select...")
                                body = {"org_id": org_id}
                                if project_id:
                                    body["project_id"] = project_id
    
                                h_org = dict(COMMON_HEADERS)
                                h_org["referer"] = org_url
                                h_org["oai-device-id"] = device_id
                                h_org.update(generate_datadog_trace())
    
                                resp = session.post(
                                    f"{OAUTH_ISSUER}/api/accounts/organization/select",
                                    json=body, headers=h_org,
                                    verify=False, timeout=30, allow_redirects=False,
                                )
                                print(f"  状态码: {resp.status_code}")
    
                                if resp.status_code in (301, 302, 303, 307, 308):
                                    loc = resp.headers.get("Location", "")
                                    auth_code = _extract_code_from_url(loc)
                                    if auth_code:
                                        print(f"  ✅ organization/select 获取到 code（长度: {len(auth_code)}）")
                                    else:
                                        # 继续跟踪重定向链
                                        auth_code = _follow_and_extract_code(session, loc)
                                        if auth_code:
                                            print(f"  ✅ 跟踪重定向获取到 code（长度: {len(auth_code)}）")
                                elif resp.status_code == 200:
                                    org_data = resp.json()
                                    org_next = org_data.get("continue_url", "")
                                    print(f"  org continue_url: {org_next}")
                                    if org_next:
                                        full_next = org_next if org_next.startswith("http") else f"{OAUTH_ISSUER}{org_next}"
                                        auth_code = _follow_and_extract_code(session, full_next)
                                        if auth_code:
                                            print(f"  ✅ 跟踪获取到 code（长度: {len(auth_code)}）")
                            else:
                                print(f"  ⚠️ 未找到 org_id，尝试直接跟踪 consent URL...")
                                auth_code = _follow_and_extract_code(session, org_url)
                                if auth_code:
                                    print(f"  ✅ 直接跟踪获取到 code（长度: {len(auth_code)}）")
                        else:
                            # workspace/select 返回了非 organization 的 continue_url，直接跟踪
                            if ws_next:
                                full_next = ws_next if ws_next.startswith("http") else f"{OAUTH_ISSUER}{ws_next}"
                                auth_code = _follow_and_extract_code(session, full_next)
                                if auth_code:
                                    print(f"  ✅ 跟踪获取到 code（长度: {len(auth_code)}）")
                except Exception as e:
                    print(f"  ⚠️ workspace/select 异常: {e}")
                    import traceback
                    traceback.print_exc()
    
        # ----- 步骤4d: 备用策略 — allow_redirects=True 捕获 ConnectionError -----
        if not auth_code:
            print("  [4d] 备用策略: GET consent (allow_redirects=True)...")
            try:
                resp = session.get(consent_url, headers=NAVIGATE_HEADERS,
                                  verify=False, timeout=30, allow_redirects=True)
                print(f"  最终: {resp.status_code}, URL: {resp.url[:200]}")
                auth_code = _extract_code_from_url(resp.url)
                if auth_code:
                    print(f"  ✅ 最终 URL 中提取到 code")
                # 检查重定向链
                if not auth_code and resp.history:
                    for r in resp.history:
                        loc = r.headers.get("Location", "")
                        auth_code = _extract_code_from_url(loc)
                        if auth_code:
                            print(f"  ✅ 重定向链中提取到 code")
                            break
            except requests.exceptions.ConnectionError as e:
                url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                if url_match:
                    auth_code = _extract_code_from_url(url_match.group(1))
                    if auth_code:
                        print(f"  ✅ ConnectionError 中提取到 code")
            except Exception as e:
                print(f"  ⚠️ 备用策略异常: {e}")
    
        if not auth_code:
            _set_error("authorization_code_missing", consent_url)
            print("  ❌ 未获取到 authorization code")
            return None
    
        # 用 code 换 token（复用已有的 codex_exchange_code 函数）
        browser_proxy = _session_proxy_url(registrar_session) if registrar_session is not None else _effective_proxy()
        exchange_relay_state = (
            _relay_state_from_session(session)
            or relay_state
            or _relay_state_from_session(registrar_session)
            or _relay_state_from_session(mail_session)
        )
        return codex_exchange_code(
            auth_code,
            code_verifier,
            proxy_url=browser_proxy,
            relay_state=exchange_relay_state,
        )
    
    
    finally:
        _close_session(session)

# =================== Codex OAuth 登录 + CPA 回调（浏览器版，作为 fallback） ===================

def perform_codex_oauth_login(email, password, registrar_session=None):
    """
    注册成功后，通过浏览器混合模式执行 Codex OAuth 登录获取 Token。

    混合架构：
      浏览器层：完成 OAuth 登录全流程（邮箱+密码提交）
        - sentinel SDK 在浏览器内自动生成 t/c 字段（反机器人遥测+challenge response）
        - 通过 CDP 网络事件监听捕获 authorization code
      HTTP 层：用 code 换取 tokens（POST /oauth/token，无需 sentinel）

    使用 Codex 专用配置（来自 config.json）：
      client_id:    app_EMoamEEZ73f0CkXaXp7hrann（Codex CLI）
      redirect_uri: http://localhost:1455/auth/callback
      scope:        openid profile email offline_access
    
    参数:
        email: 注册的邮箱
        password: 注册的密码
        registrar_session: 注册时的 requests.Session（含 CF cookies，可选，本模式暂未使用）
    返回:
        dict: tokens 字典（含 access_token/refresh_token/id_token），失败返回 None
    """
    print("\n🔐 执行 Codex OAuth 登录获取 Token（浏览器混合模式）...")

    # 1. 构造 PKCE 参数
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(32)

    authorize_params = {
        "response_type": "code",
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "scope": "openid profile email offline_access",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    authorize_url = f"{OAUTH_ISSUER}/oauth/authorize?{urlencode(authorize_params)}"

    try:
        import undetected_chromedriver as uc
        from selenium.webdriver.common.by import By
    except ImportError:
        print("  ❌ 需要安装 undetected-chromedriver:")
        print("     pip install undetected-chromedriver selenium")
        return None

    driver = None
    try:
        # 2. 启动浏览器（带 CDP 网络事件监听）
        mode_str = "无头模式" if HEADLESS else "有头模式"
        print(f"  🌐 启动浏览器执行 OAuth 登录（{mode_str}，sentinel SDK 自动处理 t/c 字段）...")
        options = uc.ChromeOptions()
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=800,600")
        options.add_argument(f"--user-agent={USER_AGENT}")
        if HEADLESS:
            options.add_argument("--headless=new")
        browser_proxy = _effective_proxy()
        if browser_proxy:
            options.add_argument(f"--proxy-server={browser_proxy}")

        driver = uc.Chrome(version_main=145, options=options, use_subprocess=True)

        # 启用 CDP 网络事件监听（捕获请求中的 authorization code 回调）
        driver.execute_cdp_cmd("Network.enable", {})

        # 注入 JS Hook：拦截所有导航/请求，捕获回调 URL 中的 code
        # 由于 redirect_uri 是 localhost:1455（不可达），浏览器会导航失败但 URL 仍可读取
        # 同时注入 sentinel token 拦截 Hook（调试用，可查看 t/c 内容）
        hook_js = """
        // 拦截 XHR 请求头，捕获 sentinel token（调试用）
        (function() {
            window.__sentinel_tokens = [];
            const origOpen = XMLHttpRequest.prototype.open;
            const origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
            XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
                if (name === 'openai-sentinel-token') {
                    try {
                        window.__sentinel_tokens.push(JSON.parse(value));
                        console.log('SENTINEL_CAPTURED:', value.substring(0, 80));
                    } catch(e) {}
                }
                return origSetHeader.call(this, name, value);
            };

            // 同时拦截 fetch
            const origFetch = window.fetch;
            window.fetch = function(input, init) {
                if (init && init.headers) {
                    let sentinel = null;
                    if (init.headers instanceof Headers) {
                        sentinel = init.headers.get('openai-sentinel-token');
                    } else if (typeof init.headers === 'object') {
                        sentinel = init.headers['openai-sentinel-token'];
                    }
                    if (sentinel) {
                        try {
                            window.__sentinel_tokens.push(JSON.parse(sentinel));
                            console.log('SENTINEL_CAPTURED_FETCH:', sentinel.substring(0, 80));
                        } catch(e) {}
                    }
                }
                return origFetch.apply(this, arguments);
            };
        })();
        """
        # 在新文档加载前注入 Hook
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": hook_js}
        )

        # 3. 导航到 OAuth authorize URL
        print(f"  📡 访问 OAuth authorize URL...")
        driver.get(authorize_url)

        # 4. 等待 Cloudflare Challenge 完成 + 页面加载
        print("  ⏳ 等待 Cloudflare Challenge + 登录页面加载...")
        for i in range(60):
            try:
                current_url = driver.current_url
                # 检查是否已到达回调（极快通过的情况）
                if "localhost" in current_url and "code=" in current_url:
                    print(f"  ✅ 快速到达回调（第 {i+1}s）")
                    break
                # 检查是否有输入框或按钮（登录页加载完成）
                inputs = driver.find_elements(By.CSS_SELECTOR, "input")
                if inputs:
                    print(f"  ✅ 登录页面加载完成（第 {i+1}s）")
                    break
            except Exception:
                pass
            if i % 15 == 0 and i > 0:
                print(f"  ... 已等待 {i}s")
            time.sleep(1)

        time.sleep(1)

        # 辅助函数：检测并点击错误页面的重试按钮
        def _check_and_retry_error():
            """检测 OAuth 错误页面并点击重试按钮"""
            try:
                buttons = driver.find_elements(By.TAG_NAME, "button")
                for btn in buttons:
                    try:
                        btn_text = btn.text.strip().lower()
                        if btn_text in ["重试", "retry", "try again", "重新尝试"]:
                            if btn.is_displayed():
                                driver.execute_script("arguments[0].click();", btn)
                                print(f"  🔁 检测到错误页面，已点击重试")
                                time.sleep(3)
                                return True
                    except Exception:
                        continue
            except Exception:
                pass
            return False

        # 5. 自动化 OAuth 登录流程（邮箱 → 密码 → 确认）
        auth_code = None
        max_steps = 30  # 最大步骤数（防止无限循环）

        for step_i in range(max_steps):
            try:
                current_url = driver.current_url

                # ===== 检查是否已到达回调 URL =====
                if ("localhost" in current_url or "callback" in current_url) and "code=" in current_url:
                    parsed = urlparse(current_url)
                    params = parse_qs(parsed.query)
                    auth_code = params.get("code", [None])[0]
                    if auth_code:
                        print(f"  ✅ 获取到 authorization code（URL 回调，长度: {len(auth_code)}）")
                        break

                # ===== 检是否是错误页面 =====
                if _check_and_retry_error():
                    continue

                # ===== 邮箱输入页面 =====
                email_inputs = driver.find_elements(
                    By.CSS_SELECTOR,
                    'input[type="email"], input[name="email"], input[name="username"], input[id="email"]'
                )
                visible_email = [e for e in email_inputs if e.is_displayed()]
                if visible_email:
                    print(f"  📧 [OAuth] 输入邮箱: {email}")
                    inp = visible_email[0]
                    inp.clear()
                    inp.send_keys(email)
                    time.sleep(0.5)
                    # 点击 Continue/Submit 按钮
                    submit_btns = driver.find_elements(By.CSS_SELECTOR, 'button[type="submit"]')
                    if submit_btns:
                        driver.execute_script("arguments[0].click();", submit_btns[0])
                    else:
                        # 回退：查找任何按钮
                        buttons = driver.find_elements(By.TAG_NAME, "button")
                        for btn in buttons:
                            text = btn.text.strip().lower()
                            if text in ("continue", "继续", "next", "sign in", "log in"):
                                driver.execute_script("arguments[0].click();", btn)
                                break
                    print("  ✅ 邮箱已提交")
                    time.sleep(3)
                    continue

                # ===== 密码输入页面 =====
                pwd_inputs = driver.find_elements(
                    By.CSS_SELECTOR,
                    'input[type="password"], input[name="password"]'
                )
                visible_pwd = [e for e in pwd_inputs if e.is_displayed()]
                if visible_pwd:
                    print("  🔑 [OAuth] 输入密码...")
                    inp = visible_pwd[0]
                    inp.clear()
                    # 逐字符输入密码（模拟真实打字，避免反机器人检测）
                    for char in password:
                        inp.send_keys(char)
                        time.sleep(0.03)
                    time.sleep(0.5)
                    # 点击 Submit
                    submit_btns = driver.find_elements(By.CSS_SELECTOR, 'button[type="submit"]')
                    if submit_btns:
                        driver.execute_script("arguments[0].click();", submit_btns[0])
                    else:
                        buttons = driver.find_elements(By.TAG_NAME, "button")
                        for btn in buttons:
                            text = btn.text.strip().lower()
                            if text in ("continue", "继续", "log in", "sign in"):
                                driver.execute_script("arguments[0].click();", btn)
                                break
                    print("  ✅ 密码已提交")
                    time.sleep(3)
                    continue

                # ===== 授权确认页面 / Continue 按钮 =====
                buttons = driver.find_elements(By.TAG_NAME, "button")
                clicked_consent = False
                for btn in buttons:
                    try:
                        btn_text = btn.text.strip().lower()
                        if btn_text in ("continue", "继续", "allow", "approve", "accept", "authorize"):
                            if btn.is_displayed() and btn.is_enabled():
                                driver.execute_script("arguments[0].click();", btn)
                                print(f"  ✅ [OAuth] 已点击确认按钮: '{btn.text.strip()}'")
                                clicked_consent = True
                                time.sleep(3)
                                break
                    except Exception:
                        continue

                if clicked_consent:
                    continue

                # ===== 没有可操作的元素，等待页面变化 =====
                time.sleep(2)

            except Exception as e:
                print(f"  ⚠️ OAuth 步骤异常: {e}")
                time.sleep(2)

        # 6. 如果通过 URL 未获取到 code，尝试从网络日志中获取
        if not auth_code:
            print("  🔍 尝试从浏览器网络日志中提取 authorization code...")
            try:
                # 检查 performance log（如果可用）
                logs = driver.get_log("performance")
                for entry in logs:
                    try:
                        msg = json.loads(entry["message"])
                        method = msg.get("message", {}).get("method", "")
                        if method in ("Network.requestWillBeSent", "Network.responseReceived"):
                            url = (msg.get("message", {}).get("params", {})
                                   .get("request", {}).get("url", "")
                                   or msg.get("message", {}).get("params", {})
                                   .get("response", {}).get("url", ""))
                            if "code=" in url and "localhost" in url:
                                parsed = urlparse(url)
                                params = parse_qs(parsed.query)
                                auth_code = params.get("code", [None])[0]
                                if auth_code:
                                    print(f"  ✅ 从网络日志中获取到 code（长度: {len(auth_code)}）")
                                    break
                    except Exception:
                        continue
            except Exception:
                pass

        # 7. 最后尝试：直接读取当前 URL
        if not auth_code:
            try:
                final_url = driver.current_url
                if "code=" in final_url:
                    parsed = urlparse(final_url)
                    params = parse_qs(parsed.query)
                    auth_code = params.get("code", [None])[0]
                    if auth_code:
                        print(f"  ✅ 从最终 URL 获取到 code（长度: {len(auth_code)}）")
            except Exception:
                pass

        # 调试：打印捕获到的 sentinel tokens（如果有）
        try:
            captured = driver.execute_script("return window.__sentinel_tokens || [];")
            if captured:
                print(f"  📋 调试: 共捕获 {len(captured)} 个 sentinel tokens")
                for idx, st in enumerate(captured[:3]):  # 最多打印3个
                    t_val = st.get("t", "")
                    c_val = st.get("c", "")
                    flow = st.get("flow", "")
                    print(f"    [{idx}] flow={flow}, t长度={len(t_val)}, c长度={len(c_val)}")
        except Exception:
            pass

        # 8. 用 authorization code 换取 tokens
        if auth_code:
            return codex_exchange_code(auth_code, code_verifier, proxy_url=account_proxy, relay_state=relay_state)

        print("  ❌ 未获取到 authorization code")
        try:
            print(f"  最终 URL: {driver.current_url[:200]}")
        except Exception:
            pass
        return None

    except Exception as e:
        print(f"  ❌ Codex OAuth 登录异常: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        if driver:
            try:
                driver.quit()
                print("  🔒 OAuth 浏览器已关闭")
            except (OSError, Exception):
                pass


def codex_exchange_code(code, code_verifier, proxy_url=None, relay_state=None):
    """
    用 authorization code 换取 Codex tokens
    
    POST https://auth.openai.com/oauth/token
    Content-Type: application/x-www-form-urlencoded
    """
    print("  🔄 换取 Codex Token...")
    session = create_session(proxy_url, relay_state=relay_state)

    for attempt in range(2):
        try:
            resp = session.post(
                f"{OAUTH_ISSUER}/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "client_id": OAUTH_CLIENT_ID,
                    "code_verifier": code_verifier,
                },
                verify=False,
                timeout=60,
            )
            break
        except Exception as e:
            if attempt == 0:
                print(f"  ⚠️ Token 交换超时，重试...")
                time.sleep(2)
                continue
            print(f"  ❌ Token 交换失败: {e}")
            return None

    if resp.status_code == 200:
        data = resp.json()
        print(f"  ✅ Codex Token 获取成功！")
        print(f"    Access Token 长度: {len(data.get('access_token', ''))}")
        print(f"    Refresh Token: {'✅' if data.get('refresh_token') else '❌'}")
        print(f"    ID Token: {'✅' if data.get('id_token') else '❌'}")
        return data
    else:
        print(f"  ❌ Token 交换失败: {resp.status_code}")
        print(f"  响应: {resp.text[:300]}")
        return None


# =================== Token JSON 保存 + CPA 上传 ===================

def decode_jwt_payload(token):
    """解析 JWT token 的 payload 部分"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        # 补齐 base64 padding
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


def save_token_json(email, access_token, refresh_token=None, id_token=None, proxy_url=None, relay_state=None):
    """
    保存完整的 Token JSON 文件（格式兼容 Codex），并自动上传到 CPA 管理平台。
    
    JSON 格式与 codex_ultimate.py 一致：
    {
        "type": "codex",
        "email": "xxx@xxx.com",
        "expired": "2026-02-20T15:30:00+08:00",
        "id_token": "...",
        "account_id": "...",
        "access_token": "...",
        "last_refresh": "2026-02-18T15:30:00+08:00",
        "refresh_token": "..."
    }
    """
    try:
        from datetime import datetime, timezone, timedelta

        payload = decode_jwt_payload(access_token)

        # 提取 account_id
        auth_info = payload.get("https://api.openai.com/auth", {})
        account_id = auth_info.get("chatgpt_account_id", "")

        # 计算过期时间
        exp_timestamp = payload.get("exp", 0)
        if exp_timestamp:
            exp_dt = datetime.fromtimestamp(exp_timestamp, tz=timezone(timedelta(hours=8)))
            expired_str = exp_dt.strftime("%Y-%m-%dT%H:%M:%S+08:00")
        else:
            expired_str = ""

        now = datetime.now(tz=timezone(timedelta(hours=8)))
        last_refresh_str = now.strftime("%Y-%m-%dT%H:%M:%S+08:00")

        token_data = {
            "type": "codex",
            "email": email,
            "proxy": _effective_proxy(proxy_url),
            "expired": expired_str,
            "id_token": id_token or "",
            "account_id": account_id,
            "access_token": access_token,
            "last_refresh": last_refresh_str,
            "refresh_token": refresh_token or "",
        }

        filename = os.path.join(OUTPUT_DIR, f"{email}.json")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(token_data, f, ensure_ascii=False)
        print(f"  ✅ Token JSON 已保存到 {filename}")

        # 上传到 CPA 管理平台（支持多目标轮询）
        if has_cpa_upload_target() or UPLOAD_API_URL:
            upload_token_json(filename, proxy_url=proxy_url, relay_state=relay_state)

    except Exception as e:
        print(f"  ❌ 保存 Token JSON 失败: {e}")


def _upload_token_json_to_target(filename, target, proxy_url=None, relay_state=None):
    """上传单个 Token JSON 到指定 CPA 目标。"""
    session = None
    target_label = str(target.get("label") or target.get("base_url") or target.get("upload_api_url") or "CPA")
    upload_api_url = str(target.get("upload_api_url") or "").strip()
    upload_api_token = str(target.get("upload_api_token") or "").strip()

    if _cpa_target_is_full(target):
        print(f"  ⚠️ CPA 已达到推送上限，已跳过: {target_label}")
        return False
    if not upload_api_url or not upload_api_token:
        print(f"  ⚠️ CPA 目标配置不完整，已跳过: {target_label}")
        return False

    try:
        session = create_cpa_management_session(proxy_url, relay_state=relay_state)
        with open(filename, "rb") as f:
            files = {"file": (os.path.basename(filename), f, "application/json")}
            headers = {"Authorization": f"Bearer {upload_api_token}"}

            resp = session.post(
                upload_api_url,
                files=files,
                headers=headers,
                verify=False,
                timeout=30,
            )

            if resp.status_code == 200:
                _increment_cpa_push_count(target)
                _mark_token_push_success(filename, target)
                _bump_cpa_quota_cache_after_push(target, 1)
                maybe_schedule_cpa_auto_topup_refresh(reason="upload_success", success_count=1, immediate=False)
                print(f"  ✅ Token JSON 已上传到 CPA: {target_label}")
                return True
            print(f"  ❌ CPA 上传失败 [{target_label}]: {resp.status_code} - {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"  ❌ CPA 上传异常 [{target_label}]: {e}")
        return False
    finally:
        _close_session(session)


def upload_token_json(filename, proxy_url=None, relay_state=None):
    """上传 Token JSON 文件到 CPA 管理平台（支持多目标顺序轮询）"""
    target = _pick_cpa_target_for_upload()
    if target is None and UPLOAD_API_URL:
        target = _default_cpa_target()
    if target is None:
        print("  ⚠️ 没有可用的 CPA 目标（可能已到上限），已跳过上传")
        return False
    return _upload_token_json_to_target(filename, target, proxy_url=proxy_url, relay_state=relay_state)


def push_pending_token_json_files(limit=None):
    """将未推送凭证按当前 CPA 列表顺序平均分摊补推。"""
    targets = load_cpa_targets()
    if not targets and UPLOAD_API_URL:
        default_target = _default_cpa_target()
        if default_target is not None:
            targets = [default_target]
    if not targets:
        return {"total": 0, "success": 0, "failed": 0, "items": [], "error": "未配置可用 CPA 目标"}

    pending = list_pending_token_pushes(limit=0)
    items = pending.get("items", [])
    if limit is not None:
        try:
            limit = max(1, int(limit))
            items = items[:limit]
        except Exception:
            pass

    success = 0
    failed = 0
    results = []
    target_count = len(targets)

    exhausted = False
    for item in items:
        filename = os.path.join(OUTPUT_DIR, item.get("filename", ""))
        if not is_token_json_pending_push(filename):
            continue
        target = _pick_cpa_target_for_upload()
        if target is None:
            exhausted = True
            break
        ok = _upload_token_json_to_target(filename, target, proxy_url=None)
        results.append({
            "filename": item.get("filename", ""),
            "email": item.get("email", ""),
            "target_label": str(target.get("label") or target.get("base_url") or ""),
            "success": bool(ok),
        })
        if ok:
            success += 1
        else:
            failed += 1

    return {
        "total": len(items),
        "success": success,
        "failed": failed,
        "stopped_due_to_limit": exhausted,
        "items": results,
    }


def save_tokens(email, tokens, proxy_url=None, relay_state=None):
    """保存 tokens 到所有目标（txt + JSON + CPA 上传），线程安全"""
    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    id_token = tokens.get("id_token", "")

    with _file_lock:
        if access_token:
            with open(AK_FILE, "a", encoding="utf-8") as f:
                f.write(f"{access_token}\n")
        if refresh_token:
            with open(RK_FILE, "a", encoding="utf-8") as f:
                f.write(f"{refresh_token}\n")

    if access_token:
        save_token_json(email, access_token, refresh_token, id_token, proxy_url=proxy_url, relay_state=relay_state)


# =================== 账号持久化 ===================

def save_account(email, password, mail_auth="", proxy_url=None, relay_state=None):
    """保存账号信息（线程安全）

    格式: email:password:mail_auth
    mail_auth:
      - DuckMail: 邮箱密码（兼容旧格式）
      - ChatGPTMail: provider=chatgptmail
      - DDG: provider=ddg&account_id=...&forward_email=...
    代理绑定会单独写入 account_proxies.json，避免污染旧格式 accounts.txt。
    """
    try:
        with _file_lock:
            with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
                f.write(f"{email}:{password}:{mail_auth}\n")
            file_exists = os.path.exists(CSV_FILE)
            with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
                import csv
                w = csv.writer(f)
                if not file_exists:
                    w.writerow(["email", "password", "timestamp"])
                w.writerow([email, password, time.strftime("%Y-%m-%d %H:%M:%S")])
        remember_account_proxy(email, _effective_proxy(proxy_url))
        remember_account_relay(email, relay_state)
        print(f"  ✅ 账号已保存")
    except Exception as e:
        print(f"  ⚠️ 保存失败: {e}")


def run_mode7_full_oauth_browser(preferred_domain="", preferred_node_id="", tag=""):
    """模式7：调用 Camoufox OAuth 直链脚本，完成注册→OTP→about-you→consent→token。"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(base_dir, "scripts", "test_camoufox_ui_flow.py")
    output_dir = os.path.join(OUTPUT_DIR, "mode7_runs")
    os.makedirs(output_dir, exist_ok=True)

    def _clip(value, limit=1200):
        text = str(value or "")
        return text if len(text) <= limit else text[:limit] + "..."

    result = {
        "ok": False,
        "email": "",
        "password": "",
        "mail_auth": "",
        "tokens": None,
        "reached_add_phone": False,
        "token_obtained": False,
        "final_stage": "",
        "errors": [],
        "resolved_relay_state": None,
        "resolved_node_id": "",
        "resolved_proxy_url": "",
        "json_out": "",
    }

    if not os.path.exists(script_path):
        result["errors"].append(f"mode7 script missing: {script_path}")
        return result

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(output_dir, f"mode7_{ts}_{uuid.uuid4().hex[:8]}.json")
    cmd = [
        sys.executable or "python3",
        script_path,
        "--flow", "full_oauth",
        "--engine", MODE7_ENGINE,
        "--profile", MODE7_PROFILE,
        "--json-out", out_path,
        "--sleep-after-ms", str(MODE7_SLEEP_AFTER_MS),
    ]
    preferred_domain = _extract_email_domain(preferred_domain)
    preferred_node_id = _normalize_node_id(preferred_node_id)
    if preferred_domain:
        cmd.extend(["--preferred-domain", preferred_domain])
    if preferred_node_id:
        cmd.extend(["--preferred-node-id", preferred_node_id])
    if MODE7_COOKIE_FILE:
        cmd.extend(["--cookie-file", MODE7_COOKIE_FILE])

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    print(
        f"{tag} 🌐 模式7启动: domain={preferred_domain or '-'} "
        f"node={preferred_node_id or '-'} engine={MODE7_ENGINE} profile={MODE7_PROFILE} "
        f"cookie={'Y' if bool(MODE7_COOKIE_FILE) else 'N'}"
    )
    combined_lines = []
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        started_at = time.time()
        stream = proc.stdout
        while True:
            if stream is not None:
                ready, _, _ = select.select([stream], [], [], 1.0)
                if ready:
                    line = stream.readline()
                    if line:
                        text = line.rstrip("\r\n")
                        combined_lines.append(text)
                        print(f"{tag} {text}" if tag else text)
            if proc.poll() is not None:
                break
            if (time.time() - started_at) > MODE7_SCRIPT_TIMEOUT_SECONDS:
                try:
                    proc.kill()
                except Exception:
                    pass
                result["errors"].append(f"mode7 timeout: {MODE7_SCRIPT_TIMEOUT_SECONDS}s")
                result["json_out"] = out_path
                result["stdout_tail"] = _clip("\n".join(combined_lines), 4000)
                result["stderr_tail"] = ""
                return result

        if stream is not None:
            try:
                for line in stream.readlines():
                    text = str(line).rstrip("\r\n")
                    if text:
                        combined_lines.append(text)
                        print(f"{tag} {text}" if tag else text)
            except Exception:
                pass

        result["subprocess_returncode"] = int(proc.wait(timeout=5))
        result["stdout_tail"] = _clip("\n".join(combined_lines), 4000)
        result["stderr_tail"] = ""
    except Exception as exc:
        result["errors"].append(f"mode7 subprocess failed: {exc}")
        result["json_out"] = out_path
        result["stdout_tail"] = _clip("\n".join(combined_lines), 4000)
        result["stderr_tail"] = ""
        return result
    finally:
        try:
            if proc is not None and proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass

    result["json_out"] = out_path
    if os.path.exists(out_path):
        try:
            payload = json.loads(open(out_path, "r", encoding="utf-8").read())
            if isinstance(payload, dict):
                result.update(payload)
        except Exception as exc:
            result["errors"].append(f"mode7 json parse failed: {exc}")
    else:
        result["errors"].append("mode7 json output missing")

    summary_email = str(result.get("email") or "").strip()
    if result.get("token_obtained"):
        print(f"{tag} 🌐 模式7完成: {summary_email or '-'} -> token")
    elif result.get("reached_add_phone"):
        print(f"{tag} 🌐 模式7完成: {summary_email or '-'} -> add-phone")
    elif result.get("otp_code"):
        print(f"{tag} 🌐 模式7完成: {summary_email or '-'} -> otp={result.get('otp_code')}")
    elif result.get("errors"):
        print(f"{tag} 🌐 模式7结束: {summary_email or '-'} -> {str((result.get('errors') or [''])[0])[:200]}")

    return result



def _load_auto_oauth_retry_failures_unlocked():
    if not os.path.exists(AUTO_OAUTH_RETRY_FAILURES_FILE):
        return {}
    try:
        with open(AUTO_OAUTH_RETRY_FAILURES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    result = {}
    for key, value in data.items():
        email = str(key or "").strip().lower()
        if not email:
            continue
        item = dict(value) if isinstance(value, dict) else {"count": _int_value(value, 0)}
        item["count"] = max(0, _int_value(item.get("count"), 0))
        item["last_reason"] = str(item.get("last_reason") or "").strip()
        item["last_detail"] = str(item.get("last_detail") or "").strip()
        item["updated_at"] = str(item.get("updated_at") or "").strip()
        result[email] = item
    return result


def _save_auto_oauth_retry_failures_unlocked(data):
    with open(AUTO_OAUTH_RETRY_FAILURES_FILE, "w", encoding="utf-8") as f:
        json.dump(data if isinstance(data, dict) else {}, f, ensure_ascii=False, indent=2)


def get_auto_oauth_retry_failure_state(email):
    target = str(email or "").strip().lower()
    if not target:
        return {"count": 0, "last_reason": "", "last_detail": "", "updated_at": ""}
    with _file_lock:
        data = _load_auto_oauth_retry_failures_unlocked()
        item = data.get(target, {}) if isinstance(data, dict) else {}
    if not isinstance(item, dict):
        item = {}
    return {
        "count": max(0, _int_value(item.get("count"), 0)),
        "last_reason": str(item.get("last_reason") or "").strip(),
        "last_detail": str(item.get("last_detail") or "").strip(),
        "updated_at": str(item.get("updated_at") or "").strip(),
    }


def clear_auto_oauth_retry_failure_state(email):
    target = str(email or "").strip().lower()
    if not target:
        return False
    removed = False
    with _file_lock:
        data = _load_auto_oauth_retry_failures_unlocked()
        if target in data:
            data.pop(target, None)
            _save_auto_oauth_retry_failures_unlocked(data)
            removed = True
    return removed


def bump_auto_oauth_retry_failure_state(email, reason="", detail=""):
    target = str(email or "").strip().lower()
    if not target:
        return {"count": 0, "last_reason": "", "last_detail": "", "updated_at": ""}
    with _file_lock:
        data = _load_auto_oauth_retry_failures_unlocked()
        item = data.get(target, {}) if isinstance(data, dict) else {}
        if not isinstance(item, dict):
            item = {}
        item["count"] = max(0, _int_value(item.get("count"), 0)) + 1
        item["last_reason"] = str(reason or item.get("last_reason") or "").strip()
        item["last_detail"] = str(detail or item.get("last_detail") or "").strip()[:300]
        item["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data[target] = item
        _save_auto_oauth_retry_failures_unlocked(data)
    return {
        "count": max(0, _int_value(item.get("count"), 0)),
        "last_reason": str(item.get("last_reason") or "").strip(),
        "last_detail": str(item.get("last_detail") or "").strip(),
        "updated_at": str(item.get("updated_at") or "").strip(),
    }


def _discard_auto_oauth_retry_runtime_entry(email):
    target = str(email or "").strip().lower()
    if not target:
        return False
    removed = False
    with _auto_oauth_retry_lock:
        if target in _auto_oauth_retry_pending:
            _auto_oauth_retry_pending.pop(target, None)
            removed = True
        if target in _auto_oauth_retry_active:
            _auto_oauth_retry_active.pop(target, None)
            removed = True
    return removed


def cleanup_auto_oauth_retry_failed_account(email, detail="", failure_count=0):
    target = str(email or "").strip().lower()
    if not target:
        return {"accounts_removed": 0, "csv_removed": 0, "json_deleted": False}
    removed = delete_account_records(target)
    _discard_auto_oauth_retry_runtime_entry(target)
    clear_auto_oauth_retry_failure_state(target)
    print(
        f"  🧹 后台补登失败清理完成: {target} | 连续失败={max(0, int(failure_count or 0))} | "
        f"accounts={removed.get('accounts_removed', 0)} csv={removed.get('csv_removed', 0)} "
        f"token_json={'Y' if removed.get('json_deleted') else 'N'}"
    )
    if detail:
        print(f"     原因: {str(detail)[:300]}")
    return removed


def prune_auto_oauth_retry_exhausted_accounts(limit=0):
    threshold = max(0, int(AUTO_OAUTH_RETRY_DELETE_AFTER_FAILURES or 0))
    if threshold <= 0:
        return {"checked": 0, "removed": 0, "items": []}
    pending = list_pending_oauth_accounts(limit=0)
    items = list(pending.get("items") or [])
    removed_items = []
    checked = 0
    max_items = max(0, int(limit or 0))
    for row in items:
        email = str((row or {}).get("email") or "").strip().lower()
        if not email:
            continue
        checked += 1
        state = get_auto_oauth_retry_failure_state(email)
        count = max(0, int((state or {}).get("count") or 0))
        if count < threshold:
            continue
        removed = cleanup_auto_oauth_retry_failed_account(
            email,
            detail=(state or {}).get("last_detail") or (state or {}).get("last_reason") or f"连续失败 {count} 次",
            failure_count=count,
        )
        removed_items.append({
            "email": email,
            "count": count,
            "removed": removed,
        })
        if max_items > 0 and len(removed_items) >= max_items:
            break
    return {
        "checked": checked,
        "removed": len(removed_items),
        "items": removed_items,
    }



def delete_account_records(email):
    """从本地账号记录中删除指定邮箱（用于 OAuth 补登 401 清理）"""
    target = (email or "").strip().lower()
    if not target:
        return {"accounts_removed": 0, "csv_removed": 0, "json_deleted": False}

    accounts_removed = 0
    csv_removed = 0
    json_deleted = False

    with _file_lock:
        # 1) accounts.txt（格式: email:password:mail_auth）
        if os.path.exists(ACCOUNTS_FILE):
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()

            kept = []
            for line in lines:
                raw = line.strip()
                if not raw:
                    kept.append(line)
                    continue
                row_email = raw.split(":", 1)[0].strip().lower()
                if row_email == target:
                    accounts_removed += 1
                    continue
                kept.append(line)

            if accounts_removed > 0:
                with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
                    f.writelines(kept)

        # 2) registered_accounts.csv（首列 email）
        if os.path.exists(CSV_FILE):
            try:
                import csv
                with open(CSV_FILE, "r", newline="", encoding="utf-8") as f:
                    rows = list(csv.reader(f))

                if rows:
                    kept_rows = []
                    for idx, row in enumerate(rows):
                        # 保留表头
                        if idx == 0 and row and row[0].strip().lower() == "email":
                            kept_rows.append(row)
                            continue

                        row_email = row[0].strip().lower() if row else ""
                        if row_email == target:
                            csv_removed += 1
                            continue
                        kept_rows.append(row)

                    if csv_removed > 0:
                        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
                            w = csv.writer(f)
                            w.writerows(kept_rows)
            except Exception as e:
                print(f"  ⚠️ 清理 CSV 失败: {e}")

        proxy_map = _load_account_proxy_map_unlocked()
        if target in proxy_map:
            proxy_map.pop(target, None)
            with open(ACCOUNT_PROXY_MAP_FILE, "w", encoding="utf-8") as f:
                json.dump(proxy_map, f, ensure_ascii=False, indent=2)

        relay_map = _load_account_relay_map_unlocked()
        if target in relay_map:
            relay_map.pop(target, None)
            with open(ACCOUNT_RELAY_MAP_FILE, "w", encoding="utf-8") as f:
                json.dump(relay_map, f, ensure_ascii=False, indent=2)

    # 3) 同邮箱 token JSON（若存在）
    json_path = os.path.join(OUTPUT_DIR, f"{target}.json")
    if os.path.exists(json_path):
        try:
            os.remove(json_path)
            json_deleted = True
        except Exception as e:
            print(f"  ⚠️ 删除 Token JSON 失败: {e}")

    return {
        "accounts_removed": accounts_removed,
        "csv_removed": csv_removed,
        "json_deleted": json_deleted,
    }


def cleanup_unsupported_chatgptmail_account(email, detail=""):
    target = str(email or "").strip().lower()
    removed = delete_account_records(target)
    print(
        f"  🧹 unsupported_email 清理完成: {target} | "
        f"accounts={removed.get('accounts_removed', 0)} csv={removed.get('csv_removed', 0)} "
        f"token_json={'Y' if removed.get('json_deleted') else 'N'}"
    )
    if detail:
        print(f"    原因: {str(detail)[:200]}")
    return removed


def register_one(worker_id=0, task_index=0, total=1):
    """
    注册单个账号的完整流程（线程安全）
    返回: (email, password, success, reg_time, total_time)
    """
    tag = f"[W{worker_id}]" if CONCURRENT_WORKERS > 1 else ""
    t_start = time.time()
    bad_domain_retries = 0
    max_bad_domain_retries = BAD_EMAIL_DOMAIN_RETRY_LIMIT if AUTO_BLACKLIST_BAD_EMAIL_DOMAINS else 0

    def _pair_text(domain="", node_id=""):
        clean_domain = _extract_email_domain(domain)
        clean_node = _normalize_node_id(node_id)
        if clean_domain and clean_node:
            return f"{clean_domain} | {clean_node}"
        if clean_domain:
            return clean_domain
        if clean_node:
            return clean_node
        return "-"

    def _note_registration_pair_failure(target="", reason="", preferred_domain="", preferred_node_id="", effective_mode="random"):
        domain = _extract_email_domain(target or preferred_domain)
        node_id = _normalize_node_id(preferred_node_id)
        reason_text = str(reason or "").strip()
        suffix = f" ({reason_text})" if reason_text else ""
        if effective_mode == "manual":
            print(f"{tag} ⚠️ 手动强制组失败: {_pair_text(domain, node_id)}{suffix}")
            return {
                "tracked": False,
                "failure_count": 0,
                "threshold": max(1, int(REGISTRATION_STICKY_DOMAIN_FAILURE_LIMIT or 5)),
                "switched_to_random": False,
                "domain": domain,
                "node_id": node_id,
            }
        if effective_mode == "manual_domain":
            print(f"{tag} ⚠️ 手动域名模式失败: {domain or '-'}（节点随机）{suffix}")
            return {
                "tracked": False,
                "failure_count": 0,
                "threshold": max(1, int(REGISTRATION_STICKY_DOMAIN_FAILURE_LIMIT or 5)),
                "switched_to_random": False,
                "domain": domain,
                "node_id": "",
            }
        if effective_mode == "manual_domains":
            print(f"{tag} ⚠️ 手动多域名混合模式失败: {domain or '-'}（节点随机）{suffix}")
            return {
                "tracked": False,
                "failure_count": 0,
                "threshold": max(1, int(REGISTRATION_STICKY_DOMAIN_FAILURE_LIMIT or 5)),
                "switched_to_random": False,
                "domain": domain,
                "node_id": "",
            }

        result = mark_registration_pair_failure(domain, node_id=node_id, mode_hint=effective_mode)
        if not result.get("tracked"):
            return result

        failure_count = max(0, _int_value(result.get("failure_count"), 0))
        threshold = max(1, _int_value(result.get("threshold"), REGISTRATION_STICKY_DOMAIN_FAILURE_LIMIT))
        if result.get("switched_to_random"):
            print(f"{tag} 🔁 固定组连续失败 {failure_count}/{threshold}，切回随机: {_pair_text(domain, node_id)}{suffix}")
        else:
            print(f"{tag} ⚠️ 固定组失败 {failure_count}/{threshold}: {_pair_text(domain, node_id)}{suffix}")
        return result

    while True:
        pair_pref = get_preferred_registration_pair()
        preferred_domain = _extract_email_domain(pair_pref.get("domain"))
        preferred_node_id = _normalize_node_id(pair_pref.get("node_id"))
        preferred_mode = str(pair_pref.get("effective_mode") or "random").strip().lower()
        sticky_state = dict(pair_pref.get("state") or {})

        account_proxy = _effective_proxy()
        account_relay_state = _new_oai_registration_relay_state(
            node_id=preferred_node_id,
            strict_node_id=bool(pair_pref.get("strict_node_id")),
        )
        mail_session = None
        registrar = None
        retry_with_new_email = False
        if preferred_mode == "manual":
            print(f"{tag} 📌 本轮手动强制组: {_pair_text(preferred_domain, preferred_node_id)}")
        elif preferred_mode == "manual_domains":
            domain_pool = _normalize_email_domain_list(pair_pref.get("domain_pool") or sticky_state.get("manual_domains"))
            print(f"{tag} 📌 本轮多域名混合: {preferred_domain or '-'}（候选 {len(domain_pool)} 个，节点随机）")
        elif preferred_mode == "manual_domain":
            print(f"{tag} 📌 本轮指定域名 + 随机节点: {preferred_domain or '-'}")
        elif preferred_mode == "auto":
            print(f"{tag} 📌 本轮优先使用成功组(OAI固定/邮箱随机): {_pair_text(preferred_domain, preferred_node_id)}")
        elif REGISTRATION_STICKY_DOMAIN_ENABLED and MAIL_PROVIDER == "chatgptmail":
            selection_mode = str(sticky_state.get("selection_mode") or "auto")
            last_pair = dict(sticky_state.get("last_success_pair") or {})
            last_success_domain = _extract_email_domain(last_pair.get("domain"))
            last_success_node = _normalize_node_id(last_pair.get("node_id"))
            if last_success_domain or last_success_node:
                mode_text = "随机模式" if selection_mode == "random" else "自动模式（当前无有效固定组）"
                print(f"{tag} 🎲 当前为{mode_text}（最近成功: {_pair_text(last_success_domain, last_success_node)}）")

        if PROXY_MODE == 7:
            mode7_result = run_mode7_full_oauth_browser(
                preferred_domain=preferred_domain,
                preferred_node_id=preferred_node_id,
                tag=tag,
            )
            email = str(mode7_result.get("email") or "").strip().lower()
            password = str(mode7_result.get("password") or "").strip()
            mail_auth = str(mode7_result.get("mail_auth") or "").strip()
            tokens = mode7_result.get("tokens") if isinstance(mode7_result.get("tokens"), dict) else None
            t_total = time.time() - t_start
            t_reg = t_total
            relay_holder = (
                mode7_result.get("resolved_relay_state")
                if isinstance(mode7_result.get("resolved_relay_state"), dict)
                else account_relay_state
            )
            mode7_node_id = _normalize_node_id(mode7_result.get("resolved_node_id") or preferred_node_id)
            proxy_holder = _normalize_proxy_url(mode7_result.get("resolved_proxy_url") or account_proxy)
            mode7_errors = list(mode7_result.get("errors") or [])
            fail_reason = (
                str(mode7_errors[0] or "").strip()
                if mode7_errors else
                str(mode7_result.get("final_stage") or "").strip()
            )
            if not fail_reason:
                fail_reason = "mode7_failed"
            mode7_register_response = (
                mode7_result.get("register_response")
                if isinstance(mode7_result.get("register_response"), dict)
                else {}
            )
            mode7_register_status = _int_value(mode7_register_response.get("status"), 0)
            mode7_register_body = str(mode7_register_response.get("body") or "").strip()
            mode7_domain = _extract_email_domain(email or preferred_domain)

            if tokens and email and password:
                save_account(email, password, mail_auth, proxy_url=proxy_holder, relay_state=relay_holder)
                save_tokens(email, tokens, proxy_url=proxy_holder, relay_state=relay_holder)
                sticky_success = mark_registration_pair_success(email, relay_state=relay_holder, source="mode7_register")
                if PROXY_MODE in (4, 5, 7):
                    remember_account_relay(email, relay_holder)
                if sticky_success.get("changed"):
                    print(f"{tag} 📌 成功组已更新为: {_pair_text(sticky_success.get('active_domain'), sticky_success.get('active_node_id'))}")
                print(f"{tag} ✅ {email} | 模式7 全链路 {t_total:.1f}s")
                return email, password, True, t_reg, t_total

            partial_success = bool(
                mode7_result.get("otp_code")
                or mode7_result.get("code")
                or mode7_result.get("reached_add_phone")
            )
            if partial_success and email and password:
                save_account(email, password, mail_auth, proxy_url=proxy_holder, relay_state=relay_holder)
                if PROXY_MODE in (4, 5, 7):
                    remember_account_relay(email, relay_holder)
                queue_reason = fail_reason or "mode7_oauth_retry_pending"
                queued = enqueue_auto_oauth_retry(email, password, mail_auth=mail_auth, reason=queue_reason)
                if queued.get("queued"):
                    print(f"{tag} 🧾 模式7 已加入自动补登队列: {email} ({queue_reason})")
                else:
                    print(f"{tag} ⚠️ 模式7 部分成功但未入补登队列: {email} ({queue_reason})")
                _note_registration_pair_failure(
                    target=email,
                    reason=queue_reason,
                    preferred_domain=preferred_domain,
                    preferred_node_id=mode7_node_id,
                    effective_mode=preferred_mode,
                )
                return email, password, True, t_reg, t_total

            mode7_bad_domain_like = bool(
                mode7_domain
                and (
                    mode7_register_status == 400
                    or "create account failed: failed to create account. please try again." in fail_reason.lower()
                )
            )
            if AUTO_BLACKLIST_BAD_EMAIL_DOMAINS and mode7_bad_domain_like:
                remember_bad_email_domain(
                    mode7_domain,
                    error_code="mode7_register_400",
                    error_message=mode7_register_body or fail_reason,
                    email=email,
                )
                forget_account_proxy(email)
                forget_account_relay(email)
                _note_registration_pair_failure(
                    target=email,
                    reason=mode7_register_body or fail_reason or "mode7_register_400",
                    preferred_domain=preferred_domain,
                    preferred_node_id=mode7_node_id,
                    effective_mode=preferred_mode,
                )
                if (not preferred_domain) and bad_domain_retries < max_bad_domain_retries:
                    bad_domain_retries += 1
                    print(f"{tag} ⚠️ 模式7 域名已拉黑: {mode7_domain} (mode7_register_400)，更换邮箱重试 {bad_domain_retries}/{max_bad_domain_retries}")
                    continue
                print(f"{tag} ⚠️ 模式7 域名已拉黑: {mode7_domain} (mode7_register_400)，但已达到重试上限")
                return email or None, password or None, False, t_reg, t_total

            _note_registration_pair_failure(
                target=email,
                reason=fail_reason,
                preferred_domain=preferred_domain,
                preferred_node_id=mode7_node_id,
                effective_mode=preferred_mode,
            )
            return email or None, password or None, False, t_reg, t_total

        try:
            mail_session = create_mail_session(account_proxy, relay_state=_new_random_mail_relay_state())
            email, email_id, mail_auth = create_temp_email(mail_session, preferred_domain=preferred_domain)
            if not email:
                if preferred_domain:
                    error_code, error_message, _error_email = _chatgptmail_get_last_error(mail_session)
                    if AUTO_BLACKLIST_BAD_EMAIL_DOMAINS and error_code in BAD_EMAIL_DOMAIN_ERROR_CODES:
                        remember_bad_email_domain(
                            preferred_domain,
                            error_code=error_code,
                            error_message=error_message,
                            email=f"*@{preferred_domain}",
                        )
                    _note_registration_pair_failure(
                        reason=error_message or error_code or "create_temp_email_failed",
                        preferred_domain=preferred_domain,
                        preferred_node_id=preferred_node_id,
                        effective_mode=preferred_mode,
                    )
                return None, None, False, 0, 0
            remember_account_proxy(email, account_proxy)
            remember_account_relay(email, account_relay_state or mail_session)

            password = generate_random_password()

            registrar = ProtocolRegistrar(proxy_url=account_proxy, mail_session=mail_session, relay_state=account_relay_state)
            success, email, password = registrar.register(email, email_id, password)
            if success:
                save_account(email, password, mail_auth, proxy_url=account_proxy, relay_state=account_relay_state or registrar.session)

            t_reg = time.time() - t_start

            if not success:
                domain = _extract_email_domain(email)
                error_code = str(getattr(registrar, "last_create_account_error_code", "") or "").strip()
                error_message = str(getattr(registrar, "last_create_account_error_message", "") or "").strip()
                if AUTO_BLACKLIST_BAD_EMAIL_DOMAINS and domain and error_code in BAD_EMAIL_DOMAIN_ERROR_CODES:
                    remember_bad_email_domain(domain, error_code=error_code, error_message=error_message, email=email)
                    forget_account_proxy(email)
                    forget_account_relay(email)
                    _note_registration_pair_failure(
                        target=email,
                        reason=error_message or error_code or "create_account_failed",
                        preferred_domain=preferred_domain,
                        preferred_node_id=preferred_node_id,
                        effective_mode=preferred_mode,
                    )
                    if bad_domain_retries < max_bad_domain_retries:
                        bad_domain_retries += 1
                        retry_with_new_email = True
                        print(f"{tag} ⚠️ 域名已拉黑: {domain} ({error_code})，更换邮箱重试 {bad_domain_retries}/{max_bad_domain_retries}")
                    else:
                        print(f"{tag} ⚠️ 域名已拉黑: {domain} ({error_code})，但已达到重试上限")
                else:
                    _note_registration_pair_failure(
                        target=email,
                        reason=error_message or error_code or "register_failed",
                        preferred_domain=preferred_domain,
                        preferred_node_id=preferred_node_id,
                        effective_mode=preferred_mode,
                    )
                if not retry_with_new_email:
                    return email, password, False, t_reg, t_reg
            else:
                print(f"  📝 注册耗时: {t_reg:.1f}s")

                create_account_error_code = str(getattr(registrar, "last_create_account_error_code", "") or "").strip()
                create_account_retry_reason = str(getattr(registrar, "last_create_account_retry_reason", "") or "").strip()
                create_account_used_browser = bool(getattr(registrar, "last_create_account_used_browser", False))
                prefer_saved_account_retry = create_account_error_code in CREATE_ACCOUNT_SOFT_SUCCESS_ERROR_CODES
                prefer_immediate_browser_retry = bool(
                    BROWSER_CREATE_ACCOUNT_IMMEDIATE_RETRY
                    and create_account_used_browser
                    and create_account_retry_reason == "about_you_add_phone_pending"
                )
                tokens = None
                oauth_err = {}
                try:
                    if prefer_immediate_browser_retry:
                        print(f"{tag}  ℹ️ Playwright create_account 已推进到 add-phone，立即执行补登")
                        immediate_ok, immediate_secs = oauth_retry_one(
                            email,
                            password,
                            mail_auth=mail_auth,
                            worker_id=worker_id,
                            error_holder=oauth_err,
                        )
                        if immediate_ok:
                            t_total = time.time() - t_start
                            print(f"{tag} ✅ {email} | 注册 {t_reg:.1f}s + 立即补登 {max(0.0, t_total - t_reg):.1f}s = 总 {t_total:.1f}s")
                            return email, password, True, t_reg, t_total
                        print(f"{tag}  ⚠️ 立即补登失败，改走常规补登队列（耗时 {immediate_secs:.1f}s）")
                    elif prefer_saved_account_retry:
                        print(f"{tag}  ℹ️ 检测到 {create_account_error_code}，已转后台补登队列")
                    else:
                        tokens = perform_codex_oauth_login_http(
                            email, password,
                            registrar_session=registrar.session,
                            email_id=email_id,
                            error_holder=oauth_err,
                            proxy_url=account_proxy,
                            mail_session=mail_session,
                            relay_state=account_relay_state or _relay_state_from_session(registrar.session),
                            device_id=getattr(registrar, "device_id", None),
                            sentinel_gen=getattr(registrar, "sentinel_gen", None),
                            mode5_callback_url=getattr(registrar, "mode5_last_continue_url", ""),
                        )
                        if not tokens:
                            print(f"{tag}  ❌ 纯 HTTP OAuth 失败")

                    t_total = time.time() - t_start
                    final_relay_state = account_relay_state or getattr(registrar, "session", None) or mail_session
                    fail_reason = str(oauth_err.get("reason") or "").strip()
                    fail_detail = str(oauth_err.get("detail") or "").strip()
                    if tokens:
                        save_tokens(email, tokens, proxy_url=account_proxy, relay_state=final_relay_state)
                        sticky_success = mark_registration_pair_success(email, relay_state=final_relay_state, source="register")
                        if PROXY_MODE in (4, 5, 7):
                            remember_account_relay(email, final_relay_state)
                        if sticky_success.get("changed"):
                            print(f"{tag} 📌 成功组已更新为: {_pair_text(sticky_success.get('active_domain'), sticky_success.get('active_node_id'))}")
                        print(f"{tag} ✅ {email} | 注册 {t_reg:.1f}s + OAuth {t_total - t_reg:.1f}s = 总 {t_total:.1f}s")
                    elif fail_reason == "chatgptmail_unsupported_email":
                        _note_registration_pair_failure(
                            target=email,
                            reason=fail_detail or fail_reason or "chatgptmail_unsupported_email",
                            preferred_domain=preferred_domain,
                            preferred_node_id=preferred_node_id,
                            effective_mode=preferred_mode,
                        )
                        print(f"{tag} 🧹 ChatGPTMail 不支持该邮箱，直接清理账号: {email}")
                        cleanup_unsupported_chatgptmail_account(email, detail=fail_detail or fail_reason)
                        return email, password, False, t_reg, t_total
                    else:
                        prefer_immediate_add_phone_retry = bool(
                            fail_reason in {"mode5_post_email_add_phone", "about_you_add_phone_pending"}
                            or "add-phone" in fail_detail.lower()
                            or "add_phone" in fail_detail.lower()
                        )
                        if prefer_immediate_add_phone_retry:
                            print(f"{tag}  ℹ️ OAuth 命中 add-phone，立即执行一次补登重试")
                            immediate_oauth_err = {}
                            immediate_ok, immediate_secs = oauth_retry_one(
                                email,
                                password,
                                mail_auth=mail_auth,
                                worker_id=worker_id,
                                error_holder=immediate_oauth_err,
                            )
                            if immediate_ok:
                                t_total = time.time() - t_start
                                print(f"{tag} ✅ {email} | 注册 {t_reg:.1f}s + add-phone 立即补登 {max(0.0, t_total - t_reg):.1f}s = 总 {t_total:.1f}s")
                                return email, password, True, t_reg, t_total
                            fail_reason = str(immediate_oauth_err.get("reason") or fail_reason or "").strip()
                            fail_detail = str(immediate_oauth_err.get("detail") or fail_detail or "").strip()
                            print(f"{tag}  ⚠️ add-phone 立即补登失败，改走常规补登队列（耗时 {immediate_secs:.1f}s）")

                        _note_registration_pair_failure(
                            target=email,
                            reason=fail_detail or fail_reason or create_account_retry_reason or create_account_error_code or "oauth_retry_pending",
                            preferred_domain=preferred_domain,
                            preferred_node_id=preferred_node_id,
                            effective_mode=preferred_mode,
                        )
                        if PROXY_MODE in (4, 5, 7):
                            remember_account_relay(email, final_relay_state)
                        queue_reason = fail_reason or create_account_retry_reason or create_account_error_code or "oauth_retry_pending"
                        queued = enqueue_auto_oauth_retry(email, password, mail_auth=mail_auth, reason=queue_reason)
                        if queued.get("queued"):
                            print(f"{tag} 🧾 已加入自动补登队列: {email} ({queue_reason})")
                        else:
                            print(f"{tag} ⚠️ OAuth 失败（注册已成功）: {queued.get('message', '未入队')}")
                except Exception as e:
                    t_total = time.time() - t_start
                    relay_holder = account_relay_state or getattr(registrar, "session", None) or mail_session
                    _note_registration_pair_failure(
                        target=email,
                        reason=str(e) or create_account_retry_reason or create_account_error_code or "oauth_exception",
                        preferred_domain=preferred_domain,
                        preferred_node_id=preferred_node_id,
                        effective_mode=preferred_mode,
                    )
                    if PROXY_MODE in (4, 5, 7):
                        remember_account_relay(email, relay_holder)
                    print(f"{tag} ⚠️ OAuth 异常: {e}")
                    queued = enqueue_auto_oauth_retry(
                        email,
                        password,
                        mail_auth=mail_auth,
                        reason=create_account_retry_reason or create_account_error_code or "oauth_exception",
                    )
                    if queued.get("queued"):
                        print(f"{tag} 🧾 OAuth 异常后已加入自动补登队列: {email}")

                return email, password, True, t_reg, t_total
        finally:
            if registrar is not None:
                _close_session(getattr(registrar, "session", None))
                registrar.session = None
                registrar.mail_session = None
            _close_session(mail_session)

        if retry_with_new_email:
            continue

def run_batch():
    """批量注册入口（支持并发）"""
    workers = max(1, CONCURRENT_WORKERS)
    batch_start = time.time()

    mail_source = _mail_source_display()
    print(f"\n🚀 协议注册机 v5 — {TOTAL_ACCOUNTS} 个账号 | 并发 {workers} | 邮箱源 {mail_source}")

    ok = 0
    fail = 0
    results_lock = threading.Lock()
    reg_times = []    # 注册耗时列表
    total_times = []  # 总耗时列表

    if workers == 1:
        for i in range(TOTAL_ACCOUNTS):
            print(f"\n--- [{i+1}/{TOTAL_ACCOUNTS}] ---")

            email, password, success, t_reg, t_total = register_one(
                worker_id=0, task_index=i + 1, total=TOTAL_ACCOUNTS
            )

            if success:
                ok += 1
                reg_times.append(t_reg)
                total_times.append(t_total)
            else:
                fail += 1

            wall = time.time() - batch_start
            throughput = wall / ok if ok > 0 else 0
            print(f"📊 {i+1}/{TOTAL_ACCOUNTS} | ✅{ok} ❌{fail} | 吞吐 {throughput:.1f}s/个 | 已用 {wall:.0f}s")

            if i < TOTAL_ACCOUNTS - 1:
                wait = random.randint(3, 8)
                time.sleep(wait)
    else:
        print(f"🔀 启动 {workers} 个并发 worker...\n")

        def _worker_task(task_index, worker_id):
            if task_index > 1:
                jitter = random.uniform(1, 3) * worker_id
                time.sleep(jitter)
            try:
                email, password, success, t_reg, t_total = register_one(
                    worker_id=worker_id,
                    task_index=task_index,
                    total=TOTAL_ACCOUNTS
                )
                return task_index, email, password, success, t_reg, t_total
            except Exception as e:
                print(f"[W{worker_id}] ❌ 异常: {e}")
                return task_index, None, None, False, 0, 0

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}

            def _submit_task(task_index):
                worker_id = ((task_index - 1) % workers) + 1
                future = executor.submit(_worker_task, task_index, worker_id)
                futures[future] = task_index

            initial_batch = min(workers, TOTAL_ACCOUNTS)
            for task_index in range(1, initial_batch + 1):
                _submit_task(task_index)
            next_task_index = initial_batch + 1

            while futures:
                done_set, _ = futures_wait(set(futures), return_when=FIRST_COMPLETED)
                for future in done_set:
                    task_idx = futures.pop(future)
                    try:
                        _, email, password, success, t_reg, t_total = future.result()
                        with results_lock:
                            if success:
                                ok += 1
                                reg_times.append(t_reg)
                                total_times.append(t_total)
                            else:
                                fail += 1
                            done = ok + fail
                            wall = time.time() - batch_start
                            throughput = wall / ok if ok > 0 else 0
                            print(f"📊 {done}/{TOTAL_ACCOUNTS} | ✅{ok} ❌{fail} | 吞吐 {throughput:.1f}s/个 | 已用 {wall:.0f}s")
                    except Exception as e:
                        with results_lock:
                            fail += 1
                            print(f"❌ 任务 {task_idx} 异常: {e}")
                    if next_task_index <= TOTAL_ACCOUNTS:
                        _submit_task(next_task_index)
                        next_task_index += 1

    elapsed = time.time() - batch_start
    throughput = elapsed / ok if ok > 0 else 0
    avg_reg = sum(reg_times) / len(reg_times) if reg_times else 0
    avg_total = sum(total_times) / len(total_times) if total_times else 0
    print(f"\n🏁 完成: ✅{ok} ❌{fail} | 总耗时 {elapsed:.1f}s | 吞吐 {throughput:.1f}s/个 | 单号(注册 {avg_reg:.1f}s + OAuth {avg_total - avg_reg:.1f}s = {avg_total:.1f}s)")


# =================== OAuth 补登 ===================

def _load_accounts(filepath):
    """从 accounts.txt 读取 email:password:mail_auth 三元组

    兼容旧格式 email:password（mail_auth 为空）
    """
    accounts = []
    if not os.path.exists(filepath):
        return accounts
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            parts = line.split(":", 2)
            if len(parts) >= 2:
                email = parts[0].strip()
                password = parts[1].strip()
                mail_pw = parts[2].strip() if len(parts) >= 3 else ""
                accounts.append((email, password, mail_pw))
    return accounts


def _load_token_json_emails(directory=None):
    """扫描 OAuth 目录的 *.json 文件，提取已有 token 的邮箱地址"""
    if directory is None:
        directory = OUTPUT_DIR
    emails = set()
    if not os.path.isdir(directory):
        return emails
    for fn in os.listdir(directory):
        if fn.endswith(".json"):
            filename_email = fn[:-5].strip().lower()
            if filename_email and "@" in filename_email:
                emails.add(filename_email)
                continue
            try:
                with open(os.path.join(directory, fn), "r", encoding="utf-8") as f:
                    data = json.load(f)
                    email = data.get("email", "")
                    if email:
                        emails.add(email.lower())
            except Exception:
                pass
    return emails


def _load_existing_tokens(ak_file):
    """从 ak.txt 读取已有 access_token 数量"""
    count = 0
    if not os.path.exists(ak_file):
        return count
    with open(ak_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def list_pending_oauth_accounts(limit=100):
    """列出待补登账号：accounts.txt 中存在但尚无 token json。"""
    try:
        limit = max(0, int(limit or 0))
    except Exception:
        limit = 100
    accounts = _load_accounts(ACCOUNTS_FILE)
    done_emails = _load_token_json_emails()
    with _auto_oauth_retry_lock:
        queued_set = set(_auto_oauth_retry_pending.keys())
        active_set = set(_auto_oauth_retry_active.keys())
    seen = set()
    items = []
    for email, _password, mail_auth in accounts:
        key = str(email or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        if key in done_emails:
            continue
        queue_status = ""
        if key in active_set:
            queue_status = "running"
        elif key in queued_set:
            queue_status = "queued"
        items.append({
            "email": key,
            "mail_auth": str(mail_auth or "").strip(),
            "queue_status": queue_status,
        })
    return {
        "count": len(items),
        "items": items[:limit] if limit > 0 else items,
    }


def _failed_auth_queue_status_sets():
    with _auto_oauth_retry_lock:
        queued_set = set(_auto_oauth_retry_pending.keys())
        active_set = set(_auto_oauth_retry_active.keys())
    return queued_set, active_set


def _failed_auth_queue_status(email, queued_set=None, active_set=None):
    key = str(email or "").strip().lower()
    if not key:
        return ""
    queued_set = queued_set if isinstance(queued_set, set) else set()
    active_set = active_set if isinstance(active_set, set) else set()
    if key in active_set:
        return "running"
    if key in queued_set:
        return "queued"
    return ""


def _build_failed_auth_content(email, proxy_url=""):
    key = str(email or "").strip().lower()
    return {
        "type": "codex",
        "email": key,
        "proxy": str(proxy_url or "").strip(),
        "expired": "",
        "id_token": "",
        "account_id": "",
        "access_token": "",
        "last_refresh": "",
        "refresh_token": "",
    }


def _extract_url_from_text(text):
    raw = str(text or "").strip()
    if not raw:
        return ""
    match = re.search(r'https?://[^\s\'"]+', raw)
    if not match:
        return ""
    return str(match.group(0) or "").rstrip(".,;)]}>\"'")


def _extract_web_session_value(data, *candidates):
    payload = data if isinstance(data, dict) else {}
    for key in candidates:
        if not key:
            continue
        if "." in key:
            current = payload
            ok = True
            for part in key.split("."):
                if not isinstance(current, dict):
                    ok = False
                    break
                current = current.get(part)
            if ok and current not in (None, ""):
                return current
            continue
        if payload.get(key) not in (None, ""):
            return payload.get(key)
    return ""


def _build_failed_auth_warmup_candidates(failure=None):
    failure = failure if isinstance(failure, dict) else {}
    detail = str(failure.get("last_detail") or "").strip()
    reason = str(failure.get("last_reason") or "").strip().lower()
    detail_lower = detail.lower()

    candidates = []
    seen = set()

    def _add(url):
        raw = str(url or "").strip()
        if not raw:
            return
        if raw.startswith("/"):
            raw = f"{OAUTH_ISSUER}{raw}"
        if raw in seen:
            return
        seen.add(raw)
        candidates.append(raw)

    _add(_extract_url_from_text(detail))

    if (
        "add-phone" in detail_lower
        or "add_phone" in detail_lower
        or "add_phone" in reason
        or "about_you_add_phone_pending" in reason
    ):
        _add(f"{OAUTH_ISSUER}/add-phone")

    if (
        "email-verification" in detail_lower
        or "email_otp" in reason
        or "validate" in detail_lower
        or "otp" in detail_lower
        or "otp" in reason
    ):
        _add(f"{OAUTH_ISSUER}/email-verification")

    if (
        "consent" in detail_lower
        or "consent" in reason
        or "workspace" in reason
        or "authorization_code_missing" in reason
        or "code_missing" in reason
    ):
        _add(f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent")

    if "login_password" in detail_lower or "password" in reason:
        _add(f"{OAUTH_ISSUER}/log-in/password")

    for url in (
        f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent",
        f"{OAUTH_ISSUER}/email-verification",
        f"{OAUTH_ISSUER}/add-phone",
        f"{OAUTH_ISSUER}/log-in/password",
    ):
        _add(url)

    return candidates


def _hydrate_failed_auth_content_from_session(email, failure=None, proxy_url="", relay_state=None, timeout=20):
    key = str(email or "").strip().lower()
    proxy_url = _normalize_proxy_url(proxy_url)
    relay_state = relay_state if isinstance(relay_state, dict) else None
    failure = failure if isinstance(failure, dict) else {}
    base_content = _build_failed_auth_content(key, proxy_url=proxy_url)
    result = {
        "content": dict(base_content),
        "session_status_code": None,
        "session_error": "",
        "session_source_url": "",
        "session_has_access_token": False,
    }

    if not key:
        result["session_error"] = "missing email"
        return result

    warmup_url = _extract_url_from_text(failure.get("last_detail") or "")
    result["session_source_url"] = warmup_url
    session = None
    try:
        session = create_session(proxy_url=proxy_url, relay_state=relay_state)
        try:
            session.get(
                f"{CHATGPT_BASE}/",
                headers=_mode5_nav_headers_static(f"{CHATGPT_BASE}/"),
                verify=False,
                timeout=timeout,
                allow_redirects=True,
            )
        except Exception:
            pass

        headers = _mode5_fetch_headers_static(
            f"{CHATGPT_BASE}/",
            content_type=None,
            accept="application/json",
            origin=CHATGPT_BASE,
        )

        last_error = ""
        last_status_code = None
        for candidate_url in ([""] + _build_failed_auth_warmup_candidates(failure)):
            if candidate_url:
                result["session_source_url"] = candidate_url
                try:
                    session.get(
                        candidate_url,
                        headers=_mode5_nav_headers_static(f"{CHATGPT_BASE}/"),
                        verify=False,
                        timeout=timeout,
                        allow_redirects=True,
                    )
                except Exception:
                    pass

            resp = session.get(
                f"{CHATGPT_BASE}/api/auth/session",
                headers=headers,
                verify=False,
                timeout=timeout,
                allow_redirects=True,
            )
            try:
                last_status_code = int(resp.status_code)
            except Exception:
                last_status_code = None
            result["session_status_code"] = last_status_code

            try:
                data = resp.json() if resp is not None else {}
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}

            access_token = str(
                _extract_web_session_value(
                    data,
                    "accessToken",
                    "access_token",
                    "user.accessToken",
                    "user.access_token",
                ) or ""
            ).strip()
            refresh_token = str(
                _extract_web_session_value(
                    data,
                    "refreshToken",
                    "refresh_token",
                    "user.refreshToken",
                    "user.refresh_token",
                ) or ""
            ).strip()
            id_token = str(
                _extract_web_session_value(
                    data,
                    "idToken",
                    "id_token",
                    "user.idToken",
                    "user.id_token",
                ) or ""
            ).strip()
            expires = str(_extract_web_session_value(data, "expires", "user.expires") or "").strip()
            session_email = str(_extract_web_session_value(data, "user.email", "email") or key).strip().lower() or key

            account_id = ""
            if access_token:
                try:
                    payload = decode_jwt_payload(access_token)
                except Exception:
                    payload = {}
                auth_info = payload.get("https://api.openai.com/auth", {}) if isinstance(payload, dict) else {}
                account_id = str(
                    (auth_info or {}).get("chatgpt_account_id")
                    or (auth_info or {}).get("account_id")
                    or ""
                ).strip()

            content = _build_failed_auth_content(session_email, proxy_url=proxy_url)
            content.update({
                "email": session_email,
                "expired": expires,
                "id_token": id_token,
                "account_id": account_id,
                "access_token": access_token,
                "last_refresh": datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%dT%H:%M:%S+08:00") if access_token else "",
                "refresh_token": refresh_token,
            })
            result["content"] = content
            result["session_has_access_token"] = bool(access_token)
            if access_token:
                result["session_error"] = ""
                break

            if resp.status_code != 200:
                preview = ""
                try:
                    preview = str(resp.text or "")[:300]
                except Exception:
                    preview = ""
                last_error = preview or f"status={resp.status_code}"
            else:
                last_error = str(data.get("error") or data.get("message") or "")[:300]

        if not result["session_has_access_token"]:
            result["session_error"] = last_error
    except Exception as e:
        result["session_error"] = str(e)[:300]
    finally:
        _close_session(session)

    return result


def list_failed_auth_files(limit=100):
    """列出补登失败且仍未生成 token JSON 的账号。"""
    try:
        limit = max(0, int(limit or 0))
    except Exception:
        limit = 100

    accounts = _load_accounts(ACCOUNTS_FILE)
    done_emails = _load_token_json_emails()
    with _file_lock:
        failure_map = _load_auto_oauth_retry_failures_unlocked()
    queued_set, active_set = _failed_auth_queue_status_sets()

    seen = set()
    items = []
    for email, password, mail_auth in accounts:
        key = str(email or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        if key in done_emails:
            continue

        failure = dict((failure_map or {}).get(key) or {})
        failure_count = max(0, _int_value(failure.get("count"), 0))
        if failure_count <= 0:
            continue

        proxy_url = load_account_proxy(key, default="")
        items.append({
            "email": key,
            "queue_status": _failed_auth_queue_status(key, queued_set=queued_set, active_set=active_set),
            "failure_count": failure_count,
            "last_reason": str(failure.get("last_reason") or "").strip(),
            "last_detail": str(failure.get("last_detail") or "").strip()[:300],
            "updated_at": str(failure.get("updated_at") or "").strip(),
            "has_password": bool(password),
            "has_mail_auth": bool(mail_auth),
            "has_proxy": bool(proxy_url),
        })

    items.sort(
        key=lambda item: (
            str(item.get("updated_at") or ""),
            int(item.get("failure_count") or 0),
            str(item.get("email") or ""),
        ),
        reverse=True,
    )
    return {
        "count": len(items),
        "items": items[:limit] if limit > 0 else items,
    }


def read_failed_auth_file(email):
    """读取单个补登失败账号的拼接 auth 预览。"""
    key = str(email or "").strip().lower()
    if not key or "@" not in key:
        return None

    account_row = None
    for row_email, password, mail_auth in _load_accounts(ACCOUNTS_FILE):
        row_key = str(row_email or "").strip().lower()
        if row_key != key:
            continue
        account_row = {
            "email": row_key,
            "password": str(password or ""),
            "mail_auth": str(mail_auth or ""),
        }
        break

    if not isinstance(account_row, dict):
        return None
    if os.path.exists(os.path.join(OUTPUT_DIR, f"{key}.json")):
        return None

    failure = get_auto_oauth_retry_failure_state(key)
    failure_count = max(0, int((failure or {}).get("count") or 0))
    if failure_count <= 0:
        return None

    queued_set, active_set = _failed_auth_queue_status_sets()
    proxy_url = load_account_proxy(key, default="")
    relay_state = load_account_relay(key) if PROXY_MODE in (4, 5, 7) else None
    hydrated = _hydrate_failed_auth_content_from_session(
        key,
        failure=failure,
        proxy_url=proxy_url,
        relay_state=relay_state,
        timeout=20,
    )
    content = dict((hydrated or {}).get("content") or _build_failed_auth_content(key, proxy_url=proxy_url))
    return {
        "email": key,
        "filename": f"{key}.json",
        "modified_at": str((failure or {}).get("updated_at") or ""),
        "size": len(json.dumps(content, ensure_ascii=False)),
        "queue_status": _failed_auth_queue_status(key, queued_set=queued_set, active_set=active_set),
        "failure_count": failure_count,
        "last_reason": str((failure or {}).get("last_reason") or "").strip(),
        "last_detail": str((failure or {}).get("last_detail") or "").strip()[:300],
        "has_password": bool(account_row.get("password")),
        "has_mail_auth": bool(account_row.get("mail_auth")),
        "session_status_code": (hydrated or {}).get("session_status_code"),
        "session_error": str((hydrated or {}).get("session_error") or "")[:300],
        "session_source_url": str((hydrated or {}).get("session_source_url") or "")[:300],
        "session_has_access_token": bool((hydrated or {}).get("session_has_access_token")),
        "content": content,
        "is_json": True,
        "is_synthetic": True,
    }


def delete_pending_oauth_accounts(limit=0):
    """批量删除待补登账号及其本地关联记录。"""
    try:
        limit = max(0, int(limit or 0))
    except Exception:
        limit = 0
    pending = list_pending_oauth_accounts(limit=0)
    items = list((pending or {}).get("items") or [])
    if limit > 0:
        items = items[:limit]
    removed_items = []
    accounts_removed = 0
    csv_removed = 0
    json_deleted = 0
    for row in items:
        email = str((row or {}).get("email") or "").strip().lower()
        if not email:
            continue
        removed = delete_account_records(email)
        clear_auto_oauth_retry_failure_state(email)
        _discard_auto_oauth_retry_runtime_entry(email)
        accounts_removed += max(0, int((removed or {}).get("accounts_removed") or 0))
        csv_removed += max(0, int((removed or {}).get("csv_removed") or 0))
        if bool((removed or {}).get("json_deleted")):
            json_deleted += 1
        removed_items.append({
            "email": email,
            "accounts_removed": max(0, int((removed or {}).get("accounts_removed") or 0)),
            "csv_removed": max(0, int((removed or {}).get("csv_removed") or 0)),
            "json_deleted": bool((removed or {}).get("json_deleted")),
        })
    return {
        "found_count": len((pending or {}).get("items") or []),
        "removed_count": len(removed_items),
        "accounts_removed": accounts_removed,
        "csv_removed": csv_removed,
        "json_deleted": json_deleted,
        "items": removed_items,
    }


def enqueue_pending_oauth_accounts(limit=0, reason="pending_oauth", delay_seconds=0.0):
    """将 accounts.txt 中待补登账号批量装入后台补登队列。"""
    accounts = _load_accounts(ACCOUNTS_FILE)
    done_emails = _load_token_json_emails()
    seen = set()
    added = 0
    skipped_done = 0
    skipped_duplicate = 0
    deleted_exhausted = 0
    scanned = 0
    queued_items = []
    max_items = max(0, int(limit or 0))
    failure_threshold = max(0, int(AUTO_OAUTH_RETRY_DELETE_AFTER_FAILURES or 0))
    for email, password, mail_auth in accounts:
        key = str(email or "").strip().lower()
        if not key:
            continue
        if key in seen:
            skipped_duplicate += 1
            continue
        seen.add(key)
        if key in done_emails:
            skipped_done += 1
            continue
        if failure_threshold > 0:
            state = get_auto_oauth_retry_failure_state(key)
            fail_count = max(0, int((state or {}).get("count") or 0))
            if fail_count >= failure_threshold:
                cleanup_auto_oauth_retry_failed_account(
                    key,
                    detail=(state or {}).get("last_detail") or (state or {}).get("last_reason") or f"连续失败 {fail_count} 次",
                    failure_count=fail_count,
                )
                deleted_exhausted += 1
                continue
        scanned += 1
        result = enqueue_auto_oauth_retry(
            key,
            password,
            mail_auth=mail_auth,
            reason=reason,
            delay_seconds=delay_seconds,
        )
        if result.get("queued"):
            added += 1
            queued_items.append(key)
        if max_items > 0 and added >= max_items:
            break
    return {
        "scanned": scanned,
        "added": added,
        "skipped_done": skipped_done,
        "skipped_duplicate": skipped_duplicate,
        "deleted_exhausted": deleted_exhausted,
        "items": queued_items,
    }




def oauth_retry_one(email, password, mail_auth="", worker_id=0, error_holder=None):
    """对单个已注册账号执行 OAuth 登录

    mail_auth:
      - DuckMail: 邮箱密码，用于重新换取 bearer token
      - ChatGPTMail: provider=chatgptmail，用于启用新邮件接口
    """
    tag = f"[W{worker_id}]" if CONCURRENT_WORKERS > 1 else ""
    t_start = time.time()
    account_proxy = load_account_proxy(email)
    account_relay_state = load_account_relay(email) if PROXY_MODE in (4, 5, 7) else None
    mail_session = create_mail_session(account_proxy, relay_state=_new_random_mail_relay_state())

    try:
        # 根据 mail_auth 恢复邮箱访问能力，用于接收 OTP 验证码
        email_id = None
        auth_text = (mail_auth or "").strip()
        if auth_text.lower() == CHATGPTMAIL_AUTH_MARKER:
            email_id = CHATGPTMAIL_AUTH_MARKER
            print(f"  📧 已启用 ChatGPTMail 收件箱")
        elif _ddgmail_is_auth_marker(auth_text):
            email_id = auth_text
            print(f"  📧 已启用 DuckDuckGo Alias + Outlook 收件箱")
        elif auth_text:
            try:
                res = _duckmail_request(
                    mail_session, "POST", "/token",
                    json={"address": email, "password": auth_text},
                    headers={"Content-Type": "application/json"},
                    timeout=15,
                )
                if res is not None and res.status_code == 200:
                    email_id = res.json().get("token", "")
                    if email_id:
                        print(f"  📧 已重新获取 DuckMail token")
            except Exception:
                pass

        tokens = None
        oauth_err = error_holder if isinstance(error_holder, dict) else {}
        if isinstance(oauth_err, dict):
            oauth_err.clear()
        try:
            tokens = perform_codex_oauth_login_http(
                email, password,
                registrar_session=None,
                email_id=email_id,
                error_holder=oauth_err,
                proxy_url=account_proxy,
                mail_session=mail_session,
                relay_state=account_relay_state or getattr(mail_session, "_relay_state", None) or _relay_state_from_session(mail_session),
            )
        except Exception as e:
            print(f"\n{tag} ⚠️ {email} OAuth 异常: {e}")

        t_total = time.time() - t_start
        final_relay_state = account_relay_state or getattr(mail_session, "_relay_state", None) or mail_session

        if tokens:
            save_tokens(email, tokens, proxy_url=account_proxy, relay_state=final_relay_state)
            sticky_success = mark_registration_pair_success(email, relay_state=final_relay_state, source="oauth_retry")
            if PROXY_MODE in (4, 5, 7):
                remember_account_relay(email, final_relay_state)
            if sticky_success.get("changed"):
                print(f"{tag} 📌 成功组已更新为: {sticky_success.get('active_domain')} | {sticky_success.get('active_node_id')}")
            print(f"\n{tag} ✅ {email} | OAuth {t_total:.1f}s")
            return True, t_total
        else:
            fail_reason = str(oauth_err.get("reason") or "").strip()
            fail_detail = str(oauth_err.get("detail") or "").strip()
            if fail_reason == "password_verify_401_login_password":
                if PROXY_MODE in (4, 5, 7):
                    remember_account_relay(email, final_relay_state)
                print(f"\n{tag} 🧹 检测到步骤3 401(login_password)，删除账号: {email}")
                removed = delete_account_records(email)
                print(
                    f"{tag}    清理结果: accounts={removed.get('accounts_removed', 0)}, "
                    f"csv={removed.get('csv_removed', 0)}, "
                    f"token_json={'Y' if removed.get('json_deleted') else 'N'}"
                )
            elif fail_reason == "chatgptmail_unsupported_email":
                print(f"\n{tag} 🧹 检测到 ChatGPTMail unsupported_email，删除账号: {email}")
                cleanup_unsupported_chatgptmail_account(email, detail=fail_detail or fail_reason)
            else:
                if PROXY_MODE in (4, 5, 7):
                    remember_account_relay(email, final_relay_state)
            if fail_reason in OAUTH_SOFT_RETRY_REASONS:
                print(f"\n{tag} ℹ️ {email} | 等待下轮补登 ({fail_reason}) {t_total:.1f}s")
            else:
                print(f"\n{tag} ❌ {email} | OAuth 失败 {t_total:.1f}s")
            return False, t_total
    finally:
        _close_session(mail_session)

def oauth_retry_batch(workers=None):
    """批量 OAuth 补登入口"""
    workers = workers or max(1, CONCURRENT_WORKERS)

    # 读取所有已注册账号
    accounts = _load_accounts(ACCOUNTS_FILE)
    if not accounts:
        print(f"\n❌ 未找到账号文件或文件为空: {ACCOUNTS_FILE}")
        return

    print(f"\n📋 从 {ACCOUNTS_FILE} 读取到 {len(accounts)} 个账号")

    # 读取已有 token 的邮箱（跳过已成功的）
    done_emails = _load_token_json_emails()
    print(f"📋 已有 token 的账号: {len(done_emails)} 个")

    # 过滤出需要补登的账号
    pending = [(e, p, mp) for e, p, mp in accounts if e.lower() not in done_emails]
    if not pending:
        print("✅ 所有账号已有 token，无需补登")
        return

    print(f"🔄 需要补登: {len(pending)} 个 | 并发 {workers}\n")

    confirm = input(f"确认对 {len(pending)} 个账号执行 OAuth 补登? [Y/n]: ").strip().lower()
    if confirm == "n":
        print("已取消")
        return

    batch_start = time.time()
    ok = 0
    fail = 0
    results_lock = threading.Lock()
    total_times = []
    failed_emails = []  # 记录失败账号

    if workers == 1:
        for i, (email, password, mail_pw) in enumerate(pending):
            print(f"\n--- [{i+1}/{len(pending)}] {email} ---")
            success, t_total = oauth_retry_one(email, password, mail_auth=mail_pw)
            if success:
                ok += 1
                total_times.append(t_total)
            else:
                fail += 1
                failed_emails.append(email)
            done = ok + fail
            wall = time.time() - batch_start
            throughput = wall / ok if ok > 0 else 0
            eta = throughput * (len(pending) - done) if ok > 0 else 0
            print(f"📊 {done}/{len(pending)} | ✅{ok} ❌{fail} | 吞吐 {throughput:.1f}s/个 | 已用 {wall:.0f}s | ETA {eta:.0f}s")
            if i < len(pending) - 1:
                time.sleep(random.randint(2, 5))
    else:
        print(f"🔀 启动 {workers} 个并发 worker...\n")

        def _retry_worker(idx, email, password, mail_pw, wid):
            if idx > 0:
                time.sleep(random.uniform(1, 3) * wid)
            try:
                return oauth_retry_one(email, password, mail_auth=mail_pw, worker_id=wid)
            except Exception as e:
                print(f"\n[W{wid}] ❌ 异常: {e}")
                return False, 0

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}

            def _submit_retry(idx):
                email, password, mail_pw = pending[idx]
                wid = (idx % workers) + 1
                future = executor.submit(_retry_worker, idx, email, password, mail_pw, wid)
                futures[future] = email

            initial_batch = min(workers, len(pending))
            for idx in range(initial_batch):
                _submit_retry(idx)
            next_idx = initial_batch

            while futures:
                done_set, _ = futures_wait(set(futures), return_when=FIRST_COMPLETED)
                for future in done_set:
                    email_addr = futures.pop(future)
                    try:
                        success, t_total = future.result()
                        with results_lock:
                            if success:
                                ok += 1
                                total_times.append(t_total)
                            else:
                                fail += 1
                                failed_emails.append(email_addr)
                            done = ok + fail
                            wall = time.time() - batch_start
                            throughput = wall / ok if ok > 0 else 0
                            eta = throughput * (len(pending) - done) if ok > 0 else 0
                            print(f"📊 {done}/{len(pending)} | ✅{ok} ❌{fail} | 吞吐 {throughput:.1f}s/个 | 已用 {wall:.0f}s | ETA {eta:.0f}s")
                    except Exception:
                        with results_lock:
                            fail += 1
                            failed_emails.append(email_addr)
                    if next_idx < len(pending):
                        _submit_retry(next_idx)
                        next_idx += 1

    elapsed = time.time() - batch_start
    throughput = elapsed / ok if ok > 0 else 0
    avg_total = sum(total_times) / len(total_times) if total_times else 0
    print(f"\n🏁 OAuth 补登完成: ✅{ok} ❌{fail} | 总耗时 {elapsed:.1f}s | 吞吐 {throughput:.1f}s/个 | 单号均耗 {avg_total:.1f}s")

    # 保存失败账号列表，方便下次重试
    if failed_emails:
        retry_file = os.path.join(OUTPUT_DIR, "retry_failed.txt")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        try:
            with open(retry_file, "a", encoding="utf-8") as f:
                f.write(f"\n# {ts} 补登失败 {len(failed_emails)} 个\n")
                for em in failed_emails:
                    f.write(f"{em}\n")
            print(f"📝 失败账号已记录到: {retry_file} ({len(failed_emails)} 个)")
        except Exception as e:
            print(f"⚠️ 保存失败列表出错: {e}")



def _auto_oauth_retry_token_exists(email):
    target = str(email or "").strip().lower()
    if not target:
        return False
    return os.path.exists(os.path.join(OUTPUT_DIR, f"{target}.json"))


def _auto_oauth_retry_worker_tag(worker_id):
    return f"[AR{worker_id}]"


def _auto_oauth_retry_prune_dead_locked():
    for worker_id, spec in list(_auto_oauth_retry_worker_specs.items()):
        thread = spec.get("thread")
        if thread is not None and not thread.is_alive():
            _auto_oauth_retry_worker_specs.pop(worker_id, None)



def _auto_oauth_retry_worker_loop(worker_id, stop_event):
    tag = _auto_oauth_retry_worker_tag(worker_id)

    def _sleep_with_stop(seconds):
        slept = 0.0
        seconds = max(0.0, float(seconds or 0.0))
        while slept < seconds and not stop_event.is_set():
            chunk = min(0.5, seconds - slept)
            time.sleep(chunk)
            slept += chunk
        return stop_event.is_set()

    while not stop_event.is_set():
        got_item = False
        try:
            try:
                email_key = _auto_oauth_retry_queue.get(timeout=0.5)
                got_item = True
            except queue.Empty:
                continue

            with _auto_oauth_retry_lock:
                item = _auto_oauth_retry_pending.get(email_key)
            if not isinstance(item, dict):
                continue

            wait_sec = max(0.0, float(item.get("ready_at", 0.0) or 0.0) - time.time())
            if wait_sec > 0 and _sleep_with_stop(wait_sec):
                with _auto_oauth_retry_lock:
                    still_pending = isinstance(_auto_oauth_retry_pending.get(email_key), dict)
                if still_pending:
                    _auto_oauth_retry_queue.put(email_key)
                continue

            with _auto_oauth_retry_lock:
                item = _auto_oauth_retry_pending.pop(email_key, None)
                if not isinstance(item, dict):
                    continue
                item["started_at"] = time.time()
                item["worker_id"] = worker_id
                item["status"] = "running"
                item["last_error"] = ""
                _auto_oauth_retry_active[email_key] = item

            email = str(item.get("email") or "").strip().lower()
            password = str(item.get("password") or "")
            mail_auth = str(item.get("mail_auth") or "")
            reason = str(item.get("reason") or "").strip()
            keep_processing = True

            while keep_processing and not stop_event.is_set():
                started_at = time.time()
                success = False
                detail = ""
                oauth_err = {}
                attempts = int(item.get("attempts", 0) or 0) + 1
                item["attempts"] = attempts
                item["started_at"] = started_at
                item["status"] = "running"
                item["last_error"] = ""

                try:
                    if _auto_oauth_retry_token_exists(email):
                        success = True
                        detail = "token 已存在，跳过补登"
                        print(f"{tag} ℹ️ {email} token 已存在，跳过补登")
                    else:
                        print(f"{tag} 🔄 开始后台补登: {email} | 原因={reason or '-'} | 尝试 {attempts}/{item.get('max_attempts', AUTO_OAUTH_RETRY_MAX_ATTEMPTS)}")
                        success, _ = oauth_retry_one(email, password, mail_auth=mail_auth, worker_id=900 + worker_id, error_holder=oauth_err)
                        if success:
                            detail = "补登成功"
                        else:
                            fail_reason = str(oauth_err.get("reason") or "").strip()
                            fail_detail = str(oauth_err.get("detail") or "").strip()
                            detail = fail_reason or "补登失败"
                            if fail_detail:
                                detail = f"{detail}: {fail_detail}"
                except Exception as e:
                    detail = str(e)
                    print(f"{tag} ❌ 后台补登异常: {email} | {e}")
                    success = False

                duration = max(0.0, time.time() - started_at)
                fail_reason = str(oauth_err.get("reason") or "").strip()
                max_attempts = int(item.get("max_attempts", AUTO_OAUTH_RETRY_MAX_ATTEMPTS) or AUTO_OAUTH_RETRY_MAX_ATTEMPTS)
                soft_retries = int(item.get("soft_retries", 0) or 0)
                allow_soft_extra = (
                    (not success)
                    and fail_reason in OAUTH_SOFT_RETRY_REASONS
                    and soft_retries < AUTO_OAUTH_RETRY_SOFT_EXTRA_ATTEMPTS
                )
                should_retry_now = (
                    (not success)
                    and fail_reason not in OAUTH_NO_RETRY_REASONS
                    and (attempts < max_attempts or allow_soft_extra)
                )

                if should_retry_now and not stop_event.is_set():
                    delay_seconds = AUTO_OAUTH_RETRY_IMMEDIATE_RETRY_SECONDS
                    now = time.time()
                    item["status"] = "retry_wait"
                    item["queued_at"] = now
                    item["ready_at"] = now + delay_seconds
                    item["last_error"] = detail
                    if allow_soft_extra:
                        item["soft_retries"] = soft_retries + 1
                    with _auto_oauth_retry_lock:
                        _auto_oauth_retry_active[email_key] = item
                        _auto_oauth_retry_recent.appendleft({
                            "email": email,
                            "reason": reason,
                            "status": "retry_wait",
                            "detail": detail,
                            "attempts": attempts,
                            "queued_at": item.get("queued_at", 0.0),
                            "started_at": item.get("started_at", 0.0),
                            "finished_at": time.time(),
                            "duration_sec": round(duration, 1),
                        })
                    print(
                        f"{tag} 🔁 后台补登失败，{delay_seconds:.1f}s 后同 worker 直接重试: "
                        f"{email} | {detail}"
                    )
                    interrupted = _sleep_with_stop(delay_seconds)
                    if interrupted:
                        with _auto_oauth_retry_lock:
                            _auto_oauth_retry_active.pop(email_key, None)
                            item["status"] = "queued"
                            item["queued_at"] = time.time()
                            item["ready_at"] = time.time()
                            _auto_oauth_retry_pending[email_key] = item
                        _auto_oauth_retry_queue.put(email_key)
                        keep_processing = False
                        break
                    continue

                final_status = "success" if success else "failed"
                failure_count = 0
                if success:
                    clear_auto_oauth_retry_failure_state(email)
                else:
                    if fail_reason in {"password_verify_401_login_password", "chatgptmail_unsupported_email"}:
                        clear_auto_oauth_retry_failure_state(email)
                    else:
                        state = bump_auto_oauth_retry_failure_state(email, reason=fail_reason or reason, detail=detail)
                        failure_count = max(0, int((state or {}).get("count") or 0))
                        threshold = max(0, int(AUTO_OAUTH_RETRY_DELETE_AFTER_FAILURES or 0))
                        if threshold > 0 and failure_count >= threshold:
                            cleanup_auto_oauth_retry_failed_account(email, detail=detail, failure_count=failure_count)
                            final_status = "failed"
                            detail = f"{detail} | 连续失败{failure_count}次，已删除账号"
                            print(f"{tag} 🧹 后台补登连续失败达到阈值，删除账号: {email} | {failure_count}/{threshold}")
                        else:
                            if threshold > 0:
                                print(f"{tag} ⚠️ 后台补登累计失败: {email} | {failure_count}/{threshold} | {detail}")
                with _auto_oauth_retry_lock:
                    _auto_oauth_retry_active.pop(email_key, None)
                    _auto_oauth_retry_recent.appendleft({
                        "email": email,
                        "reason": reason,
                        "status": final_status,
                        "detail": detail,
                        "attempts": attempts,
                        "queued_at": item.get("queued_at", 0.0),
                        "started_at": item.get("started_at", 0.0),
                        "finished_at": time.time(),
                        "duration_sec": round(duration, 1),
                        "consecutive_failures": failure_count,
                    })
                keep_processing = False
        finally:
            if got_item:
                _auto_oauth_retry_queue.task_done()
    with _auto_oauth_retry_lock:
        _auto_oauth_retry_worker_specs.pop(worker_id, None)

def _ensure_auto_oauth_retry_workers():
    global _auto_oauth_retry_started, _auto_oauth_retry_next_worker_id
    if not AUTO_OAUTH_RETRY_ENABLED:
        return False
    if not _auto_oauth_retry_runtime_enabled:
        return False
    to_start = []
    with _auto_oauth_retry_lock:
        _auto_oauth_retry_prune_dead_locked()
        _auto_oauth_retry_started = True
        current = len(_auto_oauth_retry_worker_specs)
        desired = max(1, int(AUTO_OAUTH_RETRY_WORKERS or 1))
        if current < desired:
            for _ in range(desired - current):
                worker_id = _auto_oauth_retry_next_worker_id
                _auto_oauth_retry_next_worker_id += 1
                stop_event = threading.Event()
                thread = threading.Thread(
                    target=_auto_oauth_retry_worker_loop,
                    args=(worker_id, stop_event),
                    name=f"auto-oauth-retry-{worker_id}",
                    daemon=True,
                )
                _auto_oauth_retry_worker_specs[worker_id] = {"thread": thread, "stop_event": stop_event}
                to_start.append(thread)
        elif current > desired:
            extra_ids = sorted(_auto_oauth_retry_worker_specs.keys(), reverse=True)[: current - desired]
            for worker_id in extra_ids:
                spec = _auto_oauth_retry_worker_specs.get(worker_id) or {}
                stop_event = spec.get("stop_event")
                if stop_event is not None:
                    stop_event.set()
    for thread in to_start:
        thread.start()
    return True


def set_auto_oauth_retry_worker_count(worker_count):
    global AUTO_OAUTH_RETRY_WORKERS
    AUTO_OAUTH_RETRY_WORKERS = max(1, int(worker_count or 1))
    _ensure_auto_oauth_retry_workers()
    return AUTO_OAUTH_RETRY_WORKERS


def set_auto_oauth_retry_max_attempts(max_attempts):
    global AUTO_OAUTH_RETRY_MAX_ATTEMPTS
    AUTO_OAUTH_RETRY_MAX_ATTEMPTS = max(1, int(max_attempts or 1))
    with _auto_oauth_retry_lock:
        for item in _auto_oauth_retry_pending.values():
            if isinstance(item, dict):
                item["max_attempts"] = AUTO_OAUTH_RETRY_MAX_ATTEMPTS
        for item in _auto_oauth_retry_active.values():
            if isinstance(item, dict):
                item["max_attempts"] = AUTO_OAUTH_RETRY_MAX_ATTEMPTS
    return AUTO_OAUTH_RETRY_MAX_ATTEMPTS


def is_auto_oauth_retry_running():
    return bool(AUTO_OAUTH_RETRY_ENABLED and _auto_oauth_retry_runtime_enabled)


def set_auto_oauth_retry_running(enabled):
    global _auto_oauth_retry_runtime_enabled
    enabled = bool(enabled)
    with _auto_oauth_retry_lock:
        _auto_oauth_retry_runtime_enabled = enabled
        _auto_oauth_retry_prune_dead_locked()
        if not enabled:
            for spec in _auto_oauth_retry_worker_specs.values():
                stop_event = (spec or {}).get("stop_event")
                if stop_event is not None:
                    stop_event.set()
    if enabled:
        _ensure_auto_oauth_retry_workers()
    return is_auto_oauth_retry_running()


def enqueue_auto_oauth_retry(email, password, mail_auth="", reason="", delay_seconds=None):
    if not AUTO_OAUTH_RETRY_ENABLED:
        return {"enabled": False, "queued": False, "message": "自动补登队列未启用"}
    target = str(email or "").strip().lower()
    password = str(password or "")
    mail_auth = str(mail_auth or "")
    if not target or not password:
        return {"enabled": True, "queued": False, "message": "邮箱或密码为空"}
    if _auto_oauth_retry_token_exists(target):
        return {"enabled": True, "queued": False, "message": "token 已存在"}
    _ensure_auto_oauth_retry_workers()
    with _auto_oauth_retry_lock:
        if target in _auto_oauth_retry_pending:
            return {"enabled": True, "queued": False, "message": "已在补登队列中"}
        if target in _auto_oauth_retry_active:
            return {"enabled": True, "queued": False, "message": "正在补登中"}
        now = time.time()
        wait_delay = AUTO_OAUTH_RETRY_DELAY_SECONDS if delay_seconds is None else max(0.0, float(delay_seconds or 0.0))
        _auto_oauth_retry_pending[target] = {
            "email": target,
            "password": password,
            "mail_auth": mail_auth,
            "reason": str(reason or "").strip(),
            "queued_at": now,
            "ready_at": now + wait_delay,
            "started_at": 0.0,
            "status": "queued",
            "attempts": 0,
            "max_attempts": AUTO_OAUTH_RETRY_MAX_ATTEMPTS,
            "worker_id": 0,
            "last_error": "",
        }
    _auto_oauth_retry_queue.put(target)
    print(f"🧾 已加入自动补登队列: {target} | 原因={reason or '-'} | 延迟={wait_delay:.1f}s")
    return {"enabled": True, "queued": True, "message": "已加入自动补登队列", "email": target, "delay_seconds": round(wait_delay, 1)}


def get_auto_oauth_retry_status(limit=20):
    now = time.time()
    with _auto_oauth_retry_lock:
        _auto_oauth_retry_prune_dead_locked()
        worker_specs_count = len(_auto_oauth_retry_worker_specs)
        queued_items = []
        for email_key, item in sorted(_auto_oauth_retry_pending.items(), key=lambda kv: float((kv[1] or {}).get("queued_at", 0.0) or 0.0)):
            entry = dict(item)
            entry["email"] = email_key
            queued_items.append(entry)
        active_items = []
        for email_key, item in sorted(_auto_oauth_retry_active.items(), key=lambda kv: float((kv[1] or {}).get("started_at", 0.0) or 0.0)):
            entry = dict(item)
            entry["email"] = email_key
            active_items.append(entry)
        recent_items = list(_auto_oauth_retry_recent)[:max(0, int(limit or 0))]

    def _fmt_ts(value):
        try:
            ts = float(value or 0.0)
        except Exception:
            ts = 0.0
        if ts <= 0:
            return ""
        return time.strftime("%H:%M:%S", time.localtime(ts))

    return {
        "enabled": AUTO_OAUTH_RETRY_ENABLED,
        "running": is_auto_oauth_retry_running(),
        "worker_count": AUTO_OAUTH_RETRY_WORKERS,
        "delete_after_failures": AUTO_OAUTH_RETRY_DELETE_AFTER_FAILURES,
        "live_worker_count": worker_specs_count,
        "delay_seconds": round(AUTO_OAUTH_RETRY_DELAY_SECONDS, 1),
        "max_attempts": AUTO_OAUTH_RETRY_MAX_ATTEMPTS,
        "queued_count": len(queued_items),
        "active_count": len(active_items),
        "recent_count": len(recent_items),
        "queued": [
            {
                "email": item.get("email", ""),
                "reason": item.get("reason", ""),
                "attempts": int(item.get("attempts", 0) or 0),
                "max_attempts": int(item.get("max_attempts", AUTO_OAUTH_RETRY_MAX_ATTEMPTS) or AUTO_OAUTH_RETRY_MAX_ATTEMPTS),
                "queued_at": _fmt_ts(item.get("queued_at")),
                "wait_sec": round(max(0.0, float(item.get("ready_at", 0.0) or 0.0) - now), 1),
                "status": "queued",
                "detail": item.get("last_error", ""),
            }
            for item in queued_items[:max(0, int(limit or 0))]
        ],
        "active": [
            {
                "email": item.get("email", ""),
                "reason": item.get("reason", ""),
                "attempts": int(item.get("attempts", 0) or 0),
                "max_attempts": int(item.get("max_attempts", AUTO_OAUTH_RETRY_MAX_ATTEMPTS) or AUTO_OAUTH_RETRY_MAX_ATTEMPTS),
                "queued_at": _fmt_ts(item.get("queued_at")),
                "started_at": _fmt_ts(item.get("started_at")),
                "elapsed_sec": round(max(0.0, now - float(item.get("started_at", 0.0) or 0.0)), 1),
                "wait_sec": round(max(0.0, float(item.get("ready_at", 0.0) or 0.0) - now), 1),
                "status": item.get("status", "running"),
                "detail": item.get("last_error", ""),
            }
            for item in active_items[:max(0, int(limit or 0))]
        ],
        "recent": [
            {
                "email": item.get("email", ""),
                "reason": item.get("reason", ""),
                "attempts": int(item.get("attempts", 0) or 0),
                "status": item.get("status", "failed"),
                "detail": item.get("detail", ""),
                "finished_at": _fmt_ts(item.get("finished_at")),
                "duration_sec": round(float(item.get("duration_sec", 0.0) or 0.0), 1),
            }
            for item in recent_items
        ],
    }

# =================== CPA 清理（由 test/clean_codex_accounts.py.txt 合并） ===================

def _cpa_mgmt_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def _cpa_safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}


def _cpa_safe_json_text(text):
    try:
        return json.loads(text)
    except Exception:
        return {}


def _cpa_get_item_type(item):
    # 兼容后端字段命名差异（type / typo）
    return item.get("type") or item.get("typo")


def _cpa_extract_chatgpt_account_id(item):
    item = item if isinstance(item, dict) else {}
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return val
    id_token = item.get("id_token")
    if isinstance(id_token, dict):
        for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
            val = id_token.get(key)
            if val:
                return val
    return None


def _cpa_fetch_auth_files(base_url, token, timeout):
    session = None
    try:
        session = create_cpa_management_session()
        resp = session.get(
            f"{base_url}/v0/management/auth-files",
            headers=_cpa_mgmt_headers(token),
            timeout=timeout,
            verify=False,
        )
        resp.raise_for_status()
        data = _cpa_safe_json(resp)
        return data.get("files", [])
    finally:
        _close_session(session)


def _cpa_build_probe_payload(auth_index, user_agent, chatgpt_account_id=None):
    call_header = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }
    if chatgpt_account_id:
        call_header["Chatgpt-Account-Id"] = chatgpt_account_id

    return {
        "authIndex": auth_index,
        "method": "GET",
        "url": "https://chatgpt.com/backend-api/wham/usage",
        "header": call_header,
    }


def _cpa_parse_usage_probe_response(data):
    data = data if isinstance(data, dict) else {}
    status_code = data.get("status_code")
    if status_code not in (None, ""):
        try:
            status_code = int(status_code)
        except Exception:
            pass
    body = data.get("body")
    body_text = body if isinstance(body, str) else ""
    if isinstance(body, dict):
        payload = body
    elif body_text:
        payload = _cpa_safe_json_text(body_text)
        if not isinstance(payload, dict):
            payload = {}
    else:
        payload = {}

    rate_limit = payload.get("rate_limit") if isinstance(payload, dict) else {}
    credits = payload.get("credits") if isinstance(payload, dict) else {}
    primary_window = rate_limit.get("primary_window") if isinstance(rate_limit, dict) else {}

    reset_after_seconds = None
    reset_at = None
    if isinstance(primary_window, dict):
        if primary_window.get("reset_after_seconds") not in (None, ""):
            reset_after_seconds = _int_value(primary_window.get("reset_after_seconds"), None)
        if primary_window.get("reset_at") not in (None, ""):
            reset_at = _int_value(primary_window.get("reset_at"), None)

    credits_has = bool(credits.get("has_credits")) if isinstance(credits, dict) else False
    credits_unlimited = bool(credits.get("unlimited")) if isinstance(credits, dict) else False
    allowed = rate_limit.get("allowed") if isinstance(rate_limit, dict) else None
    limit_reached = bool(rate_limit.get("limit_reached")) if isinstance(rate_limit, dict) else False

    usage_state = "unknown"
    detail = ""
    if status_code == 401:
        usage_state = "invalid"
    elif status_code == 200:
        if allowed is True or credits_has or credits_unlimited:
            usage_state = "available"
        elif allowed is False:
            usage_state = "exhausted"
        elif limit_reached:
            usage_state = "exhausted"
        elif isinstance(payload, dict) and payload.get("error"):
            detail = str(payload.get("error") or "")
    elif status_code is not None:
        detail = f"status_code={status_code}"

    if not detail and isinstance(payload, dict):
        for key in ("detail", "message", "error"):
            val = payload.get(key)
            if val:
                detail = str(val)
                break
    if not detail and body_text and not isinstance(payload, dict):
        detail = body_text[:200]

    return {
        "status_code": status_code,
        "usage_state": usage_state,
        "allowed": allowed if isinstance(allowed, bool) else None,
        "limit_reached": limit_reached,
        "credits_has": credits_has,
        "credits_unlimited": credits_unlimited,
        "reset_after_seconds": reset_after_seconds,
        "reset_at": reset_at,
        "inner_email": str(payload.get("email") or "") if isinstance(payload, dict) else "",
        "inner_account_id": str(payload.get("account_id") or payload.get("user_id") or "") if isinstance(payload, dict) else "",
        "detail": detail[:300],
    }


async def _cpa_probe_account_async(
    session,
    semaphore,
    base_url,
    token,
    item,
    user_agent,
    fallback_account_id=None,
    timeout=10,
    retries=1,
):
    auth_index = item.get("auth_index")
    name = item.get("name") or item.get("id")
    account = item.get("account") or item.get("email") or ""

    result = {
        "name": name,
        "account": account,
        "auth_index": auth_index,
        "type": _cpa_get_item_type(item),
        "provider": item.get("provider"),
        "status_code": None,
        "invalid_401": False,
        "usage_state": "unknown",
        "allowed": None,
        "limit_reached": False,
        "credits_has": False,
        "credits_unlimited": False,
        "reset_after_seconds": None,
        "reset_at": None,
        "detail": "",
        "error": None,
    }

    if not auth_index:
        result["error"] = "missing auth_index"
        return result

    chatgpt_account_id = _cpa_extract_chatgpt_account_id(item) or fallback_account_id
    payload = _cpa_build_probe_payload(auth_index, user_agent, chatgpt_account_id)

    for attempt in range(retries + 1):
        try:
            async with semaphore:
                async with session.post(
                    f"{base_url}/v0/management/api-call",
                    headers={**_cpa_mgmt_headers(token), "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        raise RuntimeError(f"management api-call http {resp.status}: {text[:200]}")

                    data = _cpa_safe_json_text(text)
                    parsed = _cpa_parse_usage_probe_response(data)
                    result.update(parsed)
                    result["invalid_401"] = (result.get("status_code") == 401)
                    if result.get("status_code") is None:
                        result["error"] = "missing status_code in api-call response"
                    else:
                        result["error"] = None
                    return result
        except Exception as e:
            result["error"] = str(e)
            if attempt >= retries:
                return result
    return result


async def _cpa_delete_account_async(session, semaphore, base_url, token, name, timeout):
    if not name:
        return {"name": None, "deleted": False, "error": "missing name"}

    encoded_name = quote(name, safe="")
    url = f"{base_url}/v0/management/auth-files?name={encoded_name}"

    try:
        async with semaphore:
            async with session.delete(url, headers=_cpa_mgmt_headers(token), timeout=timeout) as resp:
                text = await resp.text()
                data = _cpa_safe_json_text(text)
                ok = resp.status == 200 and data.get("status") == "ok"
                return {
                    "name": name,
                    "deleted": ok,
                    "status_code": resp.status,
                    "error": None if ok else f"delete failed, response={text[:200]}",
                }
    except Exception as e:
        return {"name": name, "deleted": False, "error": str(e)}


async def _cpa_run_probe_async(
    base_url,
    token,
    target_type,
    provider,
    workers,
    timeout,
    retries,
    user_agent,
    chatgpt_account_id,
    output_file,
):
    files = _cpa_fetch_auth_files(base_url, token, timeout)
    candidates = []
    for f in files:
        if str(_cpa_get_item_type(f) or "").lower() != target_type.lower():
            continue
        if provider and str(f.get("provider", "")).lower() != provider.lower():
            continue
        candidates.append(f)

    print(f"总账号数: {len(files)}")
    print(f"符合过滤条件账号数: {len(candidates)}")
    print(f"异步检测并发: workers={workers}, timeout={timeout}s, retries={retries}")

    if not candidates:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)
        print(f"已导出: {output_file}")
        return []

    connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    semaphore = asyncio.Semaphore(max(1, workers))

    probe_results = []
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=client_timeout,
        trust_env=(not CPA_MANAGEMENT_NO_PROXY),
    ) as session:
        tasks = [
            asyncio.create_task(
                _cpa_probe_account_async(
                    session,
                    semaphore,
                    base_url,
                    token,
                    item,
                    user_agent,
                    chatgpt_account_id,
                    timeout,
                    retries,
                )
            )
            for item in candidates
        ]

        total = len(tasks)
        done = 0
        next_report = 100
        for task in asyncio.as_completed(tasks):
            probe_results.append(await task)
            done += 1
            if (done >= next_report) or (done == total):
                print(f"检测进度: {done}/{total}")
                next_report += 100

    invalid_401 = [r for r in probe_results if r.get("invalid_401")]
    failed_probe = [r for r in probe_results if r.get("error")]

    invalid_401.sort(key=lambda x: (x.get("name") or ""))
    print(f"探测完成: 401失效={len(invalid_401)}，探测异常={len(failed_probe)}")

    for r in invalid_401:
        print(f"[401] {r.get('name')} | account={r.get('account')} | auth_index={r.get('auth_index')}")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(invalid_401, f, ensure_ascii=False, indent=2)
    print(f"已导出: {output_file}")

    return invalid_401


def _run_async_blocking(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError as exc:
        if "asyncio.run() cannot be called from a running event loop" not in str(exc):
            raise
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _cpa_build_quota_error_summary(target, error_message):
    quota = _cpa_target_quota_config(target)
    auto_delete_state = _get_cpa_auto_delete_401_state(str((target or {}).get("id") or "").strip())
    return {
        "id": str((target or {}).get("id") or "").strip(),
        "label": str((target or {}).get("label") or (target or {}).get("base_url") or "").strip(),
        "base_url": str((target or {}).get("base_url") or "").strip(),
        **quota,
        "total_accounts": None,
        "available": None,
        "exhausted": None,
        "invalid": None,
        "unknown": None,
        "recover_lt_6h": None,
        "recover_lt_24h": None,
        "need_topup": None,
        "plan_topup": None,
        "quota_updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "quota_state": "error",
        "quota_error": str(error_message or "")[:300],
        "quota_estimated": False,
        "sample_errors": [],
        "probe_duration_seconds": 0.0,
        **_cpa_auto_delete_401_public_fields(auto_delete_state),
    }


async def _cpa_probe_usage_summary_async(
    base_url,
    token,
    target_type,
    provider,
    workers,
    timeout,
    retries,
    user_agent,
    chatgpt_account_id,
):
    files = _cpa_fetch_auth_files(base_url, token, timeout)
    target_type = str(target_type or CPA_TARGET_TYPE or "codex").strip() or "codex"
    provider = str(provider or CPA_PROVIDER or "").strip()

    candidates = []
    for item in files:
        if str(_cpa_get_item_type(item) or "").lower() != target_type.lower():
            continue
        if provider and str(item.get("provider", "")).lower() != provider.lower():
            continue
        candidates.append(item)

    if not candidates:
        return files, candidates, []

    workers = max(1, int(workers or 1))
    connector = aiohttp.TCPConnector(limit=workers, limit_per_host=workers)
    client_timeout = aiohttp.ClientTimeout(total=max(1, int(timeout or 1)))
    semaphore = asyncio.Semaphore(workers)
    probe_results = []

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=client_timeout,
        trust_env=(not CPA_MANAGEMENT_NO_PROXY),
    ) as session:
        tasks = [
            asyncio.create_task(
                _cpa_probe_account_async(
                    session,
                    semaphore,
                    base_url,
                    token,
                    item,
                    user_agent,
                    chatgpt_account_id,
                    timeout,
                    retries,
                )
            )
            for item in candidates
        ]
        for task in asyncio.as_completed(tasks):
            probe_results.append(await task)

    return files, candidates, probe_results


def _cpa_build_usage_quota_summary(target, files, candidates, probe_results, duration_seconds=0.0):
    counts = {"available": 0, "exhausted": 0, "invalid": 0, "unknown": 0}
    auto_delete_state = _get_cpa_auto_delete_401_state(str((target or {}).get("id") or "").strip())
    recover_lt_6h = 0
    recover_lt_24h = 0
    sample_errors = []

    for row in list(probe_results or []):
        state = str(row.get("usage_state") or "unknown")
        if state not in counts:
            state = "unknown"
        counts[state] += 1

        reset_after_seconds = row.get("reset_after_seconds")
        if state == "exhausted" and reset_after_seconds is not None:
            try:
                reset_after_seconds = int(reset_after_seconds)
            except Exception:
                reset_after_seconds = None
            if reset_after_seconds is not None:
                if reset_after_seconds <= 6 * 3600:
                    recover_lt_6h += 1
                if reset_after_seconds <= 24 * 3600:
                    recover_lt_24h += 1

        issue_text = ""
        if row.get("error"):
            issue_text = str(row.get("error") or "").strip()
        elif state == "unknown":
            issue_text = str(row.get("detail") or "").strip()
        status_code = row.get("status_code")
        if issue_text and len(sample_errors) < 5:
            sample_errors.append({
                "email": str(row.get("account") or row.get("inner_email") or ""),
                "status_code": status_code,
                "message": issue_text[:240],
            })

    stats = get_cpa_push_stats()
    plan = _plan_cpa_topup_for_available_count(target, counts["available"], stats=stats)
    quota_state = "ok"
    if sample_errors:
        quota_state = "partial"

    return {
        "id": str((target or {}).get("id") or "").strip(),
        "label": str((target or {}).get("label") or (target or {}).get("base_url") or "").strip(),
        "base_url": str((target or {}).get("base_url") or "").strip(),
        **plan,
        "total_accounts": len(candidates or []),
        "available": counts["available"],
        "exhausted": counts["exhausted"],
        "invalid": counts["invalid"],
        "unknown": counts["unknown"],
        "recover_lt_6h": recover_lt_6h,
        "recover_lt_24h": recover_lt_24h,
        "quota_updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "quota_state": quota_state,
        "quota_error": "",
        "quota_estimated": False,
        "sample_errors": sample_errors,
        "probe_duration_seconds": round(float(duration_seconds or 0.0), 1),
        "total_files": len(files or []),
        "scanned_accounts": len(probe_results or []),
        **_cpa_auto_delete_401_public_fields(auto_delete_state),
    }


async def _cpa_delete_accounts_batch_async(base_url, token, names_to_delete, delete_workers, timeout):
    ordered_names = []
    seen = set()
    for name in list(names_to_delete or []):
        key = str(name or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered_names.append(key)

    if not ordered_names:
        return {"requested": 0, "success": 0, "failed": 0, "items": []}

    connector = aiohttp.TCPConnector(limit=max(1, delete_workers), limit_per_host=max(1, delete_workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    semaphore = asyncio.Semaphore(max(1, delete_workers))
    delete_results = []
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=client_timeout,
        trust_env=(not CPA_MANAGEMENT_NO_PROXY),
    ) as session:
        tasks = [
            asyncio.create_task(_cpa_delete_account_async(session, semaphore, base_url, token, name, timeout))
            for name in ordered_names
        ]
        for task in asyncio.as_completed(tasks):
            delete_results.append(await task)

    success = [r for r in delete_results if r.get("deleted")]
    failed = [r for r in delete_results if not r.get("deleted")]
    return {
        "requested": len(ordered_names),
        "success": len(success),
        "failed": len(failed),
        "items": delete_results,
    }


def _run_cpa_auto_delete_invalid_401(target, names_to_delete, invalid_count, reason="quota_probe"):
    target = _normalize_cpa_target(target)
    if not target:
        return False

    target_id = str(target.get("id") or "").strip()
    label = str(target.get("label") or target.get("base_url") or target_id)
    started_at = time.time()
    status = "success"
    message = ""
    deleted_count = 0
    failed_count = 0

    try:
        result = _run_async_blocking(
            _cpa_delete_accounts_batch_async(
                target.get("base_url"),
                target.get("upload_api_token"),
                names_to_delete,
                CPA_AUTO_DELETE_401_WORKERS,
                CPA_TIMEOUT,
            )
        )
        deleted_count = max(0, int((result or {}).get("success") or 0))
        failed_count = max(0, int((result or {}).get("failed") or 0))
        message = f"401={invalid_count}，已删 {deleted_count}，失败 {failed_count}"
        print(f"🧹 CPA 自动清理401: {label} | {message}")
        clear_cpa_quota_cache([target_id])
    except Exception as e:
        status = "error"
        failed_count = max(0, len(list(names_to_delete or [])))
        message = str(e)
        print(f"⚠️ CPA 自动清理401失败: {label} | {e}")
    finally:
        with _cpa_auto_delete_401_lock:
            state = _cpa_auto_delete_401_default_state()
            existing = _cpa_auto_delete_401_state.get(target_id)
            if isinstance(existing, dict):
                state.update(existing)
            state.update({
                "inflight": False,
                "last_invalid": max(0, int(invalid_count or 0)),
                "last_deleted": deleted_count,
                "last_failed": failed_count,
                "last_run_ts": time.time(),
                "last_run_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_status": status,
                "last_message": str(message or "")[:300],
                "last_reason": str(reason or "quota_probe"),
                "last_duration_seconds": round(max(0.0, time.time() - started_at), 1),
            })
            _cpa_auto_delete_401_state[target_id] = state
    return status == "success"


def maybe_schedule_cpa_auto_delete_invalid_401(target, probe_results, reason="quota_probe", force=False):
    target = _normalize_cpa_target(target)
    if not target or not CPA_AUTO_DELETE_401_ENABLED or aiohttp is None:
        return False

    target_id = str(target.get("id") or "").strip()
    invalid_names = []
    seen = set()
    for row in list(probe_results or []):
        if not bool((row or {}).get("invalid_401")):
            continue
        name = str((row or {}).get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        invalid_names.append(name)

    invalid_count = len(invalid_names)
    threshold = max(1, int(CPA_AUTO_DELETE_401_THRESHOLD or 1))
    if invalid_count < threshold:
        with _cpa_auto_delete_401_lock:
            state = _cpa_auto_delete_401_default_state()
            existing = _cpa_auto_delete_401_state.get(target_id)
            if isinstance(existing, dict):
                state.update(existing)
            state.update({
                "last_invalid": invalid_count,
                "last_status": "idle" if invalid_count <= 0 else "below_threshold",
                "last_message": "" if invalid_count <= 0 else f"401={invalid_count}，未达到自动清理阈值 {threshold}",
            })
            _cpa_auto_delete_401_state[target_id] = state
        return False

    limit = max(0, int(CPA_AUTO_DELETE_401_MAX_DELETE_PER_RUN or 0))
    if limit > 0:
        invalid_names = invalid_names[:limit]

    now_ts = time.time()
    with _cpa_auto_delete_401_lock:
        state = _cpa_auto_delete_401_default_state()
        existing = _cpa_auto_delete_401_state.get(target_id)
        if isinstance(existing, dict):
            state.update(existing)
        if state.get("inflight"):
            state.update({
                "last_invalid": invalid_count,
                "last_status": "running",
                "last_message": f"401={invalid_count}，自动清理进行中",
            })
            _cpa_auto_delete_401_state[target_id] = state
            return False
        last_run_ts = float(state.get("last_run_ts") or 0.0)
        if (not force) and last_run_ts > 0 and ((now_ts - last_run_ts) < float(CPA_AUTO_DELETE_401_MIN_INTERVAL_SECONDS or 0.0)):
            wait_left = max(0, int(float(CPA_AUTO_DELETE_401_MIN_INTERVAL_SECONDS or 0.0) - (now_ts - last_run_ts)))
            state.update({
                "last_invalid": invalid_count,
                "last_status": "cooldown",
                "last_message": f"401={invalid_count}，自动清理冷却中 {wait_left}s",
            })
            _cpa_auto_delete_401_state[target_id] = state
            return False
        state.update({
            "inflight": True,
            "last_invalid": invalid_count,
            "last_deleted": 0,
            "last_failed": 0,
            "last_run_ts": now_ts,
            "last_run_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_status": "scheduled",
            "last_message": f"401={invalid_count}，准备自动清理 {len(invalid_names)} 个账号",
            "last_reason": str(reason or "quota_probe"),
            "last_duration_seconds": 0.0,
        })
        _cpa_auto_delete_401_state[target_id] = state

    thread = threading.Thread(
        target=_run_cpa_auto_delete_invalid_401,
        args=(target, list(invalid_names), invalid_count, str(reason or "quota_probe")),
        daemon=True,
        name=f"cpa-auto-del401-{target_id[:8] or 'default'}",
    )
    thread.start()
    return True


def probe_cpa_usage_once(
    target,
    force=False,
    use_cache=True,
    workers=None,
    timeout=None,
    retries=None,
    user_agent=None,
    chatgpt_account_id=None,
    target_type=None,
    provider=None,
):
    target = _normalize_cpa_target(target)
    if not target:
        raise RuntimeError("invalid cpa target")

    target_id = str(target.get("id") or "").strip()
    now_ts = time.time()
    if use_cache and not force and target_id:
        with _cpa_quota_cache_lock:
            cached = _cpa_quota_cache.get(target_id)
            if isinstance(cached, dict) and isinstance(cached.get("data"), dict):
                age = now_ts - float(cached.get("ts") or 0.0)
                if age < float(CPA_QUOTA_CACHE_SECONDS or 0.0):
                    return dict(cached.get("data") or {})

    if aiohttp is None:
        summary = _cpa_build_quota_error_summary(target, "aiohttp not installed")
        _store_cpa_quota_cache(summary)
        return summary

    started_at = time.time()
    try:
        files, candidates, probe_results = _run_async_blocking(
            _cpa_probe_usage_summary_async(
                target.get("base_url"),
                target.get("upload_api_token"),
                target_type or CPA_TARGET_TYPE,
                provider if provider is not None else CPA_PROVIDER,
                workers if workers is not None else CPA_QUOTA_WORKERS,
                timeout if timeout is not None else CPA_QUOTA_TIMEOUT,
                retries if retries is not None else CPA_QUOTA_RETRIES,
                user_agent or CPA_USER_AGENT,
                chatgpt_account_id if chatgpt_account_id is not None else CPA_CHATGPT_ACCOUNT_ID,
            )
        )
        summary = _cpa_build_usage_quota_summary(
            target,
            files,
            candidates,
            probe_results,
            duration_seconds=time.time() - started_at,
        )
        maybe_schedule_cpa_auto_delete_invalid_401(target, probe_results, reason="quota_probe", force=force)
        summary.update(_cpa_auto_delete_401_public_fields(_get_cpa_auto_delete_401_state(target_id)))
    except Exception as e:
        summary = _cpa_build_quota_error_summary(target, e)
        summary["probe_duration_seconds"] = round(max(0.0, time.time() - started_at), 1)

    _store_cpa_quota_cache(summary)
    return dict(summary)


def probe_all_cpa_usage(target_ids=None, force=False, use_cache=True):
    targets = load_cpa_targets()
    if not targets and UPLOAD_API_URL:
        default_target = _default_cpa_target()
        if default_target is not None:
            targets = [default_target]

    if isinstance(target_ids, (str, bytes)):
        target_ids = [target_ids]
    wanted_ids = {str(item or "").strip() for item in list(target_ids or []) if str(item or "").strip()}
    if wanted_ids:
        targets = [target for target in targets if str((target or {}).get("id") or "").strip() in wanted_ids]

    if not targets:
        return {
            "count": 0,
            "items": [],
            "pending_local_count": list_pending_token_pushes(limit=0).get("count", 0),
            "refreshed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    results = {}
    max_workers = max(1, min(int(CPA_QUOTA_TARGET_PARALLELISM or 1), len(targets)))
    if max_workers <= 1:
        for target in targets:
            summary = probe_cpa_usage_once(target, force=force, use_cache=use_cache)
            results[str((target or {}).get("id") or "").strip()] = summary
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(probe_cpa_usage_once, target, force, use_cache): str((target or {}).get("id") or "").strip()
                for target in targets
            }
            for future, target_id in future_map.items():
                try:
                    results[target_id] = future.result()
                except Exception as e:
                    target = _find_cpa_target_by_id(target_id, targets=targets)
                    results[target_id] = _cpa_build_quota_error_summary(target or {}, e)
                    _store_cpa_quota_cache(results[target_id])

    items = [results.get(str((target or {}).get("id") or "").strip()) for target in targets]
    items = [item for item in items if isinstance(item, dict)]
    items = _apply_used_auth_file_marks_to_quota_items(items, targets=targets)
    return {
        "count": len(items),
        "items": items,
        "pending_local_count": list_pending_token_pushes(limit=0).get("count", 0),
        "refreshed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def push_pending_token_json_files_to_target(target, limit=None):
    target = _normalize_cpa_target(target)
    if not target:
        return {"success": 0, "failed": 0, "attempted": 0, "items": [], "error": "无效 CPA 目标"}

    pending_files = _list_pending_token_json_files()
    if limit is not None:
        try:
            limit = max(0, int(limit))
        except Exception:
            limit = None
    attempted = 0
    success = 0
    failed = 0
    stopped_due_to_limit = False
    items = []

    for filename in pending_files:
        if limit is not None and attempted >= limit:
            break
        if not is_token_json_pending_push(filename):
            continue
        if _cpa_target_is_full(target):
            stopped_due_to_limit = True
            break
        ok = _upload_token_json_to_target(filename, target, proxy_url=None)
        attempted += 1
        if ok:
            success += 1
        else:
            failed += 1
        items.append({
            "filename": os.path.basename(filename),
            "email": os.path.basename(filename)[:-5] if filename.endswith('.json') else os.path.basename(filename),
            "success": bool(ok),
        })


    return {
        "target_id": str(target.get("id") or ""),
        "target_label": str(target.get("label") or target.get("base_url") or ""),
        "attempted": attempted,
        "success": success,
        "failed": failed,
        "stopped_due_to_limit": stopped_due_to_limit,
        "items": items,
    }


def topup_cpa_targets_on_demand(target_ids=None, force_probe=True):
    targets = load_cpa_targets()
    if not targets and UPLOAD_API_URL:
        default_target = _default_cpa_target()
        if default_target is not None:
            targets = [default_target]

    if isinstance(target_ids, (str, bytes)):
        target_ids = [target_ids]
    wanted_ids = {str(item or "").strip() for item in list(target_ids or []) if str(item or "").strip()}
    if wanted_ids:
        targets = [target for target in targets if str((target or {}).get("id") or "").strip() in wanted_ids]

    if not targets:
        return {
            "count": 0,
            "success": 0,
            "failed": 0,
            "items": [],
            "error": "未配置可用 CPA 目标",
            "pending_before": list_pending_token_pushes(limit=0).get("count", 0),
            "pending_after": list_pending_token_pushes(limit=0).get("count", 0),
        }

    quota_result = probe_all_cpa_usage(target_ids=[t.get("id") for t in targets], force=bool(force_probe), use_cache=True)
    quota_map = {str((item or {}).get("id") or "").strip(): item for item in quota_result.get("items", []) if isinstance(item, dict)}

    pending_files = _list_pending_token_json_files()
    pending_before = len(pending_files)
    cursor = 0
    overall_success = 0
    overall_failed = 0
    overall_attempted = 0
    results = []
    ordered_targets = []
    for order, target in enumerate(targets, start=1):
        target_id = str((target or {}).get("id") or "").strip()
        summary = quota_map.get(target_id, {})
        ordered_targets.append({
            "target": target,
            "summary": summary,
            "order": order,
        })
    ordered_targets.sort(key=lambda row: _cpa_topup_priority_key({
        "target_id": str(((row or {}).get("target") or {}).get("id") or "").strip(),
        "available": ((row or {}).get("summary") or {}).get("available"),
        "need_topup": ((row or {}).get("summary") or {}).get("need_topup"),
        "plan_topup": ((row or {}).get("summary") or {}).get("plan_topup"),
        "order": (row or {}).get("order"),
    }))

    result_map = {}
    allocation_states = []
    for row in ordered_targets:
        target = row.get("target") or {}
        summary = row.get("summary") or {}
        target_id = str((target or {}).get("id") or "").strip()
        need_topup = summary.get("need_topup")
        plan_topup = summary.get("plan_topup")
        quota_state = str(summary.get("quota_state") or "idle")
        reason = ""
        if quota_state == "error":
            reason = str(summary.get("quota_error") or "额度探测失败")
            plan_topup = 0
        elif not _cpa_target_quota_config(target).get("quota_enabled"):
            reason = "按需补给已关闭"
            plan_topup = 0
        else:
            try:
                plan_topup = max(0, int(plan_topup or 0))
            except Exception:
                plan_topup = 0
            if plan_topup <= 0:
                reason = "当前无缺口"

        target_result = {
            "target_id": target_id,
            "target_label": str((target or {}).get("label") or (target or {}).get("base_url") or ""),
            "available_before": summary.get("available"),
            "need_topup": need_topup,
            "planned": plan_topup,
            "attempted": 0,
            "success": 0,
            "failed": 0,
            "reason": reason,
        }
        result_map[target_id] = target_result
        if plan_topup <= 0:
            continue
        available_before = summary.get("available")
        available_sort = 10 ** 9 if available_before in (None, "") else _normalize_cpa_quota_int(available_before, 10 ** 9)
        allocation_states.append({
            "target": target,
            "target_id": target_id,
            "remaining": max(0, int(plan_topup or 0)),
            "available_sort": available_sort,
            "need_topup": _normalize_cpa_quota_int(need_topup, 0),
            "order": _normalize_cpa_quota_int((row or {}).get("order"), 10 ** 6),
        })

    while cursor < len(pending_files):
        candidates = [item for item in allocation_states if int(item.get("remaining") or 0) > 0]
        if not candidates:
            break
        candidates.sort(
            key=lambda item: (
                _normalize_cpa_quota_int(item.get("available_sort"), 10 ** 9),
                -_normalize_cpa_quota_int(item.get("need_topup"), 0),
                _normalize_cpa_quota_int(item.get("order"), 10 ** 6),
                str(item.get("target_id") or ""),
            )
        )
        state = candidates[0]
        target = state.get("target") or {}
        target_id = str(state.get("target_id") or "").strip()
        target_result = result_map.get(target_id)
        if not isinstance(target_result, dict):
            state["remaining"] = 0
            continue

        filename = pending_files[cursor]
        cursor += 1
        if not is_token_json_pending_push(filename):
            continue
        if _cpa_target_is_full(target):
            target_result["reason"] = "CPA 推送上限已满"
            state["remaining"] = 0
            continue

        ok = _upload_token_json_to_target(filename, target, proxy_url=None)
        target_result["attempted"] += 1
        overall_attempted += 1
        state["remaining"] = max(0, int(state.get("remaining") or 0) - 1)
        if ok:
            target_result["success"] += 1
            overall_success += 1
            if _normalize_cpa_quota_int(state.get("available_sort"), 10 ** 9) < 10 ** 9:
                state["available_sort"] = _normalize_cpa_quota_int(state.get("available_sort"), 10 ** 9) + 1
        else:
            target_result["failed"] += 1
            overall_failed += 1

    for row in ordered_targets:
        target = row.get("target") or {}
        summary = row.get("summary") or {}
        target_id = str((target or {}).get("id") or "").strip()
        plan_topup = max(0, _normalize_cpa_quota_int(summary.get("plan_topup"), 0))
        target_result = result_map.get(target_id)
        if not isinstance(target_result, dict):
            continue
        if target_result["success"] > 0:
            available_before = summary.get("available")
            if isinstance(available_before, int):
                target_result["available_after_estimate"] = available_before + target_result["success"]
        if target_result["attempted"] < plan_topup and not target_result["reason"]:
            target_result["reason"] = "本地未推送凭证不足"
        results.append(target_result)

    pending_after = list_pending_token_pushes(limit=0).get("count", 0)
    return {
        "count": len(results),
        "attempted": overall_attempted,
        "success": overall_success,
        "failed": overall_failed,
        "pending_before": pending_before,
        "pending_after": pending_after,
        "items": results,
        "quota": probe_all_cpa_usage(target_ids=[t.get("id") for t in targets], force=False, use_cache=True).get("items", []),
    }


def _cpa_load_names_from_output(output_file):
    try:
        with open(output_file, "r", encoding="utf-8") as f:
            rows = json.load(f)
    except Exception as e:
        raise RuntimeError(f"读取 output 文件失败: {e}")

    names_to_delete = []
    for r in rows if isinstance(rows, list) else []:
        name = (r or {}).get("name")
        if name:
            names_to_delete.append(name)
    return names_to_delete


async def _cpa_run_delete_async(base_url, token, names_to_delete, delete_workers, timeout, need_confirm=True):
    if not names_to_delete:
        print("没有可删除账号。")
        return

    print(f"待删除账号数: {len(names_to_delete)}")
    if need_confirm:
        confirm = _safe_input(f"即将删除 {len(names_to_delete)} 个账号，输入 DELETE 确认: ")
        if confirm != "DELETE":
            print("已取消删除。")
            return

    connector = aiohttp.TCPConnector(limit=max(1, delete_workers), limit_per_host=max(1, delete_workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    semaphore = asyncio.Semaphore(max(1, delete_workers))

    delete_results = []
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=client_timeout,
        trust_env=(not CPA_MANAGEMENT_NO_PROXY),
    ) as session:
        tasks = [
            asyncio.create_task(
                _cpa_delete_account_async(session, semaphore, base_url, token, name, timeout)
            )
            for name in names_to_delete
        ]

        total = len(tasks)
        done = 0
        next_report = 100
        for task in asyncio.as_completed(tasks):
            delete_results.append(await task)
            done += 1
            if (done >= next_report) or (done == total):
                print(f"删除进度: {done}/{total}")
                next_report += 100

    success = [r for r in delete_results if r.get("deleted")]
    failed = [r for r in delete_results if not r.get("deleted")]
    print(f"删除完成: 成功={len(success)}，失败={len(failed)}")
    if failed:
        for r in failed:
            print(f"[删除失败] {r.get('name')} | {r.get('error')}")


def _cpa_prompt_int(label, default_value, min_value=1):
    raw = _safe_input(f"{label}（默认 {default_value}）: ")
    if not raw:
        return default_value
    try:
        value = int(raw)
        if value < min_value:
            print(f"输入过小，使用最小值 {min_value}")
            return min_value
        return value
    except Exception:
        print("输入无效，使用默认值")
        return default_value


def _cpa_choose_mode():
    print("\n请选择操作:")
    print("1) 仅检查 401 并导出")
    print("2) 检查 401 并立即删除")
    print("3) 直接删除 output 文件中的账号")
    print("0) 退出")
    while True:
        choice = _safe_input("请输入选项编号: ")
        if choice == "1":
            return "check"
        if choice == "2":
            return "check_delete"
        if choice == "3":
            return "delete_from_output"
        if choice == "0":
            return "exit"
        print("无效选项，请重新输入。")


def cpa_clean_codex_accounts():
    """CPA 侧批量检测并清理无效 codex 账号（401）"""
    if aiohttp is None:
        print("❌ 未安装 aiohttp，请先执行: pip install aiohttp")
        return

    base_url = (CPA_BASE_URL or "").strip().rstrip("/")
    token = (CPA_PASSWORD or "").strip()
    target_type = (CPA_TARGET_TYPE or "codex").strip()
    provider = (CPA_PROVIDER or "").strip()
    workers = max(1, int(CPA_WORKERS))
    delete_workers = max(1, int(CPA_DELETE_WORKERS))
    timeout = max(1, int(CPA_TIMEOUT))
    retries = max(0, int(CPA_RETRIES))
    user_agent = (CPA_USER_AGENT or "").strip()
    chatgpt_account_id = (CPA_CHATGPT_ACCOUNT_ID or "").strip()
    output_file = INVALID_CODEX_FILE

    # 允许用户覆盖占位配置
    if not base_url or "你的" in base_url:
        base_url = _safe_input("请输入 CPA Base URL (如 https://example.com): ").strip().rstrip("/")
    if not token or "你的" in token:
        token = _safe_input("请输入 CPA 管理 token(即 cpa_password): ").strip()
    if not user_agent:
        user_agent = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"

    if not base_url or not token:
        print("❌ 缺少 base_url 或 token，无法执行清理。")
        return

    print("\n🧹 CPA Codex 清理")
    print(f"  base_url: {base_url}")
    print(f"  target_type: {target_type}")
    print(f"  provider: {provider or '(全部)'}")
    print(f"  output: {output_file}")

    mode = _cpa_choose_mode()
    if mode == "exit":
        print("已取消")
        return

    workers = _cpa_prompt_int("请输入检测并发 workers", workers)
    delete_workers = _cpa_prompt_int("请输入删除并发 delete-workers", delete_workers)
    timeout = _cpa_prompt_int("请输入请求超时 timeout(秒)", timeout)
    retries = _cpa_prompt_int("请输入失败重试 retries", retries, min_value=0)

    try:
        if mode == "check":
            asyncio.run(
                _cpa_run_probe_async(
                    base_url,
                    token,
                    target_type,
                    provider,
                    workers,
                    timeout,
                    retries,
                    user_agent,
                    chatgpt_account_id,
                    output_file,
                )
            )
            return

        if mode == "check_delete":
            invalid_401 = asyncio.run(
                _cpa_run_probe_async(
                    base_url,
                    token,
                    target_type,
                    provider,
                    workers,
                    timeout,
                    retries,
                    user_agent,
                    chatgpt_account_id,
                    output_file,
                )
            )
            names_to_delete = [r.get("name") for r in invalid_401 if r.get("name")]
            asyncio.run(
                _cpa_run_delete_async(
                    base_url,
                    token,
                    names_to_delete,
                    delete_workers,
                    timeout,
                    need_confirm=True,
                )
            )
            return

        if mode == "delete_from_output":
            names_to_delete = _cpa_load_names_from_output(output_file)
            asyncio.run(
                _cpa_run_delete_async(
                    base_url,
                    token,
                    names_to_delete,
                    delete_workers,
                    timeout,
                    need_confirm=True,
                )
            )
            return
    except Exception as e:
        print(f"❌ CPA 清理执行异常: {e}")


# =================== 交互式菜单 ===================

# ANSI 颜色码
class _C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RED   = "\033[91m"
    GREEN = "\033[92m"
    YELLOW= "\033[93m"
    BLUE  = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN  = "\033[96m"
    WHITE = "\033[97m"
    # 背景
    BG_DARK  = "\033[48;5;235m"
    BG_BLUE  = "\033[48;5;24m"


def _clear_screen():
    """清屏（兼容 Windows/Unix）"""
    os.system("cls" if os.name == "nt" else "clear")


def _safe_input(prompt, default=""):
    """安全输入（捕获 Ctrl+C / EOF）"""
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return default


def _get_stats():
    """获取文件统计信息"""
    acc_count = len(_load_accounts(ACCOUNTS_FILE)) if os.path.exists(ACCOUNTS_FILE) else 0
    ak_count = _load_existing_tokens(AK_FILE)
    token_count = len(_load_token_json_emails())
    pending = max(0, acc_count - token_count)
    return acc_count, ak_count, token_count, pending


def _print_banner():
    """打印主菜单"""
    acc, ak, tok, pending = _get_stats()
    C = _C

    # 标题栏
    print()
    print(f"  {C.CYAN}{C.BOLD}{'=' * 50}{C.RST}")
    print(f"  {C.CYAN}{C.BOLD}       OPENAI  CODEX  PROTOCOL  KEYGEN{C.RST}")
    print(f"  {C.DIM}                   v5.1{C.RST}")
    print(f"  {C.CYAN}{C.BOLD}{'=' * 50}{C.RST}")
    print()

    # 菜单项
    print(f"  {C.WHITE}  {C.GREEN}1{C.DIM} >{C.RST}  {C.WHITE}批量注册{C.RST}        {C.DIM}注册 + OAuth 全自动{C.RST}")
    print(f"  {C.WHITE}  {C.GREEN}2{C.DIM} >{C.RST}  {C.WHITE}OAuth 补登{C.RST}      {C.DIM}已注册账号补获 Token{C.RST}")
    print(f"  {C.WHITE}  {C.GREEN}3{C.DIM} >{C.RST}  {C.WHITE}状态总览{C.RST}        {C.DIM}配置与文件统计{C.RST}")
    print(f"  {C.WHITE}  {C.GREEN}4{C.DIM} >{C.RST}  {C.WHITE}修改参数{C.RST}        {C.DIM}并发 / 代理 / 目标数{C.RST}")
    print(f"  {C.WHITE}  {C.GREEN}5{C.DIM} >{C.RST}  {C.WHITE}CPA 清理{C.RST}        {C.DIM}检测401并批量删除{C.RST}")
    print(f"  {C.WHITE}  {C.RED}0{C.DIM} >{C.RST}  {C.DIM}退出{C.RST}")
    print()

    # 状态条
    print(f"  {C.CYAN}{'─' * 50}{C.RST}")
    status_parts = [
        f"{C.WHITE}{acc}{C.DIM} 账号{C.RST}",
        f"{C.GREEN}{tok}{C.DIM} Token{C.RST}",
        f"{C.BLUE}{ak}{C.DIM} AK{C.RST}",
    ]
    if pending > 0:
        status_parts.append(f"{C.YELLOW}{pending}{C.DIM} 待补登{C.RST}")

    print(f"  {C.DIM}  {C.RST}" + f"  {C.DIM}|{C.RST}  ".join(status_parts))
    print(f"  {C.DIM}  {MAIL_PROVIDER} / {_mail_source_display()} / {_proxy_mode_label()} / 并发 {CONCURRENT_WORKERS} / 目标 {TOTAL_ACCOUNTS}{C.RST}")
    print(f"  {C.CYAN}{'─' * 50}{C.RST}")
    print()


def _show_config():
    """显示详细配置与统计"""
    C = _C
    acc, ak, tok, pending = _get_stats()
    rk_count = _load_existing_tokens(RK_FILE)

    proxy_display = _proxy_display(_effective_proxy())
    mail_proxy_status = (
        f"{C.GREEN}启用{C.RST} node relay / session proxy"
        if MAIL_PROXY_ENABLED else f"{C.DIM}未启用{C.RST}"
    )
    api_key_status = (
        f"{C.GREEN}已配置{C.RST}" if DUCKMAIL_API_KEY else f"{C.DIM}未配置{C.RST}"
    ) if MAIL_PROVIDER == "duckmail" else f"{C.DIM}N/A{C.RST}"
    upload_status = f"{C.GREEN}已配置{C.RST}" if UPLOAD_API_URL and "你的" not in UPLOAD_API_URL else f"{C.DIM}未配置{C.RST}"
    cpa_status = f"{C.GREEN}已配置{C.RST}" if CPA_BASE_URL and "你的" not in CPA_BASE_URL else f"{C.DIM}未配置{C.RST}"

    print()
    print(f"  {C.CYAN}{C.BOLD}  运行配置{C.RST}")
    print(f"  {C.CYAN}{'─' * 44}{C.RST}")
    print(f"  {C.DIM}  注册目标     {C.RST}{C.WHITE}{TOTAL_ACCOUNTS}{C.RST}")
    print(f"  {C.DIM}  并发数       {C.RST}{C.WHITE}{CONCURRENT_WORKERS}{C.RST}")
    print(f"  {C.DIM}  邮件接口     {C.RST}{C.WHITE}{MAIL_PROVIDER}{C.RST}")
    print(f"  {C.DIM}  邮箱源       {C.RST}{C.WHITE}{_mail_source_display()}{C.RST}")
    print(f"  {C.DIM}  代理模式     {C.RST}{C.WHITE}{_proxy_mode_label()}{C.RST}")
    print(f"  {C.DIM}  邮件间隔     {C.RST}{C.WHITE}{CHATGPTMAIL_REQUEST_INTERVAL:.2f}s{C.RST}")
    print(f"  {C.DIM}  邮箱代理     {C.RST}{mail_proxy_status}")
    print(f"  {C.DIM}  API Key      {C.RST}{api_key_status}")
    print(f"  {C.DIM}  代理         {C.RST}{C.WHITE}{proxy_display}{C.RST}")
    print(f"  {C.DIM}  CPA 上传     {C.RST}{upload_status}")
    print(f"  {C.DIM}  CPA 清理     {C.RST}{cpa_status}")
    print(f"  {C.DIM}  输出目录     {C.RST}{C.DIM}{OUTPUT_DIR}{C.RST}")
    print()
    print(f"  {C.CYAN}{C.BOLD}  文件统计{C.RST}")
    print(f"  {C.CYAN}{'─' * 44}{C.RST}")
    print(f"  {C.DIM}  accounts.txt     {C.WHITE}{acc:>6}{C.RST}{C.DIM}  已注册{C.RST}")
    print(f"  {C.DIM}  *.json           {C.GREEN}{tok:>6}{C.RST}{C.DIM}  Token 文件{C.RST}")
    print(f"  {C.DIM}  ak.txt           {C.BLUE}{ak:>6}{C.RST}{C.DIM}  access token{C.RST}")
    print(f"  {C.DIM}  rk.txt           {C.BLUE}{rk_count:>6}{C.RST}{C.DIM}  refresh token{C.RST}")

    if pending > 0:
        print(f"\n  {C.YELLOW}  ! {pending} 个账号缺少 Token (可用选项 2 补登){C.RST}")
    else:
        print(f"\n  {C.GREEN}  * 所有账号均已获取 Token{C.RST}")
    print()


def _modify_params():
    """运行时修改参数（仅本次运行生效）"""
    global TOTAL_ACCOUNTS, CONCURRENT_WORKERS, PROXY
    C = _C

    print()
    print(f"  {C.CYAN}{C.BOLD}  修改参数{C.RST}  {C.DIM}(回车保持当前值){C.RST}")
    print(f"  {C.CYAN}{'─' * 44}{C.RST}")
    print()

    val = _safe_input(f"  {C.DIM}注册目标{C.RST}  [{C.WHITE}{TOTAL_ACCOUNTS}{C.RST}]: ")
    if val.isdigit() and int(val) > 0:
        TOTAL_ACCOUNTS = int(val)
        print(f"  {C.GREEN}  -> {TOTAL_ACCOUNTS}{C.RST}")

    val = _safe_input(f"  {C.DIM}并发数{C.RST}    [{C.WHITE}{CONCURRENT_WORKERS}{C.RST}]: ")
    if val.isdigit() and int(val) > 0:
        CONCURRENT_WORKERS = int(val)
        print(f"  {C.GREEN}  -> {CONCURRENT_WORKERS}{C.RST}")

    val = _safe_input(f"  {C.DIM}代理{C.RST}      [{C.WHITE}{_proxy_display(PROXY)}{C.RST}]: ")
    if val:
        if val.lower() in ("none", "no", "off", "直连", "无"):
            PROXY = ""
            print(f"  {C.GREEN}  -> 直连 (无代理){C.RST}")
        else:
            try:
                candidate = _normalize_proxy_url(val)
                _assert_proxy_supported(candidate)
                PROXY = candidate
                print(f"  {C.GREEN}  -> {PROXY}{C.RST}")
            except Exception as e:
                print(f"  {C.RED}  代理不可用: {e}{C.RST}")

    print()
    if PROXY_MODE == 2:
        print(f"  {C.YELLOW}  模式2：邮箱请求走 node-relay，注册/OAuth/CPA 直连{C.RST}")
    elif PROXY_MODE == 3:
        if CPA_MANAGEMENT_NO_PROXY:
            print(f"  {C.YELLOW}  模式3：邮箱走 node-relay，注册/OAuth 走全局代理，CPA 管理直连{C.RST}")
        else:
            print(f"  {C.YELLOW}  模式3：邮箱请求走 node-relay，注册/OAuth/CPA 走全局代理{C.RST}")
    elif PROXY_MODE == 4:
        if CPA_MANAGEMENT_NO_PROXY and MODE4_MAIL_USE_NODE_RELAY:
            print(f"  {C.YELLOW}  模式4：邮箱走 node-relay，注册/OAuth 走 node-session-proxy，CPA 管理直连{C.RST}")
        elif CPA_MANAGEMENT_NO_PROXY:
            print(f"  {C.YELLOW}  模式4：邮箱/注册/OAuth 走 node-session-proxy，CPA 管理直连{C.RST}")
        elif MODE4_MAIL_USE_NODE_RELAY:
            print(f"  {C.YELLOW}  模式4：邮箱走 node-relay，注册/OAuth 走 node-session-proxy{C.RST}")
        else:
            print(f"  {C.YELLOW}  模式4：邮箱/注册/OAuth/CPA 全部走 node-session-proxy（同账号复用同一 session/node）{C.RST}")
    elif PROXY_MODE == 5:
        if CPA_MANAGEMENT_NO_PROXY:
            print(f"  {C.YELLOW}  模式5：邮箱走 node-relay，注册走 ChatGPT 新链路，注册/OAuth 走 node-session-proxy，CPA 管理直连{C.RST}")
        else:
            print(f"  {C.YELLOW}  模式5：邮箱走 node-relay，注册走 ChatGPT 新链路，注册/OAuth 走 node-session-proxy{C.RST}")
    elif PROXY_MODE == 7:
        if CPA_MANAGEMENT_NO_PROXY:
            print(f"  {C.YELLOW}  模式7：邮箱走 node-relay，注册走 Camoufox OAuth 直链+Cookie，Token 走 node-session-proxy，CPA 管理直连{C.RST}")
        else:
            print(f"  {C.YELLOW}  模式7：邮箱走 node-relay，注册走 Camoufox OAuth 直链+Cookie，Token 走 node-session-proxy{C.RST}")
    else:
        if CPA_MANAGEMENT_NO_PROXY:
            print(f"  {C.YELLOW}  模式1：全局代理/直连，邮箱不走 node-relay，CPA 管理直连{C.RST}")
        else:
            print(f"  {C.YELLOW}  模式1：所有请求使用同一套全局代理/直连，邮箱不走 node-relay{C.RST}")
    print(f"  {C.GREEN}  已生效: 目标={TOTAL_ACCOUNTS}  并发={CONCURRENT_WORKERS}  代理={_proxy_display(_effective_proxy())}{C.RST}")
    print()


def _confirm_and_run_batch():
    """批量注册确认与执行"""
    global TOTAL_ACCOUNTS, CONCURRENT_WORKERS
    C = _C

    print()
    print(f"  {C.CYAN}{C.BOLD}  批量注册{C.RST}")
    print(f"  {C.CYAN}{'─' * 44}{C.RST}")
    print(f"  {C.DIM}  当前: {TOTAL_ACCOUNTS} 个 / 并发 {CONCURRENT_WORKERS} / {MAIL_PROVIDER} / {_mail_source_display()}{C.RST}")
    print()

    val = _safe_input(f"  {C.DIM}数量{C.RST}    [{C.WHITE}{TOTAL_ACCOUNTS}{C.RST}]: ")
    count = int(val) if val.isdigit() and int(val) > 0 else TOTAL_ACCOUNTS

    val = _safe_input(f"  {C.DIM}并发{C.RST}    [{C.WHITE}{CONCURRENT_WORKERS}{C.RST}]: ")
    wk = int(val) if val.isdigit() and int(val) > 0 else CONCURRENT_WORKERS

    print()
    print(f"  {C.YELLOW}  >> 即将注册 {count} 个账号, 并发 {wk}{C.RST}")
    confirm = _safe_input(f"  {C.DIM}确认?{C.RST} [{C.GREEN}Y{C.RST}/n]: ", default="y").lower()

    if confirm != "n":
        old_total, old_workers = TOTAL_ACCOUNTS, CONCURRENT_WORKERS
        TOTAL_ACCOUNTS, CONCURRENT_WORKERS = count, wk
        print()
        run_batch()
        TOTAL_ACCOUNTS, CONCURRENT_WORKERS = old_total, old_workers
    else:
        print(f"  {C.DIM}  已取消{C.RST}")


def _confirm_and_run_oauth():
    """OAuth 补登确认与执行"""
    C = _C

    print()
    print(f"  {C.CYAN}{C.BOLD}  OAuth 补登{C.RST}")
    print(f"  {C.CYAN}{'─' * 44}{C.RST}")
    print()

    val = _safe_input(f"  {C.DIM}并发{C.RST}    [{C.WHITE}{CONCURRENT_WORKERS}{C.RST}]: ")
    wk = int(val) if val.isdigit() and int(val) > 0 else CONCURRENT_WORKERS
    print()
    oauth_retry_batch(workers=wk)


def main_menu():
    """交互式主菜单"""
    C = _C
    _clear_screen()

    while True:
        _print_banner()
        choice = _safe_input(f"  {C.CYAN}>{C.RST} ")

        if choice == "1":
            _confirm_and_run_batch()
            _safe_input(f"\n  {C.DIM}[Enter] 返回主菜单{C.RST}")
            _clear_screen()

        elif choice == "2":
            _confirm_and_run_oauth()
            _safe_input(f"\n  {C.DIM}[Enter] 返回主菜单{C.RST}")
            _clear_screen()

        elif choice == "3":
            _show_config()
            _safe_input(f"\n  {C.DIM}[Enter] 返回主菜单{C.RST}")
            _clear_screen()

        elif choice == "4":
            _modify_params()
            _safe_input(f"\n  {C.DIM}[Enter] 返回主菜单{C.RST}")
            _clear_screen()

        elif choice == "5":
            cpa_clean_codex_accounts()
            _safe_input(f"\n  {C.DIM}[Enter] 返回主菜单{C.RST}")
            _clear_screen()

        elif choice == "0":
            print(f"\n  {C.DIM}再见!{C.RST}\n")
            break

        else:
            print(f"  {C.RED}无效选项, 请输入 0-5{C.RST}")
            time.sleep(0.6)
            _clear_screen()


if __name__ == "__main__":
    # 启用 Windows 终端 ANSI 支持
    if os.name == "nt":
        os.system("")  # 激活 VT100 转义序列

    # 启动日志系统
    _setup_logging()

    # 支持命令行参数直接运行
    if len(sys.argv) > 1 and sys.argv[1] == "--batch":
        run_batch()
    elif len(sys.argv) > 1 and sys.argv[1] == "--oauth":
        oauth_retry_batch()
    elif len(sys.argv) > 1 and sys.argv[1] == "--clean":
        cpa_clean_codex_accounts()
    else:
        main_menu()
