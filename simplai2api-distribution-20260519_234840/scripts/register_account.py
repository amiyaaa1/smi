#!/usr/bin/env python3
import contextlib
import copy
import html
import importlib.util
import json
import os
import random
import re
import string
import sys
import time
import uuid
from pathlib import Path

import requests
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from browser_runtime import ManagedBrowserRuntime
from runtime_paths import resolve_cloakbrowser_path, resolve_profile_base_dir, resolve_protocol_keygen_path

CLOAKBROWSER_PATH = str(resolve_cloakbrowser_path())
PROTOCOL_KEYGEN_PATH = str(resolve_protocol_keygen_path())
PROFILE_BASE_DIR = resolve_profile_base_dir()
REGISTER_URL = 'https://app.simplai.ai/register?utm_source=WEBSITE&utm_campaign=HEADER_LOGIN'
SESSION_URL = 'https://app.simplai.ai/api/auth/session'
PROJECT_LIST_URL = 'https://edge-service.simplai.ai/identity-service/api/v1/project/list'
PROJECT_CREATE_URL = 'https://edge-service.simplai.ai/identity-service/api/v1/project'
PROJECT_DETAIL_URL_TEMPLATE = 'https://edge-service.simplai.ai/identity-service/api/v1/project/{project_id}'
WALLET_URL = 'https://edge-service.simplai.ai/wallet/api/v1/wallet'
CONVERSATION_URL = 'https://edge-service.simplai.ai/interact/api/v1/intract/conversation'
POLL_URL_TEMPLATE = 'https://edge-service.simplai.ai/interact/api/v1/intract/conversation/{conversation_id}'
AGENT_LIST_URL = 'https://edge-service.simplai.ai/agent/agents/'
PREFERRED_PROJECT_RUNS_LIMIT = 200
CLAUDE_OPUS_MODEL_DETAIL = {
    'model_id': '69ca48f263f91b0d4d34f078',
    'model_name': 'anthropic/claude-opus-4-6',
    'model_version': None,
    'model_parameters': None,
    'model_attributes_type': None,
    'model_distributor': None,
    'model_type': 'LLM',
    'model_provider': None,
    'rtm_model_id': None,
    'rtm_model_name': None,
    'rtm_model_version': None,
    'rtm_model_parameters': None,
    'rtm_model_attributes_type': None,
    'rtm_model_distributor': None,
    'rtm_model_provider': None,
}
KNOWN_RELAY_ERROR_PATTERNS = [
    re.compile(r'agent not found', re.I),
    re.compile(r'project run limit exhausted', re.I),
    re.compile(r'invalid session id', re.I),
    re.compile(r'access denied', re.I),
    re.compile(r'unauthorized', re.I),
]
LINK_PATTERNS = [
    re.compile(r'https://urls\.simplai\.ai/[^\s"\'<>]+'),
    re.compile(r'https://app\.simplai\.ai/register/active-account[^\s"\'<>]+'),
]


def log(message):
    print(message, file=sys.stderr, flush=True)


def now_iso():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def load_template_account():
    raw = os.environ.get('SIMPLAI_TEMPLATE_ACCOUNT_JSON', '').strip()
    if not raw:
        raise RuntimeError('SIMPLAI_TEMPLATE_ACCOUNT_JSON is required')
    data = json.loads(raw)
    if not data.get('agentName') or not data.get('agentPipelineId'):
        raise RuntimeError('template account is missing agentName or agentPipelineId')
    return {
        'label': str(data.get('label') or '').strip() or 'SimplAI Auto Template',
        'accessToken': str(data.get('accessToken') or '').strip(),
        'userId': str(data.get('userId') or '').strip(),
        'tenantId': str(data.get('tenantId') or '').strip(),
        'projectId': str(data.get('projectId') or '').strip(),
        'agentName': str(data.get('agentName') or '').strip(),
        'agentPipelineId': str(data.get('agentPipelineId') or '').strip(),
        'versionId': str(data.get('versionId') or 'latest').strip() or 'latest',
    }


def load_protocol_module():
    if not Path(PROTOCOL_KEYGEN_PATH).is_file():
        raise RuntimeError(f'Protocol helper not found: {PROTOCOL_KEYGEN_PATH}')
    spec = importlib.util.spec_from_file_location('protocol_keygen', PROTOCOL_KEYGEN_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Unable to load protocol module from {PROTOCOL_KEYGEN_PATH}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_password():
    digits = ''.join(random.choice(string.digits) for _ in range(5))
    return f'Zx{digits}Aa@'


@contextlib.contextmanager
def helper_stdout_to_stderr():
    with contextlib.redirect_stdout(sys.stderr):
        yield


def create_temp_mailbox(protocol_module):
    session = requests.Session()
    with helper_stdout_to_stderr():
        email, email_id, mail_token = protocol_module.create_temp_email(session)
    if not email:
        raise RuntimeError('failed to create temp mailbox')
    return session, str(email).strip(), email_id, mail_token


def extract_links(text):
    data = html.unescape(str(text or ''))
    found = []
    for pattern in LINK_PATTERNS:
        found.extend(pattern.findall(data))
    return [link.replace('&amp;', '&') for link in found]


def wait_for_verification_link(protocol_module, session, email, mail_token, timeout_seconds=240):
    log(f'[register] waiting for verification email: {email}')
    deadline = time.time() + timeout_seconds
    seen_ids = set()
    while time.time() < deadline:
        with helper_stdout_to_stderr():
            messages = protocol_module.fetch_emails(
                session,
                email,
                mail_token,
                skip_ids=None,
                include_body=True,
                max_messages=20,
            ) or []
        for message in messages:
            msg_id = str(message.get('id') or '')
            source = str(message.get('source') or '')
            subject = str(message.get('subject') or '')
            raw = str(message.get('raw') or '')
            haystack = '\n'.join([source, subject, raw])
            if msg_id and msg_id in seen_ids:
                continue
            links = extract_links(haystack)
            for link in links:
                if 'simplai.ai' in link:
                    if msg_id:
                        seen_ids.add(msg_id)
                    log(f'[register] verification link found: {link}')
                    return link
            if msg_id:
                seen_ids.add(msg_id)
        time.sleep(5)
    raise RuntimeError('timed out waiting for SimplAI verification email')


def profile_dir_for_email(email):
    safe_name = re.sub(r'[^a-zA-Z0-9]+', '_', email.split('@', 1)[0]).strip('_') or 'simplai'
    PROFILE_BASE_DIR.mkdir(parents=True, exist_ok=True)
    return str(PROFILE_BASE_DIR / f'simplai_profile_auto_{safe_name}_{int(time.time())}_{random.randint(1000, 9999)}')


def remove_profile_locks(profile_dir):
    for name in ('SingletonLock', 'SingletonCookie', 'SingletonSocket'):
        path = os.path.join(profile_dir, name)
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def launch_browser(profile_dir):
    if not Path(CLOAKBROWSER_PATH).exists():
        raise RuntimeError(f'CloakBrowser path does not exist: {CLOAKBROWSER_PATH}')
    if CLOAKBROWSER_PATH not in sys.path:
        sys.path.insert(0, CLOAKBROWSER_PATH)
    from cloakbrowser import launch_persistent_context  # type: ignore

    remove_profile_locks(profile_dir)
    return launch_persistent_context(profile_dir, headless=True)


def wait_and_fill(locator, value, delay=25):
    locator.click()
    locator.press_sequentially(value, delay=delay)


def robust_goto(page, url, label, *, timeout_ms=90000):
    log(f'[register] opening {label}')
    last_error = None
    for attempt, wait_until in enumerate(('domcontentloaded', 'load'), start=1):
        try:
            page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            return
        except PlaywrightTimeoutError as error:
            last_error = error
            log(f'[register] {label} navigation attempt {attempt} timed out with wait_until={wait_until}; continuing check')
            if page.url and page.url != 'about:blank':
                return
    raise last_error


def submit_registration_email(page, email):
    robust_goto(page, REGISTER_URL, 'register page')
    page.wait_for_timeout(1500)
    wait_and_fill(page.locator('#SignIn_email'), email)
    page.wait_for_timeout(500)
    page.get_by_role('button', name='Get Started For Free', exact=True).click()
    page.wait_for_timeout(2500)


def complete_account_activation(page, email, password, verification_link):
    full_name = 'Ewfwefwef'
    org_name = 'Ewfwefwef Org'

    robust_goto(page, verification_link, 'verification link')
    page.wait_for_timeout(1500)
    wait_and_fill(page.locator('#SignUp_user_full_name'), full_name)
    wait_and_fill(page.locator('#SignUp_org_name'), org_name)
    wait_and_fill(page.locator('#SignUp_password'), password)
    wait_and_fill(page.locator('#SignUp_confirm_password'), password)
    page.wait_for_timeout(1000)
    page.get_by_role('button', name='Create account', exact=True).click()
    page.wait_for_timeout(8000)

    try:
        skip = page.get_by_text('Skip & Launch SimplAI', exact=True)
        if skip.count() > 0:
            log('[register] clicking Skip & Launch SimplAI')
            skip.click()
            page.wait_for_timeout(8000)
    except Exception:
        pass


def fetch_session_from_browser(page):
    log('[register] fetching session JSON')
    robust_goto(page, SESSION_URL, 'session endpoint', timeout_ms=60000)
    page.wait_for_timeout(1200)
    raw = page.locator('body').inner_text()
    data = json.loads(raw)
    access_token = str(data.get('accessToken') or '').strip()
    user = data.get('user', {}) if isinstance(data, dict) else {}
    details = user.get('details', {}) if isinstance(user, dict) else {}
    user_id = str(details.get('id') or '').strip()
    tenant_id = str(details.get('tenantId') or '').strip()
    email = str(details.get('email') or '').strip()
    if not access_token or not user_id or not tenant_id:
        raise RuntimeError(f'invalid session payload: {raw[:500]}')
    return {
        'accessToken': access_token,
        'userId': user_id,
        'tenantId': tenant_id,
        'email': email,
    }


def simplai_headers(access_token, user_id, tenant_id, project_id=''):
    return {
        'accept': 'application/json, text/plain, */*',
        'content-type': 'application/json',
        'referer': 'https://app.simplai.ai/',
        'x-device-id': 'simplai',
        'pim-sid': access_token,
        'x-user-id': user_id,
        'x-seller-profile-id': user_id,
        'x-seller-id': user_id,
        'x-client-id': user_id,
        'x-tenant-id': tenant_id,
        'x-project-id': project_id,
    }


def fetch_project_id(access_token, user_id, tenant_id):
    response = requests.get(
        PROJECT_LIST_URL,
        headers=simplai_headers(access_token, user_id, tenant_id, ''),
        timeout=30,
    )
    if response.status_code != 200:
        raise RuntimeError(f'project list failed: {response.status_code} {response.text[:500]}')
    data = response.json()
    results = data.get('result') if isinstance(data, dict) else None
    if not isinstance(results, list) or not results:
        raise RuntimeError(f'project list empty: {response.text[:500]}')
    project_id = results[0].get('project_id')
    if not project_id:
        raise RuntimeError(f'project_id missing: {response.text[:500]}')
    return str(project_id)


def fetch_projects(access_token, user_id, tenant_id):
    response = requests.get(
        PROJECT_LIST_URL,
        headers=simplai_headers(access_token, user_id, tenant_id, ''),
        timeout=30,
    )
    if response.status_code != 200:
        raise RuntimeError(f'project list failed: {response.status_code} {response.text[:500]}')
    data = response.json()
    results = data.get('result') if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise RuntimeError(f'project list malformed: {response.text[:500]}')
    return results


def fetch_project_detail(access_token, user_id, tenant_id, project_id):
    response = requests.get(
        PROJECT_DETAIL_URL_TEMPLATE.format(project_id=project_id),
        headers=simplai_headers(access_token, user_id, tenant_id, project_id),
        timeout=30,
    )
    if response.status_code != 200:
        raise RuntimeError(f'project detail failed: {response.status_code} {response.text[:500]}')
    data = response.json()
    result = data.get('result') if isinstance(data, dict) else None
    project = result.get('project') if isinstance(result, dict) else None
    if not isinstance(project, dict):
        raise RuntimeError(f'project detail malformed: {response.text[:500]}')
    return project


def project_runs_limit(project):
    config = project.get('config') if isinstance(project, dict) else None
    value = (config or {}).get('runs_limit')
    try:
        return int(value)
    except Exception:
        return 0


def create_project(access_token, user_id, tenant_id, seed_project_id=''):
    response = requests.post(
        PROJECT_CREATE_URL,
        headers=simplai_headers(access_token, user_id, tenant_id, seed_project_id),
        json={},
        timeout=30,
    )
    if response.ok:
        data = response.json()
        result = data.get('result') if isinstance(data, dict) else None
        if not isinstance(result, dict) or not result.get('id'):
            raise RuntimeError(f'project create malformed: {response.text[:500]}')
        return result
    text = response.text[:500]
    if response.status_code == 403 and 'maximum limit of 2 projects' in response.text:
        return None
    raise RuntimeError(f'project create failed: {response.status_code} {text}')


def project_id_of(project):
    return str(
        (project or {}).get('id')
        or (project or {}).get('project_id')
        or ''
    ).strip()


def ensure_preferred_project(access_token, user_id, tenant_id):
    projects = fetch_projects(access_token, user_id, tenant_id)
    if not projects:
        raise RuntimeError('no project available after signup')

    detailed_projects = []
    for item in projects:
        project_id = str(item.get('project_id') or item.get('id') or '').strip()
        if not project_id:
            continue
        detail = fetch_project_detail(access_token, user_id, tenant_id, project_id)
        detailed_projects.append(detail)

    detailed_projects.sort(key=project_runs_limit, reverse=True)
    if detailed_projects and project_runs_limit(detailed_projects[0]) >= PREFERRED_PROJECT_RUNS_LIMIT:
        chosen = detailed_projects[0]
        log(f'[register] using existing preferred project {chosen.get("id")} runs_limit={project_runs_limit(chosen)}')
        return str(chosen.get('id'))

    seed_project_id = str(detailed_projects[0].get('id') or '').strip() if detailed_projects else ''
    created = create_project(access_token, user_id, tenant_id, seed_project_id=seed_project_id)
    if created and created.get('id'):
        created_detail = fetch_project_detail(access_token, user_id, tenant_id, str(created['id']))
        log(
            f'[register] created preferred project {created_detail.get("id")} '
            f'runs_limit={project_runs_limit(created_detail)}'
        )
        return str(created_detail.get('id'))

    if detailed_projects:
        chosen = detailed_projects[0]
        log(
            f'[register] fallback to best existing project {chosen.get("id")} '
            f'runs_limit={project_runs_limit(chosen)}'
        )
        return str(chosen.get('id'))

    raise RuntimeError('unable to select project for relay')


def delete_agents_in_project(access_token, user_id, tenant_id, project_id):
    headers = simplai_headers(access_token, user_id, tenant_id, project_id)
    deleted = []
    for agent in fetch_agents(access_token, user_id, tenant_id, project_id):
        agent_id = str(agent.get('id') or '').strip()
        if not agent_id:
            continue
        response = requests.delete(f'{AGENT_LIST_URL}{agent_id}', headers=headers, timeout=60)
        if not response.ok:
            raise RuntimeError(f'agent delete failed: {response.status_code} {response.text[:500]}')
        deleted.append(agent_id)
    return deleted


def project_still_exists(access_token, user_id, tenant_id, project_id):
    projects = fetch_projects(access_token, user_id, tenant_id)
    target = str(project_id).strip()
    return any(project_id_of(item) == target for item in projects)


def delete_project_best_effort(access_token, user_id, tenant_id, project_id):
    target = str(project_id).strip()
    if not target:
        raise RuntimeError('project_id is required for deletion')

    candidates = [
        ('DELETE', PROJECT_DETAIL_URL_TEMPLATE.format(project_id=target), None),
        ('DELETE', f'{PROJECT_CREATE_URL}?project_id={target}', None),
        ('DELETE', f'{PROJECT_CREATE_URL}?id={target}', None),
        ('DELETE', PROJECT_CREATE_URL, {'project_id': target}),
        ('DELETE', f'{PROJECT_CREATE_URL}/', {'project_id': target}),
    ]
    errors = []
    for header_project_id in (target, '', None):
        headers = simplai_headers(access_token, user_id, tenant_id, header_project_id or '')
        for method, url, body in candidates:
            response = requests.request(method, url, headers=headers, json=body, timeout=30)
            if not project_still_exists(access_token, user_id, tenant_id, target):
                return {
                    'ok': True,
                    'status_code': response.status_code,
                    'url': url,
                }
            errors.append(f'{method} {url} => {response.status_code} {response.text[:180]}')
    raise RuntimeError('project delete failed; attempts: ' + ' | '.join(errors[:8]))


def fetch_wallet(access_token, user_id, tenant_id, project_id):
    response = requests.get(
        WALLET_URL,
        headers=simplai_headers(access_token, user_id, tenant_id, project_id),
        timeout=30,
    )
    if response.status_code != 200:
        raise RuntimeError(f'wallet fetch failed: {response.status_code} {response.text[:500]}')
    data = response.json()
    if not data.get('ok'):
        raise RuntimeError(f'wallet fetch returned not ok: {response.text[:500]}')
    result = data.get('result') or {}
    return {
        'wallet_balance': result.get('wallet_balance'),
        'usable_balance': result.get('usable_balance'),
    }

def safe_json_loads(value):
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def flatten_texts(value, bucket=None):
    if bucket is None:
        bucket = []
    if value is None:
        return bucket
    if isinstance(value, str):
        text = value.strip()
        if text:
            bucket.append(text)
        parsed = safe_json_loads(text)
        if parsed is not None and parsed != value:
            flatten_texts(parsed, bucket)
        return bucket
    if isinstance(value, list):
        for item in value:
            flatten_texts(item, bucket)
        return bucket
    if isinstance(value, dict):
        for key in ('message', 'content', 'result', 'detail'):
            text = value.get(key)
            if isinstance(text, str) and text.strip():
                bucket.append(text.strip())
        if value.get('error') is not None:
            flatten_texts(value.get('error'), bucket)
        if value.get('data') is not None:
            flatten_texts(value.get('data'), bucket)
    return bucket


def extract_known_relay_error(value):
    for text in flatten_texts(value):
        for pattern in KNOWN_RELAY_ERROR_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0)
    return None


def fetch_agents(access_token, user_id, tenant_id, project_id):
    response = requests.get(
        AGENT_LIST_URL,
        headers=simplai_headers(access_token, user_id, tenant_id, project_id),
        timeout=60,
    )
    if response.status_code != 200:
        raise RuntimeError(f'agent list failed: {response.status_code} {response.text[:500]}')
    data = response.json()
    agents = data.get('agents') if isinstance(data, dict) else None
    if not isinstance(agents, list):
        raise RuntimeError(f'agent list malformed: {response.text[:500]}')
    return agents


def fetch_template_agent_blueprint(template):
    if not all([
        template.get('accessToken'),
        template.get('userId'),
        template.get('tenantId'),
        template.get('projectId'),
    ]):
        return None
    try:
        agents = fetch_agents(
            template['accessToken'],
            template['userId'],
            template['tenantId'],
            template['projectId'],
        )
    except Exception as exc:
        log(f'[register] template blueprint fetch skipped: {exc}')
        return None
    for agent in agents:
        if str(agent.get('pipeline_id') or '').strip() == template.get('agentPipelineId'):
            return agent
    for agent in agents:
        if str(agent.get('agent_name') or '').strip() == template.get('agentName'):
            return agent
    return agents[0] if agents else None


def create_agent(access_token, user_id, tenant_id, project_id, agent_name):
    response = requests.post(
        AGENT_LIST_URL,
        headers=simplai_headers(access_token, user_id, tenant_id, project_id),
        json={
            'agent_name': agent_name or 'Untitled',
            'agent_description': 'Placeholder description',
            'agent_state': 'CREATED',
        },
        timeout=60,
    )
    if not response.ok:
        raise RuntimeError(f'agent create failed: {response.status_code} {response.text[:500]}')
    return response.json()


def build_clean_agent_config(existing_config, blueprint):
    if isinstance(blueprint, dict) and isinstance(blueprint.get('config'), dict):
        return copy.deepcopy(blueprint['config'])

    config = copy.deepcopy(existing_config or {})
    config['context_window_config'] = config.get('context_window_config') or 1
    config['context_window_config_details'] = None

    voice_agent = copy.deepcopy(config.get('voice_agent_config') or {})
    voice_agent['tts_key'] = ''
    voice_agent['stt_key'] = ''
    voice_agent['tts_access_key'] = ''
    voice_agent['tts_secret_key'] = ''
    voice_agent['tts_region'] = ''
    voice_agent['stt_access_key'] = ''
    voice_agent['stt_secret_key'] = ''
    voice_agent['stt_region'] = ''
    config['voice_agent_config'] = voice_agent

    voice_config = copy.deepcopy(config.get('voice_config') or {})
    voice_config['enabled'] = False
    voice_config['is_avatar_enabled'] = False
    config['voice_config'] = voice_config

    follow_up = copy.deepcopy(config.get('follow_up_config') or {})
    follow_up['enabled'] = False
    config['follow_up_config'] = follow_up

    config['browser_use_config'] = {'enabled': False}
    config['code_execution_config'] = {'enabled': False}
    config['file_upload_config'] = {'enabled': False}

    reflection = copy.deepcopy(config.get('reflection_config') or {})
    reflection['enabled'] = False
    reflection['max_reflection_runs'] = None
    reflection['use_custom_reflection_prompt'] = False
    config['reflection_config'] = reflection

    memory = copy.deepcopy(config.get('memory_config') or {})
    memory['enabled'] = False
    memory['includes'] = None
    memory['excludes'] = None
    memory['last_cleared_at'] = None
    memory['model_id'] = CLAUDE_OPUS_MODEL_DETAIL['model_id']
    memory['agent_memory'] = {
        'enabled': False,
        'default_agent_memory_prompt': '',
        'custom_agent_memory_prompt': '',
    }
    memory['user_memory'] = {
        'enabled': False,
        'default_user_memory_prompt': '',
        'custom_user_memory_prompt': '',
    }
    config['memory_config'] = memory

    tool_config = copy.deepcopy(config.get('tool_config') or {})
    tool_config['max_tool_runs'] = tool_config.get('max_tool_runs') or 20
    config['tool_config'] = tool_config
    config['artifact_config'] = {'enabled': False}
    config['skills_config'] = {'enabled': False, 'skills': []}
    return config


def build_clean_agent_payload(agent, template_blueprint, template):
    payload = copy.deepcopy(agent)
    payload['agent_name'] = (
        str((template_blueprint or {}).get('agent_name') or '').strip()
        or template.get('agentName')
        or str(agent.get('agent_name') or '').strip()
        or 'SimplAI Relay Agent'
    )
    payload['agent_description'] = ''
    payload['model_detail'] = copy.deepcopy(
        (template_blueprint or {}).get('model_detail') or CLAUDE_OPUS_MODEL_DETAIL
    )
    payload['base_instructions'] = ''
    payload['welcome_message'] = {'message': ''}
    payload['kb'] = []
    payload['tools'] = []
    payload['tool_choice'] = 'auto'
    payload['sub_agent_ids'] = []
    payload['sub_agents'] = []
    payload['deployed'] = False
    payload['published'] = False
    payload['is_agent_published'] = False
    payload['last_published_time'] = None
    payload['start_messages'] = []
    payload['enable_request_demo_in_playground'] = False
    payload['guardrail_config'] = None
    payload['agent_type'] = None
    payload['citations'] = {'enabled': False}
    payload['tool_citations'] = {'enabled': False}
    payload['config'] = build_clean_agent_config(agent.get('config'), template_blueprint)
    payload['orchestration_type'] = 'none'
    payload['orchestration_config'] = {}
    payload['is_hidden_in_interact_screen'] = False
    payload['is_shown_on_home_page'] = True
    return payload


def configure_account_agent(template, access_token, user_id, tenant_id, project_id):
    template_blueprint = fetch_template_agent_blueprint(template)
    agents = fetch_agents(access_token, user_id, tenant_id, project_id)
    if agents:
        agent = agents[0]
    else:
        log('[register] no draft agent found, creating one')
        agent = create_agent(access_token, user_id, tenant_id, project_id, template.get('agentName') or 'Untitled')

    payload = build_clean_agent_payload(agent, template_blueprint, template)
    headers = simplai_headers(access_token, user_id, tenant_id, project_id)
    update = requests.put(
        f'{AGENT_LIST_URL}{agent["id"]}',
        headers=headers,
        json=payload,
        timeout=60,
    )
    if not update.ok:
        raise RuntimeError(f'agent update failed: {update.status_code} {update.text[:500]}')

    version = requests.post(
        f'{AGENT_LIST_URL}{agent["id"]}/version',
        headers=headers,
        json={'source_version_id': 'latest'},
        timeout=60,
    )
    if not version.ok:
        raise RuntimeError(f'agent version failed: {version.status_code} {version.text[:500]}')
    version_data = version.json()
    version_id = str(version_data.get('version_id') or 'latest').strip() or 'latest'

    publish = requests.put(
        f'{AGENT_LIST_URL}{agent["id"]}/publish',
        headers=headers,
        json={'version_id': version_id},
        timeout=60,
    )
    if not publish.ok:
        raise RuntimeError(f'agent publish failed: {publish.status_code} {publish.text[:500]}')
    publish_data = publish.json()
    return {
        'agentId': str(agent.get('id') or '').strip(),
        'agentName': str(publish_data.get('agent_name') or payload.get('agent_name') or '').strip(),
        'agentPipelineId': str(publish_data.get('pipeline_id') or agent.get('pipeline_id') or '').strip(),
        'versionId': version_id,
    }


def rotate_exhausted_project(template, access_token, user_id, tenant_id, current_project_id):
    current_project_id = str(current_project_id or '').strip()
    projects = fetch_projects(access_token, user_id, tenant_id)
    detailed_projects = []
    for item in projects:
        pid = project_id_of(item)
        if not pid:
            continue
        detailed_projects.append(fetch_project_detail(access_token, user_id, tenant_id, pid))

    preferred_candidates = [
        project for project in detailed_projects
        if project_id_of(project) != current_project_id
        and project_runs_limit(project) >= PREFERRED_PROJECT_RUNS_LIMIT
    ]
    preferred_candidates.sort(key=project_runs_limit, reverse=True)
    if preferred_candidates:
        chosen = preferred_candidates[0]
        chosen_project_id = project_id_of(chosen)
        relay_agent = configure_account_agent(template, access_token, user_id, tenant_id, chosen_project_id)
        relay_test(relay_agent, access_token, user_id, tenant_id, chosen_project_id)
        return {
            'projectId': chosen_project_id,
            'projectRunsLimit': project_runs_limit(chosen),
            'agentName': relay_agent['agentName'],
            'agentPipelineId': relay_agent['agentPipelineId'],
            'versionId': relay_agent.get('versionId') or 'latest',
            'recycledProjectId': None,
            'deletedAgentIds': [],
        }

    if len(detailed_projects) < 2:
        new_project_id = ensure_preferred_project(access_token, user_id, tenant_id)
        new_detail = fetch_project_detail(access_token, user_id, tenant_id, new_project_id)
        relay_agent = configure_account_agent(template, access_token, user_id, tenant_id, new_project_id)
        relay_test(relay_agent, access_token, user_id, tenant_id, new_project_id)
        return {
            'projectId': new_project_id,
            'projectRunsLimit': project_runs_limit(new_detail),
            'agentName': relay_agent['agentName'],
            'agentPipelineId': relay_agent['agentPipelineId'],
            'versionId': relay_agent.get('versionId') or 'latest',
            'recycledProjectId': None,
            'deletedAgentIds': [],
        }

    victims = sorted(
        detailed_projects,
        key=lambda project: (
            0 if project_id_of(project) != current_project_id else 1,
            project_runs_limit(project),
            int(project.get('agent_count') or 0),
            str(project.get('created_at') or ''),
        ),
    )
    victim = victims[0]
    victim_project_id = project_id_of(victim)
    log(
        f'[register] recycling project {victim_project_id} '
        f'runs_limit={project_runs_limit(victim)} current={current_project_id}'
    )
    deleted_agent_ids = delete_agents_in_project(access_token, user_id, tenant_id, victim_project_id)
    delete_project_best_effort(access_token, user_id, tenant_id, victim_project_id)

    new_project_id = ensure_preferred_project(access_token, user_id, tenant_id)
    new_detail = fetch_project_detail(access_token, user_id, tenant_id, new_project_id)
    relay_agent = configure_account_agent(template, access_token, user_id, tenant_id, new_project_id)
    relay_test(relay_agent, access_token, user_id, tenant_id, new_project_id)
    return {
        'projectId': new_project_id,
        'projectRunsLimit': project_runs_limit(new_detail),
        'agentName': relay_agent['agentName'],
        'agentPipelineId': relay_agent['agentPipelineId'],
        'versionId': relay_agent.get('versionId') or 'latest',
        'recycledProjectId': victim_project_id,
        'deletedAgentIds': deleted_agent_ids,
    }


def relay_test(relay_agent, access_token, user_id, tenant_id, project_id):
    payload = {
        'model': relay_agent['agentName'],
        'language_code': 'EN',
        'source': 'APP',
        'app_id': relay_agent['agentPipelineId'],
        'model_id': relay_agent['agentPipelineId'],
        'version_id': relay_agent.get('versionId') or 'latest',
        'state_override': {
            'sys': {
                'user_timezone': os.environ.get('TZ', 'Asia/Shanghai'),
                'language_code': 'en-US',
            }
        },
        'action': 'START_SCREEN',
        'query': {
            'message': 'Reply with OK only.',
            'message_type': 'text',
            'message_category': '',
        },
    }
    headers = simplai_headers(access_token, user_id, tenant_id, project_id)
    response = requests.post(CONVERSATION_URL, headers=headers, json=payload, timeout=60)
    if response.status_code != 200:
        raise RuntimeError(f'relay test start failed: {response.status_code} {response.text[:500]}')
    data = response.json()
    start_error = extract_known_relay_error(data)
    if start_error:
        raise RuntimeError(f'relay test upstream error: {start_error}')
    result = data.get('result') or {}
    conversation_id = result.get('conversation_id')
    if not conversation_id:
        raise RuntimeError(f'relay test missing conversation_id: {response.text[:500]}')

    deadline = time.time() + 90
    last_text = ''
    while time.time() < deadline:
        poll = requests.get(
            POLL_URL_TEMPLATE.format(conversation_id=conversation_id),
            headers=headers,
            timeout=60,
        )
        if poll.status_code != 200:
            raise RuntimeError(f'relay test poll failed: {poll.status_code} {poll.text[:500]}')
        poll_data = poll.json()
        messages = (poll_data.get('result') or {}).get('response') or []
        if messages:
            last = messages[-1]
            relay_error = extract_known_relay_error(last.get('tool_calls') or last)
            if relay_error:
                raise RuntimeError(f'relay test upstream error: {relay_error}')
            last_text = str(last.get('query_result') or '')
            if last.get('message_status') == 2:
                if not last_text.strip():
                    raise RuntimeError('relay test completed with empty response')
                return last_text
        time.sleep(1.5)
    raise RuntimeError(f'relay test timed out; last text: {last_text[:200]}')


def main():
    template = load_template_account()
    protocol_module = load_protocol_module()
    password = valid_password()
    mailbox_session, email, _email_id, mail_token = create_temp_mailbox(protocol_module)
    profile_dir = profile_dir_for_email(email)
    Path(profile_dir).mkdir(parents=True, exist_ok=True)

    runtime = ManagedBrowserRuntime(profile_dir, logger=log)
    try:
        ctx = launch_browser(profile_dir)
        runtime.set_context(ctx)
        page = ctx.new_page()
        page.set_default_timeout(120000)
        page.set_default_navigation_timeout(120000)
        submit_registration_email(page, email)
        verification_link = wait_for_verification_link(protocol_module, mailbox_session, email, mail_token)
        complete_account_activation(page, email, password, verification_link)
        session_data = fetch_session_from_browser(page)
    finally:
        runtime.cleanup()

    access_token = session_data['accessToken']
    user_id = session_data['userId']
    tenant_id = session_data['tenantId']
    session_email = session_data['email'] or email
    project_id = ensure_preferred_project(access_token, user_id, tenant_id)
    wallet = fetch_wallet(access_token, user_id, tenant_id, project_id)
    relay_agent = configure_account_agent(template, access_token, user_id, tenant_id, project_id)
    relay_output = relay_test(relay_agent, access_token, user_id, tenant_id, project_id)

    now = now_iso()
    result = {
        'id': f'acct-{uuid.uuid4().hex}',
        'label': f'Auto {session_email}',
        'email': session_email,
        'password': password,
        'accessToken': access_token,
        'userId': user_id,
        'tenantId': tenant_id,
        'projectId': project_id,
        'agentName': relay_agent['agentName'],
        'agentPipelineId': relay_agent['agentPipelineId'],
        'versionId': relay_agent.get('versionId') or 'latest',
        'browserProfileDir': profile_dir,
        'enabled': True,
        'notes': 'Auto registered by SimplAI replenish helper',
        'createdAt': now,
        'updatedAt': now,
        'lastKnownWalletBalance': wallet.get('wallet_balance'),
        'lastKnownUsableBalance': wallet.get('usable_balance'),
        'lastBalanceAt': now,
        'autoRegistered': True,
        'agentRelayVerifiedAt': now,
        'relayTestPreview': str(relay_output or '')[:120],
    }
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        log(f'[register] fatal: {exc}')
        raise
