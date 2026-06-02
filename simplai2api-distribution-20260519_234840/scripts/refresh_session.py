#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from browser_runtime import ManagedBrowserRuntime
from runtime_paths import resolve_cloakbrowser_path, resolve_profile_dir

profile_dir = str(resolve_profile_dir(sys.argv[1] if len(sys.argv) > 1 else None))
cloak_path = str(resolve_cloakbrowser_path())

if not Path(cloak_path).exists():
    raise RuntimeError(f'CloakBrowser path does not exist: {cloak_path}')
if cloak_path not in sys.path:
    sys.path.insert(0, cloak_path)

runtime = ManagedBrowserRuntime(profile_dir)
runtime.remove_profile_locks()

from cloakbrowser import launch_persistent_context  # type: ignore

ctx = launch_persistent_context(profile_dir, headless=True)
runtime.set_context(ctx)
try:
    page = ctx.new_page()
    page.set_default_timeout(90000)
    page.goto('https://app.simplai.ai/api/auth/session', wait_until='networkidle')
    text = page.locator('body').inner_text()
    data = json.loads(text)
    print(json.dumps({
        'accessToken': data.get('accessToken'),
        'refreshToken': data.get('refreshToken'),
        'expiresAt': data.get('expiresAt'),
        'userId': str(data.get('user', {}).get('details', {}).get('id', '')),
        'tenantId': str(data.get('user', {}).get('details', {}).get('tenantId', '')),
        'email': data.get('user', {}).get('details', {}).get('email', ''),
        'name': data.get('user', {}).get('details', {}).get('name', '')
    }, ensure_ascii=False))
finally:
    runtime.cleanup()
