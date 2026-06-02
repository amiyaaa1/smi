#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from register_account import load_template_account, rotate_exhausted_project  # noqa: E402


def main():
    raw = os.environ.get('SIMPLAI_ACCOUNT_JSON', '').strip()
    if not raw:
        raise RuntimeError('SIMPLAI_ACCOUNT_JSON is required')
    account = json.loads(raw)
    template = load_template_account()
    result = rotate_exhausted_project(
        template,
        str(account.get('accessToken') or '').strip(),
        str(account.get('userId') or '').strip(),
        str(account.get('tenantId') or '').strip(),
        str(account.get('projectId') or '').strip(),
    )
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
