#!/usr/bin/env python3
import os
from pathlib import Path
from typing import Optional


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _expand(path_value: str) -> Path:
    expanded = os.path.expandvars(str(path_value or '').strip())
    path = Path(expanded).expanduser()
    if not path.is_absolute():
        path = project_root() / path
    return path


def resolve_cloakbrowser_path() -> Path:
    value = os.environ.get('SIMPLAI_CLOAKBROWSER_PATH', '').strip()
    if value:
        return _expand(value)
    return project_root() / 'third_party' / 'CloakBrowser'


def resolve_protocol_keygen_path() -> Path:
    value = os.environ.get('SIMPLAI_PROTOCOL_KEYGEN_PATH', '').strip()
    if value:
        return _expand(value)
    return project_root() / 'third_party' / 'protocol_keygen.py'


def resolve_profile_base_dir() -> Path:
    value = os.environ.get('SIMPLAI_PROFILE_BASE_DIR', '').strip()
    if value:
        return _expand(value)
    return project_root() / 'profiles'


def resolve_profile_dir(profile_dir: Optional[str] = None, default_name: str = 'simplai_profile_reg') -> Path:
    raw = str(profile_dir or '').strip()
    if raw:
        return _expand(raw)
    return resolve_profile_base_dir() / default_name
