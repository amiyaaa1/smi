#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${SIMPLAI_PACKAGE_TARGET_DIR:-${ROOT}/dist}"
STAMP="$(date +%Y%m%d_%H%M%S)"
INCLUDE_PROFILES=1
DISTRIBUTION=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --distribution|--dist|distribution|dist)
      DISTRIBUTION=1
      INCLUDE_PROFILES=0
      ;;
    --without-profiles|lite|--lite)
      INCLUDE_PROFILES=0
      ;;
    --with-profiles)
      INCLUDE_PROFILES=1
      ;;
    *)
      echo "Usage: $0 [--distribution|--dist] [--without-profiles|--lite|--with-profiles]" >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "${SIMPLAI_INCLUDE_PROFILES:-}" == "0" ]]; then
  INCLUDE_PROFILES=0
fi

if [[ "$DISTRIBUTION" == "1" ]]; then
  INCLUDE_PROFILES=0
  PKG_NAME="simplai2api-distribution-${STAMP}"
elif [[ "$INCLUDE_PROFILES" == "1" ]]; then
  PKG_NAME="simplai2api-deploy-${STAMP}"
else
  PKG_NAME="simplai2api-lite-noprofiles-${STAMP}"
fi

STAGE_BASE="$(mktemp -d /tmp/simplai2api-pack.XXXXXX)"
STAGE_DIR="${STAGE_BASE}/${PKG_NAME}"
ZIP_PATH="${TARGET_DIR}/${PKG_NAME}.zip"

mkdir -p "$TARGET_DIR" "$STAGE_DIR"

python3 - "$ROOT" "$STAGE_DIR" "$INCLUDE_PROFILES" "$DISTRIBUTION" <<'PY'
import json
import shutil
import sys
from pathlib import Path

root = Path(sys.argv[1])
stage = Path(sys.argv[2])
include_profiles = sys.argv[3] == '1'
distribution = sys.argv[4] == '1'

ignore_names = {
    '.agents',
    '.codex',
    '.git',
    'node_modules',
    'dist',
    '__pycache__',
}
ignore_suffixes = ('.pyc', '.pyo', '.zip')
ignore_dirs_by_name = {'logs', 'profiles', 'cloakbrowser-cache'}


def should_skip(path: Path) -> bool:
    name = path.name
    if name in ignore_names:
        return True
    if name.endswith(ignore_suffixes):
        return True
    parts = set(path.parts)
    if '__pycache__' in parts:
        return True
    return False

for source in root.iterdir():
    if should_skip(source):
        continue
    dest = stage / source.name
    if source.is_dir():
        if source.name in ignore_dirs_by_name:
            dest.mkdir(parents=True, exist_ok=True)
            continue
        shutil.copytree(
            source,
            dest,
            ignore=shutil.ignore_patterns('node_modules', '.git', '__pycache__', '*.pyc', '*.pyo', '*.zip'),
            dirs_exist_ok=True,
        )
    else:
        shutil.copy2(source, dest)

for name in ('profiles', 'logs', 'cloakbrowser-cache', 'dist'):
    target = stage / name
    target.mkdir(parents=True, exist_ok=True)

for keep in ('profiles/.gitkeep', 'logs/.gitkeep', 'cloakbrowser-cache/.gitkeep'):
    (stage / keep).touch()

accounts_path = stage / 'data' / 'accounts.json'
if distribution:
    dist_compose = root / 'docker-compose.dist.yml'
    if not dist_compose.exists():
        raise SystemExit('docker-compose.dist.yml not found')
    shutil.copy2(dist_compose, stage / 'docker-compose.yml')

    data_dir = stage / 'data'
    source_accounts_path = data_dir / 'accounts.json'
    if not source_accounts_path.exists():
        raise SystemExit('accounts.json not found in stage package')
    with source_accounts_path.open('r', encoding='utf-8') as f:
        source_data = json.load(f)
    source_items = source_data.get('items') if isinstance(source_data, dict) else []
    if not isinstance(source_items, list):
        source_items = []
    template_id = source_data.get('activeAccountId') if isinstance(source_data, dict) else None
    template = next((item for item in source_items if item.get('id') == template_id), None)
    if template is None and source_items:
        template = source_items[0]
        template_id = template.get('id')
    if not template or not template_id:
        raise SystemExit('template account not found in accounts.json')
    source_settings = source_data.get('settings') if isinstance(source_data, dict) else {}

    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    accounts_path = data_dir / 'accounts.json'
    data = {
        'activeAccountId': template_id,
        'settings': source_settings if isinstance(source_settings, dict) else {},
        'lastReconcileAt': None,
        'lastReconcileSummary': None,
        'items': [template],
    }
elif not accounts_path.exists():
    raise SystemExit('accounts.json not found in stage package')
else:
    with accounts_path.open('r', encoding='utf-8') as f:
        data = json.load(f)

items = data.get('items') if isinstance(data, dict) else None
if not isinstance(items, list):
    items = []
    data['items'] = items

copied = []
for item in items:
    profile_dir = str((item or {}).get('browserProfileDir') or '').strip()
    if distribution or not include_profiles:
        item['browserProfileDir'] = ''
        continue
    if not profile_dir:
        continue
    src = Path(profile_dir)
    if not src.exists() or not src.is_dir():
        continue
    dest_name = src.name
    dest = stage / 'profiles' / dest_name
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    item['browserProfileDir'] = f'profiles/{dest_name}'
    copied.append(dest_name)

with accounts_path.open('w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

profile_mode = 'included' if include_profiles else 'excluded'
if distribution:
    package_type = 'distribution'
    extra_note = (
        'WARP default: disabled. No external warp-net dependency is included.\n'
        'Accounts included: current template account only; non-template relay accounts are excluded.\n'
        'Browser profiles removed: token refresh via profile is unavailable until you relogin.\n'
    )
else:
    package_type = 'private deploy'
    extra_note = '' if include_profiles else 'Browser profiles removed: token refresh via profile is unavailable until you relogin.\n'
(stage / 'PACKAGE_INFO.txt').write_text(
    'Deploy command: bash install.sh\n'
    'Admin URL: http://SERVER_IP:8031/\n'
    'Admin password: Nishibaka114514.\n'
    f'Package type: {package_type}\n'
    f'Profiles mode: {profile_mode}\n'
    f'Profiles copied: {len(copied)}\n'
    + extra_note,
    encoding='utf-8'
)

for cache_dir in stage.rglob('__pycache__'):
    if cache_dir.is_dir():
        shutil.rmtree(cache_dir, ignore_errors=True)
for file in stage.rglob('*'):
    if file.is_file() and file.suffix in {'.pyc', '.pyo'}:
        file.unlink(missing_ok=True)
PY

(cd "$STAGE_BASE" && zip -qr "$ZIP_PATH" "$PKG_NAME")

echo "$ZIP_PATH"
