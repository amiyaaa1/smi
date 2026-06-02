#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p data profiles logs cloakbrowser-cache

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  echo "docker compose 未安装，请先安装 Docker / Docker Compose" >&2
  exit 1
fi

"${COMPOSE_CMD[@]}" up -d --build --remove-orphans
"${COMPOSE_CMD[@]}" ps

echo
echo "SimplAI2API 已启动"
echo "管理页面: http://服务器IP:8031/"
echo "登录密码: Nishibaka114514."
