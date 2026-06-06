#!/usr/bin/env sh
set -eu

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

export APP_HOST="${APP_HOST:-127.0.0.1}"
export APP_PORT="${APP_PORT:-5000}"
export DATABASE_URL="${DATABASE_URL:-sqlite:///proxy_manager.db}"

python main.py
