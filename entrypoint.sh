#!/usr/bin/env bash
set -euo pipefail

host="${APP_HOST:-0.0.0.0}"
port="${APP_PORT:-8000}"

args=("app.main:app" "--host" "$host" "--port" "$port")

if [[ -n "${SSL_CERTFILE:-}" && -n "${SSL_KEYFILE:-}" ]]; then
  args+=("--ssl-certfile" "$SSL_CERTFILE" "--ssl-keyfile" "$SSL_KEYFILE")
  if [[ -n "${SSL_CA_CERTS:-}" ]]; then
    args+=("--ssl-ca-certs" "$SSL_CA_CERTS")
  fi
fi

exec uvicorn "${args[@]}"
