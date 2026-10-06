#!/bin/sh
set -eu

mkdir -p /data
chown configmask:configmask /data

port="${CONFIGMASK_PORT:-8741}"

if command -v setpriv >/dev/null 2>&1; then
  exec setpriv --reuid=configmask --regid=configmask --init-groups -- \
    python -m uvicorn app.main:app --host 0.0.0.0 --port "$port"
fi

exec python -m uvicorn app.main:app --host 0.0.0.0 --port "$port"
