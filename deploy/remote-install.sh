#!/bin/bash
# Install ConfigMask on the Ubuntu server. Run from the uploaded tree.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${CONFIGMASK_PORT:-5599}"
NEW_ENV=0

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2
  sudo systemctl enable --now docker
fi

if ! sudo docker compose version >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2
fi

if ! command -v python3 >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3
fi

if ! command -v curl >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl
fi

if [ ! -f .env ]; then
  NEW_ENV=1
  umask 077
  ADMIN_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
  SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  FERNET_KEY="$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
  cat > .env <<EOF
CONFIGMASK_ADMIN_PASSWORD=${ADMIN_PASSWORD}
CONFIGMASK_SECRET_KEY=${SECRET_KEY}
CONFIGMASK_FERNET_KEY=${FERNET_KEY}
CONFIGMASK_PORT=${PORT}
CONFIGMASK_COOKIE_SECURE=0
CONFIGMASK_DB_PATH=/data/configmask.db
CONFIGMASK_MAX_UPLOAD_BYTES=10485760
EOF
  chmod 600 .env
else
  # Keep the existing password and Fernet key. Publish the requested host port.
  if grep -q '^CONFIGMASK_PORT=' .env; then
    sed -i "s/^CONFIGMASK_PORT=.*/CONFIGMASK_PORT=${PORT}/" .env
  else
    echo "CONFIGMASK_PORT=${PORT}" >> .env
  fi
fi

if sudo ufw status 2>/dev/null | grep -q 'Status: active'; then
  sudo ufw allow "${PORT}/tcp"
fi

sudo docker compose up -d --build

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null; then
    ready=1
    break
  fi
  sleep 2
done

echo
echo "Installed in ${ROOT}"
echo "Open http://$(hostname -I | awk '{print $1}'):${PORT}"
if [ "$ready" -ne 1 ]; then
  echo "The container is up but /health did not answer yet. Check: sudo docker compose logs --tail 50"
fi
if [ "$NEW_ENV" -eq 1 ]; then
  echo "Admin password: ${ADMIN_PASSWORD}"
  echo "Back up ${ROOT}/.env with the Docker volume. The Fernet key is in that file."
else
  echo "Kept the existing .env. The admin password was not changed."
fi
