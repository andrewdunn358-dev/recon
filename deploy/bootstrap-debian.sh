#!/usr/bin/env bash
#
# Recon — Phase 0 bootstrap.
# Run as root on a fresh Debian 12 box (privileged LXC, or a VM).
# Takes you from bare OS to a running stack in one go.
#
#   curl -fsSL <raw-url>/bootstrap-debian.sh | bash
# or: scp it over and `bash bootstrap-debian.sh`
#
set -euo pipefail

REPO="https://github.com/andrewdunn358-dev/recon.git"

echo "==> [1/5] Installing Docker + git"
apt-get update
apt-get install -y ca-certificates curl git openssl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "==> [2/5] Cloning Recon"
cd /root
[ -d recon ] || git clone "$REPO"
cd recon

echo "==> [3/5] Writing .env (auto-detected host IP, generated secrets)"
IP="$(hostname -I | awk '{print $1}')"
cat > .env <<EOF
DJANGO_SECRET_KEY=$(openssl rand -hex 32)
DJANGO_DEBUG=0
DJANGO_ALLOWED_HOSTS=${IP},localhost
DB_NAME=recon
DB_USER=recon
DB_PASSWORD=$(openssl rand -hex 16)
DB_PORT=5432
EOF

echo "==> [4/5] Publishing the web port (test box — no Traefik yet)"
cat > docker-compose.override.yml <<'EOF'
services:
  web:
    ports:
      - "8000:8000"
EOF

echo "==> [5/5] Building and starting the stack"
docker compose up -d --build

cat <<EOF

================================================================
Recon is up.

  UI:     http://${IP}:8000/
  Admin:  http://${IP}:8000/admin/

Finish setup:
  docker compose exec web python manage.py createsuperuser
  docker compose exec web python manage.py seed_demo
  docker compose exec web python manage.py run_watch_loop   # proves the loop on the box

Reach it over LAN/VPN — don't forward a port inbound (§11).
================================================================
EOF
