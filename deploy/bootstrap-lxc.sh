#!/usr/bin/env bash
#
# Recon — Phase 0 NATIVE bootstrap (no Docker).
# Run as root on a fresh Debian 12 LXC. Unprivileged is fine — nothing here
# needs nesting, overlayfs, sysctl writes or AppArmor changes.
#
#   bash bootstrap-lxc.sh
#
set -euo pipefail

REPO="https://github.com/andrewdunn358-dev/recon.git"
APP_DIR=/opt/recon
NUCLEI_VERSION=3.3.0

echo "==> [1/8] System packages"
apt-get update
apt-get install -y python3 python3-venv python3-dev build-essential libpq-dev \
                   postgresql redis-server git curl openssl unzip
systemctl enable --now postgresql redis-server

echo "==> [2/8] Service user + clone"
id recon &>/dev/null || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin recon
[ -d "$APP_DIR" ] || git clone "$REPO" "$APP_DIR"
chown -R recon:recon "$APP_DIR"

echo "==> [3/8] Python venv + dependencies"
cd "$APP_DIR/control-plane"
su recon -s /bin/bash -c "python3 -m venv .venv && .venv/bin/pip install -q -U pip && .venv/bin/pip install -q -r requirements.txt"

echo "==> [4/8] Postgres database + user"
DB_PASS="$(openssl rand -hex 16)"
su - postgres -c "psql -v ON_ERROR_STOP=0" <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='recon') THEN
    CREATE ROLE recon LOGIN PASSWORD '${DB_PASS}';
  ELSE
    ALTER ROLE recon PASSWORD '${DB_PASS}';
  END IF;
END \$\$;
SELECT 'CREATE DATABASE recon OWNER recon'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='recon')\gexec
SQL

echo "==> [5/8] .env (auto-detected IP, generated secrets)"
IP="$(hostname -I | awk '{print $1}')"
cat > "$APP_DIR/control-plane/.env" <<EOF
DJANGO_SECRET_KEY=$(openssl rand -hex 32)
DJANGO_DEBUG=0
DJANGO_ALLOWED_HOSTS=${IP},localhost
DB_HOST=127.0.0.1
DB_NAME=recon
DB_USER=recon
DB_PASSWORD=${DB_PASS}
DB_PORT=5432
CELERY_BROKER_URL=redis://127.0.0.1:6379/0
CELERY_RESULT_BACKEND=redis://127.0.0.1:6379/1
EOF
chown recon:recon "$APP_DIR/control-plane/.env"
chmod 600 "$APP_DIR/control-plane/.env"

echo "==> [6/8] Nuclei binary"
curl -sSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei && rm /tmp/nuclei.zip

echo "==> [7/8] Migrate + collect static"
su recon -s /bin/bash -c ".venv/bin/python manage.py migrate --noinput"
su recon -s /bin/bash -c ".venv/bin/python manage.py collectstatic --noinput"

echo "==> [8/8] systemd services"
cp "$APP_DIR/deploy/systemd/"*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now recon-web recon-worker recon-beat

cat <<EOF

================================================================
Recon is up — running natively, no Docker.

  UI:     http://${IP}:8000/
  Admin:  http://${IP}:8000/admin/

Create your login + prove the loop:
  cd /opt/recon/control-plane
  su recon -s /bin/bash -c ".venv/bin/python manage.py createsuperuser"
  su recon -s /bin/bash -c ".venv/bin/python manage.py seed_demo"
  su recon -s /bin/bash -c ".venv/bin/python manage.py run_watch_loop"

Service control:  systemctl status recon-web recon-worker recon-beat
Reach it over LAN/VPN — don't forward a port inbound (§11).
================================================================
EOF
