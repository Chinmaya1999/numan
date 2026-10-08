#!/usr/bin/env bash
# One-time server bootstrap for Amazon Linux 2023. Run as root: sudo bash setup-server.sh <domain> <email>
set -euo pipefail
DOMAIN="${1:?domain}"; EMAIL="${2:?email}"
APP=/opt/namuna

echo "== packages"
dnf install -y nodejs22 nodejs22-npm nginx certbot python3-certbot-nginx rsync >/dev/null
node -v

echo "== swap (1 GB box: keeps npm/sharp installs from being OOM-killed)"
if ! swapon --show | grep -q swapfile; then
  fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "== app user + layout"
id namuna >/dev/null 2>&1 || useradd --system --home-dir $APP --shell /sbin/nologin namuna
mkdir -p $APP/releases $APP/shared/private/pages $APP/shared/data
chown ec2-user:ec2-user $APP            # deploy user creates the 'current' symlink here
chown -R ec2-user:ec2-user $APP/releases
chown -R namuna:namuna $APP/shared && chmod 750 $APP/shared
[ -f $APP/shared/.env ] || cat > $APP/shared/.env <<ENV
NODE_ENV=production
PORT=3000
DATA_DIR=$APP/shared/data
PRIVATE_DIR=$APP/shared/private
ENV
chown namuna:namuna $APP/shared/.env && chmod 600 $APP/shared/.env

echo "== systemd"
cat > /etc/systemd/system/namuna.service <<'UNIT'
[Unit]
Description=Namuna private viewer
After=network.target

[Service]
User=namuna
WorkingDirectory=/opt/namuna/current
EnvironmentFile=/opt/namuna/shared/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=3
# hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/namuna/shared
MemoryMax=600M

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable namuna >/dev/null

echo "== nginx (http first; certbot adds https)"
cat > /etc/nginx/conf.d/namuna.conf <<NGX
limit_req_zone \$binary_remote_addr zone=namuna:10m rate=20r/s;
server {
    listen 80;
    server_name $DOMAIN;
    server_tokens off;
    client_max_body_size 1m;
    location / {
        limit_req zone=namuna burst=60 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
    }
}
NGX
nginx -t && systemctl enable --now nginx && systemctl reload nginx

echo "== sudo for deploys (restart + status only)"
cat > /etc/sudoers.d/namuna-deploy <<'S'
ec2-user ALL=(root) NOPASSWD: /usr/bin/systemctl restart namuna, /usr/bin/systemctl is-active namuna, /usr/bin/journalctl -u namuna *
S
chmod 440 /etc/sudoers.d/namuna-deploy

echo "== HTTPS certificate"
certbot --nginx -d "$DOMAIN" -m "$EMAIL" --agree-tos --no-eff-email --redirect --non-interactive
systemctl enable --now certbot-renew.timer 2>/dev/null || echo "0 3,15 * * * root certbot renew -q --deploy-hook 'systemctl reload nginx'" > /etc/cron.d/certbot-renew
echo "== done"
