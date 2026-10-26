#!/usr/bin/env bash
# Installs or updates the Cyber Hygiene Grader on AlmaLinux 8, 9 or 10 (Rocky Linux and RHEL work too).
#
#   sudo bash install.sh grader.yourdomain.co.za you@yourdomain.co.za
#
# Before you run it:
#   * Point the domain at this server: an A record for grader.yourdomain.co.za -> this server's public IP.
#   * Copy this whole project folder to the server (e.g. with scp or git) and run the script from inside it.
#
# What it does: installs Python, nginx and certbot; creates a "cybergrader" service account; installs the app
# in /opt/cybergrader with its data in /var/lib/cybergrader; runs it as a systemd service behind nginx;
# opens the firewall; gets a free Let's Encrypt HTTPS certificate; and asks you for the super-admin password.
#
# Run it again at any time (e.g. after copying newer code) to update. Your data and certificate are kept.
set -Eeuo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"
APP_DIR=/opt/cybergrader
DATA_DIR=/var/lib/cybergrader
APP_USER=cybergrader
PORT=8000
NGINX_CONF=/etc/nginx/conf.d/cybergrader.conf
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\n\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "the command on line $LINENO failed: $BASH_COMMAND"' ERR

# --- checks ---------------------------------------------------------------------------------------------

[[ $EUID -eq 0 ]] || die "Run this as root: sudo bash install.sh <domain> <email>"
[[ -f "$SRC_DIR/cybergrader/webapp.py" ]] || die "Run install.sh from the project folder (cybergrader/ wasn't found next to it)."
[[ -r /etc/os-release ]] || die "Can't identify this Linux distribution."
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" rhel "*|*" almalinux "*|*" rocky "*|*" centos "*) ;;
  *) die "This installer is for AlmaLinux, Rocky Linux or RHEL; this server runs ${PRETTY_NAME:-something else}." ;;
esac
MAJOR="${VERSION_ID%%.*}"
[[ $MAJOR =~ ^[0-9]+$ && $MAJOR -ge 8 ]] || die "Version 8 or newer is required (found ${VERSION_ID:-unknown})."

if [[ -z $DOMAIN ]]; then read -rp "Domain for the grader (e.g. grader.yourdomain.co.za): " DOMAIN; fi
DOMAIN="${DOMAIN,,}"; DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"; DOMAIN="${DOMAIN%.}"
[[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$ ]] || die "'$DOMAIN' isn't a valid domain name."
if [[ -z $EMAIL ]]; then read -rp "Email for certificate expiry notices: " EMAIL; fi
[[ $EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "'$EMAIL' isn't a valid email address."

say "Installing on ${PRETTY_NAME} for https://$DOMAIN"

# --- system packages ------------------------------------------------------------------------------------

say "Installing system packages (this can take a few minutes)"
dnf -y -q install dnf-plugins-core curl
if ! rpm -q epel-release &>/dev/null; then
  if [[ ${ID} == rhel ]]; then
    dnf -y -q install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${MAJOR}.noarch.rpm"
  else
    dnf -y -q install epel-release
  fi
fi
# Some EPEL packages (certbot's dependencies) come from CRB, called PowerTools on version 8.
dnf config-manager --set-enabled crb &>/dev/null || dnf config-manager --set-enabled powertools &>/dev/null || true

PYTHON=""
for candidate in python3.12 python3.11; do
  if command -v "$candidate" &>/dev/null || dnf -y -q install "$candidate" "$candidate-pip" &>/dev/null; then
    if command -v "$candidate" &>/dev/null; then PYTHON="$(command -v "$candidate")"; break; fi
  fi
done
if [[ -z $PYTHON ]]; then
  dnf -y -q install python3 python3-pip &>/dev/null || true
  if command -v python3 &>/dev/null && python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
    PYTHON="$(command -v python3)"
  fi
fi
[[ -n $PYTHON ]] || die "Couldn't install Python 3.10 or newer from the AppStream repository."
echo "Using $("$PYTHON" --version) at $PYTHON"

dnf -y -q install nginx certbot python3-certbot-nginx || die "Installing nginx/certbot failed. Check that EPEL is reachable."

# --- application ----------------------------------------------------------------------------------------

say "Installing the application in $APP_DIR"
id -u "$APP_USER" &>/dev/null || useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /sbin/nologin "$APP_USER"
install -d -m 755 "$APP_DIR"
install -d -m 700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
if [[ "$SRC_DIR" != "$APP_DIR" ]]; then
  rm -rf "$APP_DIR/cybergrader.new"
  cp -r "$SRC_DIR/cybergrader" "$APP_DIR/cybergrader.new"
  find "$APP_DIR/cybergrader.new" -name __pycache__ -type d -prune -exec rm -rf {} +
  rm -rf "$APP_DIR/cybergrader"
  mv "$APP_DIR/cybergrader.new" "$APP_DIR/cybergrader"
  cp "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"
  rm -rf "$APP_DIR/tools"
  if [[ -d "$SRC_DIR/tools" ]]; then
    cp -r "$SRC_DIR/tools" "$APP_DIR/tools"  # the on-site agent customers can download
  fi
fi
if [[ ! -x "$APP_DIR/venv/bin/python" ]] || ! "$APP_DIR/venv/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
  rm -rf "$APP_DIR/venv"
  "$PYTHON" -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt" waitress
"$APP_DIR/venv/bin/python" -m compileall -q "$APP_DIR/cybergrader" >/dev/null
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"

cat > /usr/local/bin/cybergrader-manage <<EOF
#!/bin/sh
# Maintenance commands for the grader, e.g.: sudo cybergrader-manage status
cd "$APP_DIR" && exec runuser -u "$APP_USER" -- env GRADER_DATA_DIR="$DATA_DIR" "$APP_DIR/venv/bin/python" -m cybergrader.manage "\$@"
EOF
chmod 755 /usr/local/bin/cybergrader-manage

say "Configuring the site address"
cybergrader-manage configure --site-url "https://$DOMAIN" --trust-proxy

if ! grep -q '"admin_password_hash": "[^"]' "$DATA_DIR/settings.json" 2>/dev/null; then
  say "Choose the super-admin password (you'll sign in at https://$DOMAIN/admin/ with it)"
  if [[ -t 0 ]]; then
    until cybergrader-manage set-admin-password; do echo "Let's try that again."; done
  else
    cybergrader-manage set-admin-password --generate
  fi
fi

# --- services -------------------------------------------------------------------------------------------

say "Setting up the background service"
cat > /etc/systemd/system/cybergrader.service <<EOF
[Unit]
Description=Cyber Hygiene Grader website
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=GRADER_DATA_DIR=$DATA_DIR
Environment=GRADER_ADMIN_REMOTE=1
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_DIR/venv/bin/waitress-serve --host 127.0.0.1 --port $PORT --threads 24 --channel-timeout 180 --call cybergrader.webapp:create_app
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/cybergrader-daily.service <<EOF
[Unit]
Description=Cyber Hygiene Grader daily jobs (plan reminders and database backup)

[Service]
Type=oneshot
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=GRADER_DATA_DIR=$DATA_DIR
ExecStart=$APP_DIR/venv/bin/python -m cybergrader.manage daily
EOF

cat > /etc/systemd/system/cybergrader-daily.timer <<EOF
[Unit]
Description=Run the Cyber Hygiene Grader daily jobs

[Timer]
OnCalendar=*-*-* 07:00:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable -q cybergrader.service cybergrader-daily.timer
systemctl restart cybergrader.service
systemctl start cybergrader-daily.timer

up=""
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then up=yes; break; fi
  sleep 1
done
[[ -n $up ]] || die "The grader didn't start. See what went wrong with: journalctl -u cybergrader -n 50"

# --- nginx, SELinux, firewall ---------------------------------------------------------------------------

say "Configuring nginx"
if [[ -f $NGINX_CONF ]] && grep -q "managed by Certbot" "$NGINX_CONF"; then
  echo "Keeping the existing nginx config (it already has the HTTPS certificate)."
else
  ipv6_listen=""
  [[ -f /proc/net/if_inet6 ]] && ipv6_listen="listen [::]:80;"  # nginx won't start on servers with IPv6 disabled
  cat > "$NGINX_CONF" <<EOF
# Cyber Hygiene Grader (written by install.sh; certbot adds the HTTPS part)
server {
    listen 80;
    $ipv6_listen
    server_name $DOMAIN;
    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_read_timeout 120s;
    }
}
EOF
fi
nginx -t -q || die "nginx rejected its configuration (see above)."
systemctl enable -q nginx
systemctl restart nginx

if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
  setsebool -P httpd_can_network_connect 1  # lets nginx pass requests to the app on port $PORT
fi

if systemctl is-active --quiet firewalld; then
  firewall-cmd -q --permanent --add-service=http --add-service=https
  firewall-cmd -q --reload
else
  warn "firewalld isn't running. Make sure ports 80 and 443 are open in your hosting provider's firewall."
fi

# --- HTTPS certificate ----------------------------------------------------------------------------------

say "Getting the HTTPS certificate"
server_ip="$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
domain_ips="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
try_cert=yes
if [[ -n $server_ip && " $domain_ips " != *" $server_ip "* ]]; then
  warn "$DOMAIN points to [${domain_ips:-nothing}] but this server's public IP is $server_ip."
  try_cert=no
  if [[ -t 0 ]]; then
    read -rp "Try to get the certificate anyway (e.g. the domain is behind Cloudflare)? [y/N] " answer
    [[ ${answer,,} == y* ]] && try_cert=yes
  fi
fi
cert=no
if [[ $try_cert == yes ]]; then
  if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect --keep-until-expiring; then
    cert=yes
  else
    warn "certbot couldn't get a certificate (see above)."
  fi
fi
systemctl enable -q --now certbot-renew.timer 2>/dev/null || true

# --- done -----------------------------------------------------------------------------------------------

trap - ERR
echo
if [[ $cert == yes ]]; then
  printf '\033[1;32mAll done!\033[0m\n'
else
  printf '\033[1;33mInstalled, but without HTTPS yet.\033[0m\n'
  echo "Once $DOMAIN points to ${server_ip:-this server}, run:  sudo certbot --nginx -d $DOMAIN --redirect"
  echo "Sign-in needs HTTPS, so do this before using the site."
fi
cat <<EOF

  Website:      https://$DOMAIN/
  Super admin:  https://$DOMAIN/admin/

Next, sign in to the super admin and work through the go-live checklist on its dashboard:
  1. Settings > Website & scanning: business name and contact details
  2. Settings > Invoices & tax: registered name, address and VAT details
  3. Settings > Payments & pricing: Yoco secret key, then "Register webhook with Yoco"
  4. Settings > Email: your SMTP server, then send a test email
  5. Settings > Legal pages: review the terms and privacy policy

Useful commands:
  sudo cybergrader-manage status            go-live checklist
  sudo systemctl status cybergrader         is the site running?
  sudo journalctl -u cybergrader -f         live log
  sudo bash install.sh $DOMAIN $EMAIL   update after copying newer code

Your data (database, settings, nightly backups) lives in $DATA_DIR. Copy it off the server regularly.
EOF
