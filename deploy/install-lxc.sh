#!/bin/bash
# Run inside the gateway container as root, from the directory that holds the deploy files.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cd "$(dirname "$0")"
apt-get update -qq
apt-get install -y -qq --no-install-recommends openssh-client ca-certificates nftables openssl xz-utils curl
# the gateway has no inbound SSH: management is via `pct exec` from the PVE host
systemctl disable --now ssh 2>/dev/null || true
apt-get purge -y -qq openssh-server 2>/dev/null || true

id mcpgw >/dev/null 2>&1 || useradd --system --home-dir /var/lib/mcpgw --no-create-home --shell /usr/sbin/nologin mcpgw
install -d -o root -g mcpgw -m 0750 /etc/mcpgw /etc/mcpgw/tls
install -d -o mcpgw -g mcpgw -m 0700 /etc/mcpgw/keys
install -d -o mcpgw -g mcpgw -m 0750 /srv/mcp /srv/mcp/kb /srv/mcp/tmp /var/lib/mcpgw /var/log/mcpgw

install -m 0755 mcpgw /usr/local/bin/mcpgw
[ -f lego.xz ] && xz -dc lego.xz > /usr/local/bin/lego && chmod 0755 /usr/local/bin/lego
install -m 0755 mcpgw-renew-cert /usr/local/sbin/mcpgw-renew-cert
install -m 0644 mcpgw.service mcpgw-renew.service mcpgw-renew.timer /etc/systemd/system/
[ -f /etc/mcpgw/config.json ] || install -m 0640 -o root -g mcpgw config.json /etc/mcpgw/config.json

# seed the knowledge base without overwriting anything that already exists
cp -rn kb/. /srv/mcp/kb/
chown -R mcpgw:mcpgw /srv/mcp

# one key per host and role, generated here and never leaving the container
for h in pve xr nas mikrotik; do
  for r in ro rw; do
    f=/etc/mcpgw/keys/${h}_${r}
    [ -f "$f" ] || ssh-keygen -q -t ed25519 -N "" -C "mcpgw-${h}-${r}" -f "$f"
  done
done
chown -R mcpgw:mcpgw /etc/mcpgw/keys; chmod 600 /etc/mcpgw/keys/*; chmod 644 /etc/mcpgw/keys/*.pub

# temporary self-signed certificate so the service can start before Let's Encrypt is configured
if [ ! -f /etc/mcpgw/tls/fullchain.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=mcp.example.com" \
    -keyout /etc/mcpgw/tls/privkey.pem -out /etc/mcpgw/tls/fullchain.pem 2>/dev/null
  chown root:mcpgw /etc/mcpgw/tls/*; chmod 640 /etc/mcpgw/tls/privkey.pem; chmod 644 /etc/mcpgw/tls/fullchain.pem
fi
touch /etc/mcpgw/known_hosts; chown root:mcpgw /etc/mcpgw/known_hosts; chmod 640 /etc/mcpgw/known_hosts
systemctl daemon-reload
echo "installed. Next: public keys are in /etc/mcpgw/keys/*.pub; run 'mcpgw setup' to create the login; then enable the service and nftables."
