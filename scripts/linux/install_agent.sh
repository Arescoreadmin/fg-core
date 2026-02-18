#!/usr/bin/env bash
set -euo pipefail

id -u frostgate-agent >/dev/null 2>&1 || useradd --system --home /var/lib/frostgate-agent --shell /usr/sbin/nologin frostgate-agent
install -d -m 750 -o root -g root /etc/frostgate/agent
install -d -m 750 -o frostgate-agent -g frostgate-agent /var/lib/frostgate-agent

if [[ -f dist/frostgate-agent ]]; then
  install -m 755 dist/frostgate-agent /usr/local/bin/frostgate-agent
else
  cat >/usr/local/bin/frostgate-agent <<'EOF'
#!/usr/bin/env bash
exec python3 -m agent.main
EOF
  chmod 755 /usr/local/bin/frostgate-agent
fi

install -m 644 deploy/systemd/frostgate-agent.service /etc/systemd/system/frostgate-agent.service
systemctl daemon-reload
systemctl enable --now frostgate-agent.service
