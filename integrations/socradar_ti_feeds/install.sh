#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SOCRadar → Wazuh IOC Sync — Installer                             ║
# ╚══════════════════════════════════════════════════════════════════════╝

APP_NAME="socradar-wazuh-sync"
INSTALL_DIR="/opt/${APP_NAME}"
CONFIG_DIR="/etc/${APP_NAME}"
LOG_DIR="/var/log/${APP_NAME}"
STATE_DIR="/var/lib/${APP_NAME}"
SYSTEMD_DIR="/etc/systemd/system"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }
step()  { echo -e "\n${CYAN}═══ $* ═══${NC}"; }

# ── Pre-flight checks ───────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This installer must be run as root."
    echo "  Usage: sudo bash install.sh"
    exit 1
fi

step "SOCRadar → Wazuh IOC Sync Installer"
echo "  Version : 1.0.0"
echo "  Target  : ${INSTALL_DIR}"
echo ""

# Detect script location (works whether run from repo or via curl)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Check Wazuh installation ────────────────────────────────────────
step "Checking prerequisites"

if [[ -d "/var/ossec" ]]; then
    info "Wazuh installation found at /var/ossec"
else
    warn "Wazuh not found at /var/ossec — lists will still be generated"
    warn "but you will need to configure the list_dir path in config.yaml"
fi

# ── Install Python dependencies ─────────────────────────────────────
step "Installing Python dependencies"

if ! command -v python3 &>/dev/null; then
    error "python3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Python ${PYTHON_VERSION} found"

# Install pip if missing
if ! command -v pip3 &>/dev/null; then
    warn "pip3 not found, installing..."
    apt-get update -qq && apt-get install -y -qq python3-pip
fi

pip3 install --quiet --break-system-packages pyyaml requests 2>/dev/null || \
pip3 install --quiet pyyaml requests

info "Python packages installed (pyyaml, requests)"

# ── Create directories ──────────────────────────────────────────────
step "Creating directories"

mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${STATE_DIR}"

info "Created ${INSTALL_DIR}"
info "Created ${CONFIG_DIR}"
info "Created ${LOG_DIR}"
info "Created ${STATE_DIR}"

# ── Copy files ──────────────────────────────────────────────────────
step "Installing application files"

cp "${SCRIPT_DIR}/socradar_wazuh_sync.py" "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/socradar_wazuh_sync.py"
info "Installed sync script → ${INSTALL_DIR}/socradar_wazuh_sync.py"

# Config — only copy if not already present (don't overwrite user config)
if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    cp "${SCRIPT_DIR}/config.yaml.example" "${CONFIG_DIR}/config.yaml"
    chmod 600 "${CONFIG_DIR}/config.yaml"
    info "Installed config template → ${CONFIG_DIR}/config.yaml"
    warn "You MUST edit ${CONFIG_DIR}/config.yaml with your API key and feed UUIDs"
else
    info "Config already exists — skipping (not overwriting)"
fi

# ── Create symlink for CLI access ───────────────────────────────────
ln -sf "${INSTALL_DIR}/socradar_wazuh_sync.py" "/usr/local/bin/${APP_NAME}"
info "Created symlink: /usr/local/bin/${APP_NAME}"

# ── Create systemd service + timer ──────────────────────────────────
step "Setting up systemd service and daily timer"

cat > "${SYSTEMD_DIR}/${APP_NAME}.service" <<EOF
[Unit]
Description=SOCRadar → Wazuh IOC Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/socradar_wazuh_sync.py -c ${CONFIG_DIR}/config.yaml
StandardOutput=journal
StandardError=journal

# Security hardening
ProtectSystem=strict
ReadWritePaths=${LOG_DIR} ${STATE_DIR} /var/ossec/etc/lists
ProtectHome=true
NoNewPrivileges=false
EOF

info "Created ${SYSTEMD_DIR}/${APP_NAME}.service"

cat > "${SYSTEMD_DIR}/${APP_NAME}.timer" <<EOF
[Unit]
Description=Run SOCRadar → Wazuh IOC Sync daily

[Timer]
# Run every day at 03:00 UTC (adjust as needed)
OnCalendar=*-*-* 03:00:00
# Add random delay up to 30 min to avoid API thundering herd
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

info "Created ${SYSTEMD_DIR}/${APP_NAME}.timer"

systemctl daemon-reload
systemctl enable "${APP_NAME}.timer"
info "Timer enabled (daily at 03:00 UTC)"

# ── Wazuh CDB list configuration hint ───────────────────────────────
step "Wazuh Configuration Reminder"

echo ""
echo "  Add the following to your /var/ossec/etc/ossec.conf inside <ruleset>:"
echo ""
echo "    <list>etc/lists/socradar-ip</list>"
echo "    <list>etc/lists/socradar-domain</list>"
echo "    <list>etc/lists/socradar-url</list>"
echo "    <list>etc/lists/socradar-hash</list>"
echo ""
echo "  Then add custom rules to trigger alerts. Example:"
echo ""
echo '    <rule id="100200" level="10">'
echo '      <if_sid>5700</if_sid>'
echo '      <list field="srcip" lookup="address_match_key">'
echo '        etc/lists/socradar-ip'
echo '      </list>'
echo '      <description>Connection from SOCRadar malicious IP: $(srcip)</description>'
echo '      <group>threat_intel,socradar,</group>'
echo '    </rule>'
echo ""

# ── Done ─────────────────────────────────────────────────────────────
step "Installation complete!"

echo ""
echo "  Next steps:"
echo "  ─────────────────────────────────────────────────────────────"
echo "  1. Edit config    : sudo nano ${CONFIG_DIR}/config.yaml"
echo "  2. Test manually  : sudo ${APP_NAME} --dry-run -v"
echo "  3. Run first sync : sudo ${APP_NAME} -v"
echo "  4. Check timer    : systemctl status ${APP_NAME}.timer"
echo "  5. View logs      : tail -f ${LOG_DIR}/${APP_NAME}.log"
echo ""
echo "  Useful commands:"
echo "  ─────────────────────────────────────────────────────────────"
echo "  Force sync now    : sudo ${APP_NAME} --force -v"
echo "  Dry-run           : sudo ${APP_NAME} --dry-run -v"
echo "  Timer status      : systemctl list-timers ${APP_NAME}*"
echo "  Journal logs      : journalctl -u ${APP_NAME}.service"
echo ""
