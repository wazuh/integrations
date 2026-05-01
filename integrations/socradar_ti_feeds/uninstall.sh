#!/usr/bin/env bash
set -euo pipefail

APP_NAME="socradar-wazuh-sync"
INSTALL_DIR="/opt/${APP_NAME}"
CONFIG_DIR="/etc/${APP_NAME}"
LOG_DIR="/var/log/${APP_NAME}"
STATE_DIR="/var/lib/${APP_NAME}"
SYSTEMD_DIR="/etc/systemd/system"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[✗]${NC} Run as root: sudo bash uninstall.sh"
    exit 1
fi

echo ""
echo "This will remove ${APP_NAME} from this system."
echo ""
read -rp "Remove configuration and logs too? [y/N]: " REMOVE_ALL

# Stop and disable timer
systemctl stop "${APP_NAME}.timer" 2>/dev/null || true
systemctl disable "${APP_NAME}.timer" 2>/dev/null || true
info "Stopped and disabled timer"

# Remove systemd units
rm -f "${SYSTEMD_DIR}/${APP_NAME}.service"
rm -f "${SYSTEMD_DIR}/${APP_NAME}.timer"
systemctl daemon-reload
info "Removed systemd units"

# Remove application
rm -rf "${INSTALL_DIR}"
rm -f "/usr/local/bin/${APP_NAME}"
info "Removed application files"

# Remove CDB list files (but not the directory itself)
for f in socradar-ip socradar-domain socradar-url socradar-hash; do
    rm -f "/var/ossec/etc/lists/${f}" 2>/dev/null || true
done
info "Removed CDB list files"

if [[ "${REMOVE_ALL,,}" == "y" ]]; then
    rm -rf "${CONFIG_DIR}"
    rm -rf "${LOG_DIR}"
    rm -rf "${STATE_DIR}"
    info "Removed config, logs, and state"
else
    warn "Kept config (${CONFIG_DIR}), logs (${LOG_DIR}), state (${STATE_DIR})"
fi

echo ""
info "Uninstall complete."
echo ""
echo "  Don't forget to remove <list> entries from /var/ossec/etc/ossec.conf"
echo "  and any custom rules referencing socradar lists."
echo ""
