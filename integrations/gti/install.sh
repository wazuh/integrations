#!/bin/bash
# ============================================================================
# GTI Native Integration for Wazuh — One-Click Installer
# ============================================================================
# Usage:
#   sudo ./install.sh
#
# Requirements:
#   - Wazuh Manager 4.x installed
#   - Python 3.6+
#   - GTI API Key
#
# The installer will:
#   1. Copy integration files to correct Wazuh directories
#   2. Set proper permissions (root:wazuh ownership)
#   3. Prompt for GTI API credentials
#   4. Inject wodle + integration blocks into ossec.conf
#   5. Restart Wazuh Manager
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║               GTI Native Integration for Wazuh               ║"
echo "║                     Installer v1.0.0                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# --- Pre-flight checks ---

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root (sudo ./install.sh)${NC}"
    exit 1
fi

if [ ! -d "$WAZUH_HOME" ]; then
    echo -e "${RED}ERROR: Wazuh not found at $WAZUH_HOME${NC}"
    echo "Set WAZUH_HOME if installed elsewhere."
    exit 1
fi

if ! command -v python3 &>/dev/null && [ ! -x "$WAZUH_HOME/framework/python/bin/python3" ]; then
    echo -e "${RED}ERROR: Python 3 not found${NC}"
    exit 1
fi

WAZUH_GROUP="wazuh"
if ! getent group wazuh &>/dev/null; then
    WAZUH_GROUP="ossec"
fi

echo -e "${GREEN}✓ Wazuh found at $WAZUH_HOME${NC}"
echo -e "${GREEN}✓ Python 3 available${NC}"
echo ""

# --- Prompt for API credentials ---

echo -e "${YELLOW}GTI API Configuration${NC}"
echo "─────────────────────────────────────"

read -sp "GTI API Key: " API_KEY
echo ""
if [ -z "$API_KEY" ]; then
    echo -e "${RED}ERROR: API Key is required${NC}"
    exit 1
fi

read -p "Fetch interval in minutes (default: 60): " INTERVAL
INTERVAL="${INTERVAL:60}"

if ! [[ "${INTERVAL}" =~ ^[0-9]+$ ]]; then
  echo -e "${YELLOW}  ⚠ Invalid interval '${INTERVAL}', using 60 minute${NC}"
  INTERVAL=60
fi

echo ""
echo -e "${BLUE}Installing integration files...${NC}"

# --- Step 1: Copy wodle files ---

mkdir -p "$WAZUH_HOME/wodles/gti"

# Copy config from example if not exists, otherwise update API key
ESCAPED_API_KEY=$(printf '%s' "$API_KEY" | sed -e 's/[\\/&|]/\\\\&/g')
if [ ! -f "$WAZUH_HOME/wodles/gti/gti-config.ini" ]; then
    cp "$SCRIPT_DIR/wodles/gti-config.ini.example" "$WAZUH_HOME/wodles/gti/gti-config.ini"
    sed -i "s/YOUR_API_KEY_HERE/${ESCAPED_API_KEY}/" "$WAZUH_HOME/wodles/gti/gti-config.ini"
else
    echo -e "${YELLOW}  ⚠ Config file exists, updating API key only${NC}"
    sed -i "s|^[[:space:]]*api_key[[:space:]]*=.*$|api_key = ${ESCAPED_API_KEY}|"  "$WAZUH_HOME/wodles/gti/gti-config.ini"
fi

cp "$SCRIPT_DIR/wodles/gti-sync.py" "$WAZUH_HOME/wodles/gti/gti-sync.py"
chmod 750 "$WAZUH_HOME/wodles/gti/gti-config.ini"
chmod 750 "$WAZUH_HOME/wodles/gti/gti-sync.py"
chown root:$WAZUH_GROUP "$WAZUH_HOME/wodles/gti/gti-config.ini"
chown root:$WAZUH_GROUP "$WAZUH_HOME/wodles/gti/gti-sync.py"
sed -i 's/\r$//' "$WAZUH_HOME/wodles/gti/gti-sync.py" "$WAZUH_HOME/wodles/gti/gti-config.ini"
echo -e "${GREEN}  ✓ Wodle files installed${NC}"

# --- Step 2: Copy integration files ---

cp "$SCRIPT_DIR/integration/custom-gti" "$WAZUH_HOME/integrations/custom-gti"
cp "$SCRIPT_DIR/integration/custom-gti.py" "$WAZUH_HOME/integrations/custom-gti.py"
chmod 750 "$WAZUH_HOME/integrations/custom-gti"
chmod 750 "$WAZUH_HOME/integrations/custom-gti.py"
chown root:$WAZUH_GROUP "$WAZUH_HOME/integrations/custom-gti"
chown root:$WAZUH_GROUP "$WAZUH_HOME/integrations/custom-gti.py"
sed -i 's/\r$//' "$WAZUH_HOME/integrations/custom-gti" "$WAZUH_HOME/integrations/custom-gti.py"
echo -e "${GREEN}  ✓ Integration files installed${NC}"

# --- Step 3: Copy decoder and rules ---

cp "$SCRIPT_DIR/ruleset/rules/1001-gti_rules.xml" "$WAZUH_HOME/etc/rules/"
chown root:$WAZUH_GROUP "$WAZUH_HOME/etc/rules/1001-gti_rules.xml"
echo -e "${GREEN}  ✓ Rules installed${NC}"

# --- Step 4: Create JSON file ---

mkdir -p "$WAZUH_HOME/integrations/gti_iocs"
touch "$WAZUH_HOME/integrations/gti_iocs/malicious_ips.json"
touch "$WAZUH_HOME/integrations/gti_iocs/malicious_urls.json"
touch "$WAZUH_HOME/integrations/gti_iocs/malicious_domains.json"
touch "$WAZUH_HOME/integrations/gti_iocs/malicious_filehashes.json"
echo "{}" > "$WAZUH_HOME/integrations/gti_iocs/malicious_ips.json"
echo "{}" > "$WAZUH_HOME/integrations/gti_iocs/malicious_urls.json"
echo "{}" > "$WAZUH_HOME/integrations/gti_iocs/malicious_domains.json"
echo "{}" > "$WAZUH_HOME/integrations/gti_iocs/malicious_filehashes.json"
chown root:$WAZUH_GROUP "$WAZUH_HOME/integrations/gti_iocs/malicious_ips.json" "$WAZUH_HOME/integrations/gti_iocs/malicious_urls.json" "$WAZUH_HOME/integrations/gti_iocs/malicious_domains.json" "$WAZUH_HOME/integrations/gti_iocs/malicious_filehashes.json"
echo -e "${GREEN}  ✓ JSON files created${NC}"

# --- Step 5: Inject ossec.conf blocks ---

if grep -q -e "<name>custom-gti</name>" -e "<tag>gti-sync</tag>" "$WAZUH_HOME/etc/ossec.conf"; then
    echo -e "${YELLOW}  ⚠ GTI blocks already exist in ossec.conf — skipping injection${NC}"
else
    cp "$WAZUH_HOME/etc/ossec.conf" "$WAZUH_HOME/etc/ossec.conf.bak.$(date +%s)"

    sed -i "/<\/ossec_config>/i\\
\\
  <!-- GTI Native Integration -->\\
  <wodle name=\"command\">\\
    <disabled>no</disabled>\\
    <tag>gti-sync</tag>\\
    <command>/var/ossec/framework/python/bin/python3.10 ${WAZUH_HOME}/wodles/gti/gti-sync.py</command>\\
    <interval>${INTERVAL}m</interval>\\
    <ignore_output>no</ignore_output>\\
    <run_on_start>yes</run_on_start>\\
    <timeout>300</timeout>\\
  </wodle>\\
\\
  <integration>\\
    <name>custom-gti</name>\\
    <api_key>${API_KEY}</api_key>\\
    <alert_format>json</alert_format>\\
    <options>{\"mitre_attack\": true, \"realtime\": false, \"log_level\": \"INFO\", \"ip_fields\": \"\", \"domain_fields\": \"\", \"url_fields\": \"\", \"filehash_fields\": \"\", \"vuln_fields\": \"\"}</options>\\
  </integration>" "$WAZUH_HOME/etc/ossec.conf"

    echo -e "${GREEN}  ✓ ossec.conf updated${NC}"
fi


# --- Step 6: Install Python dependencies (optional and non-blocking) ---
 
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo -e "${BLUE}Installing Python dependencies...${NC}"
    if "$WAZUH_HOME/framework/python/bin/python3.10" -m pip install -r "$SCRIPT_DIR/requirements.txt" 2>&1; then
        echo -e "${GREEN}  ✓ Python packages installed${NC}"
    else
        echo -e "${YELLOW}  ⚠ Failed to install Python packages (non-critical)${NC}"
        echo -e "${YELLOW}  → You may need to install dependencies manually later${NC}"
    fi
else
    echo -e "${YELLOW}  ⚠ requirements.txt not found — skipping package installation${NC}"
fi || true
 
echo ""

# --- Step 7: Restart Wazuh ---

echo ""
echo -e "${BLUE}Restarting Wazuh Manager...${NC}"
systemctl restart wazuh-manager

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Installation completed successfully!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
