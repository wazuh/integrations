#!/bin/bash
# ============================================================================
# SOCRadar Native Integration for Wazuh — One-Click Installer
# ============================================================================
# Usage:
#   sudo ./install.sh
#
# Requirements:
#   - Wazuh Manager 4.x installed
#   - Python 3.6+
#   - SOCRadar API Key and Company ID
#
# The installer will:
#   1. Copy integration files to correct Wazuh directories
#   2. Set proper permissions (root:wazuh ownership)
#   3. Prompt for SOCRadar API credentials
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
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         SOCRadar Native Integration for Wazuh               ║"
echo "║                    Installer v1.0.0                         ║"
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

echo -e "${YELLOW}SOCRadar API Configuration${NC}"
echo "─────────────────────────────────────"

read -p "SOCRadar Company ID: " COMPANY_ID
if [ -z "$COMPANY_ID" ]; then
    echo -e "${RED}ERROR: Company ID is required${NC}"
    exit 1
fi

read -p "SOCRadar API Key: " API_KEY
if [ -z "$API_KEY" ]; then
    echo -e "${RED}ERROR: API Key is required${NC}"
    exit 1
fi

read -p "Your email (for SOCRadar comments) [optional]: " USER_EMAIL
read -p "Initial lookback hours (default: 24): " LOOKBACK
LOOKBACK="${LOOKBACK:-24}"

read -p "Fetch interval in minutes (default: 1): " INTERVAL
INTERVAL="${INTERVAL:-1}"

echo ""
echo -e "${BLUE}Installing integration files...${NC}"

# --- Step 1: Copy wodle files ---

mkdir -p "$WAZUH_HOME/wodles/socradar"
cp "$SCRIPT_DIR/wodles/socradar" "$WAZUH_HOME/wodles/socradar/socradar"
cp "$SCRIPT_DIR/wodles/socradar.py" "$WAZUH_HOME/wodles/socradar/socradar.py"
chmod 750 "$WAZUH_HOME/wodles/socradar/socradar"
chmod 750 "$WAZUH_HOME/wodles/socradar/socradar.py"
chown root:$WAZUH_GROUP "$WAZUH_HOME/wodles/socradar/socradar"
chown root:$WAZUH_GROUP "$WAZUH_HOME/wodles/socradar/socradar.py"
echo -e "${GREEN}  ✓ Wodle files installed${NC}"

# --- Step 2: Copy integration files ---

cp "$SCRIPT_DIR/integrations/custom-socradar" "$WAZUH_HOME/integrations/custom-socradar"
cp "$SCRIPT_DIR/integrations/custom-socradar.py" "$WAZUH_HOME/integrations/custom-socradar.py"
chmod 750 "$WAZUH_HOME/integrations/custom-socradar"
chmod 750 "$WAZUH_HOME/integrations/custom-socradar.py"
chown root:$WAZUH_GROUP "$WAZUH_HOME/integrations/custom-socradar"
chown root:$WAZUH_GROUP "$WAZUH_HOME/integrations/custom-socradar.py"
echo -e "${GREEN}  ✓ Integration files installed${NC}"

# --- Step 3: Copy decoder and rules ---

cp "$SCRIPT_DIR/decoders/0910-socradar_decoders.xml" "$WAZUH_HOME/etc/decoders/"
cp "$SCRIPT_DIR/rules/0910-socradar_rules.xml" "$WAZUH_HOME/etc/rules/"
chown root:$WAZUH_GROUP "$WAZUH_HOME/etc/decoders/0910-socradar_decoders.xml"
chown root:$WAZUH_GROUP "$WAZUH_HOME/etc/rules/0910-socradar_rules.xml"
echo -e "${GREEN}  ✓ Decoder and rules installed${NC}"

# --- Step 4: Create config file ---

cat > "$WAZUH_HOME/etc/socradar.conf" << CONFEOF
{
  "company_id": "$COMPANY_ID",
  "api_key": "$API_KEY",
  "user_email": "$USER_EMAIL",
  "fetch_status": "OPEN",
  "min_severity": null,
  "alarm_main_types": [],
  "initial_lookback_hours": $LOOKBACK,
  "interval_seconds": 60,
  "auto_comment_on_fetch": false,
  "integration": {
    "auto_tag": true,
    "post_wazuh_context": true,
    "auto_close_rule_ids": [],
    "auto_resolve_rule_ids": [],
    "escalate_threshold": 12,
    "auto_ask_analyst": false,
    "ask_analyst_threshold": 10
  }
}
CONFEOF
chmod 640 "$WAZUH_HOME/etc/socradar.conf"
chown root:$WAZUH_GROUP "$WAZUH_HOME/etc/socradar.conf"
echo -e "${GREEN}  ✓ Configuration created${NC}"

# --- Step 5: Create state file ---

touch "$WAZUH_HOME/var/socradar_state.json"
echo "{}" > "$WAZUH_HOME/var/socradar_state.json"
chown root:$WAZUH_GROUP "$WAZUH_HOME/var/socradar_state.json"
echo -e "${GREEN}  ✓ State file created${NC}"

# --- Step 6: Inject ossec.conf blocks ---

if grep -q "socradar" "$WAZUH_HOME/etc/ossec.conf"; then
    echo -e "${YELLOW}  ⚠ SOCRadar blocks already exist in ossec.conf — skipping injection${NC}"
else
    cp "$WAZUH_HOME/etc/ossec.conf" "$WAZUH_HOME/etc/ossec.conf.bak.$(date +%s)"

    sed -i "/<\/ossec_config>/i\\
\\
  <!-- SOCRadar Native Integration -->\\
  <wodle name=\"command\">\\
    <disabled>no</disabled>\\
    <tag>socradar</tag>\\
    <command>/var/ossec/wodles/socradar/socradar</command>\\
    <interval>${INTERVAL}m</interval>\\
    <ignore_output>no</ignore_output>\\
    <run_on_start>yes</run_on_start>\\
    <timeout>300</timeout>\\
  </wodle>\\
\\
  <integration>\\
    <name>custom-socradar</name>\\
    <group>socradar</group>\\
    <alert_format>json</alert_format>\\
  </integration>" "$WAZUH_HOME/etc/ossec.conf"

    echo -e "${GREEN}  ✓ ossec.conf updated${NC}"
fi

# --- Step 7: Restart Wazuh ---

echo ""
echo -e "${BLUE}Restarting Wazuh Manager...${NC}"
"$WAZUH_HOME/bin/wazuh-control" restart

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Installation completed successfully!              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Company ID:    ${BLUE}$COMPANY_ID${NC}"
echo -e "  Interval:      ${BLUE}${INTERVAL}m${NC}"
echo -e "  Lookback:      ${BLUE}${LOOKBACK}h${NC}"
echo ""
echo -e "  ${YELLOW}Monitor logs:${NC}"
echo "    tail -f $WAZUH_HOME/logs/socradar-wodle.log"
echo ""
echo -e "  ${YELLOW}Check alerts:${NC}"
echo "    grep socradar $WAZUH_HOME/logs/alerts/alerts.json | tail"
echo ""
echo -e "  ${YELLOW}Wazuh Dashboard:${NC}"
echo "    Security Events → Filter: rule.groups:socradar"
echo ""
