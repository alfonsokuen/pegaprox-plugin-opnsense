#!/bin/bash
# ============================================================================
# PegaProx OPNsense Manager Plugin — One-Line Installer (v0.1.0+)
# ============================================================================
#
# Install:
#   curl -sSL https://git.idkmanager.com/idkmanager/pegaprox-plugin-opnsense/raw/branch/main/install.sh | sudo bash
#
# What it does:
#   1. Downloads the plugin to /opt/PegaProx/plugins/opnsense/
#   2. Creates config.json from example (you edit creds via Settings tab)
#   3. Enables the plugin in PegaProx
#   4. Restarts PegaProx
#
# Requirements:
#   - PegaProx 0.9.9.3+ installed at /opt/PegaProx
#   - Root access
#   - Network reachability from PegaProx host to OPNsense API (HTTPS)
#
# Uninstall:
#   sudo bash /opt/PegaProx/plugins/opnsense/uninstall.sh
#
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPO_URL="https://git.idkmanager.com/idkmanager/pegaprox-plugin-opnsense"
PEGAPROX_DIR="/opt/PegaProx"
PLUGIN_DIR="$PEGAPROX_DIR/plugins/opnsense"
MIN_PEGAPROX="0.9.9.3"

echo ""
echo -e "${CYAN}+==============================================================+${NC}"
echo -e "${CYAN}|   ${BOLD}PegaProx OPNsense Manager Plugin - Installer${NC}${CYAN}             |${NC}"
echo -e "${CYAN}|   Monitor & configure OPNsense from PegaProx               |${NC}"
echo -e "${CYAN}+==============================================================+${NC}"
echo ""

echo -e "${BLUE}[1/4] Checking prerequisites...${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root (sudo)${NC}"
    exit 1
fi

if [ ! -d "$PEGAPROX_DIR" ] || [ ! -f "$PEGAPROX_DIR/pegaprox/app.py" ]; then
    echo -e "${RED}ERROR: PegaProx not found at $PEGAPROX_DIR${NC}"
    exit 1
fi

PEGAPROX_VERSION=$(python3 -c "import json; print(json.load(open('$PEGAPROX_DIR/version.json'))['version'])" 2>/dev/null || echo "unknown")
echo -e "  PegaProx ${GREEN}$PEGAPROX_VERSION${NC} found at $PEGAPROX_DIR"

ver_ge() { python3 -c "
import sys
def parse(v):
    return tuple(int(x) for x in v.split('.') if x.isdigit())
sys.exit(0 if parse('$1') >= parse('$2') else 1)
"; }

if ! ver_ge "$PEGAPROX_VERSION" "$MIN_PEGAPROX"; then
    echo -e "${RED}ERROR: PegaProx >= $MIN_PEGAPROX required (found $PEGAPROX_VERSION)${NC}"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}ERROR: Python 3 not found${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}[2/4] Downloading plugin...${NC}"

if [ -d "$PLUGIN_DIR" ] && [ -f "$PLUGIN_DIR/config.json" ]; then
    cp "$PLUGIN_DIR/config.json" /tmp/_opnsense_config_backup.json
    echo "  Backed up existing config.json"
fi

if command -v git &>/dev/null; then
    if [ -d "$PLUGIN_DIR/.git" ]; then
        cd "$PLUGIN_DIR" && git pull --quiet
        echo -e "  ${GREEN}Updated via git pull${NC}"
    else
        rm -rf "$PLUGIN_DIR"
        git clone --quiet "$REPO_URL.git" "$PLUGIN_DIR"
        echo -e "  ${GREEN}Cloned from Gitea${NC}"
    fi
else
    rm -rf "$PLUGIN_DIR"
    mkdir -p "$PLUGIN_DIR"
    curl -sSL "$REPO_URL/archive/main.tar.gz" | tar xz --strip-components=1 -C "$PLUGIN_DIR"
    echo -e "  ${GREEN}Downloaded tarball${NC}"
fi

if [ -f /tmp/_opnsense_config_backup.json ]; then
    cp /tmp/_opnsense_config_backup.json "$PLUGIN_DIR/config.json"
    rm -f /tmp/_opnsense_config_backup.json
    echo "  Restored existing config.json"
elif [ ! -f "$PLUGIN_DIR/config.json" ]; then
    cp "$PLUGIN_DIR/config.example.json" "$PLUGIN_DIR/config.json"
    echo -e "  ${YELLOW}config.json initialized from example — edit credentials in Settings tab${NC}"
fi

chown -R pegaprox:pegaprox "$PLUGIN_DIR" 2>/dev/null || chown -R "$(stat -c %U "$PEGAPROX_DIR")" "$PLUGIN_DIR"
chmod 600 "$PLUGIN_DIR/config.json"

echo ""
echo -e "${BLUE}[3/4] Enabling plugin in PegaProx...${NC}"

if ! command -v sqlite3 &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sqlite3 > /dev/null 2>&1
fi

DB="$PEGAPROX_DIR/config/pegaprox.db"
if [ -f "$DB" ]; then
    sqlite3 "$DB" "INSERT OR REPLACE INTO plugin_state (plugin_id, enabled, loaded_at, error) VALUES ('opnsense', 1, datetime('now'), '')" 2>/dev/null
    echo -e "  ${GREEN}Plugin enabled in database${NC}"
else
    echo -e "  ${YELLOW}Database not found - enable via PegaProx UI: Settings > Plugins > Rescan > Enable${NC}"
fi

echo ""
echo -e "${BLUE}[4/4] Restarting PegaProx...${NC}"
systemctl restart pegaprox
sleep 2

if systemctl is-active --quiet pegaprox; then
    echo -e "${GREEN}PegaProx restarted successfully${NC}"
else
    echo -e "${RED}PegaProx failed to start - check: journalctl -u pegaprox${NC}"
fi

echo ""
echo -e "${CYAN}+==============================================================+${NC}"
echo -e "${CYAN}|   ${GREEN}${BOLD}Installation Complete!${NC}${CYAN}                                      |${NC}"
echo -e "${CYAN}+==============================================================+${NC}"
echo ""
echo -e "  ${BOLD}Plugin tab:${NC}  Look for 'OPNsense' tab in the PegaProx dashboard"
echo -e "  ${BOLD}Plugin URL:${NC}  https://YOUR_HOST/api/plugins/opnsense/api/ui"
echo -e "  ${BOLD}Config:${NC}      $PLUGIN_DIR/config.json"
echo -e "  ${BOLD}Logs:${NC}        journalctl -u pegaprox | grep opnsense"
echo ""
echo -e "  ${BOLD}Uninstall:${NC}   sudo bash $PLUGIN_DIR/uninstall.sh"
echo -e "  ${BOLD}Source:${NC}      $REPO_URL"
echo ""
