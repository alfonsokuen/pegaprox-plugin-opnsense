#!/bin/bash
# PegaProx OPNsense Manager Plugin — Uninstaller
set -e

PEGAPROX_DIR="/opt/PegaProx"
PLUGIN_DIR="$PEGAPROX_DIR/plugins/opnsense"
DB="$PEGAPROX_DIR/config/pegaprox.db"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

if [ -f "$DB" ]; then
    sqlite3 "$DB" "UPDATE plugin_state SET enabled=0 WHERE plugin_id='opnsense'" 2>/dev/null || true
    echo "Plugin disabled in database"
fi

if [ -d "$PLUGIN_DIR" ]; then
    BACKUP="/tmp/pegaprox-opnsense-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar czf "$BACKUP" -C "$(dirname "$PLUGIN_DIR")" "$(basename "$PLUGIN_DIR")" 2>/dev/null
    echo "Backup saved to $BACKUP"
    rm -rf "$PLUGIN_DIR"
    echo "Plugin removed from $PLUGIN_DIR"
fi

systemctl restart pegaprox
echo "Done."
