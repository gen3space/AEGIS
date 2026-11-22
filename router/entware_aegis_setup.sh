#!/bin/sh
# ==============================================================================
# Aegis — Entware Router Telemetry Bootstrap (Keenetic / Asuswrt-Merlin / Padavan)
# Installs lightweight `tcpdump` via Entware (`opkg` in `/opt/bin`) with zero
# persistent background daemons (`0% CPU / 0 MB RAM` when Aegis is closed).
# ==============================================================================

set -eu

export PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "[Aegis] Checking Entware environment..."
if [ ! -x /opt/bin/opkg ]; then
    echo "[Aegis] ERROR: Entware (/opt/bin/opkg) not found." >&2
    echo "        Enable OPKG/Entware on USB or internal storage first, then re-run." >&2
    exit 1
fi

if command -v tcpdump >/dev/null 2>&1; then
    echo "[Aegis] OK: tcpdump is already installed ($(command -v tcpdump))."
else
    echo "[Aegis] Updating Entware package index & installing tcpdump-mini..."
    /opt/bin/opkg update
    /opt/bin/opkg install tcpdump-mini || /opt/bin/opkg install tcpdump
fi

echo "[Aegis] Available network bridge/LAN interfaces:"
ip -o link show 2>/dev/null | awk -F': ' '{print "  - " $2}' || ifconfig -a | grep '^[a-zA-Z0-9]'

echo "[Aegis] Setup complete! Zero background services were started."
