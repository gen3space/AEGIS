#!/bin/sh
# ==============================================================================
# Aegis — OpenWrt Zero-Daemon Telemetry Bootstrap
# Installs lightweight `tcpdump-mini` (~150 KB) so Aegis can stream packet
# headers on demand over SSH with 0% background CPU and 0 MB idle RAM usage.
# Supports both OpenWrt 24.x (`opkg`) and OpenWrt 25.x+ (`apk`).
# ==============================================================================

set -eu

echo "[Aegis] Checking router environment..."
if [ -f /etc/openwrt_release ]; then
    . /etc/openwrt_release
    echo "[Aegis] Detected ${DISTRIB_DESCRIPTION:-OpenWrt}"
fi

if command -v tcpdump >/dev/null 2>&1; then
    echo "[Aegis] OK: tcpdump is already installed ($(command -v tcpdump))."
else
    echo "[Aegis] Installing lightweight tcpdump-mini..."
    if command -v apk >/dev/null 2>&1; then
        apk update
        apk add tcpdump-mini || apk add tcpdump
    elif command -v opkg >/dev/null 2>&1; then
        opkg update
        opkg install tcpdump-mini || opkg install tcpdump
    else
        echo "[Aegis] ERROR: Neither apk nor opkg package manager found." >&2
        exit 1
    fi
fi

IFACE="${1:-br-lan}"
if ip link show "$IFACE" >/dev/null 2>&1; then
    echo "[Aegis] OK: Bridge/interface '$IFACE' is up and ready."
else
    echo "[Aegis] WARNING: Interface '$IFACE' not found. Available interfaces:"
    ip -o link show | awk -F': ' '{print "  - " $2}'
fi

echo "[Aegis] Setup complete. Zero background daemons were enabled."
echo "[Aegis] Run 'aegis --router <ROUTER_IP> --iface $IFACE' on your workstation."
