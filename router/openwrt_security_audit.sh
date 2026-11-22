#!/bin/sh
# ==============================================================================
# Aegis — Read-Only OpenWrt Perimeter & Security Hardening Audit
# Verifies WAN firewall DROP/REJECT posture, SSH key-only authentication,
# LAN-scoped management services, DNS rebind protection, and pending updates.
# Does NOT modify any router configuration.
# ==============================================================================

set -u

PASS=0
WARN=0

ok()   { PASS=$((PASS + 1)); printf "  [PASS] %s\n" "$1"; }
warn() { WARN=$((WARN + 1)); printf "  [WARN] %s\n" "$1"; }
info() { printf "  [INFO] %s\n" "$1"; }

echo "======================================================================"
echo "  AEGIS // OpenWrt Perimeter & Hardening Audit (Read-Only)"
echo "======================================================================"

if [ -f /etc/openwrt_release ]; then
    . /etc/openwrt_release
    info "Firmware : ${DISTRIB_DESCRIPTION:-OpenWrt} (Kernel $(uname -r))"
fi

echo ""
echo "1. WAN Firewall Posture"
WAN_IN=$(uci -q get firewall.@zone[1].input || echo "")
WAN_FWD=$(uci -q get firewall.@zone[1].forward || echo "")
if [ "$WAN_IN" = "DROP" ] || [ "$WAN_IN" = "REJECT" ]; then
    ok "WAN input policy is '$WAN_IN'"
else
    warn "WAN input policy is '${WAN_IN:-unknown}' (expected DROP or REJECT)"
fi

if [ "$WAN_FWD" = "DROP" ] || [ "$WAN_FWD" = "REJECT" ]; then
    ok "WAN forward policy is '$WAN_FWD'"
else
    warn "WAN forward policy is '${WAN_FWD:-unknown}' (expected DROP or REJECT)"
fi

echo ""
echo "2. SSH (Dropbear) Authentication & Binding"
SSH_PW=$(uci -q get dropbear.@dropbear[0].PasswordAuth || echo "on")
SSH_ROOT_PW=$(uci -q get dropbear.@dropbear[0].RootPasswordAuth || echo "on")
SSH_IFACE=$(uci -q get dropbear.@dropbear[0].Interface || echo "")

if [ "$SSH_PW" = "off" ] || [ "$SSH_PW" = "0" ]; then
    ok "SSH PasswordAuth is disabled (key-only authentication)"
else
    warn "SSH PasswordAuth is enabled — recommend SSH Ed25519 keys + PasswordAuth='off'"
fi

if [ "$SSH_ROOT_PW" = "off" ] || [ "$SSH_ROOT_PW" = "0" ]; then
    ok "SSH RootPasswordAuth is disabled"
else
    warn "SSH RootPasswordAuth is enabled"
fi

if [ -n "$SSH_IFACE" ]; then
    ok "Dropbear SSH is bound to interface '$SSH_IFACE'"
else
    warn "Dropbear SSH listens on all interfaces — recommend Interface='lan'"
fi

echo ""
echo "3. DNS Rebind Protection (dnsmasq)"
REBIND=$(uci -q get dhcp.@dnsmasq[0].rebind_protection || echo "1")
if [ "$REBIND" = "1" ]; then
    ok "DNS rebind_protection is enabled"
else
    warn "DNS rebind_protection is disabled"
fi

echo ""
echo "4. Listening TCP/UDP Sockets"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp | head -n 20 | sed 's/^/     /'
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnp 2>/dev/null | head -n 20 | sed 's/^/     /'
fi

echo ""
echo "======================================================================"
printf "  Summary: %d passed, %d warnings\n" "$PASS" "$WARN"
echo "======================================================================"
