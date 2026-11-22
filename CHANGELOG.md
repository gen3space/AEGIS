# Changelog

All notable changes to **Aegis** are documented in this file.

## [1.0.0] — Initial Public Open-Source Release

### Added
- **Two-Tier Progressive Shield Architecture (`auto` / `system` / `router` / `demo` / `pcap`):**
  - **Tier 1 (`System Shield`):** Out-of-the-box live OS kernel TCP/UDP socket-to-PID telemetry, `Authenticode` / `codesign` signature verification, `SHA-256` binary hashing, zero-driver OS DNS Resolver Cache attribution, and live NIC throughput oscilloscope — works with zero router setup.
  - **Tier 2 (`Router Network Shield`):** Zero-idle-load on-demand SSH `tcpdump` stream from OpenWrt / Entware / Linux gateways, whole-LAN visibility, pure-Python L7 DPI, RFC 8701 GREASE-filtered TLS `JA3` fingerprinting, and cross-host **`GHOST SOCKET` (`AEGIS-001`)** differential rootkit detection.
- **Active Defense & Network Control (`aegis/shield_control.py`):**
  - Ephemeral RAM-only router firewall external IP blocking & LAN IoT device quarantine (`nftables` / `iptables`).
  - Safe local rogue process termination (`Kill PID`) and cross-platform OS firewall rule generator (`PowerShell`, `nftables`, `pfctl`).
  - Interactive **Read-Only Router Perimeter Hardening Audit** (`A+`–`D` scorecard).
  - Built-in **Router SSH Diagnostics & Tailored AI Setup Prompt Generator** inside the Web Console.
- **Forensics & Threat Intelligence:**
  - 6 live IOC feeds (`Abuse.ch Feodo`, `IPsum L3+`, `CINS Army`, `Emerging Threats`, `Tor Exits`, `URLhaus`) + 13 MITRE ATT&CK rules.
  - Wireshark `.pcap` 15,000-packet ring-buffer export/import and Markdown Incident Report export.
- **Cross-Platform Packaging:**
  - PyInstaller standalone binary build spec & scripts for **Windows (`x64`)**, **Linux (`x64`)**, and **macOS (`arm64`)**, plus GitHub Actions CI & automated Release pipelines.
