"""
Command-Line Interface for Aegis — Personal System & Router Network Digital Shield.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import List, Optional

import uvicorn

from . import __version__
from .config import AegisConfig, normalize_mode
from .server import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis — Two-Tier Personal System Shield & Out-of-Band Router NGFW / Anti-Rootkit SOC",
    )
    parser.add_argument("--version", action="version", version=f"Aegis {__version__}")
    parser.add_argument(
        "--mode",
        choices=["auto", "system", "router", "demo", "pcap"],
        help="Operating mode: auto (default), system (Tier 1 OS Shield), router (Tier 2 Gateway DPI), demo, or pcap",
    )
    parser.add_argument("--system", action="store_true", help="Force Tier 1 Host System Shield mode (no router needed)")
    parser.add_argument("--router", help="Connect to Router SSH IP/hostname and enable Tier 2 Network Shield (e.g. 192.168.1.1)")
    parser.add_argument("--ssh-port", type=int, help="Router SSH port (default: 22)")
    parser.add_argument("--user", help="Router SSH username (default: root)")
    parser.add_argument("--iface", help="Router capture interface (default: br-lan)")
    parser.add_argument("--ssh-key", help="Path to SSH private key file")
    parser.add_argument("--host", help="Local bind address for Web Console (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Local bind port for Web Console (default: 8765)")
    parser.add_argument("--lang", choices=["en", "ru"], help="Default UI language (en or ru)")
    parser.add_argument("--demo", action="store_true", help="Run in synthetic Demo Mode (simulated L7 DPI + Ghost Socket)")
    parser.add_argument("--pcap", type=Path, help="Inspect an offline .pcap file")
    parser.add_argument("--open-browser", action="store_true", help="Open the SOC Web Console in default browser")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser when launched as standalone app")
    parser.add_argument("--no-feed-bootstrap", action="store_true", help="Skip automatic Threat Intel feed download on first run")
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = AegisConfig.from_env()
    if args.mode:
        cfg.mode = normalize_mode(args.mode)
    if args.system:
        cfg.mode = "system"
    if args.router:
        cfg.router_host = args.router.strip()
        cfg.gateway_ips.add(cfg.router_host)
        cfg.router_explicitly_configured = True
        if not args.mode and not args.system and not args.demo and not args.pcap:
            cfg.mode = "router"
    if args.ssh_port:
        cfg.router_port = args.ssh_port
    if args.user:
        cfg.router_user = args.user
    if args.iface:
        cfg.router_iface = args.iface
    if args.ssh_key:
        cfg.ssh_key_path = args.ssh_key
    if args.host:
        cfg.bind_host = args.host
    if args.port:
        cfg.bind_port = args.port
    if args.lang:
        cfg.default_lang = args.lang
    if args.no_feed_bootstrap:
        cfg.auto_update_feeds = False

    if args.demo:
        cfg.mode = "demo"
    elif args.pcap:
        cfg.mode = "pcap"
        cfg.pcap_file = args.pcap

    url_host = "127.0.0.1" if cfg.bind_host in ("0.0.0.0", "::") else cfg.bind_host
    url = f"http://{url_host}:{cfg.bind_port}"

    print("=" * 76)
    print(f"  AEGIS v{__version__} // Personal System & Router Network Digital Shield")
    print("=" * 76)
    if cfg.mode in ("auto", "system") and not cfg.router_explicitly_configured:
        print("  Active Tier : TIER 1 — HOST SYSTEM SHIELD (OS Kernel Sockets & DNS Cache)")
        print("  Upgrade     : Click 'Connect Router' in UI to unlock Tier 2 Whole-LAN NGFW")
    elif cfg.mode in ("auto", "router"):
        print("  Active Tier : TIER 2 — ROUTER NETWORK SHIELD (Out-of-Band L7 DPI & JA3)")
        print(f"  Gateway     : {cfg.router_user}@{cfg.router_host}:{cfg.router_port} ({cfg.router_iface})")
        print("  Router Load : 0% CPU / 0 MB RAM when paused or closed")
    elif cfg.mode == "pcap":
        print(f"  Active Mode : FORENSIC PCAP ANALYZER ({cfg.pcap_file})")
    else:
        print("  Active Mode : DEMO SIMULATION (Synthetic L7 DPI + JA3 + Ghost-Socket)")
    print(f"  Web Console : {url}")
    print(f"  Data Store  : {cfg.data_dir}")
    print("=" * 76)

    is_frozen_binary = getattr(sys, "frozen", False)
    should_open = (args.open_browser or is_frozen_binary) and not args.no_browser
    if should_open:
        threading.Thread(
            target=lambda: (time.sleep(0.9), webbrowser.open(url)),
            daemon=True,
        ).start()

    app = create_app(cfg)
    uvicorn.run(app, host=cfg.bind_host, port=cfg.bind_port, log_level="warning")
