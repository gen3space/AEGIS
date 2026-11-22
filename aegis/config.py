"""
Configuration management for Aegis Digital Shield (System & Router NGFW SOC).
Loads settings from environment variables and optional `.env` file with zero hardcoded secrets.
Supports PyInstaller standalone binaries (`sys._MEIPASS`) and runtime mode switching.
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


VALID_MODES = ("auto", "system", "router", "demo", "pcap")


def get_static_dir() -> Path:
    """Resolve bundled `static/` directory in both source installs and PyInstaller one-file binaries."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = Path(meipass) / "aegis" / "static"
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parent / "static"


def _resolve_writable_data_dir(explicit_env: str = "") -> Path:
    if explicit_env:
        target = Path(explicit_env).expanduser().resolve()
        target.mkdir(parents=True, exist_ok=True)
        (target / "feeds").mkdir(parents=True, exist_ok=True)
        return target

    cwd_data = Path.cwd() / "data"
    try:
        cwd_data.mkdir(parents=True, exist_ok=True)
        (cwd_data / "feeds").mkdir(parents=True, exist_ok=True)
        probe = cwd_data / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return cwd_data
    except OSError:
        home_data = Path.home() / ".aegis" / "data"
        home_data.mkdir(parents=True, exist_ok=True)
        (home_data / "feeds").mkdir(parents=True, exist_ok=True)
        return home_data


def _load_dotenv_file(dotenv_path: Path) -> bool:
    """Minimal zero-dependency `.env` loader (does not override existing env vars). Returns True if loaded."""
    if not dotenv_path.is_file():
        return False
    loaded = False
    try:
        for raw_line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if key and key not in os.environ:
                os.environ[key] = val
                loaded = True
    except OSError:
        return False
    return loaded


def _parse_csv_set(raw: str) -> Set[str]:
    return {item.strip() for item in raw.split(",") if item.strip()}


def _parse_networks(raw: str) -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    for item in raw.split(","):
        tok = item.strip()
        if not tok:
            continue
        try:
            net = ipaddress.ip_network(tok, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                nets.append(net)
        except ValueError:
            pass
    return nets


def normalize_mode(raw: str) -> str:
    m = (raw or "auto").strip().lower()
    if m == "live":
        return "router"
    if m not in VALID_MODES:
        return "auto"
    return m


@dataclass
class AegisConfig:
    # Capture mode:
    #   "auto"   — Connects to Router (Tier 2) if explicitly configured & reachable; otherwise starts System Shield (Tier 1)
    #   "system" — Tier 1: Host OS Kernel Socket, Process Signature & DNS Cache Shield (no router needed)
    #   "router" — Tier 2: Out-of-Band Router SSH PCAP Stream + L7 DPI + TLS JA3 + Anti-Rootkit Correlation
    #   "pcap"   — Offline forensic analysis of `.pcap` file
    #   "demo"   — Synthetic RFC-5737 traffic & rootkit simulation
    mode: str = "auto"
    router_explicitly_configured: bool = False
    pcap_file: Optional[Path] = None

    # Router SSH parameters (Tier 2)
    router_host: str = "192.168.1.1"
    router_port: int = 22
    router_user: str = "root"
    router_iface: str = "br-lan"
    ssh_key_path: str = ""
    ssh_strict_host_key: str = "accept-new"  # yes | accept-new | no
    snaplen: int = 1514
    extra_bpf: str = ""

    # Web Console bind parameters (127.0.0.1 by default for strict local-only security)
    bind_host: str = "127.0.0.1"
    bind_port: int = 8765
    default_lang: str = "en"  # "en" or "ru" (UI also auto-detects browser locale on first visit)
    auto_update_feeds: bool = True

    # Optional Webhook Alerting & Active Response settings
    alert_webhook_url: str = ""
    enable_active_response: bool = True

    # Network & Routing classification (optional customization)
    lan_networks: List[ipaddress.IPv4Network] = field(
        default_factory=lambda: _parse_networks("192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
    )
    gateway_ips: Set[str] = field(default_factory=set)
    vpn_endpoints: Set[str] = field(default_factory=set)
    allowlist_ips: Set[str] = field(default_factory=set)
    router_direct_cidr_file: str = ""  # e.g. /etc/pbr/direct-subnets.txt (optional)
    direct_countries: Set[str] = field(default_factory=set)  # e.g. {"US", "DE"} for PBR display

    # Storage paths
    data_dir: Path = field(default_factory=lambda: _resolve_writable_data_dir())

    @classmethod
    def from_env(cls, dotenv_path: Optional[Path] = None) -> "AegisConfig":
        had_router_env_before = "AEGIS_ROUTER_HOST" in os.environ
        _load_dotenv_file(dotenv_path or (Path.cwd() / ".env"))
        router_configured = had_router_env_before or ("AEGIS_ROUTER_HOST" in os.environ)

        router_host = os.environ.get("AEGIS_ROUTER_HOST", "192.168.1.1").strip()
        router_port = int(os.environ.get("AEGIS_ROUTER_PORT", "22"))
        router_user = os.environ.get("AEGIS_ROUTER_USER", "root").strip()
        router_iface = os.environ.get("AEGIS_ROUTER_IFACE", "br-lan").strip()
        ssh_key_path = os.environ.get("AEGIS_SSH_KEY", "").strip()
        ssh_strict = os.environ.get("AEGIS_SSH_STRICT_HOST_KEY", "accept-new").strip()
        snaplen = max(256, min(65535, int(os.environ.get("AEGIS_SNAPLEN", "1514"))))
        extra_bpf = os.environ.get("AEGIS_EXTRA_BPF", "").strip()

        bind_host = os.environ.get("AEGIS_BIND_HOST", "127.0.0.1").strip()
        bind_port = int(os.environ.get("AEGIS_BIND_PORT", "8765"))
        default_lang = os.environ.get("AEGIS_LANG", "").strip().lower()
        if default_lang not in ("en", "ru"):
            default_lang = ""

        mode = normalize_mode(os.environ.get("AEGIS_MODE", "auto"))

        pcap_env = os.environ.get("AEGIS_PCAP_FILE", "").strip()
        pcap_file = Path(pcap_env) if pcap_env else None

        auto_feeds = os.environ.get("AEGIS_AUTO_UPDATE_FEEDS", "true").strip().lower() in ("1", "true", "yes", "on")
        webhook_url = os.environ.get("AEGIS_ALERT_WEBHOOK_URL", "").strip()
        active_resp = os.environ.get("AEGIS_ACTIVE_RESPONSE", "true").strip().lower() in ("1", "true", "yes", "on")

        lan_raw = os.environ.get("AEGIS_LAN_SUBNETS", "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
        lan_nets = _parse_networks(lan_raw)

        gw_ips = _parse_csv_set(os.environ.get("AEGIS_GATEWAY_IPS", ""))
        if router_host:
            gw_ips.add(router_host)

        vpn_eps = _parse_csv_set(os.environ.get("AEGIS_VPN_ENDPOINTS", ""))
        allow_ips = _parse_csv_set(os.environ.get("AEGIS_ALLOWLIST_IPS", ""))
        direct_cidr_file = os.environ.get("AEGIS_DIRECT_CIDR_FILE", "").strip()
        direct_cc = {c.upper() for c in _parse_csv_set(os.environ.get("AEGIS_DIRECT_COUNTRIES", ""))}

        data_dir = _resolve_writable_data_dir(os.environ.get("AEGIS_DATA_DIR", "").strip())

        return cls(
            mode=mode,
            router_explicitly_configured=router_configured,
            pcap_file=pcap_file,
            router_host=router_host,
            router_port=router_port,
            router_user=router_user,
            router_iface=router_iface,
            ssh_key_path=ssh_key_path,
            ssh_strict_host_key=ssh_strict,
            snaplen=snaplen,
            extra_bpf=extra_bpf,
            bind_host=bind_host,
            bind_port=bind_port,
            default_lang=default_lang,
            auto_update_feeds=auto_feeds,
            alert_webhook_url=webhook_url,
            enable_active_response=active_resp,
            lan_networks=lan_nets,
            gateway_ips=gw_ips,
            vpn_endpoints=vpn_eps,
            allowlist_ips=allow_ips,
            router_direct_cidr_file=direct_cidr_file,
            direct_countries=direct_cc,
            data_dir=data_dir,
        )

    def build_ssh_args(self, connect_timeout: int = 5) -> List[str]:
        args = [
            "ssh",
            "-p",
            str(self.router_port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"StrictHostKeyChecking={self.ssh_strict_host_key}",
            "-o",
            f"ConnectTimeout={connect_timeout}",
            "-o",
            "ServerAliveInterval=10",
        ]
        if self.ssh_key_path:
            args.extend(["-i", self.ssh_key_path])
        args.append(f"{self.router_user}@{self.router_host}")
        return args

    def probe_router_ready(self, timeout_sec: int = 3) -> Tuple[bool, str]:
        """Quickly verify SSH public-key login and `tcpdump` availability on the configured router."""
        try:
            cmd = (
                f"command -v tcpdump >/dev/null 2>&1 && "
                f"ip link show '{self.router_iface}' >/dev/null 2>&1 && echo AEGIS_READY"
            )
            res = subprocess.run(
                [*self.build_ssh_args(connect_timeout=max(2, timeout_sec)), cmd],
                capture_output=True,
                text=True,
                timeout=timeout_sec + 1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if res.returncode == 0 and "AEGIS_READY" in (res.stdout or ""):
                return True, "Router SSH & tcpdump ready"
            err = (res.stderr or res.stdout or "").strip()
            return False, err or "Router SSH or tcpdump check failed"
        except Exception as exc:
            return False, str(exc)

    def is_lan_client_ip(self, ip_str: str) -> bool:
        if ip_str in self.gateway_ips:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv4Address):
                if ip.is_loopback or ip.is_multicast or ip.is_link_local or ip_str.endswith(".255"):
                    return False
                return any(ip in net for net in self.lan_networks)
            if isinstance(ip, ipaddress.IPv6Address):
                return ip.is_private and not ip.is_link_local and not ip.is_multicast
        except ValueError:
            return False
        return False

    def public_metadata(self) -> Dict[str, object]:
        return {
            "mode": self.mode,
            "router_host": self.router_host,
            "router_port": self.router_port,
            "router_user": self.router_user,
            "router_iface": self.router_iface,
            "default_lang": self.default_lang or "en",
            "active_response": self.enable_active_response,
        }
