"""
Asynchronous IP Enrichment (BGP ASN, Country, Organization), IEEE OUI Vendor Lookup,
Router DHCP/ARP Device Inventory, and Configurable Route Path Classifier.
"""

from __future__ import annotations

import ipaddress
import json
import queue
import subprocess
import threading
import time
from typing import Dict, List, Optional, Set

import dns.resolver
import requests

from .config import AegisConfig

# Standard public IEEE OUI prefixes for common networking, mobile, PC, and virtualization vendors
PUBLIC_OUI_VENDORS: Dict[str, str] = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:15:5d": "Microsoft Hyper-V",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
    "28:cd:c1": "Raspberry Pi Trading",
    "24:0a:c4": "Espressif (ESP32/IoT)",
    "30:ae:a4": "Espressif (ESP32/IoT)",
    "fc:ec:da": "Ubiquiti Inc.",
    "74:83:c2": "Ubiquiti Inc.",
    "48:8f:5a": "Routerboard / MikroTik",
    "cc:2d:e0": "Routerboard / MikroTik",
    "50:ff:20": "Keenetic Limited",
    "e8:39:df": "Keenetic Limited",
    "f8:1a:67": "TP-Link",
    "50:c7:bf": "TP-Link",
    "04:d9:f5": "ASUSTek Computer",
    "2c:fd:a1": "ASUSTek Computer",
    "3c:22:fb": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "a4:83:e7": "Apple, Inc.",
    "dc:a9:04": "Apple, Inc.",
    "00:1a:79": "Intel Corporate",
    "3c:97:0e": "Intel Corporate",
    "a0:36:9f": "Intel Corporate",
    "dc:fb:48": "Intel Corporate",
    "00:e0:4c": "Realtek Semiconductor",
    "70:85:c2": "Realtek Semiconductor",
    "28:39:5e": "Samsung Electronics",
    "f4:42:8f": "Samsung Electronics",
    "64:cc:2e": "Xiaomi Communications",
    "28:6c:07": "Xiaomi Communications",
}


def mac_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""
    prefix = mac[:8].lower()
    if prefix in PUBLIC_OUI_VENDORS:
        return PUBLIC_OUI_VENDORS[prefix]
    # Locally Administered Address bit (bit 1 of first octet -> iOS/Android/Windows Randomized Private MAC)
    try:
        first_byte = int(mac[:2], 16)
        if first_byte & 0x02:
            return "Randomized MAC"
    except ValueError:
        pass
    return ""


def is_private_or_special_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_link_local
            or ip.is_unspecified
            or str(ip) == "255.255.255.255"
        )
    except ValueError:
        return True


class NetworkEnricher:
    def __init__(self, config: AegisConfig) -> None:
        self.config = config
        self.geo_cache_file = config.data_dir / "ip_geo_cache.json"
        self._lock = threading.Lock()
        self.geo_cache: Dict[str, dict] = self._load_geo_cache()
        self._lookup_queue: "queue.Queue[str]" = queue.Queue()
        self._queued_ips: Set[str] = set()

        # Device map: ip -> {"ip", "mac", "hostname", "vendor"}
        self.devices: Dict[str, dict] = {
            config.router_host: {
                "ip": config.router_host,
                "mac": "",
                "hostname": "Gateway-Router",
                "vendor": "Network Gateway",
            }
        }
        # Optional PBR direct-routing CIDR set synced from router (indexed by first IPv4 octet for O(1) lookup)
        self._direct_nets_by_octet: Dict[int, List[ipaddress.IPv4Network]] = {}
        self.direct_cidr_count: int = 0
        self._running = False

    def _load_geo_cache(self) -> Dict[str, dict]:
        if self.geo_cache_file.exists():
            try:
                return json.loads(self.geo_cache_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_geo_cache(self) -> None:
        try:
            with self._lock:
                data = dict(self.geo_cache)
            self.geo_cache_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        threading.Thread(target=self._router_inventory_loop, daemon=True, name="RouterInventorySync").start()
        for i in range(2):
            threading.Thread(target=self._geo_worker, daemon=True, name=f"GeoWorker-{i}").start()

    def stop(self) -> None:
        self._running = False
        self._save_geo_cache()

    def register_device_hint(self, ip: str, mac: str = "", hostname: str = "") -> None:
        with self._lock:
            if ip not in self.devices:
                v = mac_vendor(mac)
                lbl = hostname or (f"Host-{ip.split('.')[-1]}" + (f" ({v})" if v else ""))
                self.devices[ip] = {"ip": ip, "mac": mac, "hostname": lbl, "vendor": v}

    def sync_router_context_once(self) -> None:
        """Fetch DHCP leases, ARP neighbor table, and optional PBR CIDR list from router via SSH."""
        if self.config.mode != "router":
            return
        try:
            cmd = "cat /tmp/dhcp.leases 2>/dev/null; echo '===ARP==='; ip -4 neigh show 2>/dev/null"
            out = subprocess.check_output(
                [*self.config.build_ssh_args(), cmd],
                stderr=subprocess.DEVNULL,
                timeout=7,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).decode("utf-8", errors="ignore")

            leases_part, _, arp_part = out.partition("===ARP===")
            with self._lock:
                devs: Dict[str, dict] = dict(self.devices)

            for line in leases_part.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    mac, ip, host = parts[1].lower(), parts[2], parts[3]
                    v = mac_vendor(mac)
                    clean_host = host if host != "*" else (f"Device-{ip.split('.')[-1]}" + (f" ({v})" if v else ""))
                    devs[ip] = {"ip": ip, "mac": mac, "hostname": clean_host, "vendor": v}

            for line in arp_part.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        mac = parts[idx + 1].lower()
                        if ip not in devs:
                            v = mac_vendor(mac)
                            devs[ip] = {
                                "ip": ip,
                                "mac": mac,
                                "hostname": f"Host-{ip.split('.')[-1]}" + (f" ({v})" if v else ""),
                                "vendor": v,
                            }

            with self._lock:
                self.devices = devs
        except Exception:
            pass

        if self.config.router_direct_cidr_file and self.direct_cidr_count == 0:
            try:
                safe_path = self.config.router_direct_cidr_file.replace("'", "")
                out = subprocess.check_output(
                    [*self.config.build_ssh_args(), f"cat '{safe_path}' 2>/dev/null"],
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                ).decode("utf-8", errors="ignore")
                by_oct: Dict[int, List[ipaddress.IPv4Network]] = {}
                cnt = 0
                for line in out.splitlines():
                    tok = line.strip()
                    if not tok or tok.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(tok, strict=False)
                        if isinstance(net, ipaddress.IPv4Network):
                            first_oct = int(net.network_address.packed[0])
                            by_oct.setdefault(first_oct, []).append(net)
                            cnt += 1
                    except ValueError:
                        pass
                if cnt > 0:
                    with self._lock:
                        self._direct_nets_by_octet = by_oct
                        self.direct_cidr_count = cnt
            except Exception:
                pass

    def _router_inventory_loop(self) -> None:
        while self._running:
            self.sync_router_context_once()
            for _ in range(25):
                if not self._running:
                    break
                time.sleep(1.0)

    def get_device_label(self, ip: str, mac: str = "") -> str:
        with self._lock:
            d = self.devices.get(ip)
        if d and d.get("hostname"):
            return d["hostname"]
        if mac:
            v = mac_vendor(mac)
            if v:
                return f"{ip} ({v})"
        return ip

    def classify_route_path(self, dst_ip: str, domain: str = "", l7_proto: str = "") -> str:
        """Classify router forwarding path (LAN, WAN, or VPN policy route if configured)."""
        if is_private_or_special_ip(dst_ip):
            return "LAN"

        has_pbr = bool(self.config.vpn_endpoints or self.direct_cidr_count > 0 or self.config.direct_countries)
        if not has_pbr:
            if l7_proto == "WireGuard":
                return "VPN"
            return "WAN"

        if dst_ip in self.config.vpn_endpoints:
            return "WAN (Tunnel)"

        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if isinstance(ip_obj, ipaddress.IPv4Address) and self.direct_cidr_count > 0:
                first_oct = int(ip_obj.packed[0])
                for net in self._direct_nets_by_octet.get(first_oct, ()):
                    if ip_obj in net:
                        return "WAN (Direct)"
        except ValueError:
            pass

        geo = self.geo_cache.get(dst_ip)
        if geo and geo.get("cc") in self.config.direct_countries:
            return "WAN (Direct)"

        return "VPN"

    def seed_geo_entry(self, ip: str, cc: str, country: str, asn: str, org: str) -> None:
        with self._lock:
            self.geo_cache[ip] = {"cc": cc, "country": country, "asn": asn, "org": org}

    def get_geo_info(self, ip: str) -> dict:
        if is_private_or_special_ip(ip):
            return {"cc": "LAN", "country": "Local Network", "asn": "LAN", "org": "RFC1918 Private"}
        with self._lock:
            cached = self.geo_cache.get(ip)
            if cached:
                return cached
            if self.config.mode != "demo" and ip not in self._queued_ips and self._lookup_queue.qsize() < 400:
                self._queued_ips.add(ip)
                self._lookup_queue.put(ip)
        return {"cc": "..", "country": "Resolving...", "asn": "", "org": ""}

    def _cymru_dns_lookup(self, ip: str) -> Optional[dict]:
        """Fast DNS-based BGP ASN & Country lookup via Team Cymru (no HTTP rate limits)."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return None
            rev = ".".join(reversed(parts)) + ".origin.asn.cymru.com"
            ans = dns.resolver.resolve(rev, "TXT", lifetime=2.5)
            txt = ans[0].to_text().strip('"')
            fields = [f.strip() for f in txt.split("|")]
            asn_num = fields[0].split()[0] if fields else ""
            cc = fields[2] if len(fields) >= 3 else ""
            org = ""
            if asn_num.isdigit():
                ans2 = dns.resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT", lifetime=2.5)
                txt2 = ans2[0].to_text().strip('"')
                f2 = [f.strip() for f in txt2.split("|")]
                org = f2[-1] if f2 else ""
            return {
                "cc": cc or "??",
                "country": cc or "Unknown",
                "asn": f"AS{asn_num}" if asn_num else "",
                "org": org,
            }
        except Exception:
            return None

    def _geo_worker(self) -> None:
        saves = 0
        while self._running:
            try:
                ip = self._lookup_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            info = self._cymru_dns_lookup(ip)
            if not info or not info.get("org"):
                try:
                    r = requests.get(f"https://ipwho.is/{ip}", timeout=4)
                    if r.status_code == 200:
                        d = r.json()
                        if d.get("success"):
                            conn = d.get("connection") or {}
                            asn_val = conn.get("asn")
                            info = {
                                "cc": d.get("country_code") or "??",
                                "country": d.get("country") or "",
                                "asn": f"AS{asn_val}" if asn_val else "",
                                "org": conn.get("org") or conn.get("isp") or "",
                            }
                except Exception:
                    pass

            if not info:
                info = {"cc": "??", "country": "Unknown", "asn": "", "org": "Unknown Network"}

            with self._lock:
                self.geo_cache[ip] = info
            saves += 1
            if saves % 10 == 0:
                self._save_geo_cache()
