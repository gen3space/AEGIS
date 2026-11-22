"""
Core Two-Tier Telemetry & NGFW Engine for Aegis.

Supports four operational modes (plus `auto` smart tier selection):
  1. `system` (Tier 1 — Personal System Shield):
     Zero-router-setup live OS kernel TCP/UDP socket telemetry, NIC throughput oscilloscope,
     OS DNS Resolver Cache domain attribution, executable SHA-256 + Authenticode/codesign
     verification, and 50,000+ Threat Intel IOC matching.
  2. `router` (Tier 2 — Out-of-Band Network Gateway Shield):
     On-demand SSH `tcpdump` libpcap stream from router (`0%` router load when paused/closed),
     whole-LAN visibility (PCs, phones, IoT, TVs), wire-speed L7 DPI, TLS `JA3` fingerprinting,
     and cross-host `GHOST SOCKET` anti-rootkit differential correlation.
  3. `pcap` — Offline forensic analysis of any standard `.pcap` capture file.
  4. `demo` — Synthetic RFC-5737 traffic, JA3 & Ghost-Socket rootkit generator for instant testing.
"""

from __future__ import annotations

import collections
import contextlib
import hashlib
import io
import random
import socket
import struct
import subprocess
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

from .config import AegisConfig, normalize_mode
from .dpi_engine import classify_application, decode_ethernet_packet
from .enricher import NetworkEnricher, is_private_or_special_ip
from .host_correlator import HostSocketCorrelator
from .shield_control import ShieldControlEngine
from .threat_intel import ThreatIntelEngine


def _build_ipv4_tcp_frame(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    tcp_flags: int = 0x18,
) -> bytes:
    eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
    tot_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        tot_len,
        0x1234,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 1, 0x50, tcp_flags, 64240, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload


def _build_tls_client_hello(sni: str, ciphers: List[int], alpn: str = "h2") -> bytes:
    sni_b = sni.encode("ascii")
    sni_ext_data = struct.pack("!HBH", len(sni_b) + 3, 0, len(sni_b)) + sni_b
    ext_sni = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    curves_data = struct.pack("!HHH", 4, 29, 23)
    ext_curves = struct.pack("!HH", 0x000A, len(curves_data)) + curves_data

    pf_data = struct.pack("!BB", 1, 0)
    ext_pf = struct.pack("!HH", 0x000B, len(pf_data)) + pf_data

    alpn_b = alpn.encode("ascii")
    alpn_data = struct.pack("!HB", len(alpn_b) + 1, len(alpn_b)) + alpn_b
    ext_alpn = struct.pack("!HH", 0x0010, len(alpn_data)) + alpn_data

    ver_data = struct.pack("!BH", 2, 0x0304)
    ext_ver = struct.pack("!HH", 0x002B, len(ver_data)) + ver_data

    exts = ext_sni + ext_curves + ext_pf + ext_alpn + ext_ver
    cs_bytes = b"".join(struct.pack("!H", c) for c in ciphers)

    body = (
        struct.pack("!H", 0x0303)
        + (b"\x11" * 32)
        + b"\x00"
        + struct.pack("!H", len(cs_bytes))
        + cs_bytes
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class NGFWTelemetryCore:
    def __init__(self, config: Optional[AegisConfig] = None) -> None:
        self.config = config or AegisConfig.from_env()
        self.correlator = HostSocketCorrelator(self.config)
        self.enricher = NetworkEnricher(self.config)
        self.shield = ShieldControlEngine(self.config)
        allow_ips = set(self.config.vpn_endpoints) | set(self.config.allowlist_ips)
        self.threat_intel = ThreatIntelEngine(
            feeds_dir=self.config.data_dir / "feeds",
            allowlist_ips=allow_ips,
        )

        self._lock = threading.Lock()
        self.capturing: bool = False
        self.capture_error: str = ""
        self.fallback_notice: str = ""
        self.capture_started_at: float = 0.0
        self._ssh_proc: Optional[subprocess.Popen] = None
        self._capture_thread: Optional[threading.Thread] = None

        # Passive DNS state: ip -> (domain, ts)
        self.dns_ip_map: Dict[str, Tuple[str, float]] = {}
        self.recent_dns: Deque[dict] = collections.deque(maxlen=200)
        self._checked_os_dns_domains: set[str] = set()

        # Active & recent flows: flow_id -> dict
        self.flows: Dict[str, dict] = {}
        # Rolling PCAP ring buffer for Wireshark export (populated in `router`, `pcap`, and `demo` modes)
        self.pcap_ring: Deque[Tuple[int, int, int, int, bytes]] = collections.deque(maxlen=15000)
        self.pcap_global_hdr: bytes = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, self.config.snaplen, 1)

        # Counters & 90-second bandwidth time-series
        self.total_packets: int = 0
        self.total_bytes_in: int = 0
        self.total_bytes_out: int = 0
        self._sec_bytes_in: int = 0
        self._sec_bytes_out: int = 0
        self._sec_vpn_bytes: int = 0
        self._sec_wan_bytes: int = 0
        self._sec_pkts: int = 0
        self.timeseries: Deque[dict] = collections.deque(maxlen=90)

        # Idle-Watch ("Silence Mode") baseline detector
        self.idle_watch_active: bool = False
        self.idle_watch_since: float = 0.0

    def _resolve_initial_mode(self) -> None:
        if self.config.mode != "auto":
            self.config.mode = normalize_mode(self.config.mode)
            return

        if self.config.router_explicitly_configured:
            ok, reason = self.config.probe_router_ready(timeout_sec=3)
            if ok:
                self.config.mode = "router"
                self.fallback_notice = ""
                return
            self.config.mode = "system"
            self.fallback_notice = (
                f"Router {self.config.router_host} not reachable ({reason}) — "
                f"running Tier 1 System Shield locally."
            )
        else:
            # Default out-of-the-box experience: live OS-level System Shield with zero router setup needed!
            self.config.mode = "system"
            self.fallback_notice = ""

    def startup(self) -> None:
        self._resolve_initial_mode()
        self.correlator.start()
        self.enricher.start()

        if (
            self.config.mode in ("system", "router")
            and self.config.auto_update_feeds
            and self.threat_intel.summary_counts()["c2_ips"] == 0
        ):
            threading.Thread(
                target=self.threat_intel.update_all_feeds,
                daemon=True,
                name="InitialFeedBootstrap",
            ).start()

        if self.config.mode == "pcap" and self.config.pcap_file:
            self.load_pcap_file(self.config.pcap_file)
        else:
            self.start_capture()

    def shutdown(self) -> None:
        self.stop_capture()
        self.correlator.stop()
        self.enricher.stop()

    def switch_mode(
        self,
        new_mode: str,
        router_host: Optional[str] = None,
        router_port: Optional[int] = None,
        router_user: Optional[str] = None,
        router_iface: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
    ) -> dict:
        """Dynamically transition between `system` (Tier 1), `router` (Tier 2), and `demo` without restarting."""
        target = normalize_mode(new_mode)
        if target == "auto":
            target = "system"

        self.stop_capture()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=1.5)

        if router_host:
            self.config.router_host = router_host.strip()
            self.config.gateway_ips.add(self.config.router_host)
            self.config.router_explicitly_configured = True
        if router_port:
            self.config.router_port = int(router_port)
        if router_user:
            self.config.router_user = router_user.strip()
        if router_iface:
            self.config.router_iface = router_iface.strip()
        if ssh_key_path is not None:
            self.config.ssh_key_path = ssh_key_path.strip()

        self.config.mode = target
        self.fallback_notice = ""
        self.clear_session()
        if target != "pcap":
            self.start_capture()
        return {"ok": True, "mode": self.config.mode}

    def start_capture(self) -> None:
        with self._lock:
            if self.capturing:
                return
            self.capturing = True
            self.capture_error = ""
            self.capture_started_at = time.time()

        if self.config.mode == "demo":
            worker = self._demo_worker
        elif self.config.mode == "system":
            self.correlator._reset_nic_baseline()
            worker = self._system_worker
        else:
            worker = self._router_capture_worker

        self._capture_thread = threading.Thread(target=worker, daemon=True, name=f"AegisWorker-{self.config.mode}")
        self._capture_thread.start()

    def stop_capture(self) -> None:
        with self._lock:
            self.capturing = False
            proc = self._ssh_proc
            self._ssh_proc = None
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.terminate()
                proc.wait(timeout=2)
            with contextlib.suppress(Exception):
                proc.kill()

    def clear_session(self) -> None:
        with self._lock:
            self.flows.clear()
            self.recent_dns.clear()
            self.pcap_ring.clear()
            self.threat_intel.alerts.clear()
            self.threat_intel._fired_keys.clear()
            self._checked_os_dns_domains.clear()
            self.total_packets = 0
            self.total_bytes_in = 0
            self.total_bytes_out = 0
            self.timeseries.clear()

    def toggle_idle_watch(self, enable: Optional[bool] = None) -> bool:
        with self._lock:
            self.idle_watch_active = (not self.idle_watch_active) if enable is None else bool(enable)
            if self.idle_watch_active:
                self.idle_watch_since = time.time()
            return self.idle_watch_active

    def load_pcap_file(self, path: Path) -> int:
        if not path.is_file():
            with self._lock:
                self.capture_error = f"PCAP file not found: {path}"
            return 0
        return self.ingest_pcap_bytes(path.read_bytes())

    def ingest_pcap_bytes(self, data: bytes) -> int:
        """Parse standard libpcap bytes (little or big endian) into the NGFW flow engine."""
        stream = io.BytesIO(data)
        ghdr = stream.read(24)
        if len(ghdr) < 24:
            raise ValueError("Invalid PCAP file (shorter than 24-byte global header)")
        magic = struct.unpack("<I", ghdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
            nano = magic == 0xA1B23C4D
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
            nano = magic == 0x4D3CB2A1
        else:
            raise ValueError(f"Unsupported capture format (magic={hex(magic)}); use standard .pcap")

        self.config.mode = "pcap"
        count = 0
        while True:
            phdr = stream.read(16)
            if len(phdr) < 16:
                break
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", phdr)
            if incl_len > 65535:
                break
            raw_frame = stream.read(incl_len)
            if len(raw_frame) < incl_len:
                break
            usec = ts_sub // 1000 if nano else ts_sub
            pkt_ts = ts_sec + (usec / 1_000_000.0)
            self._process_frame(pkt_ts, ts_sec, usec, incl_len, orig_len, raw_frame, use_wall_clock=True)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Tier 1 Worker: Live Host OS System Shield (Zero Router Needed)
    # ------------------------------------------------------------------
    def _system_worker(self) -> None:
        """Continuously ingest real OS kernel TCP/UDP connections, process signatures, and DNS cache."""
        while True:
            with self._lock:
                if not self.capturing or self.config.mode != "system":
                    break

            now = time.time()
            local_host_label = self.correlator.hostname
            for lip in self.correlator.local_ips:
                self.enricher.register_device_hint(lip, "", local_host_label)

            conns = self.correlator.get_live_connections()
            active_keys_now: set[str] = set()

            for c in conns:
                # Ignore connections to our own local Web Console (127.0.0.1:8765)
                if c.remote_port == self.config.bind_port and c.remote_ip in self.correlator.local_ips:
                    continue

                flow_key_raw = f"{c.proto}:{c.local_ip}:{c.local_port}->{c.remote_ip}:{c.remote_port}"
                flow_id = hashlib.blake2b(flow_key_raw.encode("ascii"), digest_size=6).hexdigest()
                active_keys_now.add(flow_id)

                os_dom = self.correlator.lookup_os_dns(c.remote_ip)
                if os_dom and os_dom not in self._checked_os_dns_domains:
                    self._checked_os_dns_domains.add(os_dom)
                    new_dns_alerts = self.threat_intel.check_dns_query(c.local_ip, local_host_label, os_dom)
                    for al in new_dns_alerts:
                        self.shield.notify_webhook_async(asdict(al))

                with self._lock:
                    flow = self.flows.get(flow_id)
                    if flow is None:
                        flow = {
                            "id": flow_id,
                            "first_seen": now,
                            "last_seen": now,
                            "seen_syn": False,  # OS socket table lacks wire SYN/SNI; avoids false Direct-IP notices
                            "proto": c.proto,
                            "l7_proto": "QUIC" if (c.proto == "UDP" and c.remote_port == 443) else ("TLS" if c.remote_port == 443 else c.proto),
                            "src_ip": c.local_ip,
                            "src_port": c.local_port,
                            "src_mac": "",
                            "src_device": local_host_label,
                            "is_local_pc": True,
                            "dst_ip": c.remote_ip,
                            "dst_port": c.remote_port,
                            "domain": os_dom,
                            "domain_source": "OS DNS Cache" if os_dom else "",
                            "sni": "",
                            "alpn": "",
                            "tls_version": c.status,
                            "ja3": "",
                            "http_ua": "",
                            "http_uri": "",
                            "ssh_banner": "",
                            "is_stratum": c.remote_port in (3333, 14444),
                            "app": "",
                            "category": "",
                            "route": "",
                            "packets_out": 1,
                            "packets_in": 1,
                            "bytes_out": 0,
                            "bytes_in": 0,
                            "rate_bps": 0,
                            "_win_bytes": 0,
                            "pid": c.pid,
                            "ppid": c.proc.ppid,
                            "proc_name": c.proc.name,
                            "proc_parent": c.proc.parent_name,
                            "proc_exe": c.proc.exe,
                            "proc_user": c.proc.username,
                            "proc_sig_status": c.proc.sig_status,
                            "proc_sig_signer": c.proc.sig_signer,
                            "proc_sha256": c.proc.sha256,
                            "ghost_confirmed": False,
                            "beacon_interval": None,
                            "risk": "CLEAN",
                            "alert_ids": [],
                        }
                        self.flows[flow_id] = flow

                        if not is_private_or_special_ip(c.remote_ip):
                            b_res = self.threat_intel.record_connection_for_beaconing(c.local_ip, c.remote_ip, c.remote_port, now)
                            if b_res:
                                flow["beacon_interval"] = b_res
                    else:
                        flow["last_seen"] = now
                        flow["tls_version"] = c.status
                        if os_dom and not flow["domain"]:
                            flow["domain"] = os_dom
                            flow["domain_source"] = "OS DNS Cache"
                        p_fresh = self.correlator.get_cached_process(c.pid) or c.proc
                        flow["proc_sig_status"] = p_fresh.sig_status
                        flow["proc_sig_signer"] = p_fresh.sig_signer
                        flow["proc_sha256"] = p_fresh.sha256

                    app_name, category = classify_application(
                        domain=flow["domain"],
                        dst_ip=c.remote_ip,
                        dst_port=c.remote_port,
                        proto=c.proto,
                        l7_proto=flow["l7_proto"],
                        proc_name=flow["proc_name"],
                        vpn_endpoints=self.config.vpn_endpoints,
                    )
                    flow["app"] = app_name
                    flow["category"] = category
                    flow["route"] = self.enricher.classify_route_path(c.remote_ip, flow["domain"], flow["l7_proto"])

                    if not is_private_or_special_ip(c.remote_ip):
                        # For Idle-Watch in system mode, treat active ESTABLISHED sockets opened after arming as >=1500B
                        if self.idle_watch_active and flow["first_seen"] >= self.idle_watch_since and flow["bytes_out"] == 0:
                            flow["bytes_out"] = 1500
                        new_alerts = self.threat_intel.evaluate_flow(
                            flow,
                            idle_watch_active=self.idle_watch_active,
                            idle_watch_since=self.idle_watch_since,
                        )
                        if new_alerts:
                            sev_rank = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                            for al in new_alerts:
                                if al.id not in flow["alert_ids"]:
                                    flow["alert_ids"].append(al.id)
                                if sev_rank.get(al.severity, 0) > sev_rank.get(flow["risk"], 0):
                                    flow["risk"] = al.severity
                                self.shield.notify_webhook_async(asdict(al))

            time.sleep(0.5)

    # ------------------------------------------------------------------
    # Tier 2 Worker: Out-of-Band Router SSH PCAP Stream
    # ------------------------------------------------------------------
    def _read_exact(self, stream, n: int) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < n:
            chunk = stream.read(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _router_capture_worker(self) -> None:
        base_bpf = f"not (host {self.config.router_host} and port {self.config.router_port})"
        if self.config.extra_bpf:
            bpf = f"({base_bpf}) and ({self.config.extra_bpf})"
        else:
            bpf = base_bpf
        remote_cmd = f"tcpdump -i {self.config.router_iface} -nn -U -s {self.config.snaplen} -w - '{bpf}'"

        while True:
            with self._lock:
                if not self.capturing or self.config.mode != "router":
                    break

            proc = None
            try:
                proc = subprocess.Popen(
                    [*self.config.build_ssh_args(), remote_cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                with self._lock:
                    if not self.capturing:
                        proc.kill()
                        break
                    self._ssh_proc = proc

                stdout = proc.stdout
                if stdout is None:
                    raise RuntimeError("No stdout pipe from SSH process")

                ghdr = self._read_exact(stdout, 24)
                if not ghdr:
                    err_txt = (proc.stderr.read(400).decode("utf-8", errors="ignore") if proc.stderr else "").strip()
                    raise RuntimeError(f"SSH PCAP stream failed ({self.config.router_host}): {err_txt or 'EOF'}")

                magic = struct.unpack("<I", ghdr[:4])[0]
                if magic == 0xA1B2C3D4:
                    endian = "<"
                elif magic == 0xD4C3B2A1:
                    endian = ">"
                else:
                    raise RuntimeError(f"Invalid libpcap header magic: {hex(magic)}")

                with self._lock:
                    self.pcap_global_hdr = ghdr
                    self.capture_error = ""

                while True:
                    with self._lock:
                        if not self.capturing or self.config.mode != "router":
                            break
                    phdr = self._read_exact(stdout, 16)
                    if not phdr:
                        break
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", phdr)
                    if incl_len > 65535:
                        break
                    raw_frame = self._read_exact(stdout, incl_len)
                    if not raw_frame:
                        break

                    pkt_ts = ts_sec + (ts_usec / 1_000_000.0)
                    self._process_frame(pkt_ts, ts_sec, ts_usec, incl_len, orig_len, raw_frame)

            except Exception as exc:
                with self._lock:
                    if self.capturing and self.config.mode == "router":
                        self.capture_error = str(exc)
            finally:
                if proc is not None:
                    with contextlib.suppress(Exception):
                        proc.kill()

            with self._lock:
                if not self.capturing or self.config.mode != "router":
                    break
            time.sleep(2.5)

    # ------------------------------------------------------------------
    # Synthetic Demo Worker (RFC 5737 & RFC 7042 Clean Test Vectors)
    # ------------------------------------------------------------------
    def _demo_worker(self) -> None:
        """Generate realistic RFC-5737 synthetic flows & threat alerts for `--demo` mode."""
        local_ip = sorted(self.correlator.local_ips)[0] if self.correlator.local_ips else "192.168.1.100"
        self.correlator.local_ips.add(local_ip)
        self.enricher.register_device_hint(local_ip, "00:00:5e:00:53:10", "Workstation-PC")
        self.enricher.register_device_hint("192.168.1.105", "00:00:5e:00:53:20", "MacBook-Pro")
        self.enricher.register_device_hint("192.168.1.112", "00:00:5e:00:53:30", "SmartCam-IoT")

        demo_targets = [
            ("140.82.121.4", "US", "United States", "AS36459", "GitHub, Inc.", "api.github.com", [0x1301, 0x1302, 0xC02F]),
            ("104.18.32.7", "US", "United States", "AS13335", "Cloudflare, Inc.", "chatgpt.com", [0x1301, 0x1302, 0x1303]),
            ("142.250.74.14", "US", "United States", "AS15169", "Google LLC", "youtube.com", [0x1301, 0xC02B, 0xC02F]),
            ("149.154.167.91", "NL", "Netherlands", "AS62041", "Telegram Messenger Inc", "venus.web.telegram.org", [0x1301, 0x1302]),
            ("198.51.100.42", "DE", "Germany", "AS64501", "TestNet Relay", "relay-01.net.anydesk.com", [0x1301, 0xC02F]),
            ("203.0.113.99", "NL", "Netherlands", "AS64496", "Bulletproof Test C2", "", [0x002F, 0x0035]),
        ]
        for ip, cc, country, asn, org, _sni, _cs in demo_targets:
            self.enricher.seed_geo_entry(ip, cc, country, asn, org)

        # Strictly IANA RFC 7042 documentation MAC addresses (00:00:5E:00:53:00 - 00:00:5E:00:53:FF)
        gw_mac = b"\x00\x00\x5e\x00\x53\x01"
        pc_mac = b"\x00\x00\x5e\x00\x53\x10"
        mb_mac = b"\x00\x00\x5e\x00\x53\x20"
        iot_mac = b"\x00\x00\x5e\x00\x53\x30"

        tick = 0
        while True:
            with self._lock:
                if not self.capturing or self.config.mode != "demo":
                    break
            now = time.time()
            ts_sec = int(now)
            ts_usec = int((now - ts_sec) * 1_000_000)

            for idx, (dst_ip, _cc, _ctry, _asn, _org, sni, ciphers) in enumerate(demo_targets[:4]):
                src_ip = local_ip if idx % 2 == 0 else "192.168.1.105"
                smac = pc_mac if src_ip == local_ip else mb_mac
                sport = 52100 + idx
                ch = _build_tls_client_hello(sni, ciphers) if tick % 10 == 0 else b"\x17\x03\x03\x00\x40" + (b"\xaa" * 64)
                out_frame = _build_ipv4_tcp_frame(smac, gw_mac, src_ip, dst_ip, sport, 443, ch, 0x02 if tick == 0 else 0x18)
                in_frame = _build_ipv4_tcp_frame(gw_mac, smac, dst_ip, src_ip, 443, sport, b"\x17\x03\x03\x02\x00" + (b"\xbb" * 512), 0x18)
                self._process_frame(now, ts_sec, ts_usec, len(out_frame), len(out_frame) + random.randint(80, 400), out_frame)
                self._process_frame(now, ts_sec, ts_usec, len(in_frame), len(in_frame) + random.randint(600, 4200), in_frame)

            if tick >= 2 and tick % 4 == 0:
                ad_ch = _build_tls_client_hello("relay-01.net.anydesk.com", [0x1301, 0xC02F])
                ad_frame = _build_ipv4_tcp_frame(iot_mac, gw_mac, "192.168.1.112", "198.51.100.42", 54321, 443, ad_ch, 0x18)
                self._process_frame(now, ts_sec, ts_usec, len(ad_frame), len(ad_frame), ad_frame)

                # Simulated Out-of-Band GHOST SOCKET from local PC on unowned port 61337
                ghost_frame = _build_ipv4_tcp_frame(pc_mac, gw_mac, local_ip, "203.0.113.99", 61337, 4444, b"\x90" * 160, 0x02 if tick == 4 else 0x18)
                self._process_frame(now, ts_sec, ts_usec, len(ghost_frame), len(ghost_frame), ghost_frame)

            tick += 1
            time.sleep(0.5)

    # ------------------------------------------------------------------
    # Wire Packet Frame Processor (`router`, `pcap`, `demo`)
    # ------------------------------------------------------------------
    def _process_frame(
        self,
        pkt_ts: float,
        ts_sec: int,
        ts_usec: int,
        incl_len: int,
        orig_len: int,
        raw: bytes,
        use_wall_clock: bool = False,
    ) -> None:
        pkt = decode_ethernet_packet(pkt_ts, orig_len, raw)
        if pkt is None:
            return

        if pkt.dst_ip in ("255.255.255.255", "224.0.0.251", "224.0.0.252", "239.255.255.250") or pkt.dst_ip.startswith("ff02::"):
            with self._lock:
                self.pcap_ring.append((ts_sec, ts_usec, incl_len, orig_len, raw))
            return

        now = time.time() if (not use_wall_clock and self.config.mode != "pcap") else (time.time() if use_wall_clock else pkt_ts)

        if pkt.l7_proto == "DNS" and pkt.dns_qname:
            if pkt.dns_qname.endswith(".asn.cymru.com") or pkt.dns_qname == "ipwho.is":
                return
            if pkt.dns_is_response:
                for ip_ans in pkt.dns_resolved_ips:
                    self.dns_ip_map[ip_ans] = (pkt.dns_qname, now)
                client_ip = pkt.dst_ip
                dev_lbl = self.enricher.get_device_label(client_ip, pkt.dst_mac)
                with self._lock:
                    self.recent_dns.appendleft({
                        "ts": now,
                        "client_ip": client_ip,
                        "device": dev_lbl,
                        "qname": pkt.dns_qname,
                        "ips": pkt.dns_resolved_ips[:4],
                    })
            else:
                client_ip = pkt.src_ip
                dev_lbl = self.enricher.get_device_label(client_ip, pkt.src_mac)
                dns_alerts = self.threat_intel.check_dns_query(client_ip, dev_lbl, pkt.dns_qname)
                for al in dns_alerts:
                    self.shield.notify_webhook_async(asdict(al))

        src_is_lan = self.config.is_lan_client_ip(pkt.src_ip)
        dst_is_lan = self.config.is_lan_client_ip(pkt.dst_ip)

        if src_is_lan and not dst_is_lan:
            is_outbound = True
            c_ip, c_port, c_mac = pkt.src_ip, pkt.src_port, pkt.src_mac
            s_ip, s_port = pkt.dst_ip, pkt.dst_port
        elif dst_is_lan and not src_is_lan:
            is_outbound = False
            c_ip, c_port, c_mac = pkt.dst_ip, pkt.dst_port, pkt.dst_mac
            s_ip, s_port = pkt.src_ip, pkt.src_port
        elif src_is_lan and dst_is_lan:
            if pkt.dst_port <= pkt.src_port:
                is_outbound = True
                c_ip, c_port, c_mac = pkt.src_ip, pkt.src_port, pkt.src_mac
                s_ip, s_port = pkt.dst_ip, pkt.dst_port
            else:
                is_outbound = False
                c_ip, c_port, c_mac = pkt.dst_ip, pkt.dst_port, pkt.dst_mac
                s_ip, s_port = pkt.src_ip, pkt.src_port
        else:
            return

        if s_ip in self.config.gateway_ips and s_port not in (80, 443, 22, self.config.router_port):
            return

        flow_key_raw = f"{pkt.proto}:{c_ip}:{c_port}->{s_ip}:{s_port}"
        flow_id = hashlib.blake2b(flow_key_raw.encode("ascii"), digest_size=6).hexdigest()

        with self._lock:
            self.pcap_ring.append((ts_sec, ts_usec, incl_len, orig_len, raw))
            self.total_packets += 1
            self._sec_pkts += 1
            if is_outbound:
                self.total_bytes_out += orig_len
                self._sec_bytes_out += orig_len
            else:
                self.total_bytes_in += orig_len
                self._sec_bytes_in += orig_len

            flow = self.flows.get(flow_id)
            if flow is None:
                dns_hit = self.dns_ip_map.get(s_ip)
                initial_domain = dns_hit[0] if dns_hit else ""
                dev_label = self.enricher.get_device_label(c_ip, c_mac)
                is_pc = c_ip in self.correlator.local_ips
                is_syn = (pkt.proto == "TCP" and (pkt.tcp_flags & 0x02) != 0 and (pkt.tcp_flags & 0x10) == 0) or (
                    pkt.proto == "UDP" and (now - self.capture_started_at) > 2.5
                )
                flow = {
                    "id": flow_id,
                    "first_seen": now,
                    "last_seen": now,
                    "seen_syn": is_syn,
                    "proto": pkt.proto,
                    "l7_proto": pkt.l7_proto or pkt.proto,
                    "src_ip": c_ip,
                    "src_port": c_port,
                    "src_mac": c_mac,
                    "src_device": dev_label,
                    "is_local_pc": is_pc,
                    "dst_ip": s_ip,
                    "dst_port": s_port,
                    "domain": initial_domain,
                    "domain_source": "DNS" if initial_domain else "",
                    "sni": "",
                    "alpn": "",
                    "tls_version": "",
                    "ja3": "",
                    "http_ua": "",
                    "http_uri": "",
                    "ssh_banner": "",
                    "is_stratum": False,
                    "app": "",
                    "category": "",
                    "route": "",
                    "packets_out": 0,
                    "packets_in": 0,
                    "bytes_out": 0,
                    "bytes_in": 0,
                    "rate_bps": 0,
                    "_win_bytes": 0,
                    "pid": None,
                    "ppid": 0,
                    "proc_name": "",
                    "proc_parent": "",
                    "proc_exe": "",
                    "proc_user": "",
                    "proc_sig_status": "",
                    "proc_sig_signer": "",
                    "proc_sha256": "",
                    "ghost_confirmed": False,
                    "beacon_interval": None,
                    "risk": "CLEAN",
                    "alert_ids": [],
                }
                self.flows[flow_id] = flow

                if is_outbound and not is_private_or_special_ip(s_ip):
                    b_res = self.threat_intel.record_connection_for_beaconing(c_ip, s_ip, s_port, now)
                    if b_res:
                        flow["beacon_interval"] = b_res

            flow["last_seen"] = now
            flow["_win_bytes"] += orig_len
            if is_outbound:
                flow["packets_out"] += 1
                flow["bytes_out"] += orig_len
            else:
                flow["packets_in"] += 1
                flow["bytes_in"] += orig_len

            if pkt.l7_proto and (flow["l7_proto"] in ("TCP", "UDP", "") or pkt.l7_proto in ("TLS", "HTTP", "QUIC", "Stratum-Mining", "BitTorrent")):
                flow["l7_proto"] = pkt.l7_proto
            if pkt.sni:
                flow["sni"] = pkt.sni
                flow["domain"] = pkt.sni
                flow["domain_source"] = "TLS SNI"
            if pkt.http_host and not flow["sni"]:
                flow["domain"] = pkt.http_host
                flow["domain_source"] = "HTTP Host"
            if pkt.dns_qname and s_port == 53:
                flow["domain"] = pkt.dns_qname
                flow["domain_source"] = "DNS Query"
            if not flow["domain"]:
                dns_hit = self.dns_ip_map.get(s_ip)
                if dns_hit:
                    flow["domain"] = dns_hit[0]
                    flow["domain_source"] = "DNS"

            if pkt.alpn:
                flow["alpn"] = pkt.alpn
            if pkt.tls_version:
                flow["tls_version"] = pkt.tls_version
            if pkt.ja3:
                flow["ja3"] = pkt.ja3
            if pkt.http_ua:
                flow["http_ua"] = pkt.http_ua
            if pkt.http_uri:
                flow["http_uri"] = f"{pkt.http_method} {pkt.http_uri}"
            if pkt.ssh_banner:
                flow["ssh_banner"] = pkt.ssh_banner
            if pkt.is_stratum:
                flow["is_stratum"] = True

            if flow["is_local_pc"] and pkt.proto in ("TCP", "UDP") and self.config.mode != "pcap":
                if flow["pid"] is None:
                    pinfo = self.correlator.lookup_host_socket(pkt.proto, c_ip, c_port, s_ip, s_port)
                    if pinfo is not None:
                        flow["pid"] = pinfo.pid
                        flow["ppid"] = pinfo.ppid
                        flow["proc_name"] = pinfo.name
                        flow["proc_parent"] = pinfo.parent_name
                        flow["proc_exe"] = pinfo.exe
                        flow["proc_user"] = pinfo.username
                        flow["proc_sig_status"] = pinfo.sig_status
                        flow["proc_sig_signer"] = pinfo.sig_signer
                        flow["proc_sha256"] = pinfo.sha256
                        flow["ghost_confirmed"] = False
                    elif self.config.mode == "demo" and c_port != 61337:
                        flow["pid"] = 4242
                        flow["proc_name"] = "browser-demo"
                        flow["proc_exe"] = "/usr/bin/browser-demo"
                        flow["proc_user"] = "demo"
                        flow["proc_sig_status"] = "Valid"
                        flow["proc_sig_signer"] = "Verified Publisher"
                        flow["proc_sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    elif (
                        is_outbound
                        and not flow["ghost_confirmed"]
                        and (flow["packets_out"] >= 3 or (self.config.mode == "demo" and c_port == 61337 and flow["packets_out"] >= 2))
                        and ((now - flow["first_seen"]) >= 0.70 or self.config.mode == "demo")
                        and s_port not in (53, 67, 68, 123, 137, 138, 1900, 5353, 5355)
                    ):
                        self.correlator.poll_sync()
                        pinfo2 = self.correlator.lookup_host_socket(pkt.proto, c_ip, c_port, s_ip, s_port)
                        if pinfo2 is not None:
                            flow["pid"] = pinfo2.pid
                            flow["ppid"] = pinfo2.ppid
                            flow["proc_name"] = pinfo2.name
                            flow["proc_parent"] = pinfo2.parent_name
                            flow["proc_exe"] = pinfo2.exe
                            flow["proc_user"] = pinfo2.username
                            flow["proc_sig_status"] = pinfo2.sig_status
                            flow["proc_sig_signer"] = pinfo2.sig_signer
                            flow["proc_sha256"] = pinfo2.sha256
                        else:
                            flow["ghost_confirmed"] = True
                else:
                    pinfo = self.correlator.get_cached_process(flow["pid"])
                    if pinfo:
                        flow["proc_sig_status"] = pinfo.sig_status
                        flow["proc_sig_signer"] = pinfo.sig_signer
                        flow["proc_sha256"] = pinfo.sha256

            app_name, category = classify_application(
                domain=flow["domain"],
                dst_ip=s_ip,
                dst_port=s_port,
                proto=pkt.proto,
                l7_proto=flow["l7_proto"],
                proc_name=flow["proc_name"],
                vpn_endpoints=self.config.vpn_endpoints,
            )
            flow["app"] = app_name
            flow["category"] = category
            route_path = self.enricher.classify_route_path(s_ip, flow["domain"], flow["l7_proto"])
            flow["route"] = route_path

            if route_path.startswith("VPN"):
                self._sec_vpn_bytes += orig_len
            elif route_path.startswith("WAN"):
                self._sec_wan_bytes += orig_len

            if not is_private_or_special_ip(s_ip):
                new_alerts = self.threat_intel.evaluate_flow(
                    flow,
                    idle_watch_active=self.idle_watch_active,
                    idle_watch_since=self.idle_watch_since,
                )
                if new_alerts:
                    sev_rank = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                    for al in new_alerts:
                        if al.id not in flow["alert_ids"]:
                            flow["alert_ids"].append(al.id)
                        if sev_rank.get(al.severity, 0) > sev_rank.get(flow["risk"], 0):
                            flow["risk"] = al.severity
                        self.shield.notify_webhook_async(asdict(al))

            if len(self.flows) > 900:
                cutoff = now - 90.0
                stale_ids = [k for k, v in self.flows.items() if v["last_seen"] < cutoff]
                for k in stale_ids[:200]:
                    self.flows.pop(k, None)

    # ------------------------------------------------------------------
    # 1 Hz Real-Time SOC Snapshot Aggregator
    # ------------------------------------------------------------------
    def tick_1s_snapshot(self) -> dict:
        now = time.time()

        # In Tier 1 (`system` mode), sample real host NIC deltas for the live bandwidth oscilloscope
        if self.config.mode == "system" and self.capturing:
            nic_in, nic_out, nic_pkts = self.correlator.sample_nic_delta()
        else:
            nic_in, nic_out, nic_pkts = 0, 0, 0

        with self._lock:
            if self.config.mode == "system" and self.capturing:
                b_in = nic_in
                b_out = nic_out
                b_wan = nic_in + nic_out
                b_vpn = 0
                pkts = nic_pkts
                self.total_bytes_in += nic_in
                self.total_bytes_out += nic_out
                self.total_packets += nic_pkts
            else:
                b_in = self._sec_bytes_in
                b_out = self._sec_bytes_out
                b_vpn = self._sec_vpn_bytes
                b_wan = self._sec_wan_bytes
                pkts = self._sec_pkts
                self._sec_bytes_in = 0
                self._sec_bytes_out = 0
                self._sec_vpn_bytes = 0
                self._sec_wan_bytes = 0
                self._sec_pkts = 0

            mbps_down = round((b_in * 8) / 1_000_000.0, 2)
            mbps_up = round((b_out * 8) / 1_000_000.0, 2)
            mbps_vpn = round((b_vpn * 8) / 1_000_000.0, 2)
            mbps_wan = round((b_wan * 8) / 1_000_000.0, 2)

            point = {
                "ts": round(now, 1),
                "down_mbps": mbps_down,
                "up_mbps": mbps_up,
                "vpn_mbps": mbps_vpn,
                "wan_mbps": mbps_wan,
                "pps": pkts,
            }
            self.timeseries.append(point)

            active_flows: List[dict] = []
            app_totals: Dict[str, dict] = {}
            dev_totals: Dict[str, dict] = {}
            ghost_count = 0
            verified_pc_flows = 0

            idle_cutoff = 15.0 if self.config.mode == "system" else 90.0
            purge_cutoff = 45.0 if self.config.mode == "system" else 180.0

            for fid, f in list(self.flows.items()):
                age_idle = max(0.0, now - f["last_seen"])
                if age_idle > purge_cutoff and f["risk"] == "CLEAN" and self.config.mode != "pcap":
                    self.flows.pop(fid, None)
                    continue

                f["rate_bps"] = f["_win_bytes"] * 8
                f["_win_bytes"] = 0
                if self.config.mode != "system":
                    f["src_device"] = self.enricher.get_device_label(f["src_ip"], f["src_mac"])
                geo = self.enricher.get_geo_info(f["dst_ip"])

                if f["is_local_pc"]:
                    if f["ghost_confirmed"]:
                        ghost_count += 1
                    elif f["pid"] is not None:
                        verified_pc_flows += 1

                tot_b = f["bytes_in"] + f["bytes_out"]
                metric_weight = tot_b if tot_b > 0 else 1024  # In system mode socket table lacks per-socket bytes
                app_key = f["app"]
                arec = app_totals.get(app_key)
                if not arec:
                    arec = {"app": app_key, "category": f["category"], "bytes": 0, "flows": 0}
                    app_totals[app_key] = arec
                arec["bytes"] += metric_weight
                arec["flows"] += 1

                dip = f["src_ip"]
                drec = dev_totals.get(dip)
                if not drec:
                    drec = {
                        "ip": dip,
                        "mac": f["src_mac"],
                        "device": f["src_device"],
                        "is_local_pc": f["is_local_pc"],
                        "bytes_in": 0,
                        "bytes_out": 0,
                        "flows": 0,
                        "alerts": 0,
                    }
                    dev_totals[dip] = drec
                drec["bytes_in"] += f["bytes_in"]
                drec["bytes_out"] += f["bytes_out"]
                drec["flows"] += 1
                if f["risk"] in ("HIGH", "CRITICAL", "MEDIUM"):
                    drec["alerts"] += 1

                if age_idle <= idle_cutoff or f["risk"] != "CLEAN" or self.config.mode == "pcap":
                    active_flows.append({
                        "id": f["id"],
                        "last_seen": round(f["last_seen"], 1),
                        "idle_sec": round(age_idle, 1),
                        "proto": f["proto"],
                        "l7_proto": f["l7_proto"],
                        "src_ip": f["src_ip"],
                        "src_port": f["src_port"],
                        "src_device": f["src_device"],
                        "is_local_pc": f["is_local_pc"],
                        "dst_ip": f["dst_ip"],
                        "dst_port": f["dst_port"],
                        "domain": f["domain"],
                        "domain_source": f["domain_source"],
                        "seen_syn": f.get("seen_syn", False),
                        "ja3": f["ja3"],
                        "tls_version": f["tls_version"],
                        "alpn": f["alpn"],
                        "app": f["app"],
                        "category": f["category"],
                        "route": f["route"],
                        "cc": geo.get("cc", ""),
                        "org": geo.get("org", ""),
                        "asn": geo.get("asn", ""),
                        "bytes_in": f["bytes_in"],
                        "bytes_out": f["bytes_out"],
                        "rate_bps": f["rate_bps"],
                        "pid": f["pid"],
                        "proc_name": f["proc_name"],
                        "proc_exe": f["proc_exe"],
                        "proc_sig_status": f["proc_sig_status"],
                        "proc_sig_signer": f["proc_sig_signer"],
                        "proc_sha256": f.get("proc_sha256", ""),
                        "ghost_confirmed": f["ghost_confirmed"],
                        "risk": f["risk"],
                    })

            if self.config.mode == "router":
                for dip, dmeta in self.enricher.devices.items():
                    if dip not in dev_totals and dip not in self.config.gateway_ips:
                        dev_totals[dip] = {
                            "ip": dip,
                            "mac": dmeta.get("mac", ""),
                            "device": dmeta.get("hostname", dip),
                            "is_local_pc": dip in self.correlator.local_ips,
                            "bytes_in": 0,
                            "bytes_out": 0,
                            "flows": 0,
                            "alerts": 0,
                        }

            sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
            active_flows.sort(
                key=lambda x: (
                    sev_order.get(x["risk"], 0),
                    1 if x["rate_bps"] > 0 else 0,
                    x["rate_bps"],
                    x["last_seen"],
                ),
                reverse=True,
            )

            pc_procs = self.correlator.get_active_host_processes_summary(active_flows)
            alerts_serialized = [asdict(a) for a in self.threat_intel.alerts[:100]]
            crit_cnt = sum(1 for a in self.threat_intel.alerts if a.severity == "CRITICAL")
            high_cnt = sum(1 for a in self.threat_intel.alerts if a.severity == "HIGH")
            med_cnt = sum(1 for a in self.threat_intel.alerts if a.severity == "MEDIUM")

            # Compute intuitive Shield Health Score (0 - 100)
            score = 100
            score -= ghost_count * 40
            score -= crit_cnt * 25
            score -= high_cnt * 8
            score -= med_cnt * 2
            shield_score = max(0, min(100, score))

            tier_num = 2 if self.config.mode in ("router", "demo") else 1
            tier_lbl = (
                "Tier 2 // Router Network Shield"
                if self.config.mode == "router"
                else "Tier 1 // Host System Shield"
                if self.config.mode == "system"
                else "Tier 2 // Demo Simulation"
                if self.config.mode == "demo"
                else "Forensic PCAP Analyzer"
            )

            dns_stream = (
                list(self.correlator.recent_os_dns)[:40]
                if self.config.mode == "system"
                else list(self.recent_dns)[:40]
            )

            return {
                "ts": now,
                "status": {
                    "mode": self.config.mode,
                    "tier": tier_num,
                    "tier_label": tier_lbl,
                    "default_lang": self.config.default_lang,
                    "os_name": self.correlator.os_name,
                    "hostname": self.correlator.hostname,
                    "router_host": self.config.router_host,
                    "router_port": self.config.router_port,
                    "router_user": self.config.router_user,
                    "router_iface": self.config.router_iface,
                    "capturing": self.capturing,
                    "error": self.capture_error,
                    "fallback_notice": self.fallback_notice,
                    "idle_watch": self.idle_watch_active,
                    "idle_watch_since": self.idle_watch_since,
                    "local_pc_ips": sorted(self.correlator.local_ips),
                    "os_sockets_polled": self.correlator.total_os_sockets,
                    "poll_ms": round(self.correlator.last_poll_ms, 2),
                    "direct_cidrs_synced": self.enricher.direct_cidr_count,
                    "pcap_buffered_pkts": len(self.pcap_ring),
                    "active_response": self.config.enable_active_response,
                },
                "kpis": {
                    "shield_score": shield_score,
                    "down_mbps": mbps_down,
                    "up_mbps": mbps_up,
                    "total_bytes_in": self.total_bytes_in,
                    "total_bytes_out": self.total_bytes_out,
                    "total_packets": self.total_packets,
                    "active_flows": len(active_flows),
                    "verified_pc_flows": verified_pc_flows,
                    "ghost_sockets": ghost_count,
                    "alerts_critical": crit_cnt,
                    "alerts_high": high_cnt,
                    "alerts_medium": med_cnt,
                    "active_blocks": len(self.shield.active_rules),
                },
                "timeseries": list(self.timeseries),
                "flows": active_flows[:250],
                "top_apps": sorted(app_totals.values(), key=lambda x: (x["bytes"], x["flows"]), reverse=True)[:20],
                "devices": sorted(dev_totals.values(), key=lambda x: (x["bytes_in"] + x["bytes_out"], x["flows"]), reverse=True),
                "pc_processes": pc_procs,
                "alerts": alerts_serialized,
                "recent_dns": dns_stream,
                "intel": self.threat_intel.summary_counts(),
                "active_rules": self.shield.list_active_rules(),
                "router_audit": self.shield.last_router_audit,
            }

    def export_pcap_bytes(self) -> bytes:
        with self._lock:
            out = bytearray(self.pcap_global_hdr)
            for ts_sec, ts_usec, incl_len, orig_len, raw in self.pcap_ring:
                out.extend(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
                out.extend(raw)
            return bytes(out)

    def get_flow_details(self, flow_id: str) -> Optional[dict]:
        with self._lock:
            f = self.flows.get(flow_id)
            if not f:
                return None
            geo = self.enricher.get_geo_info(f["dst_ip"])
            matched_alerts = [asdict(a) for a in self.threat_intel.alerts if a.flow_id == flow_id]
            fw_cmds = {}
            if not is_private_or_special_ip(f["dst_ip"]):
                with contextlib.suppress(Exception):
                    fw_cmds = self.shield.generate_host_firewall_commands(f["dst_ip"])
            return {
                **{k: v for k, v in f.items() if not k.startswith("_")},
                "geo": geo,
                "matched_alerts": matched_alerts,
                "firewall_commands": fw_cmds,
            }
