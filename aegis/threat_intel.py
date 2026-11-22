"""
Threat Intelligence Feeds & NGFW IDS Signature Engine.
Combines live Abuse.ch / EmergingThreats / IPsum / CINS / Tor IOC feeds with Suricata-style
L7 DPI, JA3, C2 Beaconing, DNS Tunneling, LOLBin, and Rootkit Ghost-Socket rules.
"""

from __future__ import annotations

import csv
import io
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests

from .dpi_engine import shannon_entropy

# Curated Malware / C2 / RAT TLS JA3 Fingerprints (MD5)
BUILTIN_MALICIOUS_JA3: Dict[str, str] = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike Beacon (Default TLS)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit Meterpreter Reverse HTTPS",
    "e7d705a3286e19ea42f587b344ee6865": "Tor Client / Onion Router",
    "51c64c77e60f3980eea90869b68c58a8": "TrickBot / Emotet Banking Trojan",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet / IcedID Loader",
    "6734f37431670b3ab4292b8f60f29984": "TrickBot C2 Channel",
    "fc54e0d16d9764783542f0146a98b300": "AsyncRAT / QuasarRAT (.NET C2)",
    "19e29534fd49dd27d09234e639c4057e": "RedLine Stealer / Clipper",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Dridex Malware",
    "8f52d1ce303fb4a6515836aec3cc16b1": "DarkComet / NjRAT",
    "e35df3e00ca4ef31d42b34bebaa2f86e": "Sliver C2 Implant",
    "b386946a5a44d1ddcc843bc75336dfce": "IcedID / BokBot C2",
    "ec74a5c51106f0419184d0dd08fb05bc": "QakBot / QBot C2",
    "c12f54a3f91dc7bafd92cb59fe009a35": "BazarLoader / Conti C2",
    "8916410db85077a5460817142dcbc8de": "Ursnif / Gozi ISFB",
    "2d1eb5817ece335c24904f516ad5da12": "PoshC2 / PowerShell Empire",
    "b742b407517bac9536a77a7b0fee28e9": "Vidar / Raccoon InfoStealer",
    "bc6c386f480ee97b9d9e52d472b772d8": "Remcos RAT C2",
}

# Classic Backdoor / RAT / Reverse-Shell / Miner Ports
SUSPICIOUS_PORTS: Dict[int, str] = {
    1337: "Backdoor / Leet Shell (1337)",
    3333: "Stratum Crypto-Mining Pool (3333)",
    4444: "Metasploit / Reverse Shell (4444)",
    4445: "Reverse Shell / Worm (4445)",
    5554: "Sasser / ADB / Worm (5554)",
    5555: "Android ADB / Backdoor (5555)",
    6666: "IRC Botnet C2 (6666)",
    6667: "IRC Botnet C2 (6667)",
    6697: "IRC-TLS Botnet C2 (6697)",
    7777: "Backdoor / Trojan Port (7777)",
    8888: "Alt C2 / Proxy Port (8888)",
    9001: "Tor ORPort / Relay (9001)",
    9050: "Tor SOCKS Proxy (9050)",
    14444: "Monero XMRig Mining Pool (14444)",
    31337: "Back Orifice / Elite Backdoor (31337)",
}

# Living-off-the-Land binaries rarely supposed to initiate arbitrary external sessions
LOLBIN_PROCESSES: Set[str] = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "installutil.exe",
    "csc.exe",
    "vbc.exe",
}

# Public Anycast DNS resolvers excluded from Direct-to-IP medium alerts
PUBLIC_DNS_IPS: Set[str] = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "77.88.8.8",
    "77.88.8.1",
}

FEED_DEFINITIONS = [
    {
        "id": "feodo_c2",
        "name": "Abuse.ch Feodo Tracker (Active Botnet C2 Servers)",
        "name_ru": "Abuse.ch Feodo Tracker (Активные C2-серверы ботнетов)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "filename": "feodo_ips.txt",
        "kind": "ip",
        "label": "Feodo Botnet C2",
    },
    {
        "id": "ipsum_l3",
        "name": "IPsum Threat Intel L3+ (30+ Aggregated C2 & Malware Lists)",
        "name_ru": "IPsum Threat Intel L3+ (Агрегатор 30+ баз C2 и ВПО)",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "filename": "ipsum_l3.txt",
        "kind": "ip",
        "label": "IPsum Multi-Feed Threat IP",
    },
    {
        "id": "cins_army",
        "name": "CINS Army Sentinel (Active Scanners & Hostile Nodes)",
        "name_ru": "CINS Army Sentinel (Активные атакующие узлы и сканеры)",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "filename": "cins_army.txt",
        "kind": "ip",
        "label": "CINS Army Malicious Host",
    },
    {
        "id": "et_compromised",
        "name": "Proofpoint Emerging Threats (Compromised Hosts)",
        "name_ru": "Proofpoint Emerging Threats (Скомпрометированные хосты)",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "filename": "et_compromised.txt",
        "kind": "ip",
        "label": "EmergingThreats Compromised Host",
    },
    {
        "id": "tor_exits",
        "name": "Tor Project Bulk Exit Nodes",
        "name_ru": "Tor Project Bulk Exit Nodes (Выходные узлы сети Tor)",
        "url": "https://check.torproject.org/torbulkexitlist",
        "filename": "tor_exits.txt",
        "kind": "tor_ip",
        "label": "Tor Network Exit Node",
    },
    {
        "id": "urlhaus_domains",
        "name": "URLhaus Malware Filter (Online Malware & C2 Domains)",
        "name_ru": "URLhaus Malware Filter (Онлайн-домены ВПО и C2)",
        "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt",
        "filename": "urlhaus_hosts.txt",
        "kind": "domain",
        "label": "URLhaus Malware Domain",
    },
]


@dataclass
class SecurityAlert:
    id: str
    ts: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    sig_id: str
    mitre: str
    title: str
    description: str
    title_ru: str
    description_ru: str
    src_ip: str
    src_device: str
    dst_ip: str
    dst_port: int
    domain: str
    process_name: str
    flow_id: str


class ThreatIntelEngine:
    def __init__(
        self,
        feeds_dir: Path,
        allowlist_ips: Optional[Iterable[str]] = None,
    ) -> None:
        self.feeds_dir = feeds_dir
        self.feeds_dir.mkdir(parents=True, exist_ok=True)
        self.benign_direct_ips: Set[str] = set(PUBLIC_DNS_IPS)
        if allowlist_ips:
            self.benign_direct_ips.update(allowlist_ips)

        self.malicious_ips: Dict[str, str] = {}
        self.tor_ips: Set[str] = set()
        self.malicious_ja3: Dict[str, str] = dict(BUILTIN_MALICIOUS_JA3)
        self.malicious_domains: Dict[str, str] = {}
        self.feed_stats: List[dict] = []
        self.last_update_ts: float = 0.0

        self._beacon_times: Dict[Tuple[str, str, int], List[float]] = {}
        self._fired_keys: Set[Tuple[str, str]] = set()
        self._alert_seq: int = 0
        self.alerts: List[SecurityAlert] = []

        self.reload_from_disk()

    def update_all_feeds(self, timeout: int = 12) -> List[dict]:
        """Download fresh IOC feeds from public Threat Intel repositories."""
        headers = {"User-Agent": "Aegis-NGFW-SOC/0.1"}
        for fdef in FEED_DEFINITIONS:
            target = self.feeds_dir / fdef["filename"]
            try:
                resp = requests.get(fdef["url"], headers=headers, timeout=timeout)
                if resp.status_code == 200 and len(resp.text) > 32:
                    target.write_text(resp.text, encoding="utf-8", errors="ignore")
            except Exception:
                pass
        self.reload_from_disk()
        return self.feed_stats

    def reload_from_disk(self) -> None:
        mal_ips: Dict[str, str] = {}
        tor_ips: Set[str] = set()
        mal_ja3: Dict[str, str] = dict(BUILTIN_MALICIOUS_JA3)
        mal_domains: Dict[str, str] = {}
        stats: List[dict] = []

        for fdef in FEED_DEFINITIONS:
            path = self.feeds_dir / fdef["filename"]
            count = 0
            mtime = path.stat().st_mtime if path.exists() else 0.0

            if path.exists():
                text = path.read_text(encoding="utf-8", errors="ignore")
                kind = fdef["kind"]

                if kind == "ip":
                    for line in text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith(";"):
                            continue
                        ip = line.split()[0].split(",")[0].strip()
                        if ip.count(".") == 3 and ip not in self.benign_direct_ips:
                            mal_ips[ip] = fdef["label"]
                            count += 1

                elif kind == "tor_ip":
                    for line in text.splitlines():
                        ip = line.strip()
                        if ip and not ip.startswith("#") and ip.count(".") == 3:
                            tor_ips.add(ip)
                            count += 1

                elif kind == "ja3":
                    reader = csv.reader(io.StringIO(text))
                    for row in reader:
                        if not row or row[0].startswith("#") or len(row) < 2:
                            continue
                        ja3_h = row[0].strip().lower()
                        if len(ja3_h) == 32:
                            desc = row[-1].strip() or fdef["label"]
                            mal_ja3[ja3_h] = f"SSLBL: {desc}"
                            count += 1

                elif kind == "domain":
                    for line in text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        dom = (
                            parts[1].lower().strip(".")
                            if len(parts) >= 2 and parts[0] in ("127.0.0.1", "0.0.0.0")
                            else parts[0].lower().strip(".")
                        )
                        if "." in dom and dom not in ("localhost", "localhost.localdomain"):
                            mal_domains[dom] = fdef["label"]
                            count += 1

            stats.append({
                "id": fdef["id"],
                "name": fdef["name"],
                "name_ru": fdef["name_ru"],
                "loaded_count": count,
                "updated_at": mtime,
                "online": path.exists() and count > 0,
            })

        stats.append({
            "id": "builtin_ngfw",
            "name": "Built-in Aegis NGFW Pack (RAT JA3, Miners, Rootkit Heuristics, LOLBins, DPI)",
            "name_ru": "Встроенная база Aegis NGFW (RAT JA3, Майнеры, Руткит-эвристики, LOLBins, DPI)",
            "loaded_count": len(BUILTIN_MALICIOUS_JA3) + len(SUSPICIOUS_PORTS) + len(LOLBIN_PROCESSES) + 220,
            "updated_at": time.time(),
            "online": True,
        })

        self.malicious_ips = mal_ips
        self.tor_ips = tor_ips
        self.malicious_ja3 = mal_ja3
        self.malicious_domains = mal_domains
        self.feed_stats = stats
        self.last_update_ts = time.time()

    def summary_counts(self) -> dict:
        return {
            "c2_ips": len(self.malicious_ips),
            "tor_nodes": len(self.tor_ips),
            "malicious_ja3": len(self.malicious_ja3),
            "malicious_domains": len(self.malicious_domains),
            "total_ioc": len(self.malicious_ips) + len(self.tor_ips) + len(self.malicious_ja3) + len(self.malicious_domains),
            "feeds": self.feed_stats,
        }

    def _emit_alert(
        self,
        dedup_key: str,
        sig_id: str,
        severity: str,
        mitre: str,
        title: str,
        description: str,
        title_ru: str,
        description_ru: str,
        src_ip: str,
        src_device: str,
        dst_ip: str,
        dst_port: int,
        domain: str,
        process_name: str,
        flow_id: str,
    ) -> Optional[SecurityAlert]:
        key = (dedup_key, sig_id)
        if key in self._fired_keys:
            return None
        self._fired_keys.add(key)
        self._alert_seq += 1
        alert = SecurityAlert(
            id=f"ALT-{self._alert_seq:05d}",
            ts=time.time(),
            severity=severity,
            sig_id=sig_id,
            mitre=mitre,
            title=title,
            description=description,
            title_ru=title_ru,
            description_ru=description_ru,
            src_ip=src_ip,
            src_device=src_device,
            dst_ip=dst_ip,
            dst_port=dst_port,
            domain=domain,
            process_name=process_name,
            flow_id=flow_id,
        )
        self.alerts.insert(0, alert)
        if len(self.alerts) > 400:
            self.alerts.pop()
        return alert

    def check_dns_query(self, src_ip: str, src_device: str, qname: str) -> List[SecurityAlert]:
        out: List[SecurityAlert] = []
        if not qname:
            return out

        d = qname.lower().strip(".")
        parts = d.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self.malicious_domains:
                lbl = self.malicious_domains[cand]
                al = self._emit_alert(
                    dedup_key=f"dns:{src_ip}:{cand}",
                    sig_id="AEGIS-004",
                    severity="CRITICAL",
                    mitre="T1566 / C2",
                    title=f"Malicious Domain DNS Query: {cand}",
                    description=f"Host {src_device} ({src_ip}) queried {qname}, listed in {lbl}.",
                    title_ru=f"Обращение к вредоносному домену: {cand}",
                    description_ru=f"Устройство {src_device} ({src_ip}) запросило DNS для домена {qname} (база {lbl}).",
                    src_ip=src_ip,
                    src_device=src_device,
                    dst_ip="DNS",
                    dst_port=53,
                    domain=qname,
                    process_name="",
                    flow_id="",
                )
                if al:
                    out.append(al)
                break

        longest_label = max((len(lbl) for lbl in parts[:-2]), default=0) if len(parts) >= 3 else 0
        if len(d) > 62 and longest_label >= 36 and not d.endswith((".arpa", ".local", ".icloud.com", ".apple.com", ".akadns.net", ".cloudfront.net")):
            sub = "".join(parts[:-2])
            ent = shannon_entropy(sub)
            if ent >= 3.85:
                al = self._emit_alert(
                    dedup_key=f"dnstun:{src_ip}:{parts[-2]}.{parts[-1]}",
                    sig_id="AEGIS-007",
                    severity="HIGH",
                    mitre="T1071.004",
                    title="Suspected DNS Tunneling / Exfiltration (High Entropy)",
                    description=f"Anomalous subdomain length {len(d)} chars (Shannon entropy {ent:.2f}): {qname[:70]}...",
                    title_ru="Подозрение на скрытый DNS-туннель (высокая энтропия)",
                    description_ru=f"Аномальный поддомен длиной {len(d)} симв. (энтропия Шеннона {ent:.2f}): {qname[:70]}...",
                    src_ip=src_ip,
                    src_device=src_device,
                    dst_ip="DNS",
                    dst_port=53,
                    domain=qname,
                    process_name="",
                    flow_id="",
                )
                if al:
                    out.append(al)

        return out

    def record_connection_for_beaconing(self, src_ip: str, dst_ip: str, dst_port: int, now: float) -> Optional[Tuple[float, float]]:
        """Record new flow start; return (mean_interval_sec, cv) if periodic C2 beaconing is detected."""
        key = (src_ip, dst_ip, dst_port)
        arr = self._beacon_times.setdefault(key, [])
        if arr and (now - arr[-1]) < 4.0:
            return None
        arr.append(now)
        if len(arr) > 12:
            arr.pop(0)
        if len(arr) < 6:
            return None

        intervals = [arr[i] - arr[i - 1] for i in range(1, len(arr))]
        mean = sum(intervals) / len(intervals)
        if mean < 12.0:
            return None
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std = math.sqrt(variance)
        cv = std / mean if mean > 0 else 1.0
        if cv <= 0.12:
            return mean, cv
        return None

    def evaluate_flow(self, flow: dict, idle_watch_active: bool, idle_watch_since: float) -> List[SecurityAlert]:
        """Evaluate an active flow against IOC feeds, L7 DPI signatures, and out-of-band rootkit checks."""
        triggered: List[SecurityAlert] = []
        fid = flow["id"]
        src_ip = flow["src_ip"]
        src_dev = flow["src_device"]
        dst_ip = flow["dst_ip"]
        dst_port = flow["dst_port"]
        domain = flow["domain"]
        ja3 = flow["ja3"]
        app = flow["app"]
        cat = flow["category"]
        proc_name = flow.get("proc_name") or ""
        proc_exe = flow.get("proc_exe") or ""
        proc_sig = flow.get("proc_sig_status") or ""

        # 1. CRITICAL: Ghost Socket (Out-of-Band Rootkit differential check)
        if flow.get("ghost_confirmed"):
            al = self._emit_alert(
                dedup_key=f"ghost:{src_ip}:{dst_ip}:{dst_port}",
                sig_id="AEGIS-001",
                severity="CRITICAL",
                mitre="T1014 (Rootkit)",
                title=f"GHOST SOCKET: Hidden Outbound Connection ({dst_ip}:{dst_port})",
                description=(
                    f"Router captured outbound packets ({flow['packets_out']} pkts, {flow['bytes_out']} B) "
                    f"from local host ({src_ip}:{flow['src_port']}) to {dst_ip}:{dst_port}, "
                    f"but the local OS kernel socket table shows NO owning process! "
                    f"Strong indicator of a kernel/userland rootkit or raw-socket bypass."
                ),
                title_ru=f"GHOST SOCKET: Скрытое от ОС соединение ({dst_ip}:{dst_port})",
                description_ru=(
                    f"Роутер зафиксировал исходящий трафик ({flow['packets_out']} пак., {flow['bytes_out']} Б) "
                    f"с этого узла ({src_ip}:{flow['src_port']}) на {dst_ip}:{dst_port}, "
                    f"но ядро ОС НЕ показывает этот открытый порт ни в одном процессе! "
                    f"Классический признак ядерного/пользовательского руткита или обхода сетевого стека ОС."
                ),
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name="[HIDDEN FROM OS]",
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        # 2. CRITICAL: Botnet C2 / Compromised IP match
        if dst_ip in self.malicious_ips:
            feed_lbl = self.malicious_ips[dst_ip]
            al = self._emit_alert(
                dedup_key=f"c2ip:{src_ip}:{dst_ip}",
                sig_id="AEGIS-002",
                severity="CRITICAL",
                mitre="T1071 (C2)",
                title=f"Threat Intel C2 Match ({feed_lbl}): {dst_ip}",
                description=f"Device {src_dev} ({src_ip}) connected to {dst_ip}:{dst_port} listed in {feed_lbl}. Process: {proc_name or 'N/A'}.",
                title_ru=f"Совпадение с базой C2 ботнетов ({feed_lbl}): {dst_ip}",
                description_ru=f"Устройство {src_dev} ({src_ip}) установило соединение с IP {dst_ip}:{dst_port} из базы угроз ({feed_lbl}). Процесс: {proc_name or 'н/д'}.",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        # 3. CRITICAL: Malicious TLS JA3 Fingerprint
        if ja3 and ja3 in self.malicious_ja3:
            ja3_lbl = self.malicious_ja3[ja3]
            al = self._emit_alert(
                dedup_key=f"ja3:{src_ip}:{ja3}:{dst_ip}",
                sig_id="AEGIS-003",
                severity="CRITICAL",
                mitre="T1573 (Encrypted C2)",
                title=f"Malicious TLS JA3 Fingerprint: {ja3_lbl}",
                description=f"TLS ClientHello from {src_dev} matched JA3 {ja3} ('{ja3_lbl}') targeting {domain or dst_ip}:{dst_port}.",
                title_ru=f"Вредоносный TLS JA3 отпечаток: {ja3_lbl}",
                description_ru=f"TLS ClientHello от {src_dev} имеет отпечаток JA3 {ja3} ('{ja3_lbl}'). Цель: {domain or dst_ip}:{dst_port}.",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        # 4. CRITICAL: Malicious Domain match on SNI / Host
        if domain:
            parts = domain.lower().strip(".").split(".")
            for i in range(max(0, len(parts) - 1)):
                cand = ".".join(parts[i:])
                if cand in self.malicious_domains:
                    lbl = self.malicious_domains[cand]
                    al = self._emit_alert(
                        dedup_key=f"maldom:{src_ip}:{cand}",
                        sig_id="AEGIS-004",
                        severity="CRITICAL",
                        mitre="T1566 / IOC",
                        title=f"Connection to Malicious Domain: {domain}",
                        description=f"Domain {domain} matched Threat Intel feed ({lbl}).",
                        title_ru=f"Соединение с вредоносным доменом: {domain}",
                        description_ru=f"Домен {domain} найден в базе вредоносных хостов ({lbl}).",
                        src_ip=src_ip,
                        src_device=src_dev,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        domain=domain,
                        process_name=proc_name,
                        flow_id=fid,
                    )
                    if al:
                        triggered.append(al)
                    break

        # 5. HIGH: Crypto-Mining (Stratum or Mining Pool)
        if cat == "Crypto-Mining" or flow.get("is_stratum"):
            al = self._emit_alert(
                dedup_key=f"miner:{src_ip}:{dst_ip}:{dst_port}",
                sig_id="AEGIS-005",
                severity="HIGH",
                mitre="T1496",
                title=f"Crypto-Mining Traffic Detected ({domain or dst_ip}:{dst_port})",
                description=f"Stratum protocol or mining pool connection from {src_dev} ({proc_name or src_ip}).",
                title_ru=f"Обнаружен трафик крипто-майнера ({domain or dst_ip}:{dst_port})",
                description_ru=f"Зафиксирован протокол Stratum или обращение к майнинг-пулу с {src_dev} ({proc_name or src_ip}).",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        # 6. HIGH: Remote Access Tool (AnyDesk / TeamViewer / RustDesk / RDP / VNC / Tunnel)
        if cat == "Remote Access":
            al = self._emit_alert(
                dedup_key=f"rat:{src_ip}:{app}:{dst_ip}",
                sig_id="AEGIS-006",
                severity="HIGH",
                mitre="T1219",
                title=f"Remote Access / Tunnel Tool Active: {app}",
                description=f"Device {src_dev} is communicating via {app} ({domain or dst_ip}:{dst_port}). Verify authorization.",
                title_ru=f"Активность средства удалённого доступа: {app}",
                description_ru=f"Устройство {src_dev} использует {app} ({domain or dst_ip}:{dst_port}). Убедитесь, что сеанс запущен вами.",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        # 7. HIGH: Tor Network Node
        if dst_ip in self.tor_ips:
            al = self._emit_alert(
                dedup_key=f"tor:{src_ip}:{dst_ip}",
                sig_id="AEGIS-008",
                severity="HIGH",
                mitre="T1090.003",
                title=f"Tor Network Node Connection ({dst_ip})",
                description=f"Traffic from {src_dev} ({proc_name or src_ip}) directed to known Tor node {dst_ip}:{dst_port}.",
                title_ru=f"Обращение к узлу сети Tor ({dst_ip})",
                description_ru=f"Трафик с {src_dev} ({proc_name or src_ip}) направлен на известный узел Tor ({dst_ip}:{dst_port}).",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        # 8. HIGH: LOLBin or Unsigned executable from Temp/Downloads
        p_low = proc_name.lower()
        exe_low = proc_exe.lower()
        if p_low in LOLBIN_PROCESSES:
            al = self._emit_alert(
                dedup_key=f"lolbin:{p_low}:{dst_ip}:{dst_port}",
                sig_id="AEGIS-010",
                severity="HIGH",
                mitre="T1218 (LOLBin)",
                title=f"LOLBin Interpreter Network Activity: {proc_name}",
                description=f"System utility {proc_name} ({proc_exe}) opened an external connection to {domain or dst_ip}:{dst_port}.",
                title_ru=f"Сетевая активность системного интерпретатора: {proc_name}",
                description_ru=f"Системная утилита {proc_name} ({proc_exe}) открыла внешнее соединение с {domain or dst_ip}:{dst_port}.",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)
        elif exe_low and any(seg in exe_low for seg in ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\", "/tmp/", "/dev/shm/")) and proc_sig == "NotSigned":
            al = self._emit_alert(
                dedup_key=f"unsigned_tmp:{proc_exe}:{dst_ip}",
                sig_id="AEGIS-010",
                severity="HIGH",
                mitre="T1204",
                title=f"Unsigned Binary in Temp/Downloads Communicating: {proc_name}",
                description=f"Unsigned binary ({proc_exe}) is sending traffic to {domain or dst_ip}:{dst_port}.",
                title_ru=f"Неподписанный бинарник из временной папки в сети: {proc_name}",
                description_ru=f"Файл без цифровой подписи ({proc_exe}) передаёт данные на {domain or dst_ip}:{dst_port}.",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        # 9. HIGH: Periodic C2 Beaconing
        if flow.get("beacon_interval"):
            iv, cv = flow["beacon_interval"]
            if cat not in ("Infrastructure", "OS & Telemetry", "Messaging"):
                al = self._emit_alert(
                    dedup_key=f"beacon:{src_ip}:{dst_ip}:{dst_port}",
                    sig_id="AEGIS-009",
                    severity="HIGH",
                    mitre="T1071 (Beaconing)",
                    title=f"Periodic Network Beacon Detected (~every {iv:.0f}s)",
                    description=f"Host {src_dev} connects to {domain or dst_ip}:{dst_port} at a fixed {iv:.1f}s interval (CV={cv:.2f}).",
                    title_ru=f"Обнаружен ритмичный сетевой маяк (~каждые {iv:.0f} сек)",
                    description_ru=f"Устройство {src_dev} регулярно стучится на {domain or dst_ip}:{dst_port} со средним интервалом {iv:.1f} сек (CV={cv:.2f}).",
                    src_ip=src_ip,
                    src_device=src_dev,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    domain=domain,
                    process_name=proc_name,
                    flow_id=fid,
                )
                if al:
                    triggered.append(al)

        # 10. HIGH: Idle-Watch ("Silence Mode") unplanned activity
        if idle_watch_active and flow["first_seen"] >= idle_watch_since and (flow["bytes_out"] + flow["bytes_in"]) > 1200:
            if dst_port not in (53, 67, 68, 123, 5353, 1900):
                al = self._emit_alert(
                    dedup_key=f"idle:{fid}",
                    sig_id="AEGIS-011",
                    severity="HIGH",
                    mitre="IDLE-WATCH",
                    title=f"Unplanned Traffic in Silence Mode: {app} ({domain or dst_ip})",
                    description=f"During active Silence Mode, {src_dev} ({proc_name or 'LAN device'}) exchanged {flow['bytes_out'] + flow['bytes_in']} B with {domain or dst_ip}:{dst_port}.",
                    title_ru=f"Активность в «Режиме тишины»: {app} ({domain or dst_ip})",
                    description_ru=f"Во время включённого контроля тишины {src_dev} ({proc_name or 'устройство LAN'}) передало {flow['bytes_out'] + flow['bytes_in']} Б на {domain or dst_ip}:{dst_port}.",
                    src_ip=src_ip,
                    src_device=src_dev,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    domain=domain,
                    process_name=proc_name,
                    flow_id=fid,
                )
                if al:
                    triggered.append(al)

        # 11. MEDIUM: Suspicious backdoor port
        if dst_port in SUSPICIOUS_PORTS:
            al = self._emit_alert(
                dedup_key=f"port:{src_ip}:{dst_ip}:{dst_port}",
                sig_id="AEGIS-013",
                severity="MEDIUM",
                mitre="T1048",
                title=f"Suspicious Destination Port: {SUSPICIOUS_PORTS[dst_port]}",
                description=f"Connection from {src_dev} to non-standard port {dst_ip}:{dst_port} ({proc_name or 'N/A'}).",
                title_ru=f"Нетипичный порт назначения: {SUSPICIOUS_PORTS[dst_port]}",
                description_ru=f"Соединение с {src_dev} на подозрительный порт {dst_ip}:{dst_port} ({proc_name or 'н/д'}).",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain,
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        # 12. MEDIUM: Direct-to-IP (no DNS resolution and no TLS SNI on newly initiated connection)
        if (
            not domain
            and flow.get("seen_syn")
            and dst_ip not in self.benign_direct_ips
            and cat not in ("Messaging", "Infrastructure", "VPN & Security", "P2P & Torrent")
            and dst_port not in (53, 123, 67, 68, 5353, 1900)
            and flow["packets_out"] >= 4
            and flow["bytes_out"] >= 400
        ):
            al = self._emit_alert(
                dedup_key=f"directip:{src_ip}:{dst_ip}:{dst_port}",
                sig_id="AEGIS-012",
                severity="MEDIUM",
                mitre="T1071",
                title=f"Direct-to-IP Session (No DNS & No TLS SNI): {dst_ip}:{dst_port}",
                description=f"Host {src_dev} ({proc_name or 'unknown'}) initiated direct IP communication with {dst_ip}:{dst_port} ({flow['proto']}) without prior DNS or SNI.",
                title_ru=f"Direct-to-IP (без DNS и без SNI): {dst_ip}:{dst_port}",
                description_ru=f"Устройство {src_dev} ({proc_name or 'без имени процесса'}) обменивается данными напрямую по IP {dst_ip}:{dst_port} ({flow['proto']}) без DNS и TLS SNI.",
                src_ip=src_ip,
                src_device=src_dev,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain="",
                process_name=proc_name,
                flow_id=fid,
            )
            if al:
                triggered.append(al)

        return triggered
