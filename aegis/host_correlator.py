"""
Cross-Platform Host Socket, Binary Signature, SHA-256 & OS DNS Cache Correlator.

Powers BOTH tiers of Aegis:
  - Tier 1 (`system` mode — Personal System Shield): Provides real-time OS TCP/UDP connection
    enumeration, NIC throughput telemetry, zero-driver OS DNS Resolver Cache correlation,
    executable SHA-256 hashing, and Authenticode / codesign verification with zero router setup.
  - Tier 2 (`router` mode — Out-of-Band Network Shield): Cross-checks external packets captured
    on the physical router bridge (`br-lan`) every 250 ms against the local OS kernel socket table
    to unmask hidden rootkits (`GHOST SOCKET` / `AEGIS-001`).
"""

from __future__ import annotations

import hashlib
import json
import platform
import queue
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import psutil

from .config import AegisConfig

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    parent_name: str
    exe: str
    username: str
    sig_status: str = "Checking"  # Valid, NotSigned, System, Unknown, Checking
    sig_signer: str = ""
    sha256: str = ""


@dataclass
class HostConnectionRecord:
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    pid: int
    proc: ProcessInfo


def _compute_file_sha256(path_str: str, max_bytes: int = 128 * 1024 * 1024) -> str:
    """Compute SHA-256 of an executable binary safely (capped at 128 MB to avoid I/O stalls)."""
    try:
        p = Path(path_str)
        if not p.is_file() or p.stat().st_size > max_bytes:
            return ""
        h = hashlib.sha256()
        with p.open("rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


class HostSocketCorrelator:
    def __init__(self, config: AegisConfig) -> None:
        self.config = config
        self.os_name = platform.system()
        self.hostname = platform.node() or "Local-Workstation"
        self.sig_cache_file = config.data_dir / "sig_cache.json"
        self.local_ips: Set[str] = self._detect_local_lan_ips()
        self._lock = threading.Lock()

        # Exact 4-tuple: (proto, lport, rip, rport) -> pid
        self._exact_map: Dict[Tuple[str, int, str, int], int] = {}
        # Local port map: (proto, lport) -> (pid, last_seen_ts)
        self._port_map: Dict[Tuple[str, int], Tuple[int, float]] = {}
        # Latest live outbound/established host connections snapshot for Tier 1 (`system` mode)
        self._live_conns: List[HostConnectionRecord] = []

        # Cached PID -> ProcessInfo
        self._proc_cache: Dict[int, ProcessInfo] = {}
        # Cached exe_lower -> {"status": str, "signer": str, "sha256": str}
        self._sig_cache: Dict[str, dict] = self._load_sig_cache()
        self._sig_queue: "queue.Queue[str]" = queue.Queue()
        self._queued_exes: Set[str] = set()

        # Zero-driver OS DNS Resolver Cache: ip -> domain
        self.os_dns_map: Dict[str, str] = {}
        self.recent_os_dns: List[dict] = []

        # Host NIC throughput counters for Tier 1 (`system` mode)
        self._last_nic_io = None
        self._last_nic_ts: float = 0.0

        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._sig_thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self.last_poll_ms: float = 0.0
        self.total_os_sockets: int = 0

    def _detect_local_lan_ips(self) -> Set[str]:
        ips: Set[str] = set()
        try:
            for _iface, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and not a.address.startswith("127.") and not a.address.startswith("169.254."):
                        if self.config.is_lan_client_ip(a.address):
                            ips.add(a.address)
            if not ips:
                for _iface, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        if a.family == socket.AF_INET and not a.address.startswith("127.") and not a.address.startswith("169.254."):
                            ips.add(a.address)
        except Exception:
            pass
        return ips

    def _load_sig_cache(self) -> Dict[str, dict]:
        if self.sig_cache_file.exists():
            try:
                raw = json.loads(self.sig_cache_file.read_text(encoding="utf-8"))
                out: Dict[str, dict] = {}
                for k, v in raw.items():
                    if isinstance(v, dict):
                        out[k] = {
                            "status": str(v.get("status", "Unknown")),
                            "signer": str(v.get("signer", "")),
                            "sha256": str(v.get("sha256", "")),
                        }
                    elif isinstance(v, list) and len(v) >= 2:
                        out[k] = {"status": str(v[0]), "signer": str(v[1]), "sha256": str(v[2]) if len(v) > 2 else ""}
                return out
            except Exception:
                pass
        return {}

    def _save_sig_cache(self) -> None:
        try:
            with self._lock:
                payload = dict(self._sig_cache)
            self.sig_cache_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._reset_nic_baseline()
        self._poll_sync()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True, name="HostSocketPoller")
        self._sig_thread = threading.Thread(target=self._sig_worker, daemon=True, name="BinarySignatureWorker")
        self._dns_thread = threading.Thread(target=self._os_dns_loop, daemon=True, name="HostDnsCachePoller")
        self._poll_thread.start()
        self._sig_thread.start()
        self._dns_thread.start()

    def stop(self) -> None:
        self._running = False

    def _reset_nic_baseline(self) -> None:
        try:
            self._last_nic_io = psutil.net_io_counters()
            self._last_nic_ts = time.time()
        except Exception:
            self._last_nic_io = None

    def sample_nic_delta(self) -> Tuple[int, int, int]:
        """Return (bytes_recv_delta, bytes_sent_delta, packets_delta) across host NICs since last call."""
        try:
            cur = psutil.net_io_counters()
            now = time.time()
            if cur is None:
                return 0, 0, 0
            if self._last_nic_io is None:
                self._last_nic_io = cur
                self._last_nic_ts = now
                return 0, 0, 0
            b_in = max(0, cur.bytes_recv - self._last_nic_io.bytes_recv)
            b_out = max(0, cur.bytes_sent - self._last_nic_io.bytes_sent)
            pkts = max(0, (cur.packets_recv + cur.packets_sent) - (self._last_nic_io.packets_recv + self._last_nic_io.packets_sent))
            self._last_nic_io = cur
            self._last_nic_ts = now
            return b_in, b_out, pkts
        except Exception:
            return 0, 0, 0

    def _resolve_pid(self, pid: int) -> ProcessInfo:
        if pid in self._proc_cache:
            info = self._proc_cache[pid]
            if info.exe and info.exe.lower() in self._sig_cache:
                rec = self._sig_cache[info.exe.lower()]
                info.sig_status = rec.get("status", info.sig_status)
                info.sig_signer = rec.get("signer", info.sig_signer)
                if rec.get("sha256"):
                    info.sha256 = rec["sha256"]
            return info

        if pid == 0:
            info = ProcessInfo(
                pid=0,
                ppid=0,
                name="Kernel / TIME_WAIT",
                parent_name="",
                exe="",
                username="SYSTEM",
                sig_status="System",
                sig_signer=f"{self.os_name} Kernel",
            )
            self._proc_cache[pid] = info
            return info
        if IS_WINDOWS and pid == 4:
            info = ProcessInfo(
                pid=4,
                ppid=0,
                name="System (NT Kernel)",
                parent_name="",
                exe="ntoskrnl.exe",
                username="SYSTEM",
                sig_status="Valid",
                sig_signer="Microsoft Windows",
            )
            self._proc_cache[pid] = info
            return info

        name = f"PID-{pid}"
        ppid = 0
        parent_name = ""
        exe = ""
        user = ""
        try:
            p = psutil.Process(pid)
            name = p.name() or name
            try:
                ppid = p.ppid() or 0
                if ppid > 0:
                    parent_name = psutil.Process(ppid).name() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                exe = p.exe() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = ""
            try:
                user = p.username() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                user = ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        sys_daemons = ("svchost.exe", "services.exe", "lsass.exe", "system", "systemd-resolved", "mdnsresponder", "launchd")
        sig_status = "System" if (not exe and name.lower() in sys_daemons) or name.lower() in sys_daemons else "Unknown"
        sig_signer = f"{self.os_name} System" if sig_status == "System" else ""
        sha256 = ""

        if exe:
            el = exe.lower()
            if el in self._sig_cache:
                rec = self._sig_cache[el]
                sig_status = rec.get("status", "Unknown")
                sig_signer = rec.get("signer", "")
                sha256 = rec.get("sha256", "")
            else:
                if IS_WINDOWS or IS_MACOS:
                    sig_status = "Checking"
                else:
                    if exe.startswith(("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/", "/lib/")):
                        sig_status, sig_signer = "System", "Linux Root FS"
                    elif exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                        sig_status, sig_signer = "NotSigned", "Writable Temp Path"
                    else:
                        sig_status, sig_signer = "Unknown", "ELF Binary"
                if el not in self._queued_exes:
                    self._queued_exes.add(el)
                    self._sig_queue.put(exe)

        info = ProcessInfo(
            pid=pid,
            ppid=ppid,
            name=name,
            parent_name=parent_name,
            exe=exe,
            username=user,
            sig_status=sig_status,
            sig_signer=sig_signer,
            sha256=sha256,
        )
        self._proc_cache[pid] = info
        return info

    def poll_sync(self) -> None:
        self._poll_sync()

    def _poll_sync(self) -> None:
        t0 = time.perf_counter()
        now = time.time()
        detected = self._detect_local_lan_ips()
        if detected:
            self.local_ips = detected

        exact: Dict[Tuple[str, int, str, int], int] = {}
        ports_update: Dict[Tuple[str, int], Tuple[int, float]] = {}
        live_conns: List[HostConnectionRecord] = []
        count = 0

        try:
            conns = psutil.net_connections(kind="inet")
            count = len(conns)
            for c in conns:
                if not c.laddr:
                    continue
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                lip = c.laddr.ip
                lport = c.laddr.port
                pid = c.pid if c.pid is not None else 0
                ports_update[(proto, lport)] = (pid, now)

                pinfo = self._resolve_pid(pid) if pid else self._resolve_pid(0)
                if c.raddr and c.raddr.ip:
                    rip = c.raddr.ip
                    rport = c.raddr.port
                    exact[(proto, lport, rip, rport)] = pid
                    if not rip.startswith("127.") and rip not in ("::1", "0.0.0.0", "::"):
                        st = getattr(c, "status", "") or ("UDP" if proto == "UDP" else "ACTIVE")
                        if st != "LISTEN":
                            live_conns.append(
                                HostConnectionRecord(
                                    proto=proto,
                                    local_ip=lip,
                                    local_port=lport,
                                    remote_ip=rip,
                                    remote_port=rport,
                                    status=st,
                                    pid=pid,
                                    proc=pinfo,
                                )
                            )
        except Exception:
            pass

        with self._lock:
            self._exact_map = exact
            cutoff = now - 25.0
            stale = [k for k, (_, ts) in self._port_map.items() if ts < cutoff]
            for k in stale:
                self._port_map.pop(k, None)
            self._port_map.update(ports_update)
            self._live_conns = live_conns
            self.total_os_sockets = count
            self.last_poll_ms = (time.perf_counter() - t0) * 1000.0

    def get_live_connections(self) -> List[HostConnectionRecord]:
        with self._lock:
            return list(self._live_conns)

    def lookup_os_dns(self, ip: str) -> str:
        with self._lock:
            return self.os_dns_map.get(ip, "")

    def _poll_loop(self) -> None:
        ticks = 0
        while self._running:
            self._poll_sync()
            ticks += 1
            if ticks % 120 == 0:
                alive = set(psutil.pids()) | {0, 4}
                with self._lock:
                    for p in list(self._proc_cache.keys()):
                        if p not in alive:
                            self._proc_cache.pop(p, None)
            time.sleep(0.25)

    def _os_dns_loop(self) -> None:
        """Periodically read local OS DNS Resolver Cache (zero driver / user-mode) for System Shield."""
        while self._running:
            self.refresh_os_dns_cache_once()
            for _ in range(16):
                if not self._running:
                    break
                time.sleep(0.25)

    def refresh_os_dns_cache_once(self) -> None:
        now = time.time()
        discovered: Dict[str, str] = {}

        # 1. Windows user-mode DNS Client Cache (locale-independent via PowerShell cmdlet)
        if IS_WINDOWS:
            try:
                cmd = (
                    "Get-DnsClientCache -Type A,AAAA -ErrorAction SilentlyContinue | "
                    "Select-Object Entry,Data | ConvertTo-Json -Compress"
                )
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                ).decode("utf-8", errors="ignore").strip()
                if out:
                    parsed = json.loads(out)
                    rows = parsed if isinstance(parsed, list) else [parsed]
                    for r in rows:
                        if not isinstance(r, dict):
                            continue
                        dom = str(r.get("Entry") or "").strip().lower().strip(".")
                        ip = str(r.get("Data") or "").strip()
                        if dom and ip and "." in dom and not dom.endswith((".arpa", ".local")):
                            discovered[ip] = dom
            except Exception:
                pass

        # 2. Cross-platform `/etc/hosts` (or Windows `drivers/etc/hosts`) fallback
        hosts_path = (
            Path(r"C:\Windows\System32\drivers\etc\hosts")
            if IS_WINDOWS
            else Path("/etc/hosts")
        )
        if hosts_path.is_file():
            try:
                for line in hosts_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    parts = s.split()
                    if len(parts) >= 2 and parts[0] not in ("127.0.0.1", "::1", "0.0.0.0"):
                        discovered.setdefault(parts[0], parts[1].lower())
            except OSError:
                pass

        if discovered:
            with self._lock:
                new_events: List[dict] = []
                for ip, dom in discovered.items():
                    if ip not in self.os_dns_map:
                        new_events.append(
                            {
                                "ts": now,
                                "client_ip": next(iter(self.local_ips), "127.0.0.1"),
                                "device": self.hostname,
                                "qname": dom,
                                "ips": [ip],
                            }
                        )
                    self.os_dns_map[ip] = dom
                if new_events:
                    self.recent_os_dns = (new_events[:25] + self.recent_os_dns)[:80]

    def _sig_worker(self) -> None:
        """Batch-verify Authenticode (Windows) / codesign (macOS) / Linux FS paths + SHA-256 hashes."""
        while self._running:
            batch: List[str] = []
            try:
                first = self._sig_queue.get(timeout=1.0)
                batch.append(first)
                while len(batch) < 8:
                    try:
                        batch.append(self._sig_queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                continue

            hashes = {exe.lower(): _compute_file_sha256(exe) for exe in batch}

            if IS_WINDOWS:
                self._verify_windows_authenticode(batch, hashes)
            elif IS_MACOS:
                self._verify_macos_codesign(batch, hashes)
            else:
                self._verify_linux_binaries(batch, hashes)

    def _verify_windows_authenticode(self, batch: List[str], hashes: Dict[str, str]) -> None:
        try:
            ps_paths = ",".join("'" + p.replace("'", "''") + "'" for p in batch)
            cmd = (
                f"@({ps_paths}) | ForEach-Object {{ "
                f"$s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; "
                f"if ($s) {{ [PSCustomObject]@{{ p=$_; st=[string]$s.Status; sg=[string]$s.SignerCertificate.Subject }} }} "
                f"}} | ConvertTo-Json -Compress"
            )
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                stderr=subprocess.DEVNULL,
                timeout=12,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).decode("utf-8", errors="ignore").strip()

            if out:
                parsed = json.loads(out)
                items = parsed if isinstance(parsed, list) else [parsed]
                with self._lock:
                    for it in items:
                        pth = (it.get("p") or "").lower()
                        st = it.get("st") or "Unknown"
                        subj = it.get("sg") or ""
                        signer = ""
                        for part in subj.split(","):
                            part = part.strip()
                            if part.startswith("CN="):
                                signer = part[3:].strip('"')
                                break
                        if pth:
                            self._sig_cache[pth] = {
                                "status": st,
                                "signer": signer,
                                "sha256": hashes.get(pth, ""),
                            }
                    self._sync_proc_cache_unlocked()
                self._save_sig_cache()
        except Exception:
            pass

    def _verify_macos_codesign(self, batch: List[str], hashes: Dict[str, str]) -> None:
        for exe in batch:
            try:
                res = subprocess.run(["codesign", "-dv", exe], capture_output=True, text=True, timeout=5)
                text = (res.stderr or "") + (res.stdout or "")
                if res.returncode == 0:
                    signer = "Apple / Signed"
                    for line in text.splitlines():
                        if line.startswith("Authority="):
                            signer = line.split("=", 1)[1].strip()
                            break
                    st = "Valid"
                else:
                    st, signer = "NotSigned", ""
                with self._lock:
                    self._sig_cache[exe.lower()] = {
                        "status": st,
                        "signer": signer,
                        "sha256": hashes.get(exe.lower(), ""),
                    }
                    self._sync_proc_cache_unlocked()
            except Exception:
                pass
        self._save_sig_cache()

    def _verify_linux_binaries(self, batch: List[str], hashes: Dict[str, str]) -> None:
        with self._lock:
            for exe in batch:
                if exe.startswith(("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/", "/lib/")):
                    st, signer = "System", "Linux Root FS"
                elif exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                    st, signer = "NotSigned", "Writable Temp Path"
                else:
                    st, signer = "Unknown", "ELF Binary"
                self._sig_cache[exe.lower()] = {
                    "status": st,
                    "signer": signer,
                    "sha256": hashes.get(exe.lower(), ""),
                }
            self._sync_proc_cache_unlocked()
        self._save_sig_cache()

    def _sync_proc_cache_unlocked(self) -> None:
        for pinfo in self._proc_cache.values():
            if pinfo.exe and pinfo.exe.lower() in self._sig_cache:
                rec = self._sig_cache[pinfo.exe.lower()]
                pinfo.sig_status = rec.get("status", pinfo.sig_status)
                pinfo.sig_signer = rec.get("signer", pinfo.sig_signer)
                if rec.get("sha256"):
                    pinfo.sha256 = rec["sha256"]

    def lookup_host_socket(self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Optional[ProcessInfo]:
        if src_ip not in self.local_ips:
            return None
        with self._lock:
            pid = self._exact_map.get((proto, src_port, dst_ip, dst_port))
            if pid is None:
                entry = self._port_map.get((proto, src_port))
                if entry is not None:
                    pid = entry[0]
            if pid is None:
                return None
            return self._resolve_pid(pid)

    def get_cached_process(self, pid: Optional[int]) -> Optional[ProcessInfo]:
        if pid is None:
            return None
        with self._lock:
            return self._proc_cache.get(pid)

    def get_active_host_processes_summary(self, flows: List[dict]) -> List[dict]:
        """Aggregate active flows belonging to this host grouped by executable."""
        by_proc: Dict[str, dict] = {}
        for f in flows:
            if not f.get("is_local_pc"):
                continue
            pname = f.get("proc_name")
            pexe = f.get("proc_exe") or ""
            sig_st = f.get("proc_sig_status") or ""
            sig_sg = f.get("proc_sig_signer") or ""
            sha256 = f.get("proc_sha256") or ""
            pid_val = f.get("pid") or 0

            if not pname:
                if f.get("ghost_confirmed"):
                    pname = "GHOST SOCKET (Hidden from OS)"
                    sig_st = "GHOST"
                elif f.get("dst_port") == 53:
                    pname = "OS DNS Resolver"
                    sig_st = "System"
                    sig_sg = f"{self.os_name} System"
                else:
                    pname = "Short-lived Socket (<250 ms)"
                    sig_st = "System"
                    sig_sg = "Ephemeral Session"

            key = pexe or pname
            rec = by_proc.get(key)
            if not rec:
                rec = {
                    "proc_name": pname,
                    "proc_exe": pexe,
                    "pid": pid_val,
                    "sig_status": sig_st or "Unknown",
                    "sig_signer": sig_sg,
                    "sha256": sha256,
                    "flows_count": 0,
                    "bytes_out": 0,
                    "bytes_in": 0,
                    "ghost": bool(f.get("ghost_confirmed")),
                    "sample_targets": [],
                }
                by_proc[key] = rec
            rec["flows_count"] += 1
            rec["bytes_out"] += f["bytes_out"]
            rec["bytes_in"] += f["bytes_in"]
            if f.get("ghost_confirmed"):
                rec["ghost"] = True
            tgt = f["domain"] or f["dst_ip"]
            if tgt and tgt not in rec["sample_targets"] and len(rec["sample_targets"]) < 5:
                rec["sample_targets"].append(tgt)

        return sorted(by_proc.values(), key=lambda x: (not x["ghost"], -(x["bytes_out"] + x["bytes_in"]), -x["flows_count"]))
