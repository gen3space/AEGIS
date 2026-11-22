"""
Active Defense, Network Control, Router Security Audit & Incident Reporting Engine for Aegis.

Provides:
  - Tier 1 (System Shield): Safe local rogue process termination & OS firewall rule generation.
  - Tier 2 (Router Network Shield):
      * Interactive SSH + `tcpdump` + interface diagnostics
      * Read-only Router Perimeter Hardening Audit (WAN Firewall, SSH, DNS Rebind, UPnP)
      * Ephemeral RAM-only Router Firewall IP Blocking & LAN IoT Quarantine (`nftables` / `iptables`)
  - Optional Webhook Alerting & Markdown/JSON Forensic Report Export.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Set, Tuple

import psutil
import requests

from .config import AegisConfig

SAFE_IFACE_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,32}$")

PROTECTED_PROCESS_NAMES: Set[str] = {
    "system",
    "ntoskrnl.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "systemd",
    "init",
    "launchd",
    "windowserver",
    "kernel_task",
    "sshd",
    "aegis",
    "aegis.exe",
}


@dataclass
class ActiveBlockRule:
    target: str
    scope: str  # "router_remote_ip" | "router_lan_quarantine"
    reason: str
    created_at: float
    backend: str


class ShieldControlEngine:
    def __init__(self, config: AegisConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self.active_rules: Dict[str, ActiveBlockRule] = {}
        self.last_router_audit: Optional[dict] = None

    def list_active_rules(self) -> List[dict]:
        with self._lock:
            return [asdict(r) for r in sorted(self.active_rules.values(), key=lambda x: x.created_at, reverse=True)]

    # ------------------------------------------------------------------
    # Tier 1: Host System Shield Controls
    # ------------------------------------------------------------------
    @staticmethod
    def generate_host_firewall_commands(remote_ip: str) -> Dict[str, str]:
        ip_obj = ipaddress.ip_address(remote_ip.strip())
        ip_s = str(ip_obj)
        return {
            "windows_powershell": (
                f'New-NetFirewallRule -DisplayName "Aegis Block {ip_s}" '
                f"-Direction Outbound -RemoteAddress {ip_s} -Action Block"
            ),
            "windows_unblock": f'Remove-NetFirewallRule -DisplayName "Aegis Block {ip_s}"',
            "linux_nftables": f"sudo nft add rule inet filter output ip daddr {ip_s} drop",
            "linux_ufw": f"sudo ufw deny out to {ip_s}",
            "macos_pf": f'echo "block drop out quick to {ip_s}" | sudo pfctl -a com.aegis -f -',
        }

    def terminate_local_process(self, pid: int) -> Tuple[bool, str]:
        if not self.config.enable_active_response:
            return False, "Active response is disabled by configuration (AEGIS_ACTIVE_RESPONSE=false)."
        if pid <= 4 or pid == os.getpid():
            return False, f"Refusing to terminate protected system/self PID {pid}."
        try:
            proc = psutil.Process(pid)
            pname = (proc.name() or "").lower()
            if pname in PROTECTED_PROCESS_NAMES:
                return False, f"Refusing to terminate protected OS process '{proc.name()}' (PID {pid})."
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except psutil.TimeoutExpired:
                proc.kill()
            return True, f"Terminated local process '{pname}' (PID {pid})."
        except psutil.NoSuchProcess:
            return False, f"Process PID {pid} has already exited."
        except psutil.AccessDenied:
            return False, f"Access denied terminating PID {pid} (run Aegis with elevated privileges if required)."
        except Exception as exc:
            return False, f"Failed to terminate PID {pid}: {exc}"

    # ------------------------------------------------------------------
    # Tier 2: Router Diagnostics, Security Audit & Network-Wide Controls
    # ------------------------------------------------------------------
    def diagnose_router(
        self,
        router_host: str,
        router_port: int,
        router_user: str,
        router_iface: str,
        ssh_key_path: str = "",
    ) -> dict:
        host = router_host.strip()
        iface = router_iface.strip() or "br-lan"
        if not SAFE_IFACE_RE.match(iface):
            return {"ok": False, "error": f"Invalid interface name: {iface}"}

        temp_cfg = AegisConfig(
            router_host=host,
            router_port=int(router_port),
            router_user=router_user.strip() or "root",
            router_iface=iface,
            ssh_key_path=ssh_key_path.strip(),
            ssh_strict_host_key=self.config.ssh_strict_host_key,
        )

        probe_script = (
            "echo '===OS==='; "
            "(grep PRETTY_NAME /etc/os-release 2>/dev/null || grep DISTRIB_DESCRIPTION /etc/openwrt_release 2>/dev/null || uname -sr); "
            "echo '===TCPDUMP==='; "
            "(command -v tcpdump 2>/dev/null || echo MISSING); "
            "echo '===IFACE==='; "
            f"(ip link show '{iface}' >/dev/null 2>&1 && echo PRESENT || echo MISSING); "
            "echo '===IFACES_LIST==='; "
            "ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr '\\n' ','; "
            "echo ''; echo '===FW==='; "
            "(command -v nft >/dev/null 2>&1 && echo nftables) || (command -v iptables >/dev/null 2>&1 && echo iptables) || echo none"
        )

        try:
            res = subprocess.run(
                [*temp_cfg.build_ssh_args(connect_timeout=5), probe_script],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if res.returncode != 0:
                err = (res.stderr or res.stdout or "").strip()
                return {
                    "ok": False,
                    "ssh_ok": False,
                    "tcpdump_ok": False,
                    "iface_ok": False,
                    "error": err or f"SSH connection to {router_user}@{host}:{router_port} failed",
                }

            out = res.stdout or ""
            sections: Dict[str, str] = {}
            current = ""
            for line in out.splitlines():
                if line.startswith("===") and line.endswith("==="):
                    current = line.strip("=")
                    sections[current] = ""
                elif current:
                    sections[current] = (sections[current] + " " + line.strip()).strip()

            os_desc = sections.get("OS", "Linux Gateway").replace('PRETTY_NAME=', '').replace('DISTRIB_DESCRIPTION=', '').strip('"\'')
            tcpdump_bin = sections.get("TCPDUMP", "MISSING")
            iface_status = sections.get("IFACE", "MISSING")
            ifaces_all = [x.split("@")[0] for x in sections.get("IFACES_LIST", "").split(",") if x.strip()]
            fw_backend = sections.get("FW", "none")

            tcpdump_ok = tcpdump_bin != "MISSING" and bool(tcpdump_bin)
            iface_ok = iface_status == "PRESENT"
            all_ok = tcpdump_ok and iface_ok

            err_msg = ""
            if not tcpdump_ok:
                err_msg = "SSH connected, but `tcpdump` is not installed on router (run `router/openwrt_aegis_setup.sh`)."
            elif not iface_ok:
                err_msg = f"SSH connected, but interface '{iface}' was not found. Available: {', '.join(ifaces_all[:10])}"

            return {
                "ok": all_ok,
                "ssh_ok": True,
                "tcpdump_ok": tcpdump_ok,
                "tcpdump_path": tcpdump_bin if tcpdump_ok else "",
                "iface_ok": iface_ok,
                "available_ifaces": ifaces_all[:20],
                "router_os": os_desc,
                "firewall_backend": fw_backend,
                "error": err_msg,
            }
        except Exception as exc:
            return {
                "ok": False,
                "ssh_ok": False,
                "tcpdump_ok": False,
                "iface_ok": False,
                "error": str(exc),
            }

    def run_router_security_audit(self) -> dict:
        """Execute a read-only security posture audit on the connected router via SSH."""
        script = (
            "OS=$(grep DISTRIB_DESCRIPTION /etc/openwrt_release 2>/dev/null | cut -d= -f2 | tr -d \"'\\\"\" || uname -sr); "
            "WAN_IN=$(uci -q get firewall.@zone[1].input 2>/dev/null || echo N/A); "
            "WAN_FWD=$(uci -q get firewall.@zone[1].forward 2>/dev/null || echo N/A); "
            "SSH_PW=$(uci -q get dropbear.@dropbear[0].PasswordAuth 2>/dev/null || echo N/A); "
            "SSH_IF=$(uci -q get dropbear.@dropbear[0].Interface 2>/dev/null || echo ''); "
            "REBIND=$(uci -q get dhcp.@dnsmasq[0].rebind_protection 2>/dev/null || echo N/A); "
            "UPNP=$(ps w 2>/dev/null | grep -E 'miniupnpd|upnp' | grep -v grep >/dev/null && echo active || echo inactive); "
            "printf 'OS=%s\\nWAN_IN=%s\\nWAN_FWD=%s\\nSSH_PW=%s\\nSSH_IF=%s\\nREBIND=%s\\nUPNP=%s\\n' "
            "\"$OS\" \"$WAN_IN\" \"$WAN_FWD\" \"$SSH_PW\" \"$SSH_IF\" \"$REBIND\" \"$UPNP\""
        )
        try:
            res = subprocess.run(
                [*self.config.build_ssh_args(connect_timeout=5), script],
                capture_output=True,
                text=True,
                timeout=9,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if res.returncode != 0:
                return {"ok": False, "error": (res.stderr or "Router SSH unreachable").strip()}

            kv: Dict[str, str] = {}
            for line in (res.stdout or "").splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    kv[k.strip()] = v.strip()

            checks = []
            score = 100

            wan_in = kv.get("WAN_IN", "N/A")
            if wan_in in ("DROP", "REJECT"):
                checks.append({"id": "wan_in", "status": "PASS", "title": "WAN Input Policy", "detail": f"Inbound WAN traffic is set to {wan_in}."})
            elif wan_in == "N/A":
                checks.append({"id": "wan_in", "status": "INFO", "title": "WAN Input Policy", "detail": "Non-UCI Linux gateway (verify nftables/iptables input chain)."})
            else:
                score -= 30
                checks.append({"id": "wan_in", "status": "WARN", "title": "WAN Input Policy", "detail": f"WAN input is '{wan_in}' — set to DROP or REJECT immediately!"})

            wan_fwd = kv.get("WAN_FWD", "N/A")
            if wan_fwd in ("DROP", "REJECT"):
                checks.append({"id": "wan_fwd", "status": "PASS", "title": "WAN Forward Policy", "detail": f"Unrequested WAN->LAN forwarding is set to {wan_fwd}."})
            elif wan_fwd != "N/A":
                score -= 30
                checks.append({"id": "wan_fwd", "status": "WARN", "title": "WAN Forward Policy", "detail": f"WAN forward is '{wan_fwd}' — recommend DROP or REJECT."})

            ssh_pw = kv.get("SSH_PW", "N/A")
            if ssh_pw in ("off", "0"):
                checks.append({"id": "ssh_pw", "status": "PASS", "title": "SSH Key-Only Auth", "detail": "PasswordAuth is disabled (Ed25519/RSA key-only)."})
            elif ssh_pw != "N/A":
                score -= 15
                checks.append({"id": "ssh_pw", "status": "WARN", "title": "SSH Password Login Enabled", "detail": "Disable PasswordAuth after adding your SSH public key."})

            ssh_if = kv.get("SSH_IF", "")
            if ssh_if:
                checks.append({"id": "ssh_if", "status": "PASS", "title": "SSH LAN Scope", "detail": f"Dropbear SSH is bound strictly to '{ssh_if}'."})
            elif ssh_pw != "N/A":
                score -= 10
                checks.append({"id": "ssh_if", "status": "WARN", "title": "SSH All-Interface Binding", "detail": "Recommend binding SSH to 'lan' interface only."})

            rebind = kv.get("REBIND", "N/A")
            if rebind == "1":
                checks.append({"id": "rebind", "status": "PASS", "title": "DNS Rebind Protection", "detail": "dnsmasq private IP rebind protection is active."})
            elif rebind == "0":
                score -= 15
                checks.append({"id": "rebind", "status": "WARN", "title": "DNS Rebind Protection Disabled", "detail": "Enable rebind_protection=1 to block browser LAN pivoting."})

            upnp = kv.get("UPNP", "inactive")
            if upnp == "inactive":
                checks.append({"id": "upnp", "status": "PASS", "title": "UPnP Auto-Port-Forwarding", "detail": "UPnP daemon is inactive (malware cannot silently open WAN ports)."})
            else:
                score -= 10
                checks.append({"id": "upnp", "status": "WARN", "title": "UPnP Daemon Active", "detail": "Active UPnP allows LAN IoT/apps to open inbound WAN ports automatically."})

            score = max(0, min(100, score))
            grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D"
            report = {
                "ok": True,
                "ts": time.time(),
                "router_os": kv.get("OS", "Linux Gateway"),
                "score": score,
                "grade": grade,
                "checks": checks,
            }
            with self._lock:
                self.last_router_audit = report
            return report
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def block_remote_ip_on_router(self, ip_str: str, reason: str = "Manual SOC Block") -> Tuple[bool, str]:
        """Block traffic to/from a malicious external IPv4 address across the entire LAN on the router (RAM-only)."""
        if not self.config.enable_active_response:
            return False, "Active response is disabled."
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False, f"Invalid IP address: {ip_str}"

        if not isinstance(ip_obj, ipaddress.IPv4Address) or ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            return False, f"Refusing to block private, loopback, or non-global IPv4 address: {ip_obj}"
        if str(ip_obj) in self.config.gateway_ips or str(ip_obj) in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
            return False, f"Refusing to block protected infrastructure IP: {ip_obj}"

        safe_ip = str(ip_obj)
        cmd = (
            "if command -v nft >/dev/null 2>&1; then "
            "  nft add table inet aegis_shield 2>/dev/null || true; "
            "  nft 'add chain inet aegis_shield forward { type filter hook forward priority -10; policy accept; }' 2>/dev/null || true; "
            f"  nft add rule inet aegis_shield forward ip daddr {safe_ip} drop && echo NFT_OK; "
            "elif command -v iptables >/dev/null 2>&1; then "
            "  iptables -N AEGIS_SHIELD 2>/dev/null || true; "
            "  iptables -C FORWARD -j AEGIS_SHIELD 2>/dev/null || iptables -I FORWARD 1 -j AEGIS_SHIELD; "
            f"  iptables -C AEGIS_SHIELD -d {safe_ip} -j DROP 2>/dev/null || iptables -A AEGIS_SHIELD -d {safe_ip} -j DROP; "
            "  echo IPT_OK; "
            "else echo NO_FW; exit 1; fi"
        )
        try:
            res = subprocess.run(
                [*self.config.build_ssh_args(connect_timeout=5), cmd],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            out = (res.stdout or "").strip()
            if res.returncode == 0 and ("NFT_OK" in out or "IPT_OK" in out):
                backend = "nftables" if "NFT_OK" in out else "iptables"
                with self._lock:
                    self.active_rules[f"ip:{safe_ip}"] = ActiveBlockRule(
                        target=safe_ip,
                        scope="router_remote_ip",
                        reason=reason[:120],
                        created_at=time.time(),
                        backend=backend,
                    )
                return True, f"Blocked {safe_ip} across entire LAN via router {backend} (ephemeral RAM rule)."
            return False, (res.stderr or out or "Router firewall command failed").strip()
        except Exception as exc:
            return False, str(exc)

    def quarantine_lan_device_on_router(self, lan_ip: str, local_pc_ips: Set[str], reason: str = "IoT Quarantine") -> Tuple[bool, str]:
        """Isolate a compromised LAN device (e.g. IoT camera) from WAN internet access via ephemeral router rule."""
        if not self.config.enable_active_response:
            return False, "Active response is disabled."
        try:
            ip_obj = ipaddress.ip_address(lan_ip.strip())
        except ValueError:
            return False, f"Invalid LAN IP: {lan_ip}"

        safe_ip = str(ip_obj)
        if not self.config.is_lan_client_ip(safe_ip):
            return False, f"{safe_ip} is not a LAN client IP."
        if safe_ip in local_pc_ips or safe_ip in self.config.gateway_ips:
            return False, f"Safety guard: refusing to quarantine this workstation or gateway ({safe_ip})."

        cmd = (
            "if command -v nft >/dev/null 2>&1; then "
            "  nft add table inet aegis_shield 2>/dev/null || true; "
            "  nft 'add chain inet aegis_shield forward { type filter hook forward priority -10; policy accept; }' 2>/dev/null || true; "
            f"  nft add rule inet aegis_shield forward ip saddr {safe_ip} drop && echo NFT_OK; "
            "elif command -v iptables >/dev/null 2>&1; then "
            "  iptables -N AEGIS_SHIELD 2>/dev/null || true; "
            "  iptables -C FORWARD -j AEGIS_SHIELD 2>/dev/null || iptables -I FORWARD 1 -j AEGIS_SHIELD; "
            f"  iptables -C AEGIS_SHIELD -s {safe_ip} -j DROP 2>/dev/null || iptables -A AEGIS_SHIELD -s {safe_ip} -j DROP; "
            "  echo IPT_OK; "
            "else echo NO_FW; exit 1; fi"
        )
        try:
            res = subprocess.run(
                [*self.config.build_ssh_args(connect_timeout=5), cmd],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            out = (res.stdout or "").strip()
            if res.returncode == 0 and ("NFT_OK" in out or "IPT_OK" in out):
                backend = "nftables" if "NFT_OK" in out else "iptables"
                with self._lock:
                    self.active_rules[f"lan:{safe_ip}"] = ActiveBlockRule(
                        target=safe_ip,
                        scope="router_lan_quarantine",
                        reason=reason[:120],
                        created_at=time.time(),
                        backend=backend,
                    )
                return True, f"Quarantined LAN host {safe_ip} from WAN forwarding via router {backend}."
            return False, (res.stderr or out or "Router quarantine failed").strip()
        except Exception as exc:
            return False, str(exc)

    def flush_all_router_blocks(self) -> Tuple[bool, str]:
        """Remove all ephemeral Aegis firewall rules from the router immediately."""
        cmd = (
            "nft delete table inet aegis_shield 2>/dev/null || true; "
            "iptables -D FORWARD -j AEGIS_SHIELD 2>/dev/null || true; "
            "iptables -F AEGIS_SHIELD 2>/dev/null || true; "
            "iptables -X AEGIS_SHIELD 2>/dev/null || true; "
            "echo FLUSH_OK"
        )
        try:
            res = subprocess.run(
                [*self.config.build_ssh_args(connect_timeout=5), cmd],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if res.returncode == 0 and "FLUSH_OK" in (res.stdout or ""):
                with self._lock:
                    self.active_rules.clear()
                return True, "Cleared all ephemeral Aegis shield rules on router."
            return False, (res.stderr or "Failed to flush router rules").strip()
        except Exception as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    # Webhook Alerting & Forensic Incident Report Export
    # ------------------------------------------------------------------
    def notify_webhook_async(self, alert_dict: dict) -> None:
        url = self.config.alert_webhook_url
        if not url or alert_dict.get("severity") not in ("CRITICAL", "HIGH"):
            return

        def _send() -> None:
            text = (
                f"🛡️ [AEGIS {alert_dict.get('severity')}] {alert_dict.get('sig_id')} — {alert_dict.get('title')}\n"
                f"Host: {alert_dict.get('src_device')} ({alert_dict.get('src_ip')}) | "
                f"Target: {alert_dict.get('domain') or alert_dict.get('dst_ip')}:{alert_dict.get('dst_port')}\n"
                f"{alert_dict.get('description')}"
            )
            payload = {"text": text, "content": text, "aegis_alert": alert_dict}
            try:
                requests.post(url, json=payload, timeout=5)
            except Exception:
                pass

        threading.Thread(target=_send, daemon=True, name="AegisWebhookSender").start()

    def build_markdown_report(self, snapshot: dict) -> str:
        st = snapshot.get("status", {})
        k = snapshot.get("kpis", {})
        alerts = snapshot.get("alerts", [])
        procs = snapshot.get("pc_processes", [])
        rules = self.list_active_rules()
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        lines = [
            "# 🛡️ Aegis Security & Forensic Telemetry Report",
            "",
            f"- **Generated:** `{ts_str}`",
            f"- **Active Tier / Mode:** `{st.get('tier_label', st.get('mode', 'unknown'))}` (`{st.get('mode')}`)",
            f"- **Shield Health Score:** `{k.get('shield_score', 100)} / 100`",
            f"- **Host OS:** `{st.get('os_name', 'Unknown')}` (`{', '.join(st.get('local_pc_ips', [])) or 'local'}`)",
            f"- **Active Flows / Inspected Packets:** `{k.get('active_flows', 0)}` flows / `{k.get('total_packets', 0)}` pkts",
            f"- **Hidden Ghost Sockets:** `{k.get('ghost_sockets', 0)}`",
            f"- **Triggered IDS Alerts:** `{k.get('alerts_critical', 0)}` CRITICAL, `{k.get('alerts_high', 0)}` HIGH, `{k.get('alerts_medium', 0)}` MEDIUM",
            "",
            "## 1. Triggered Security Alerts",
            "",
        ]
        if not alerts:
            lines.append("_No security alerts or hidden Ghost Sockets recorded in this session._")
        else:
            lines.append("| Severity | Rule / MITRE | Source Host / Process | Destination | Summary |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for a in alerts[:50]:
                tgt = f"{a.get('domain') or a.get('dst_ip')}:{a.get('dst_port')}"
                src = f"{a.get('src_device')} ({a.get('process_name') or a.get('src_ip')})"
                lines.append(
                    f"| **{a.get('severity')}** | `{a.get('sig_id')}` ({a.get('mitre')}) | `{src}` | `{tgt}` | {a.get('title')} |"
                )

        lines.extend(["", "## 2. Host Executables Observed on Network", ""])
        if not procs:
            lines.append("_No local host process flows recorded yet._")
        else:
            lines.append("| PID | Process | Signature | SHA-256 | Flows | Sample Targets |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for p in procs[:30]:
                sha = (p.get("sha256") or "—")[:16]
                if len(p.get("sha256") or "") > 16:
                    sha += "..."
                sig = "GHOST SOCKET" if p.get("ghost") else f"{p.get('sig_status')} ({p.get('sig_signer') or 'N/A'})"
                tgts = ", ".join(p.get("sample_targets", [])[:3])
                lines.append(f"| `{p.get('pid')}` | `{p.get('proc_name')}` | {sig} | `{sha}` | {p.get('flows_count')} | `{tgts}` |")

        if rules:
            lines.extend(["", "## 3. Active Router Containment Rules", ""])
            for r in rules:
                lines.append(f"- **`{r['target']}`** (`{r['scope']}` via `{r['backend']}`) — {r['reason']}")

        lines.append("")
        return "\n".join(lines)
