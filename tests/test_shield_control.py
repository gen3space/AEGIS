from __future__ import annotations

import os
from pathlib import Path

from aegis.config import AegisConfig
from aegis.shield_control import ShieldControlEngine


def test_shield_control_safety_guards_and_firewall_commands(tmp_path: Path) -> None:
    cfg = AegisConfig(data_dir=tmp_path / "data", gateway_ips={"192.168.1.1"})
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    shield = ShieldControlEngine(cfg)

    # 1. Host firewall command generation
    cmds = shield.generate_host_firewall_commands("203.0.113.55")
    assert "203.0.113.55" in cmds["windows_powershell"]
    assert "203.0.113.55" in cmds["linux_nftables"]
    assert "203.0.113.55" in cmds["macos_pf"]

    # 2. Refuses blocking private / loopback / public DNS IPs on router
    ok_priv, _ = shield.block_remote_ip_on_router("192.168.1.50")
    assert ok_priv is False
    ok_dns, _ = shield.block_remote_ip_on_router("1.1.1.1")
    assert ok_dns is False

    # 3. Refuses quarantining the local workstation or router gateway
    ok_self_lan, _ = shield.quarantine_lan_device_on_router("192.168.1.100", local_pc_ips={"192.168.1.100"})
    assert ok_self_lan is False
    ok_gw_lan, _ = shield.quarantine_lan_device_on_router("192.168.1.1", local_pc_ips={"192.168.1.100"})
    assert ok_gw_lan is False

    # 4. Refuses terminating system PIDs or Aegis itself
    ok_pid0, _ = shield.terminate_local_process(0)
    assert ok_pid0 is False
    ok_self_pid, _ = shield.terminate_local_process(os.getpid())
    assert ok_self_pid is False
