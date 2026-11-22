from __future__ import annotations

from pathlib import Path

from aegis.threat_intel import ThreatIntelEngine


def _make_base_flow(**overrides) -> dict:
    flow = {
        "id": "f001",
        "first_seen": 100.0,
        "last_seen": 105.0,
        "seen_syn": True,
        "proto": "TCP",
        "l7_proto": "TLS",
        "src_ip": "192.168.1.100",
        "src_port": 54000,
        "src_device": "Workstation",
        "dst_ip": "203.0.113.50",
        "dst_port": 443,
        "domain": "benign.example.org",
        "ja3": "",
        "app": "HTTPS / TLS",
        "category": "Cloud & Web",
        "packets_out": 8,
        "packets_in": 8,
        "bytes_out": 1500,
        "bytes_in": 4000,
        "proc_name": "chrome.exe",
        "proc_exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "proc_sig_status": "Valid",
        "ghost_confirmed": False,
        "is_stratum": False,
        "beacon_interval": None,
    }
    flow.update(overrides)
    return flow


def test_ghost_socket_and_cobalt_strike_ja3_alerts(tmp_path: Path) -> None:
    engine = ThreatIntelEngine(feeds_dir=tmp_path / "feeds")
    ghost_flow = _make_base_flow(
        ghost_confirmed=True,
        ja3="72a589da586844d7f0818ce684948eea",  # Cobalt Strike Beacon
        proc_name="",
    )
    alerts = engine.evaluate_flow(ghost_flow, idle_watch_active=False, idle_watch_since=0.0)
    sig_ids = {a.sig_id for a in alerts}
    assert "AEGIS-001" in sig_ids  # Ghost Socket CRITICAL
    assert "AEGIS-003" in sig_ids  # Malicious JA3 CRITICAL
    assert all(a.title and a.title_ru for a in alerts)


def test_dns_tunneling_and_beaconing(tmp_path: Path) -> None:
    engine = ThreatIntelEngine(feeds_dir=tmp_path / "feeds")

    # High-entropy long subdomain -> DNS Tunneling AEGIS-007
    tunnel_qname = "x9a8f7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0m9n8p7q6r5s4.c2tunnel.example"
    dns_alerts = engine.check_dns_query("192.168.1.100", "Workstation", tunnel_qname)
    assert any(a.sig_id == "AEGIS-007" for a in dns_alerts)

    # Regular 30s interval connections -> Periodic C2 Beaconing
    res = None
    for idx in range(6):
        res = engine.record_connection_for_beaconing("192.168.1.100", "198.51.100.77", 443, 1000.0 + idx * 30.0)
    assert res is not None
    mean_iv, cv = res
    assert abs(mean_iv - 30.0) < 0.1
    assert cv <= 0.12
