from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
from pathlib import Path

import httpx

from aegis.config import AegisConfig
from aegis.server import create_app


def _build_minimal_pcap() -> bytes:
    ghdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 1514, 1)
    payload = b"GET /status HTTP/1.1\r\nHost: github.com\r\nUser-Agent: pytest\r\n\r\n"
    eth = (b"\x00\x00\x5e\x00\x53\x01") + (b"\x00\x00\x5e\x00\x53\x10") + struct.pack("!H", 0x0800)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(payload),
        1,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton("192.168.1.42"),
        socket.inet_aton("140.82.121.4"),
    )
    tcp = struct.pack("!HHIIBBHHH", 50123, 80, 1, 1, 0x50, 0x18, 64240, 0, 0)
    frame = eth + ip + tcp + payload
    phdr = struct.pack("<IIII", 1700000000, 0, len(frame), len(frame))
    return ghdr + phdr + frame


def test_server_endpoints_pcap_mode_switch_and_report(tmp_path: Path) -> None:
    cfg = AegisConfig(
        mode="pcap",
        data_dir=tmp_path / "data",
        auto_update_feeds=False,
        lan_networks=[ipaddress.ip_network("192.168.0.0/16")],
        gateway_ips={"192.168.1.1"},
    )
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(cfg)

    async def _run() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            health = await client.get("/api/health")
            assert health.status_code == 200
            assert health.json()["ok"] is True

            index_resp = await client.get("/")
            assert index_resp.status_code == 200
            assert "AEGIS // DIGITAL SHIELD" in index_resp.text

            pcap_bytes = _build_minimal_pcap()
            imp = await client.post("/api/pcap/import", content=pcap_bytes)
            assert imp.status_code == 200
            assert imp.json()["imported_packets"] == 1

            snap = (await client.get("/api/snapshot")).json()
            assert snap["kpis"]["total_packets"] == 1
            assert snap["kpis"]["shield_score"] == 100
            assert len(snap["flows"]) == 1
            flow_id = snap["flows"][0]["id"]
            assert snap["flows"][0]["app"] == "GitHub"

            detail = await client.get(f"/api/flow/{flow_id}")
            assert detail.status_code == 200
            assert detail.json()["domain"] == "github.com"
            assert "windows_powershell" in detail.json()["firewall_commands"]

            dl = await client.get("/api/pcap/download")
            assert dl.status_code == 200
            assert len(dl.content) > 24

            rep = await client.get("/api/report/markdown")
            assert rep.status_code == 200
            assert "Aegis Security & Forensic Telemetry Report" in rep.text

    asyncio.run(_run())
