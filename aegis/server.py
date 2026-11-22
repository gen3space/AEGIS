"""
Aegis FastAPI + WebSocket Real-Time SOC Server.
Serves the interactive Web Console and exposes REST endpoints for:
  - Tier 1 (System Shield) & Tier 2 (Router Network Shield) live switching
  - Router SSH diagnostics & Read-Only Perimeter Hardening Audit
  - Active Response (Router WAN IP block, LAN IoT quarantine, Host rogue PID termination)
  - Forensic Flow Inspection, Threat Intel updates, Incident Report & Wireshark `.pcap` export.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import List, Optional, Set

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__
from .config import AegisConfig, get_static_dir
from .core import NGFWTelemetryCore


class ModeSwitchPayload(BaseModel):
    mode: str
    router_host: Optional[str] = None
    router_port: Optional[int] = None
    router_user: Optional[str] = None
    router_iface: Optional[str] = None
    ssh_key_path: Optional[str] = None


class RouterConnectPayload(BaseModel):
    router_host: str
    router_port: int = 22
    router_user: str = "root"
    router_iface: str = "br-lan"
    ssh_key_path: str = ""


class BlockIpPayload(BaseModel):
    ip: str
    reason: str = "Manual SOC Block"


class QuarantineHostPayload(BaseModel):
    lan_ip: str
    reason: str = "LAN Host Quarantine"


class KillPidPayload(BaseModel):
    pid: int


def create_app(config: Optional[AegisConfig] = None) -> FastAPI:
    cfg = config or AegisConfig.from_env()
    core = NGFWTelemetryCore(cfg)
    static_dir = get_static_dir()
    ws_clients: Set[WebSocket] = set()

    async def _ws_broadcast_loop() -> None:
        while True:
            await asyncio.sleep(1.0)
            snap = core.tick_1s_snapshot()
            if not ws_clients:
                continue
            dead: List[WebSocket] = []
            for ws in list(ws_clients):
                try:
                    await ws.send_json(snap)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                ws_clients.discard(ws)

    @contextlib.asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        core.startup()
        broadcaster_task = asyncio.create_task(_ws_broadcast_loop())
        try:
            yield
        finally:
            broadcaster_task.cancel()
            core.shutdown()

    app = FastAPI(
        title="Aegis // Personal System & Router Network Digital Shield",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.core = core
    app.state.config = cfg

    @app.get("/api/health")
    def api_health() -> dict:
        return {
            "ok": True,
            "version": __version__,
            **cfg.public_metadata(),
        }

    @app.get("/api/snapshot")
    def api_snapshot() -> dict:
        return core.tick_1s_snapshot()

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket) -> None:
        await ws.accept()
        ws_clients.add(ws)
        try:
            await ws.send_json(core.tick_1s_snapshot())
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            ws_clients.discard(ws)

    @app.post("/api/capture/start")
    def api_start_capture() -> dict:
        core.start_capture()
        return {"ok": True, "capturing": True}

    @app.post("/api/capture/stop")
    def api_stop_capture() -> dict:
        core.stop_capture()
        return {"ok": True, "capturing": False}

    @app.post("/api/mode")
    def api_switch_mode(payload: ModeSwitchPayload) -> dict:
        return core.switch_mode(
            new_mode=payload.mode,
            router_host=payload.router_host,
            router_port=payload.router_port,
            router_user=payload.router_user,
            router_iface=payload.router_iface,
            ssh_key_path=payload.ssh_key_path,
        )

    @app.post("/api/router/diagnose")
    def api_router_diagnose(payload: RouterConnectPayload) -> dict:
        return core.shield.diagnose_router(
            router_host=payload.router_host,
            router_port=payload.router_port,
            router_user=payload.router_user,
            router_iface=payload.router_iface,
            ssh_key_path=payload.ssh_key_path,
        )

    @app.post("/api/router/connect")
    def api_router_connect(payload: RouterConnectPayload) -> dict:
        diag = core.shield.diagnose_router(
            router_host=payload.router_host,
            router_port=payload.router_port,
            router_user=payload.router_user,
            router_iface=payload.router_iface,
            ssh_key_path=payload.ssh_key_path,
        )
        if not diag.get("ok"):
            return diag
        core.switch_mode(
            new_mode="router",
            router_host=payload.router_host,
            router_port=payload.router_port,
            router_user=payload.router_user,
            router_iface=payload.router_iface,
            ssh_key_path=payload.ssh_key_path,
        )
        return {**diag, "connected": True, "mode": "router"}

    @app.post("/api/router/audit")
    def api_router_audit() -> dict:
        return core.shield.run_router_security_audit()

    @app.post("/api/shield/block-ip")
    def api_block_ip(payload: BlockIpPayload) -> dict:
        ok, msg = core.shield.block_remote_ip_on_router(payload.ip, payload.reason)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        return {"ok": True, "message": msg, "rules": core.shield.list_active_rules()}

    @app.post("/api/shield/quarantine-host")
    def api_quarantine_host(payload: QuarantineHostPayload) -> dict:
        ok, msg = core.shield.quarantine_lan_device_on_router(
            lan_ip=payload.lan_ip,
            local_pc_ips=core.correlator.local_ips,
            reason=payload.reason,
        )
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        return {"ok": True, "message": msg, "rules": core.shield.list_active_rules()}

    @app.post("/api/shield/flush-rules")
    def api_flush_rules() -> dict:
        ok, msg = core.shield.flush_all_router_blocks()
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        return {"ok": True, "message": msg, "rules": []}

    @app.post("/api/shield/kill-pid")
    def api_kill_pid(payload: KillPidPayload) -> dict:
        ok, msg = core.shield.terminate_local_process(payload.pid)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        return {"ok": True, "message": msg}

    @app.post("/api/idle-watch/toggle")
    def api_toggle_idle() -> dict:
        state = core.toggle_idle_watch()
        return {"ok": True, "idle_watch": state}

    @app.post("/api/clear")
    def api_clear() -> dict:
        core.clear_session()
        return {"ok": True}

    @app.post("/api/feeds/update")
    def api_update_feeds() -> dict:
        stats = core.threat_intel.update_all_feeds()
        return {"ok": True, "intel": core.threat_intel.summary_counts(), "feeds": stats}

    @app.get("/api/flow/{flow_id}")
    def api_flow_detail(flow_id: str) -> dict:
        detail = core.get_flow_details(flow_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Flow not found")
        return detail

    @app.get("/api/report/markdown")
    def api_download_report() -> Response:
        snap = core.tick_1s_snapshot()
        md = core.shield.build_markdown_report(snap)
        fname = f"aegis_security_report_{int(time.time())}.md"
        return Response(
            content=md.encode("utf-8"),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @app.get("/api/pcap/download")
    def api_download_pcap() -> Response:
        data = core.export_pcap_bytes()
        fname = f"aegis_capture_{int(time.time())}.pcap"
        return Response(
            content=data,
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @app.post("/api/pcap/import")
    async def api_import_pcap(request: Request) -> dict:
        raw_bytes = await request.body()
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Empty PCAP payload")
        if len(raw_bytes) > 64 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="PCAP exceeds 64 MB limit")
        try:
            core.stop_capture()
            pkt_count = core.ingest_pcap_bytes(raw_bytes)
            return {"ok": True, "imported_packets": pkt_count}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/")
    def serve_index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    return app
