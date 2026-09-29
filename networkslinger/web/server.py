"""
FastAPI web server & WebSocket real-time event streaming for Network Slinger.
"""

import asyncio
from datetime import datetime
import json
import os
import sys
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from ..engine import (
    NetworkSlingerCrawler,
    get_active_interfaces,
    get_default_gateway,
    get_primary_interface,
    parse_targets,
)
from ..models import PortProfile, ScanConfig, ScanProgress, ScanReport
from .reporter import generate_html_report


app = FastAPI(
    title="Network Slinger Web Console",
    description="Next-Gen Async Network Crawler, Reconnaissance & Topology Auditor",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_web_dir() -> str:
    """Resolves web assets directory in development and PyInstaller bundled environments."""
    base_dirs = [os.path.dirname(os.path.abspath(__file__))]
    if getattr(sys, "frozen", False):
        if hasattr(sys, "_MEIPASS"):
            base_dirs.insert(0, sys._MEIPASS)
            base_dirs.insert(0, os.path.join(sys._MEIPASS, "_internal"))
        if hasattr(sys, "executable"):
            exe_dir = os.path.dirname(os.path.abspath(sys.executable))
            base_dirs.append(exe_dir)
            base_dirs.append(os.path.join(exe_dir, "_internal"))

    for base in base_dirs:
        for sub in ["networkslinger/web", "web", ""]:
            cand = os.path.normpath(os.path.join(base, sub))
            if os.path.exists(os.path.join(cand, "templates", "index.html")):
                return cand
    return os.path.dirname(os.path.abspath(__file__))

WEB_DIR = get_web_dir()
STATIC_DIR = os.path.join(WEB_DIR, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Active scan state and websocket client management
active_report: Optional[ScanReport] = None
active_crawler: Optional[NetworkSlingerCrawler] = None
connected_websockets: List[WebSocket] = []


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message, default=str))
            except Exception:
                dead_connections.append(connection)
        for dc in dead_connections:
            self.disconnect(dc)


manager = ConnectionManager()


@app.get("/", response_class=HTMLResponse)
async def get_index():
    """Serves the primary Single Page Application."""
    template_path = os.path.join(WEB_DIR, "templates", "index.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Network Slinger Web Console: Template Missing</h1>")


@app.get("/api/interfaces")
async def list_interfaces():
    """Returns local network interfaces, primary CIDR, and default gateway."""
    ifaces = get_active_interfaces()
    gw = get_default_gateway()
    primary = get_primary_interface()

    return {
        "interfaces": [i.to_dict() for i in ifaces],
        "gateway": gw,
        "primary_cidr": primary.cidr if primary else "127.0.0.1/32"
    }


@app.post("/api/scan")
async def trigger_scan(config: ScanConfig):
    """Triggers an asynchronous network scrawl with live WebSocket streaming."""
    global active_report, active_crawler

    crawler = NetworkSlingerCrawler(config)
    active_crawler = crawler

    loop = asyncio.get_running_loop()

    def on_progress(p: ScanProgress):
        # Schedule async broadcast from sync callback
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({
                "type": "progress",
                "data": p.model_dump()
            }),
            loop
        )

    crawler.register_progress_callback(on_progress)

    async def run_scan_job():
        global active_report
        try:
            await manager.broadcast({
                "type": "log",
                "message": f"Starting scrawl on targets: {config.targets or 'Auto-detected LAN'}"
            })
            report = await crawler.execute_crawl()
            active_report = report
            await manager.broadcast({
                "type": "complete",
                "data": report.model_dump()
            })
        except Exception as e:
            await manager.broadcast({
                "type": "log",
                "message": f"Scrawl error: {str(e)}"
            })

    asyncio.create_task(run_scan_job())

    return {
        "status": "started",
        "scan_id": crawler.scan_id,
        "targets": config.targets
    }


@app.get("/api/scan/active")
async def get_active_scan():
    """Returns latest completed or active scan report."""
    global active_report
    if active_report:
        return active_report.model_dump()
    return {}


@app.get("/api/export/{scan_id}")
async def export_scan(scan_id: str, format: str = "html"):
    """Exports scan report in JSON, CSV, or standalone HTML."""
    global active_report
    if not active_report or active_report.scan_id != scan_id:
        # If scan_id is "latest" or matches
        if not active_report:
            raise HTTPException(status_code=404, detail="No scan report available")

    report = active_report

    if format == "json":
        return Response(
            content=report.model_dump_json(indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=networkslinger-{scan_id}.json"}
        )
    elif format == "csv":
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP", "MAC", "Vendor", "Hostname", "Device Type", "Open Ports", "Risk Score", "Risk Level"])
        for h in report.hosts:
            ports = ";".join(f"{p.port}/{p.service}" for p in h.open_ports)
            writer.writerow([h.ip, h.mac_address or "", h.vendor, h.hostname, h.device_type.value, ports, h.risk_score, h.risk_level.value])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=networkslinger-{scan_id}.csv"}
        )
    else:
        # Standalone HTML report
        html_content = generate_html_report(report)
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f"inline; filename=networkslinger-{scan_id}.html"}
        )


@app.websocket("/ws/scan")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time bidirectional WebSocket stream for live scanning progress."""
    await manager.connect(websocket)
    try:
        # Send current status on connect
        if active_crawler:
            await websocket.send_text(json.dumps({
                "type": "progress",
                "data": active_crawler.progress.model_dump()
            }, default=str))
        while True:
            # Keep-alive receive loop
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


def launch_web_server(host: str = "127.0.0.1", port: int = 8000):
    """Starts the Uvicorn web server."""
    import uvicorn
    from rich.console import Console
    console = Console()

    console.print(f"\n[bold green][+] Network Slinger Web Console running at:[/bold green] [bold cyan]http://{host}:{port}[/bold cyan]")
    console.print("[dim]Press Ctrl+C to stop the server[/dim]\n")

    uvicorn.run(app, host=host, port=port, log_level="info")
