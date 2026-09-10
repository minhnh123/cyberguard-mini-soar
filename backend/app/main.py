import contextlib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db
from app.seed_data.seed import seed_database
from app.services.websocket_manager import ws_manager

from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router
from app.api.approvals import router as approvals_router
from app.api.playbooks import router as playbooks_router
from app.api.threat_intel import router as threat_intel_router
from app.api.connectors import router as connectors_router
from app.api.settings import router as settings_router
from app.api.stats import router as stats_router
from app.api.mitre import router as mitre_router

import asyncio
from app.services.ttl_worker import start_ttl_worker

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("[CyberGuard SOAR] Initializing Database & Seed Data...")
    await init_db()
    await seed_database()
    ttl_task = asyncio.create_task(start_ttl_worker(interval_seconds=15))
    print("[CyberGuard SOAR] Ready to receive alerts and orchestrate incident responses.")
    yield
    # Shutdown
    print("[CyberGuard SOAR] Shutting down.")
    ttl_task.cancel()
    try:
        await ttl_task
    except (asyncio.CancelledError, Exception):
        pass

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Mini SOAR with AI Incident Triage, MITRE ATT&CK Mapping, and Human-in-the-Loop Automation",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import os
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Register API routers
app.include_router(stats_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(incidents_router, prefix=settings.API_V1_STR)
app.include_router(approvals_router, prefix=settings.API_V1_STR)
app.include_router(playbooks_router, prefix=settings.API_V1_STR)
app.include_router(threat_intel_router, prefix=settings.API_V1_STR)
app.include_router(connectors_router, prefix=settings.API_V1_STR)
app.include_router(settings_router, prefix=settings.API_V1_STR)
app.include_router(mitre_router, prefix=settings.API_V1_STR)

# Real-time WebSocket Event Stream
@app.websocket(f"{settings.API_V1_STR}/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, Exception):
        ws_manager.disconnect(websocket)

# Serve Health & API Info
@app.get(f"{settings.API_V1_STR}/health")
async def health_check():
    return {
        "system": settings.PROJECT_NAME,
        "status": "operational",
        "version": "1.0.0"
    }

# Serve Frontend SPA
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        file_path = FRONTEND_DIST / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(FRONTEND_DIST / "index.html")
else:
    @app.get("/")
    async def root():
        return {
            "system": settings.PROJECT_NAME,
            "status": "operational",
            "version": "1.0.0",
            "docs": "/docs",
            "api_v1": settings.API_V1_STR
        }
