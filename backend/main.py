import logging ## records 
from contextlib import asynccontextmanager
# mangaes the startup and shutdoen the application 
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.config import CORS_ORIGINS, REPORT_DIR
from backend.database.connection import init_db, SessionLocal
from backend.auth.security import seed_demo_users
from backend.api.router import api_router
from backend.alerts.websocket import manager

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S", ## 
)
logger = logging.getLogger("campusshield")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup
    logger.info("=" * 60)
    logger.info("  CampusShield AI — Starting Up")
    logger.info("  SIH26145: Unidirectional Traffic Threat Detection")
    logger.info("=" * 60)

    # Initialize database
    init_db()
    logger.info("Database initialized")

    # Seed demo users
    db = SessionLocal()
    try:
        seed_demo_users(db)## if real adim login only get fulll acess or no acces only view
        logger.info("Demo users seeded (admin/analyst)")
    finally:
        db.close()

    logger.info("CampusShield AI ready")

    yield

    # Shutdown
    logger.info("CampusShield AI shutting down")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="CampusShield AI",
    description=(
        "AI-powered cyber threat detection for unidirectional IP traffic. "
        "Built for SIH26145 — detects anomalies in one-way network traffic "
        "observable through data diodes or unidirectional gateways."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Static files (reports)
# ---------------------------------------------------------------------------
REPORT_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/reports", StaticFiles(directory=str(REPORT_DIR)), name="reports")


# API Routes
# ---------------------------------------------------------------------------
app.include_router(api_router)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------
@app.websocket("/ws/alerts")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(default=None),
):
    """
    WebSocket endpoint for real-time alert streaming.
    Authenticate via query parameter: ws://host/ws/alerts?token=JWT
    """
    connected = await manager.connect(websocket, token)
    if not connected:
        return

    try:
        # Send initial connection confirmation
        await manager.send_personal(websocket, {
            "type": "connected",
            "message": "Connected to CampusShield AI alert stream",
            "active_connections": manager.connection_count,
        })

        # Keep connection alive, listen for client messages
        while True:
            data = await websocket.receive_text()
            # Client can send ping/pong or commands
            if data == "ping":
                await manager.send_personal(websocket, {"type": "pong"})
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "CampusShield AI",
        "version": "1.0.0",
    }


@app.get("/", tags=["System"])
def root():
    """Root endpoint with API information."""
    return {
        "name": "CampusShield AI",
        "description": "Unidirectional IP Traffic Threat Detection System",
        "problem_statement": "SIH26145",
        "docs": "/docs",
        "health": "/health",
    }
