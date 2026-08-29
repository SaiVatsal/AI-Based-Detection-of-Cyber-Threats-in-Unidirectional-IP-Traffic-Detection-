"""
CampusShield AI — API Router
==============================
Central router that aggregates all endpoint modules.
"""

from fastapi import APIRouter

from backend.auth.routes import router as auth_router
from backend.ingestion.routes import router as traffic_router
from backend.detection.routes import router as detection_router
from backend.alerts.routes import router as alerts_router
from backend.reports.routes import router as reports_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(traffic_router)
api_router.include_router(detection_router)
api_router.include_router(alerts_router)
api_router.include_router(reports_router)
