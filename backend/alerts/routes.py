"""
CampusShield AI — Alert Routes
================================
REST endpoints for alert management.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database import crud
from backend.database.audit import log_action
from backend.auth.security import get_current_user
from backend.database.models import User

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class AlertResponse(BaseModel):
    id: int
    session_id: int
    title: str
    description: str | None
    severity: str
    threat_category: str | None
    threat_score: float
    confidence: float | None
    status: str
    acknowledged_by: str | None
    acknowledged_at: str | None
    created_at: str

    class Config:
        from_attributes = True


class AlertStatsResponse(BaseModel):
    total: int
    by_severity: dict
    by_status: dict
    by_category: dict


class AcknowledgeRequest(BaseModel):
    notes: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("", response_model=list[AlertResponse])
def list_alerts(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    session_id: int | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List alerts with optional filtering by severity, status, or session."""
    alerts = crud.list_alerts(
        db,
        severity=severity,
        status=status,
        session_id=session_id,
        limit=limit,
        offset=offset,
    )
    return [
        AlertResponse(
            id=a.id,
            session_id=a.session_id,
            title=a.title,
            description=a.description,
            severity=a.severity,
            threat_category=a.threat_category,
            threat_score=a.threat_score,
            confidence=a.confidence,
            status=a.status,
            acknowledged_by=a.acknowledged_by,
            acknowledged_at=a.acknowledged_at.isoformat() if a.acknowledged_at else None,
            created_at=a.created_at.isoformat(),
        )
        for a in alerts
    ]


@router.get("/stats", response_model=AlertStatsResponse)
def get_alert_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get aggregate alert statistics for the dashboard."""
    return crud.get_alert_stats(db)


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single alert with full details."""
    alert = crud.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse(
        id=alert.id,
        session_id=alert.session_id,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        threat_category=alert.threat_category,
        threat_score=alert.threat_score,
        confidence=alert.confidence,
        status=alert.status,
        acknowledged_by=alert.acknowledged_by,
        acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        created_at=alert.created_at.isoformat(),
    )


@router.put("/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark an alert as acknowledged."""
    alert = crud.acknowledge_alert(db, alert_id, current_user.username)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    log_action(
        db,
        action="alert_acknowledge",
        user_id=current_user.id,
        resource_type="alert",
        resource_id=alert_id,
    )

    return {"message": "Alert acknowledged", "alert_id": alert_id}
