"""
CampusShield AI — Detection Routes
====================================
Endpoints for training, analysis, and configuration.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database import crud
from backend.database.audit import log_action
from backend.auth.security import get_current_user
from backend.database.models import User
from backend.config import MIN_CONTAMINATION, MAX_CONTAMINATION

router = APIRouter(prefix="/api/detection", tags=["Detection"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class DetectionConfigResponse(BaseModel):
    contamination: float
    n_estimators: int
    window_size_seconds: float
    burst_iat_threshold: float
    is_trained: bool
    last_trained_at: str | None
    training_session_id: int | None
    training_packet_count: int | None


class UpdateConfigRequest(BaseModel):
    contamination: float | None = Field(None, ge=MIN_CONTAMINATION, le=MAX_CONTAMINATION)
    window_size_seconds: float | None = Field(None, ge=1.0, le=300.0)
    burst_iat_threshold: float | None = Field(None, ge=0.0001, le=1.0)


class DetectionResultResponse(BaseModel):
    id: int
    session_id: int
    window_index: int
    is_anomaly: bool
    anomaly_score: float
    normalized_score: float
    threat_category: str | None
    severity: str | None
    confidence: float | None
    explanation: str | None
    created_at: str

    class Config:
        from_attributes = True


class ContributingFactorResponse(BaseModel):
    feature_name: str
    observed_value: float
    baseline_value: float
    deviation_pct: float
    contribution_rank: int
    direction: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/config", response_model=DetectionConfigResponse)
def get_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current detection configuration."""
    config = crud.get_detection_config(db)
    return DetectionConfigResponse(
        contamination=config.contamination,
        n_estimators=config.n_estimators,
        window_size_seconds=config.window_size_seconds,
        burst_iat_threshold=config.burst_iat_threshold,
        is_trained=config.is_trained,
        last_trained_at=config.last_trained_at.isoformat() if config.last_trained_at else None,
        training_session_id=config.training_session_id,
        training_packet_count=config.training_packet_count,
    )


@router.put("/config", response_model=DetectionConfigResponse)
def update_config(
    payload: UpdateConfigRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update detection sensitivity parameters."""
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No parameters to update")

    config = crud.update_detection_config(db, **update_data)

    log_action(
        db,
        action="config_change",
        user_id=current_user.id,
        resource_type="detection_config",
        details=update_data,
    )

    return DetectionConfigResponse(
        contamination=config.contamination,
        n_estimators=config.n_estimators,
        window_size_seconds=config.window_size_seconds,
        burst_iat_threshold=config.burst_iat_threshold,
        is_trained=config.is_trained,
        last_trained_at=config.last_trained_at.isoformat() if config.last_trained_at else None,
        training_session_id=config.training_session_id,
        training_packet_count=config.training_packet_count,
    )


@router.get("/results/{session_id}", response_model=list[DetectionResultResponse])
def get_detection_results(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all detection results for a session."""
    results = crud.get_detection_results_for_session(db, session_id)
    return [
        DetectionResultResponse(
            id=r.id,
            session_id=r.session_id,
            window_index=r.window_index,
            is_anomaly=r.is_anomaly,
            anomaly_score=r.anomaly_score,
            normalized_score=r.normalized_score,
            threat_category=r.threat_category,
            severity=r.severity,
            confidence=r.confidence,
            explanation=r.explanation,
            created_at=r.created_at.isoformat(),
        )
        for r in results
    ]


@router.get("/results/{session_id}/anomalies", response_model=list[DetectionResultResponse])
def get_anomalous_results(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get only anomalous detection results for a session, sorted by score."""
    results = crud.get_anomalous_results_for_session(db, session_id)
    return [
        DetectionResultResponse(
            id=r.id,
            session_id=r.session_id,
            window_index=r.window_index,
            is_anomaly=r.is_anomaly,
            anomaly_score=r.anomaly_score,
            normalized_score=r.normalized_score,
            threat_category=r.threat_category,
            severity=r.severity,
            confidence=r.confidence,
            explanation=r.explanation,
            created_at=r.created_at.isoformat(),
        )
        for r in results
    ]


@router.get("/factors/{detection_id}", response_model=list[ContributingFactorResponse])
def get_contributing_factors(
    detection_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get contributing factors for a specific detection result."""
    factors = crud.get_factors_for_detection(db, detection_id)
    return [
        ContributingFactorResponse(
            feature_name=f.feature_name,
            observed_value=f.observed_value,
            baseline_value=f.baseline_value,
            deviation_pct=f.deviation_pct,
            contribution_rank=f.contribution_rank,
            direction=f.direction,
        )
        for f in factors
    ]
