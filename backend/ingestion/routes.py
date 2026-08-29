"""
CampusShield AI — Traffic Ingestion Routes
============================================
PCAP upload, simulation, and session management endpoints.
"""

import shutil
import asyncio
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.config import UPLOAD_DIR, SIMULATION_SCENARIOS
from backend.database.connection import get_db
from backend.database import crud
from backend.database.audit import log_action
from backend.auth.security import get_current_user
from backend.database.models import User
from backend.ingestion.pcap_parser import validate_pcap_file, parse_pcap
from backend.ingestion.traffic_simulator import simulate_traffic, get_scenario_descriptions
from backend.features.extractor import extract_features_windowed, compute_baseline_stats, features_to_dataframe
from backend.features.normalizer import get_normalizer
from backend.detection.isolation_forest import get_detector
from backend.classification.categorizer import ThreatCategorizer
from backend.scoring.scorer import compute_threat_score
from backend.scoring.explainer import generate_contributing_factors, generate_explanation
from backend.alerts.manager import create_and_broadcast_alert, should_alert
from backend.alerts.websocket import broadcast_progress

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/traffic", tags=["Traffic Ingestion"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class SessionResponse(BaseModel):
    id: int
    name: str
    source_type: str
    scenario: str | None
    packet_count: int
    flow_count: int
    duration_seconds: float | None
    status: str
    error_message: str | None
    created_at: str
    completed_at: str | None
    traffic_stats: dict | None

    class Config:
        from_attributes = True


class SimulateRequest(BaseModel):
    packet_count: int = 2000


# ---------------------------------------------------------------------------
# Full Detection Pipeline
# ---------------------------------------------------------------------------
async def run_detection_pipeline(
    db: Session,
    session_id: int,
    packets: list[dict],
    user_id: int | None = None,
):
    """
    Execute the full detection pipeline on a set of packets:
    1. Extract features (windowed)
    2. Normalize features
    3. Run anomaly detection
    4. Categorize anomalies
    5. Score and explain
    6. Generate alerts
    7. Broadcast progress via WebSocket
    """
    try:
        crud.update_session_status(db, session_id, "processing")

        await broadcast_progress({
            "session_id": session_id,
            "stage": "feature_extraction",
            "message": "Extracting unidirectional features...",
            "progress": 10,
        })

        # Step 1: Feature extraction
        feature_windows = extract_features_windowed(packets)
        if not feature_windows:
            crud.update_session_status(
                db, session_id, "error",
                error_message="No feature windows extracted"
            )
            return

        features_df = features_to_dataframe(feature_windows)

        await broadcast_progress({
            "session_id": session_id,
            "stage": "detection",
            "message": f"Analyzing {len(feature_windows)} traffic windows...",
            "progress": 30,
        })

        # Step 2: Get detector and check if trained
        detector = get_detector()
        normalizer = get_normalizer()

        if not detector.is_trained:
            # Auto-train on this data as baseline
            logger.info("No trained model found — training on current data as baseline")
            if normalizer.is_fitted:
                scaled_df = normalizer.transform(features_df)
            else:
                scaled_df = normalizer.fit_transform(features_df)
                normalizer.save()

            detector.train(scaled_df)
            detector.save()

            # Store baseline stats
            baseline_stats = compute_baseline_stats(feature_windows)
        else:
            if normalizer.is_fitted:
                scaled_df = normalizer.transform(features_df)
            else:
                scaled_df = normalizer.fit_transform(features_df)
            baseline_stats = compute_baseline_stats(feature_windows)

        await broadcast_progress({
            "session_id": session_id,
            "stage": "anomaly_detection",
            "message": "Running Isolation Forest anomaly detection...",
            "progress": 50,
        })

        # Step 3: Anomaly detection
        results = detector.predict(scaled_df)
        labels = results["labels"]
        scores = results["scores"]

        # Step 4: Categorize and score each window
        categorizer = ThreatCategorizer(baseline_stats)
        detection_records = []
        alert_count = 0

        await broadcast_progress({
            "session_id": session_id,
            "stage": "classification",
            "message": "Classifying and scoring anomalies...",
            "progress": 70,
        })

        for i, window in enumerate(feature_windows):
            is_anomaly = bool(labels[i] == -1)
            raw_score = float(scores[i])

            if is_anomaly:
                # Categorize
                category_result = categorizer.categorize(window, raw_score)

                # Score
                score_result = compute_threat_score(
                    raw_score, window, baseline_stats, category_result
                )

                # Explain
                contributing = generate_contributing_factors(
                    window, score_result.get("deviations", [])
                )
                explanation = generate_explanation(
                    window, category_result, score_result
                )

                # Create detection result
                det_result = crud.create_detection_result(
                    db=db,
                    session_id=session_id,
                    window_index=i,
                    is_anomaly=True,
                    anomaly_score=raw_score,
                    normalized_score=score_result["threat_score"],
                    threat_category=category_result["label"],
                    severity=score_result["severity"],
                    confidence=score_result["confidence"],
                    features=window,
                    explanation=explanation,
                )

                # Store contributing factors
                if contributing:
                    crud.bulk_create_contributing_factors(
                        db,
                        [
                            {
                                "detection_result_id": det_result.id,
                                "feature_name": f["feature_name"],
                                "observed_value": f["observed_value"],
                                "baseline_value": f["baseline_value"],
                                "deviation_pct": f["deviation_pct"],
                                "contribution_rank": f["contribution_rank"],
                                "direction": f["direction"],
                            }
                            for f in contributing
                        ],
                    )

                # Create alert if warranted
                if should_alert(score_result):
                    await create_and_broadcast_alert(
                        db=db,
                        session_id=session_id,
                        detection_result_id=det_result.id,
                        category_result=category_result,
                        score_result=score_result,
                        features=window,
                        explanation=explanation,
                    )
                    alert_count += 1

                detection_records.append({
                    "window_index": i,
                    "is_anomaly": True,
                    "score": score_result["threat_score"],
                    "severity": score_result["severity"],
                    "category": category_result["label"],
                })
            else:
                # Normal window — still record it
                crud.create_detection_result(
                    db=db,
                    session_id=session_id,
                    window_index=i,
                    is_anomaly=False,
                    anomaly_score=raw_score,
                    normalized_score=0.0,
                    threat_category=None,
                    severity="NONE",
                    confidence=1.0,
                    features=window,
                )

        # Step 5: Update session with results
        n_anomalies = int(sum(labels == -1))
        n_normal = int(sum(labels == 1))
        duration = (
            packets[-1]["timestamp"] - packets[0]["timestamp"]
            if len(packets) > 1 else 0.0
        )

        traffic_stats = {
            "total_packets": len(packets),
            "total_windows": len(feature_windows),
            "normal_windows": n_normal,
            "anomalous_windows": n_anomalies,
            "anomaly_ratio": n_anomalies / len(feature_windows) if feature_windows else 0,
            "total_alerts": alert_count,
            "detection_records": detection_records,
        }

        crud.update_session_status(
            db=db,
            session_id=session_id,
            status="completed",
            packet_count=len(packets),
            flow_count=len(feature_windows),
            duration_seconds=duration,
            traffic_stats=traffic_stats,
        )

        await broadcast_progress({
            "session_id": session_id,
            "stage": "complete",
            "message": (
                f"Analysis complete: {n_anomalies} anomalies detected, "
                f"{alert_count} alerts generated"
            ),
            "progress": 100,
            "results": traffic_stats,
        })

        logger.info(
            f"Pipeline complete for session {session_id}: "
            f"{n_anomalies}/{len(feature_windows)} anomalous windows, "
            f"{alert_count} alerts"
        )

    except Exception as e:
        logger.exception(f"Pipeline failed for session {session_id}")
        crud.update_session_status(
            db, session_id, "error", error_message=str(e)
        )
        await broadcast_progress({
            "session_id": session_id,
            "stage": "error",
            "message": f"Analysis failed: {str(e)}",
            "progress": 0,
        })


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Upload a PCAP file for analysis."""
    # Save uploaded file
    filename = file.filename or "upload.pcap"
    file_path = UPLOAD_DIR / filename

    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    # Validate
    is_valid, error = validate_pcap_file(file_path)
    if not is_valid:
        file_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=error)

    # Create session
    session = crud.create_session(
        db=db,
        name=f"PCAP: {filename}",
        source_type="pcap",
        user_id=current_user.id,
        file_path=str(file_path),
        file_size_bytes=len(content),
    )

    log_action(
        db,
        action="upload",
        user_id=current_user.id,
        resource_type="session",
        resource_id=session.id,
        details={"filename": filename, "size": len(content)},
    )

    # Parse and run pipeline
    packets = parse_pcap(file_path)
    if not packets:
        crud.update_session_status(
            db, session.id, "error",
            error_message="No packets extracted from PCAP file"
        )
        raise HTTPException(status_code=400, detail="Could not parse any packets from the file")

    # Run pipeline in background
    asyncio.create_task(run_detection_pipeline(db, session.id, packets, current_user.id))

    return {
        "message": "PCAP uploaded and analysis started",
        "session_id": session.id,
        "packet_count": len(packets),
    }


@router.post("/simulate/{scenario}")
async def start_simulation(
    scenario: str,
    body: SimulateRequest = SimulateRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Start a traffic simulation scenario."""
    if scenario not in SIMULATION_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{scenario}'. Valid: {SIMULATION_SCENARIOS}",
        )

    # Create session
    descriptions = get_scenario_descriptions()
    desc = descriptions.get(scenario, {})
    session = crud.create_session(
        db=db,
        name=f"Simulation: {desc.get('name', scenario)}",
        source_type="simulation",
        scenario=scenario,
        user_id=current_user.id,
    )

    log_action(
        db,
        action="simulate",
        user_id=current_user.id,
        resource_type="session",
        resource_id=session.id,
        details={"scenario": scenario, "packet_count": body.packet_count},
    )

    # Generate synthetic packets
    packets = simulate_traffic(scenario, body.packet_count)

    # Run pipeline in background
    asyncio.create_task(run_detection_pipeline(db, session.id, packets, current_user.id))

    return {
        "message": f"Simulation '{scenario}' started",
        "session_id": session.id,
        "scenario": desc,
        "packet_count": len(packets),
    }


@router.get("/sessions", response_model=list[SessionResponse])
def list_sessions(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all traffic sessions."""
    sessions = crud.list_sessions(db, limit=limit, offset=offset)
    return [
        SessionResponse(
            id=s.id,
            name=s.name,
            source_type=s.source_type,
            scenario=s.scenario,
            packet_count=s.packet_count,
            flow_count=s.flow_count,
            duration_seconds=s.duration_seconds,
            status=s.status,
            error_message=s.error_message,
            created_at=s.created_at.isoformat(),
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
            traffic_stats=s.traffic_stats,
        )
        for s in sessions
    ]


@router.get("/sessions/{session_id}", response_model=SessionResponse)
def get_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get details of a specific traffic session."""
    s = crud.get_session(db, session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return SessionResponse(
        id=s.id,
        name=s.name,
        source_type=s.source_type,
        scenario=s.scenario,
        packet_count=s.packet_count,
        flow_count=s.flow_count,
        duration_seconds=s.duration_seconds,
        status=s.status,
        error_message=s.error_message,
        created_at=s.created_at.isoformat(),
        completed_at=s.completed_at.isoformat() if s.completed_at else None,
        traffic_stats=s.traffic_stats,
    )


@router.get("/scenarios")
def get_scenarios():
    """Get available simulation scenarios with descriptions."""
    return get_scenario_descriptions()
