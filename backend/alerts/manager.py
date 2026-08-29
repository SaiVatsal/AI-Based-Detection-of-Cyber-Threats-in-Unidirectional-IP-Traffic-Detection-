"""
CampusShield AI — Alert Manager
=================================
Create, store, and broadcast alerts from detection results.
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from backend.database.crud import create_alert as db_create_alert
from backend.alerts.websocket import broadcast_alert

logger = logging.getLogger(__name__)


async def create_and_broadcast_alert(
    db: Session,
    session_id: int,
    detection_result_id: int,
    category_result: dict,
    score_result: dict,
    features: dict,
    explanation: str,
) -> dict:
    """
    Create an alert from detection results and broadcast via WebSocket.

    Args:
        db: Database session
        session_id: Traffic session ID
        detection_result_id: Associated detection result ID
        category_result: From ThreatCategorizer
        score_result: From compute_threat_score
        features: Raw feature dict
        explanation: Natural language explanation

    Returns:
        Created alert dict
    """
    threat_score = score_result["threat_score"]
    severity = score_result["severity"]
    category_label = category_result["label"]

    # Build descriptive title
    title = f"{severity} — {category_label}"

    # Extract IP/port info from features or detection context
    alert = db_create_alert(
        db=db,
        session_id=session_id,
        detection_result_id=detection_result_id,
        title=title,
        description=explanation,
        severity=severity,
        threat_category=category_label,
        threat_score=threat_score,
        confidence=score_result.get("confidence", 0),
    )

    # Build WebSocket payload
    ws_payload = {
        "type": "alert",
        "alert": {
            "id": alert.id,
            "title": title,
            "severity": severity,
            "threat_category": category_label,
            "threat_score": threat_score,
            "confidence": score_result.get("confidence", 0),
            "description": explanation[:500],  # truncate for WS
            "session_id": session_id,
            "created_at": alert.created_at.isoformat(),
            "components": score_result.get("components", {}),
        },
    }

    # Broadcast to all connected WebSocket clients
    await broadcast_alert(ws_payload)

    logger.info(
        f"Alert #{alert.id} created: {title} "
        f"(score={threat_score}, severity={severity})"
    )

    return ws_payload["alert"]


def should_alert(score_result: dict, min_severity: str = "LOW") -> bool:
    """
    Determine whether a detection result warrants an alert.
    Filters out very low-confidence detections.
    """
    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    result_severity = severity_order.get(score_result["severity"], 0)
    min_level = severity_order.get(min_severity, 0)

    return (
        result_severity >= min_level
        and score_result.get("confidence", 0) > 0.2
    )
