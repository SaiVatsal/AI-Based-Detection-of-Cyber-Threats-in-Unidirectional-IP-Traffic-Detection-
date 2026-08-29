"""
CampusShield AI — CRUD Operations
===================================
Data access layer for all models. Keeps SQL out of route handlers.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from backend.database.models import (
    User,
    TrafficSession,
    DetectionResult,
    ContributingFactor,
    Alert,
    DetectionConfig,
    AuditLog,
    Report,
)


# ===================================================================
# Users
# ===================================================================
def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def create_user(
    db: Session,
    username: str,
    email: str,
    hashed_password: str,
    full_name: str = "",
    role: str = "analyst",
) -> User:
    user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        full_name=full_name,
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_last_login(db: Session, user_id: int) -> None:
    db.query(User).filter(User.id == user_id).update(
        {"last_login": datetime.now(timezone.utc)}
    )
    db.commit()


def list_users(db: Session) -> list[User]:
    return db.query(User).order_by(User.created_at).all()


# ===================================================================
# Traffic Sessions
# ===================================================================
def create_session(
    db: Session,
    name: str,
    source_type: str,
    user_id: Optional[int] = None,
    scenario: Optional[str] = None,
    file_path: Optional[str] = None,
    file_size_bytes: Optional[int] = None,
) -> TrafficSession:
    session = TrafficSession(
        name=name,
        source_type=source_type,
        user_id=user_id,
        scenario=scenario,
        file_path=file_path,
        file_size_bytes=file_size_bytes,
        status="pending",
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def get_session(db: Session, session_id: int) -> Optional[TrafficSession]:
    return db.query(TrafficSession).filter(TrafficSession.id == session_id).first()


def list_sessions(
    db: Session, limit: int = 50, offset: int = 0
) -> list[TrafficSession]:
    return (
        db.query(TrafficSession)
        .order_by(desc(TrafficSession.created_at))
        .offset(offset)
        .limit(limit)
        .all()
    )


def update_session_status(
    db: Session,
    session_id: int,
    status: str,
    packet_count: Optional[int] = None,
    flow_count: Optional[int] = None,
    duration_seconds: Optional[float] = None,
    traffic_stats: Optional[dict] = None,
    error_message: Optional[str] = None,
) -> None:
    updates: dict = {"status": status}
    if packet_count is not None:
        updates["packet_count"] = packet_count
    if flow_count is not None:
        updates["flow_count"] = flow_count
    if duration_seconds is not None:
        updates["duration_seconds"] = duration_seconds
    if traffic_stats is not None:
        updates["traffic_stats"] = traffic_stats
    if error_message is not None:
        updates["error_message"] = error_message
    if status == "completed":
        updates["completed_at"] = datetime.now(timezone.utc)

    db.query(TrafficSession).filter(TrafficSession.id == session_id).update(updates)
    db.commit()


# ===================================================================
# Detection Results
# ===================================================================
def create_detection_result(db: Session, **kwargs) -> DetectionResult:
    result = DetectionResult(**kwargs)
    db.add(result)
    db.commit()
    db.refresh(result)
    return result


def bulk_create_detection_results(
    db: Session, results: list[dict]
) -> list[DetectionResult]:
    objects = [DetectionResult(**r) for r in results]
    db.add_all(objects)
    db.commit()
    for obj in objects:
        db.refresh(obj)
    return objects


def get_detection_results_for_session(
    db: Session, session_id: int
) -> list[DetectionResult]:
    return (
        db.query(DetectionResult)
        .filter(DetectionResult.session_id == session_id)
        .order_by(DetectionResult.window_index)
        .all()
    )


def get_anomalous_results_for_session(
    db: Session, session_id: int
) -> list[DetectionResult]:
    return (
        db.query(DetectionResult)
        .filter(
            DetectionResult.session_id == session_id,
            DetectionResult.is_anomaly == True,  # noqa: E712
        )
        .order_by(desc(DetectionResult.normalized_score))
        .all()
    )


# ===================================================================
# Contributing Factors
# ===================================================================
def bulk_create_contributing_factors(
    db: Session, factors: list[dict]
) -> list[ContributingFactor]:
    objects = [ContributingFactor(**f) for f in factors]
    db.add_all(objects)
    db.commit()
    return objects


def get_factors_for_detection(
    db: Session, detection_result_id: int
) -> list[ContributingFactor]:
    return (
        db.query(ContributingFactor)
        .filter(ContributingFactor.detection_result_id == detection_result_id)
        .order_by(ContributingFactor.contribution_rank)
        .all()
    )


# ===================================================================
# Alerts
# ===================================================================
def create_alert(db: Session, **kwargs) -> Alert:
    alert = Alert(**kwargs)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def get_alert(db: Session, alert_id: int) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.id == alert_id).first()


def list_alerts(
    db: Session,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    session_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Alert]:
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if session_id:
        query = query.filter(Alert.session_id == session_id)
    return query.order_by(desc(Alert.created_at)).offset(offset).limit(limit).all()


def get_alert_stats(db: Session) -> dict:
    """Aggregate alert statistics for the dashboard."""
    total = db.query(func.count(Alert.id)).scalar() or 0
    by_severity = dict(
        db.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    by_status = dict(
        db.query(Alert.status, func.count(Alert.id))
        .group_by(Alert.status)
        .all()
    )
    by_category = dict(
        db.query(Alert.threat_category, func.count(Alert.id))
        .group_by(Alert.threat_category)
        .all()
    )
    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_category": by_category,
    }


def acknowledge_alert(
    db: Session, alert_id: int, username: str
) -> Optional[Alert]:
    alert = get_alert(db, alert_id)
    if alert is None:
        return None
    alert.status = "acknowledged"
    alert.acknowledged_by = username
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    return alert


# ===================================================================
# Detection Config
# ===================================================================
def get_detection_config(db: Session) -> DetectionConfig:
    config = db.query(DetectionConfig).first()
    if config is None:
        config = DetectionConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


def update_detection_config(db: Session, **kwargs) -> DetectionConfig:
    config = get_detection_config(db)
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
    config.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(config)
    return config


# ===================================================================
# Audit Log
# ===================================================================
def create_audit_log(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[int] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
    )
    db.add(log)
    db.commit()
    return log


def list_audit_logs(
    db: Session, limit: int = 200, offset: int = 0
) -> list[AuditLog]:
    return (
        db.query(AuditLog)
        .order_by(desc(AuditLog.timestamp))
        .offset(offset)
        .limit(limit)
        .all()
    )


# ===================================================================
# Reports
# ===================================================================
def create_report(db: Session, **kwargs) -> Report:
    report = Report(**kwargs)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_report(db: Session, report_id: int) -> Optional[Report]:
    return db.query(Report).filter(Report.id == report_id).first()


def list_reports(db: Session, limit: int = 50) -> list[Report]:
    return db.query(Report).order_by(desc(Report.created_at)).limit(limit).all()
