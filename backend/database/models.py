"""
CampusShield AI — Database Models
==================================
SQLAlchemy ORM models for all persistent entities.
Uses SQLite for MVP; schema is designed to be portable to PostgreSQL.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    Float,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    JSON,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _utcnow() -> datetime:
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=True)
    role = Column(String(32), nullable=False, default="analyst")  # admin | analyst
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    sessions = relationship("TrafficSession", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"


# ---------------------------------------------------------------------------
# Traffic Sessions
# ---------------------------------------------------------------------------
class TrafficSession(Base):
    """
    Represents a single traffic analysis session — either a PCAP upload
    or a simulation run. All packets within a session share this parent.
    """
    __tablename__ = "traffic_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(256), nullable=False)
    source_type = Column(String(32), nullable=False)  # "pcap" | "simulation"
    scenario = Column(String(64), nullable=True)  # simulation scenario name
    file_path = Column(String(512), nullable=True)  # path to uploaded PCAP
    file_size_bytes = Column(Integer, nullable=True)
    packet_count = Column(Integer, default=0)
    flow_count = Column(Integer, default=0)
    duration_seconds = Column(Float, nullable=True)
    status = Column(String(32), default="pending")  # pending | processing | completed | error
    error_message = Column(Text, nullable=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="sessions")
    detection_results = relationship(
        "DetectionResult", back_populates="session", cascade="all, delete-orphan"
    )
    alerts = relationship(
        "Alert", back_populates="session", cascade="all, delete-orphan"
    )

    # Summary stats stored as JSON for fast dashboard queries
    traffic_stats = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_sessions_status", "status"),
        Index("ix_sessions_created", "created_at"),
    )


# ---------------------------------------------------------------------------
# Detection Results
# ---------------------------------------------------------------------------
class DetectionResult(Base):
    """
    Per-flow or per-window detection output from the Isolation Forest pipeline.
    Each row represents the analysis of one traffic window.
    """
    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("traffic_sessions.id"), nullable=False)
    window_index = Column(Integer, nullable=False)  # sequential window number
    window_start = Column(DateTime, nullable=True)
    window_end = Column(DateTime, nullable=True)

    # ML outputs
    is_anomaly = Column(Boolean, nullable=False, default=False)
    anomaly_score = Column(Float, nullable=False)  # raw isolation forest score
    normalized_score = Column(Float, nullable=False)  # 0-100 threat score

    # Classification
    threat_category = Column(String(128), nullable=True)
    severity = Column(String(16), nullable=True)  # LOW | MEDIUM | HIGH | CRITICAL
    confidence = Column(Float, nullable=True)  # 0.0 - 1.0

    # Extracted features (stored as JSON for flexibility)
    features = Column(JSON, nullable=True)

    # Explanation
    explanation = Column(Text, nullable=True)

    created_at = Column(DateTime, default=_utcnow, nullable=False)

    # Relationships
    session = relationship("TrafficSession", back_populates="detection_results")
    contributing_factors = relationship(
        "ContributingFactor",
        back_populates="detection_result",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_detection_session", "session_id"),
        Index("ix_detection_anomaly", "is_anomaly"),
    )


# ---------------------------------------------------------------------------
# Contributing Factors (Explainability)
# ---------------------------------------------------------------------------
class ContributingFactor(Base):
    """
    For each anomalous detection, records which features deviated from
    baseline and by how much — the core of our explainability story.
    """
    __tablename__ = "contributing_factors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_result_id = Column(
        Integer, ForeignKey("detection_results.id"), nullable=False
    )

    feature_name = Column(String(128), nullable=False)
    observed_value = Column(Float, nullable=False)
    baseline_value = Column(Float, nullable=False)
    deviation_pct = Column(Float, nullable=False)  # percentage deviation
    contribution_rank = Column(Integer, nullable=False)  # 1 = highest contributor
    direction = Column(String(16), nullable=False)  # "above" | "below"

    # Relationships
    detection_result = relationship(
        "DetectionResult", back_populates="contributing_factors"
    )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
class Alert(Base):
    """
    User-facing alert generated when an anomaly exceeds alerting thresholds.
    Alerts can be acknowledged and have lifecycle states.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("traffic_sessions.id"), nullable=False)
    detection_result_id = Column(
        Integer, ForeignKey("detection_results.id"), nullable=True
    )

    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False)  # LOW | MEDIUM | HIGH | CRITICAL
    threat_category = Column(String(128), nullable=True)
    threat_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=True)

    # Lifecycle
    status = Column(String(32), default="new")  # new | acknowledged | resolved | false_positive
    acknowledged_by = Column(String(64), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)

    # Metadata
    source_ips = Column(JSON, nullable=True)  # list of source IPs involved
    dest_ips = Column(JSON, nullable=True)
    dest_ports = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=_utcnow, nullable=False)

    # Relationships
    session = relationship("TrafficSession", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_created", "created_at"),
    )


# ---------------------------------------------------------------------------
# Detection Configuration
# ---------------------------------------------------------------------------
class DetectionConfig(Base):
    """
    Persists the current detection configuration so that sensitivity
    adjustments survive server restarts.
    """
    __tablename__ = "detection_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    contamination = Column(Float, nullable=False, default=0.05)
    n_estimators = Column(Integer, nullable=False, default=200)
    window_size_seconds = Column(Float, nullable=False, default=10.0)
    burst_iat_threshold = Column(Float, nullable=False, default=0.001)
    is_trained = Column(Boolean, default=False)
    last_trained_at = Column(DateTime, nullable=True)
    training_session_id = Column(Integer, nullable=True)
    training_packet_count = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------
class AuditLog(Base):
    """
    Immutable log of significant user and system actions for
    compliance and forensic review.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(64), nullable=False)  # login | upload | analyze | config_change | ...
    resource_type = Column(String(64), nullable=True)  # session | alert | config | ...
    resource_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=_utcnow, nullable=False, index=True)

    # Relationships
    user = relationship("User", back_populates="audit_logs")


# ---------------------------------------------------------------------------
# Report Metadata
# ---------------------------------------------------------------------------
class Report(Base):
    """Tracks generated PDF reports for download history."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("traffic_sessions.id"), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(Integer, nullable=True)
    generated_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
