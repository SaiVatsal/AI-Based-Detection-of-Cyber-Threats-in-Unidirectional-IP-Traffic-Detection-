"""
CampusShield AI — Audit Logging
================================
Utility for writing immutable audit records for compliance
and forensic review.
"""

from typing import Optional
from sqlalchemy.orm import Session

from backend.database.crud import create_audit_log


def log_action(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[int] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Fire-and-forget audit log entry.
    Called from route handlers and background tasks.

    Actions:
        login, logout, upload, analyze, train, config_change,
        alert_acknowledge, report_generate, register
    """
    try:
        create_audit_log(
            db=db,
            action=action,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
        )
    except Exception:
        # Audit logging must never crash the main operation.
        # In production, forward to a secondary logging sink.
        pass
