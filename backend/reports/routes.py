"""
CampusShield AI — Report Routes
=================================
PDF report generation and download endpoints.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database import crud
from backend.database.audit import log_action
from backend.auth.security import get_current_user
from backend.database.models import User
from backend.reports.generator import generate_report

router = APIRouter(prefix="/api/reports", tags=["Reports"])


class ReportResponse(BaseModel):
    id: int
    session_id: int
    file_path: str
    file_size_bytes: int | None
    generated_by: str | None
    created_at: str

    class Config:
        from_attributes = True


@router.post("/generate/{session_id}")
def generate(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a PDF report for a session."""
    session = crud.get_session(db, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status != "completed":
        raise HTTPException(status_code=400, detail="Session analysis not yet complete")

    try:
        file_path = generate_report(db, session_id, current_user.username)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

    log_action(
        db,
        action="report_generate",
        user_id=current_user.id,
        resource_type="report",
        details={"session_id": session_id},
    )

    return {
        "message": "Report generated successfully",
        "file_path": str(file_path),
        "file_name": file_path.name,
    }


@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download a generated PDF report."""
    report = crud.get_report(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    return FileResponse(
        path=str(file_path),
        filename=file_path.name,
        media_type="application/pdf",
    )


@router.get("", response_model=list[ReportResponse])
def list_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all generated reports."""
    reports = crud.list_reports(db)
    return [
        ReportResponse(
            id=r.id,
            session_id=r.session_id,
            file_path=r.file_path,
            file_size_bytes=r.file_size_bytes,
            generated_by=r.generated_by,
            created_at=r.created_at.isoformat(),
        )
        for r in reports
    ]
