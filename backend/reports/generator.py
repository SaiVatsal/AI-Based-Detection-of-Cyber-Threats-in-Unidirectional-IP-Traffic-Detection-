"""
CampusShield AI — PDF Report Generator
========================================
Generate professional PDF reports from detection results
using ReportLab.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from sqlalchemy.orm import Session

from backend.config import REPORT_DIR
from backend.database import crud

logger = logging.getLogger(__name__)

# Brand colors
BRAND_DARK = colors.HexColor("#0a0e1a")
BRAND_PRIMARY = colors.HexColor("#00d4ff")
BRAND_ACCENT = colors.HexColor("#1a1f35")
BRAND_RED = colors.HexColor("#ff3b5c")
BRAND_AMBER = colors.HexColor("#ffb524")
BRAND_GREEN = colors.HexColor("#00e676")

SEVERITY_COLORS = {
    "CRITICAL": BRAND_RED,
    "HIGH": colors.HexColor("#ff6b3b"),
    "MEDIUM": BRAND_AMBER,
    "LOW": BRAND_GREEN,
    "NONE": colors.HexColor("#666666"),
}


def _build_styles():
    """Create custom paragraph styles for the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=BRAND_DARK,
        spaceAfter=12,
        alignment=TA_CENTER,
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        textColor=colors.HexColor("#666666"),
        alignment=TA_CENTER,
        spaceAfter=24,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=BRAND_DARK,
        spaceBefore=16,
        spaceAfter=8,
        borderWidth=0,
        borderColor=BRAND_PRIMARY,
        borderPadding=4,
    ))

    styles.add(ParagraphStyle(
        name="MetricLabel",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#888888"),
    ))

    styles.add(ParagraphStyle(
        name="MetricValue",
        parent=styles["Normal"],
        fontSize=14,
        textColor=BRAND_DARK,
        fontName="Helvetica-Bold",
    ))

    return styles


def generate_report(db: Session, session_id: int, generated_by: str = "system") -> Path:
    """
    Generate a PDF report for a traffic session.

    Args:
        db: Database session
        session_id: Traffic session ID
        generated_by: Username of the requester

    Returns:
        Path to the generated PDF file
    """
    # Fetch data
    session = crud.get_session(db, session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")

    results = crud.get_detection_results_for_session(db, session_id)
    alerts = crud.list_alerts(db, session_id=session_id, limit=100)

    # Generate filename
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"campusshield_report_{session_id}_{timestamp}.pdf"
    file_path = REPORT_DIR / filename

    # Build PDF
    doc = SimpleDocTemplate(
        str(file_path),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = _build_styles()
    elements = []

    # ===================================================================
    # Title Page
    # ===================================================================
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("🛡️ CampusShield AI", styles["ReportTitle"]))
    elements.append(Paragraph(
        "Unidirectional Traffic Threat Detection Report",
        styles["ReportSubtitle"],
    ))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(
        width="80%", thickness=2, color=BRAND_PRIMARY,
        spaceAfter=16, hAlign="CENTER",
    ))

    # Session Info
    elements.append(Paragraph("Session Information", styles["SectionHeader"]))

    session_data = [
        ["Session ID", str(session.id)],
        ["Name", session.name],
        ["Source", session.source_type.upper()],
        ["Scenario", session.scenario or "N/A"],
        ["Status", session.status.upper()],
        ["Created", session.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Completed", session.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if session.completed_at else "N/A"],
    ]

    session_table = Table(session_data, colWidths=[120, 350])
    session_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(session_table)

    # ===================================================================
    # Traffic Summary
    # ===================================================================
    elements.append(Spacer(1, 16))
    elements.append(Paragraph("Traffic Summary", styles["SectionHeader"]))

    stats = session.traffic_stats or {}
    total_pkts = stats.get("total_packets", session.packet_count)
    total_windows = stats.get("total_windows", session.flow_count)
    normal_windows = stats.get("normal_windows", 0)
    anomalous_windows = stats.get("anomalous_windows", 0)
    anomaly_ratio = stats.get("anomaly_ratio", 0)

    summary_data = [
        ["Metric", "Value"],
        ["Total Packets", f"{total_pkts:,}"],
        ["Analysis Windows", str(total_windows)],
        ["Normal Windows", str(normal_windows)],
        ["Anomalous Windows", str(anomalous_windows)],
        ["Anomaly Rate", f"{anomaly_ratio:.1%}"],
        ["Duration", f"{session.duration_seconds:.2f}s" if session.duration_seconds else "N/A"],
        ["Total Alerts", str(stats.get("total_alerts", len(alerts)))],
    ]

    summary_table = Table(summary_data, colWidths=[200, 270])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f8f8")]),
    ]))
    elements.append(summary_table)

    # ===================================================================
    # Alert Details
    # ===================================================================
    if alerts:
        elements.append(Spacer(1, 16))
        elements.append(Paragraph("Alert Details", styles["SectionHeader"]))

        alert_header = ["#", "Severity", "Category", "Score", "Confidence", "Status"]
        alert_rows = [alert_header]

        for alert in alerts[:20]:  # limit to top 20
            alert_rows.append([
                str(alert.id),
                alert.severity,
                (alert.threat_category or "N/A")[:30],
                f"{alert.threat_score:.1f}",
                f"{alert.confidence:.0%}" if alert.confidence else "N/A",
                alert.status,
            ])

        alert_table = Table(alert_rows, colWidths=[30, 65, 170, 50, 70, 85])
        alert_style = [
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f8f8")]),
        ]

        # Color-code severity column
        for i, alert in enumerate(alerts[:20], start=1):
            sev_color = SEVERITY_COLORS.get(alert.severity, colors.gray)
            alert_style.append(("TEXTCOLOR", (1, i), (1, i), sev_color))
            alert_style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))

        alert_table.setStyle(TableStyle(alert_style))
        elements.append(alert_table)

    # ===================================================================
    # Category Distribution
    # ===================================================================
    anomalous = [r for r in results if r.is_anomaly]
    if anomalous:
        elements.append(Spacer(1, 16))
        elements.append(Paragraph("Threat Category Distribution", styles["SectionHeader"]))

        from collections import Counter
        cat_counts = Counter(r.threat_category for r in anomalous if r.threat_category)

        cat_data = [["Category", "Count", "Percentage"]]
        for cat, count in cat_counts.most_common():
            pct = count / len(anomalous) * 100
            cat_data.append([cat, str(count), f"{pct:.1f}%"])

        cat_table = Table(cat_data, colWidths=[250, 80, 80])
        cat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(cat_table)

    # ===================================================================
    # Severity Distribution
    # ===================================================================
    if anomalous:
        elements.append(Spacer(1, 16))
        elements.append(Paragraph("Severity Distribution", styles["SectionHeader"]))

        from collections import Counter
        sev_counts = Counter(r.severity for r in anomalous if r.severity)

        sev_data = [["Severity", "Count"]]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            sev_data.append([sev, str(sev_counts.get(sev, 0))])

        sev_table = Table(sev_data, colWidths=[200, 100])
        sev_style = [
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]
        for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"], start=1):
            sev_style.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS.get(sev, colors.gray)))
            sev_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

        sev_table.setStyle(TableStyle(sev_style))
        elements.append(sev_table)

    # ===================================================================
    # Footer
    # ===================================================================
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(
        width="100%", thickness=1, color=colors.HexColor("#cccccc"),
        spaceAfter=8,
    ))
    elements.append(Paragraph(
        f"Generated by CampusShield AI on "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"SIH26145 — Unidirectional IP Traffic Threat Detection",
        ParagraphStyle(
            name="Footer",
            fontSize=8,
            textColor=colors.HexColor("#999999"),
            alignment=TA_CENTER,
        ),
    ))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        "⚠️ This is an MVP prototype report. Detection results require "
        "validation by qualified security analysts before taking action.",
        ParagraphStyle(
            name="Disclaimer",
            fontSize=7,
            textColor=colors.HexColor("#cc0000"),
            alignment=TA_CENTER,
        ),
    ))

    # Build PDF
    doc.build(elements)

    # Record in database
    file_size = file_path.stat().st_size
    crud.create_report(
        db,
        session_id=session_id,
        file_path=str(file_path),
        file_size_bytes=file_size,
        generated_by=generated_by,
    )

    logger.info(f"Generated report: {file_path} ({file_size:,} bytes)")
    return file_path
