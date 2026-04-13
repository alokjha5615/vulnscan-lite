from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from celery.result import AsyncResult

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from tasks import run_scan_task
from celery_app import celery_app
from scan_store import scan_history
from database import (
    init_db,
    save_scan,
    get_all_scans,
    get_scans_by_user,
    create_user,
    get_user_by_email,
)

app = FastAPI(title="VulnScan Lite API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()


class ScanRequest(BaseModel):
    url: str
    user_id: int | None = None


class AuthRequest(BaseModel):
    email: str
    password: str


def map_status(celery_status: str) -> str:
    if celery_status == "PENDING":
        return "queued"
    elif celery_status == "STARTED":
        return "processing"
    elif celery_status == "SUCCESS":
        return "completed"
    elif celery_status == "FAILURE":
        return "failed"
    return celery_status.lower()


def safe_html(text) -> str:
    if text is None:
        return ""
    return escape(str(text)).replace("\n", "<br/>")


@app.get("/")
def home():
    return {
        "message": "VulnScan Lite backend is running with Celery + Redis ✅",
        "disclaimer": "Only scan websites you own or are authorized to test. This tool performs passive analysis only.",
    }


@app.post("/api/signup")
def signup(auth_request: AuthRequest):
    email = auth_request.email.strip().lower()
    password = auth_request.password.strip()

    user = create_user(email, password)

    if user is None:
        return {
            "success": False,
            "message": "User already exists",
        }

    return {
        "success": True,
        "message": "Signup successful",
        "user": user,
    }


@app.post("/api/login")
def login(auth_request: AuthRequest):
    email = auth_request.email.strip().lower()
    password = auth_request.password.strip()

    user = get_user_by_email(email)

    if user is None:
        return {
            "success": False,
            "message": "User not found",
        }

    user_id, saved_email, saved_password = user

    if saved_password != password:
        return {
            "success": False,
            "message": "Invalid password",
        }

    return {
        "success": True,
        "message": "Login successful",
        "user": {
            "id": user_id,
            "email": saved_email,
        },
    }


@app.post("/api/scan")
@limiter.limit("5/minute")
def start_scan(request: Request, scan_request: ScanRequest):
    created_at = datetime.utcnow().isoformat() + "Z"
    task = run_scan_task.delay(scan_request.url)

    return {
        "scan_id": task.id,
        "status": "queued",
        "target_url": scan_request.url,
        "user_id": scan_request.user_id,
        "created_at": created_at,
        "message": "Scan started successfully",
        "disclaimer": "Only scan websites you own or are authorized to test. This tool performs passive analysis only.",
    }


@app.get("/api/scan/{scan_id}/status")
@limiter.limit("60/minute")
def get_scan_status(request: Request, scan_id: str):
    task_result = AsyncResult(scan_id, app=celery_app)
    clean_status = map_status(task_result.status)

    return {
        "scan_id": scan_id,
        "status": clean_status,
        "raw_status": task_result.status,
    }


@app.get("/api/scan/{scan_id}/result")
@limiter.limit("60/minute")
def get_scan_result(request: Request, scan_id: str):
    task_result = AsyncResult(scan_id, app=celery_app)
    clean_status = map_status(task_result.status)

    if task_result.status in ["PENDING", "STARTED"]:
        return {
            "scan_id": scan_id,
            "status": clean_status,
            "message": "Scan is not completed yet",
        }

    if task_result.status == "FAILURE":
        return {
            "scan_id": scan_id,
            "status": "failed",
            "message": str(task_result.result),
        }

    if task_result.status != "SUCCESS":
        return {
            "scan_id": scan_id,
            "status": clean_status,
            "message": "Unknown task state",
        }

    result = task_result.result

    history_item = {
        "scan_id": scan_id,
        "target": result.get("target"),
        "score": result.get("summary", {}).get("score"),
        "grade": result.get("summary", {}).get("grade"),
        "completed_at": result.get("scan_meta", {}).get("completed_at"),
    }

    already_exists = any(item["scan_id"] == scan_id for item in scan_history)
    if not already_exists:
        scan_history.append(history_item)

        save_scan(
            user_id=request.query_params.get("user_id", 1),
            target=result.get("target"),
            score=result.get("summary", {}).get("score"),
            grade=result.get("summary", {}).get("grade"),
            findings=result.get("modules", []),
            completed_at=result.get("scan_meta", {}).get("completed_at"),
        )

    return {
        "scan_id": scan_id,
        "status": "completed",
        "result": result,
    }


@app.get("/api/history")
@limiter.limit("20/minute")
def get_scan_history(request: Request):
    user_id = request.query_params.get("user_id")

    if user_id:
        rows = get_scans_by_user(user_id)
    else:
        rows = get_all_scans()

    history = []
    for row in rows:
        history.append(
            {
                "id": row[0],
                "user_id": row[1],
                "target": row[2],
                "score": row[3],
                "grade": row[4],
                "findings": row[5],
                "completed_at": row[6],
            }
        )

    return {
        "total_scans": len(history),
        "history": history,
    }


@app.get("/api/scan/{scan_id}/pdf")
@limiter.limit("20/minute")
def download_scan_pdf(request: Request, scan_id: str):
    task_result = AsyncResult(scan_id, app=celery_app)

    if task_result.status != "SUCCESS":
        return {
            "scan_id": scan_id,
            "status": map_status(task_result.status),
            "message": "PDF is available only after scan completion",
        }

    result = task_result.result
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.grey,
        spaceAfter=14,
    )

    section_style = ParagraphStyle(
        "SectionStyle",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=8,
        spaceBefore=8,
    )

    subheading_style = ParagraphStyle(
        "SubheadingStyle",
        parent=styles["Heading3"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6,
        spaceBefore=6,
    )

    wrap_style = ParagraphStyle(
        "WrapStyle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        spaceAfter=6,
    )

    story = []

    generated_at = datetime.utcnow().strftime("%d %b %Y, %I:%M:%S %p UTC")

    story.append(Paragraph("VulnScan Lite Report", title_style))
    story.append(
        Paragraph("Passive website security assessment report", subtitle_style)
    )
    story.append(
        Paragraph(
            "Only scan websites you own or are authorized to test.",
            subtitle_style,
        )
    )
    story.append(Paragraph(f"Generated at: {generated_at}", subtitle_style))
    story.append(Spacer(1, 8))

    summary_data = [
        ["Target", result.get("target", "N/A")],
        ["Score", result.get("summary", {}).get("score", "N/A")],
        ["Grade", result.get("summary", {}).get("grade", "N/A")],
        ["Total Findings", result.get("summary", {}).get("total_findings", "N/A")],
    ]

    story.append(Paragraph("Scan Summary", section_style))
    summary_table = Table(summary_data, colWidths=[120, 360])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                ("BOX", (0, 0), (-1, -1), 1, colors.lightgrey),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Passed Checks", section_style))
    passed_checks = result.get("summary", {}).get("passed_checks", [])
    if passed_checks:
        for item in passed_checks:
            story.append(Paragraph(f"• {safe_html(item)}", wrap_style))
    else:
        story.append(Paragraph("No passed checks recorded.", wrap_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Failed Checks", section_style))
    failed_checks = result.get("summary", {}).get("failed_checks", [])
    if failed_checks:
        for item in failed_checks:
            story.append(Paragraph(f"• {safe_html(item)}", wrap_style))
    else:
        story.append(Paragraph("No failed checks recorded.", wrap_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Detailed Findings", section_style))

    module_name_map = {
        "headers": "Headers",
        "ssl_tls": "SSL/TLS",
        "cms_detection": "CMS Detection",
    }

    for module in result.get("modules", []):
        pretty_name = module_name_map.get(
            module.get("category"),
            str(module.get("category", "")).replace("_", " ").title(),
        )
        story.append(Paragraph(f"Module: {pretty_name}", subheading_style))

        for finding in module.get("findings", []):
            story.append(
                Paragraph(
                    f"<b>Check:</b> {safe_html(finding.get('check_name', 'N/A'))}",
                    wrap_style,
                )
            )
            story.append(
                Paragraph(
                    f"<b>Status:</b> {safe_html(finding.get('status', 'N/A'))}",
                    wrap_style,
                )
            )
            story.append(
                Paragraph(
                    f"<b>Severity:</b> {safe_html(finding.get('severity', 'N/A'))}",
                    wrap_style,
                )
            )
            story.append(
                Paragraph(
                    f"<b>Details:</b> {safe_html(finding.get('details', 'N/A'))}",
                    wrap_style,
                )
            )
            story.append(
                Paragraph(
                    f"<b>Remediation:</b><br/>{safe_html(finding.get('remediation', 'N/A'))}",
                    wrap_style,
                )
            )
            story.append(Spacer(1, 8))

    def add_page_footer(canvas_obj, doc_obj):
        canvas_obj.setFont("Helvetica", 9)
        canvas_obj.drawString(40, 20, "Generated by VulnScan Lite")
        canvas_obj.drawRightString(A4[0] - 40, 20, f"Page {doc_obj.page}")

    doc.build(story, onFirstPage=add_page_footer, onLaterPages=add_page_footer)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=scan_report_{scan_id}.pdf"
        },
    )