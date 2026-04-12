from datetime import datetime
from io import BytesIO

from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from celery.result import AsyncResult
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from tasks import run_scan_task
from celery_app import celery_app
from scan_store import scan_history
app = FastAPI(title="VulnScan Lite API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class ScanRequest(BaseModel):
    url: str


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


@app.get("/")
def home():
    return {
        "message": "VulnScan Lite backend is running with Celery + Redis ✅",
        "disclaimer": "Only scan websites you own or are authorized to test. This tool performs passive analysis only."
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
        "created_at": created_at,
        "message": "Scan started successfully",
        "disclaimer": "Only scan websites you own or are authorized to test. This tool performs passive analysis only."
    }


@app.get("/api/scan/{scan_id}/status")
@limiter.limit("60/minute")
def get_scan_status(request: Request, scan_id: str):
    task_result = AsyncResult(scan_id, app=celery_app)
    clean_status = map_status(task_result.status)

    return {
        "scan_id": scan_id,
        "status": clean_status,
        "raw_status": task_result.status
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
            "message": "Scan is not completed yet"
        }

    if task_result.status == "FAILURE":
        return {
            "scan_id": scan_id,
            "status": "failed",
            "message": str(task_result.result)
        }

    if task_result.status != "SUCCESS":
        return {
            "scan_id": scan_id,
            "status": clean_status,
            "message": "Unknown task state"
        }

    result = task_result.result

    history_item = {
        "scan_id": scan_id,
        "target": result.get("target"),
        "score": result.get("summary", {}).get("score"),
        "grade": result.get("summary", {}).get("grade"),
        "completed_at": result.get("scan_meta", {}).get("completed_at")
    }

    already_exists = any(item["scan_id"] == scan_id for item in scan_history)
    if not already_exists:
        scan_history.append(history_item)

    return {
        "scan_id": scan_id,
        "status": "completed",
        "result": result
    }


@app.get("/api/history")
@limiter.limit("20/minute")
def get_scan_history(request: Request):
    return {
        "total_scans": len(scan_history),
        "history": scan_history
    }

@app.get("/api/scan/{scan_id}/pdf")
@limiter.limit("20/minute")
def download_scan_pdf(request: Request, scan_id: str):
    task_result = AsyncResult(scan_id, app=celery_app)

    if task_result.status != "SUCCESS":
        return {
            "scan_id": scan_id,
            "status": map_status(task_result.status),
            "message": "PDF is available only after scan completion"
        }

    result = task_result.result

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    left_margin = 50
    right_margin = 50
    top_margin = 50
    bottom_margin = 50
    usable_width = width - left_margin - right_margin
    y = height - top_margin
    page_number = 1

    def pretty_module_name(name):
        mapping = {
            "headers": "Headers",
            "ssl_tls": "SSL/TLS",
            "cms_detection": "CMS Detection"
        }
        return mapping.get(name, str(name).replace("_", " ").title())

    def shorten_text(text, max_len=180):
        text = str(text)
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    def draw_footer():
        pdf.setFont("Helvetica", 9)
        pdf.drawString(left_margin, 25, "Generated by VulnScan Lite")
        pdf.drawRightString(width - right_margin, 25, f"Page {page_number}")

    def new_page():
        nonlocal y, page_number
        draw_footer()
        pdf.showPage()
        page_number += 1
        y = height - top_margin

    def ensure_space(required_height=60):
        nonlocal y
        if y < bottom_margin + required_height:
            new_page()

    def wrap_text(text, font="Helvetica", size=11, max_width=usable_width):
        words = str(text).split()
        if not words:
            return [""]

        lines = []
        current_line = words[0]

        for word in words[1:]:
            test_line = current_line + " " + word
            if pdf.stringWidth(test_line, font, size) <= max_width:
                current_line = test_line
            else:
                lines.append(current_line)
                current_line = word

        lines.append(current_line)
        return lines

    def write_wrapped(text, font="Helvetica", size=11, gap=16, indent=0):
        nonlocal y
        lines = wrap_text(text, font, size, usable_width - indent)
        pdf.setFont(font, size)

        for line in lines:
            ensure_space(gap + 10)
            pdf.drawString(left_margin + indent, y, line)
            y -= gap

    def write_heading(text):
        nonlocal y
        ensure_space(50)
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(left_margin, y, text)
        y -= 24

    def write_subheading(text):
        nonlocal y
        ensure_space(40)
        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(left_margin, y, text)
        y -= 20

    def write_label_value(label, value, max_len=180):
        value = shorten_text(value, max_len)
        write_wrapped(f"{label}: {value}", "Helvetica", 11, 16)

    def draw_summary_box(summary_data):
        nonlocal y
        box_height = 105
        ensure_space(box_height + 20)

        box_top = y
        box_bottom = y - box_height

        pdf.roundRect(left_margin, box_bottom, usable_width, box_height, 10, stroke=1, fill=0)

        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(left_margin + 12, box_top - 20, "Scan Summary")

        pdf.setFont("Helvetica", 11)
        pdf.drawString(left_margin + 12, box_top - 42, f"Target: {summary_data['target']}")
        pdf.drawString(left_margin + 12, box_top - 62, f"Score: {summary_data['score']}")
        pdf.drawString(left_margin + 170, box_top - 62, f"Grade: {summary_data['grade']}")
        pdf.drawString(left_margin + 12, box_top - 82, f"Total Findings: {summary_data['total_findings']}")

        y = box_bottom - 20

    generated_at = datetime.utcnow().strftime("%d %b %Y, %I:%M:%S %p UTC")

    # Title block
    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(left_margin, y, "VulnScan Lite Report")
    y -= 26

    pdf.setFont("Helvetica", 10)
    pdf.drawString(left_margin, y, "Passive website security assessment report")
    y -= 16
    pdf.drawString(left_margin, y, "Only scan websites you own or are authorized to test.")
    y -= 16
    pdf.drawString(left_margin, y, f"Generated at: {generated_at}")
    y -= 28

    # Summary box
    draw_summary_box({
        "target": result.get("target"),
        "score": result.get("summary", {}).get("score"),
        "grade": result.get("summary", {}).get("grade"),
        "total_findings": result.get("summary", {}).get("total_findings")
    })

    # Passed checks
    write_heading("Passed Checks")
    passed_checks = result.get("summary", {}).get("passed_checks", [])
    if passed_checks:
        for item in passed_checks:
            write_wrapped(f"- {item}", "Helvetica", 11, 16)
    else:
        write_wrapped("No passed checks recorded.", "Helvetica", 11, 16)
    y -= 8

    # Failed checks
    write_heading("Failed Checks")
    failed_checks = result.get("summary", {}).get("failed_checks", [])
    if failed_checks:
        for item in failed_checks:
            write_wrapped(f"- {item}", "Helvetica", 11, 16)
    else:
        write_wrapped("No failed checks recorded.", "Helvetica", 11, 16)
    y -= 8

    # Detailed findings
    write_heading("Detailed Findings")

    for module in result.get("modules", []):
        ensure_space(70)
        write_subheading(f"Module: {pretty_module_name(module.get('category'))}")

        for finding in module.get("findings", []):
            ensure_space(110)

            pdf.setFont("Helvetica-Bold", 11)
            pdf.drawString(left_margin, y, f"Check: {finding.get('check_name')}")
            y -= 18

            write_label_value("Status", finding.get("status"), 80)
            write_label_value("Severity", finding.get("severity"), 80)
            write_label_value("Details", finding.get("details"), 180)
            write_label_value("Remediation", finding.get("remediation"), 180)

            y -= 8

    draw_footer()
    pdf.save()
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=scan_report_{scan_id}.pdf"
        }
    )
import threading
from celery_app import celery_app

def start_celery_worker():
    celery_app.worker_main(["worker", "--loglevel=info"])

threading.Thread(target=start_celery_worker, daemon=True).start()