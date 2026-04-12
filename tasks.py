from datetime import datetime

from celery_app import celery_app
from scanner.engine import run_scan


@celery_app.task(bind=True)
def run_scan_task(self, url: str):
    started_at = datetime.utcnow().isoformat() + "Z"

    result = run_scan(url)

    completed_at = datetime.utcnow().isoformat() + "Z"

    result["scan_meta"] = {
        "scan_id": self.request.id,
        "target_url": url,
        "started_at": started_at,
        "completed_at": completed_at,
        "disclaimer": "Only scan websites you own or are authorized to test. This tool performs passive analysis only."
    }

    return result