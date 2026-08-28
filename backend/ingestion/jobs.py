from datetime import datetime, timezone

from database import SessionLocal
from detection.behavior_engine import analyze_behavior
from detection.service import detect_record, store_record
from ingestion.access_logs import parse_access_logs
from models import IngestionJob


def process_log_job(job_id: int, content: bytes, log_format: str, default_host: str, default_dst_ip: str) -> None:
    db = SessionLocal()
    job = db.query(IngestionJob).filter(IngestionJob.id == job_id).first()
    if not job:
        db.close()
        return
    try:
        job.status = "PROCESSING"
        db.commit()
        events, errors = parse_access_logs(content.decode("utf-8-sig", errors="replace"), log_format, default_host, default_dst_ip)
        groups = {}
        for event in events:
            groups.setdefault(event["src_ip"], []).append(event)
        behaviors = {source: analyze_behavior(records) for source, records in groups.items()}
        attacks = 0
        for event in events:
            behavior = behaviors[event["src_ip"]]
            result = detect_record(event, behavior["score"], behavior["type"], behavior["evidence"])
            store_record(db, event, result)
            attacks += result["malicious"]
        job.records_processed = len(events)
        job.attacks_detected = attacks
        job.errors = len(errors)
        job.message = "; ".join(errors[:5]) if errors else "Authorized access logs analyzed successfully."
        job.status = "COMPLETED" if events else "FAILED"
    except Exception as exc:
        db.rollback()
        job = db.query(IngestionJob).filter(IngestionJob.id == job_id).first()
        job.status = "FAILED"
        job.message = f"Log processing failed: {str(exc)[:300]}"
    finally:
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.close()
