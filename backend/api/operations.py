import csv
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from audit import write_audit
from auth import Principal, current_principal, require_admin
from config import settings
from database import engine, get_db
from detection.drift import drift_report
from detection.ml_engine import active_model_info
from detection.model_registry import activate_model, read_registry
from ingestion.jobs import process_log_job
from ingestion.watcher import watcher
from models import AnalystFeedback, AuditLog, Detection, IngestionJob, NetworkEvent

router = APIRouter(prefix="/api/operations", tags=["Production Operations"])


class FeedbackRequest(BaseModel):
    reviewed_label: str = Field(min_length=2, max_length=64)
    outcome_label: str | None = Field(default=None, max_length=32)
    notes: str = Field(default="", max_length=2000)


def _job(job: IngestionJob) -> dict:
    return {"id": job.id, "source_name": job.source_name, "log_format": job.log_format, "status": job.status, "records_processed": job.records_processed, "attacks_detected": job.attacks_detected, "errors": job.errors, "message": job.message, "created_at": job.created_at.isoformat(), "completed_at": job.completed_at.isoformat() if job.completed_at else None}


@router.get("/status")
def status(db: Session = Depends(get_db)):
    model = active_model_info()
    return {
        "environment": settings.environment, "mode": "OBSERVATION" if settings.observation_mode else "ACTIVE_RESPONSE",
        "auth_enabled": settings.auth_enabled, "database": engine.url.get_backend_name(),
        "active_model": model.get("version") if model else None, "training_source": model.get("training_source") if model else None,
        "log_watcher": bool(settings.log_watch_path), "log_watch_path": settings.log_watch_path or None,
        "retention_days": settings.retention_days, "telemetry_records": db.query(NetworkEvent).count(),
        "message": "ByteForce observes and alerts only; it never blocks or attacks targets." if settings.observation_mode else "Active response integrations require an external authorized enforcement system.",
    }


@router.post("/logs/upload", status_code=202)
async def upload_access_logs(
    background: BackgroundTasks, request: Request, file: UploadFile = File(...), log_format: str = Query("auto", pattern="^(auto|combined|nginx|apache|json)$"),
    principal: Principal = Depends(current_principal), db: Session = Depends(get_db),
):
    if Path(file.filename or "").suffix.lower() not in {".log", ".txt", ".json", ".jsonl"}:
        raise HTTPException(400, "Upload an access-log file ending in .log, .txt, .json, or .jsonl.")
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, f"Log file exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit.")
    if not content:
        raise HTTPException(400, "The access-log file is empty.")
    job = IngestionJob(source_name=(file.filename or "access.log")[:255], log_format=log_format, status="QUEUED")
    db.add(job); db.flush()
    write_audit(db, "LOG_INGESTION_QUEUED", principal.email, f"job:{job.id}", {"filename": job.source_name, "bytes": len(content)}, request.client.host if request.client else None)
    db.commit(); db.refresh(job)
    background.add_task(process_log_job, job.id, content, log_format, settings.default_host, settings.default_dst_ip)
    return {"message": "Authorized logs queued for observation-only analysis.", "job": _job(job)}


@router.get("/jobs")
def jobs(limit: int = Query(20, ge=1, le=100), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return [_job(job) for job in db.query(IngestionJob).order_by(IngestionJob.created_at.desc()).limit(limit).all()]


@router.get("/jobs/{job_id}")
def job_detail(job_id: int, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    job = db.query(IngestionJob).filter(IngestionJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Ingestion job not found.")
    return _job(job)


@router.post("/watcher/scan")
def scan_watched_log(principal: Principal = Depends(require_admin)):
    if not settings.log_watch_path:
        raise HTTPException(409, "BYTEFORCE_LOG_WATCH_PATH is not configured.")
    return {"job_id": watcher.scan_once(), "message": "Configured access log checked for new records."}


@router.post("/detections/{detection_id}/feedback")
def add_feedback(detection_id: int, payload: FeedbackRequest, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    detection = db.query(Detection).filter(Detection.id == detection_id).first()
    if not detection:
        raise HTTPException(404, "Detection not found.")
    feedback = AnalystFeedback(detection_id=detection_id, analyst_email=principal.email, reviewed_label=payload.reviewed_label.upper(), outcome_label=payload.outcome_label, notes=payload.notes)
    db.add(feedback)
    write_audit(db, "DETECTION_REVIEWED", principal.email, f"detection:{detection_id}", {"label": feedback.reviewed_label}, request.client.host if request.client else None)
    db.commit(); db.refresh(feedback)
    return {"id": feedback.id, "message": "Analyst review saved for future retraining."}


@router.get("/feedback/training.csv")
def export_reviewed_training(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.query(AnalystFeedback, Detection, NetworkEvent).join(Detection, AnalystFeedback.detection_id == Detection.id).join(NetworkEvent, Detection.event_id == NetworkEvent.id).order_by(AnalystFeedback.created_at).all()
    output = io.StringIO(); writer = csv.DictWriter(output, fieldnames=["timestamp", "src_ip", "url", "label"]); writer.writeheader()
    for feedback, _, event in rows:
        writer.writerow({"timestamp": event.timestamp.isoformat(), "src_ip": event.src_ip, "url": event.normalized_url, "label": feedback.reviewed_label})
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=byteforce-reviewed-training.csv"})


@router.get("/models")
def models(principal: Principal = Depends(current_principal)):
    return read_registry()


@router.post("/models/{version}/activate")
def activate(version: str, request: Request, principal: Principal = Depends(require_admin), db: Session = Depends(get_db)):
    entry = activate_model(version)
    if not entry:
        raise HTTPException(404, "Model version or artifact not found.")
    write_audit(db, "MODEL_ACTIVATED", principal.email, f"model:{version}", source_ip=request.client.host if request.client else None); db.commit()
    return {"message": f"Model {version} is active.", "model": entry}


@router.get("/drift")
def drift(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return drift_report(db)


@router.get("/audit")
def audit_logs(limit: int = Query(100, ge=1, le=500), principal: Principal = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [{"id": row.id, "timestamp": row.timestamp.isoformat(), "actor": row.actor, "action": row.action, "resource": row.resource, "details": json.loads(row.details or "{}"), "source_ip": row.source_ip} for row in rows]


@router.post("/retention/run")
def run_retention(request: Request, principal: Principal = Depends(require_admin), db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=settings.retention_days)
    event_ids = [value for (value,) in db.query(NetworkEvent.id).filter(NetworkEvent.timestamp < cutoff).limit(10000).all()]
    detection_ids = [value for (value,) in db.query(Detection.id).filter(Detection.event_id.in_(event_ids)).all()] if event_ids else []
    if detection_ids:
        db.query(AnalystFeedback).filter(AnalystFeedback.detection_id.in_(detection_ids)).delete(synchronize_session=False)
        db.query(Detection).filter(Detection.id.in_(detection_ids)).delete(synchronize_session=False)
    if event_ids:
        db.query(NetworkEvent).filter(NetworkEvent.id.in_(event_ids)).delete(synchronize_session=False)
    write_audit(db, "RETENTION_RUN", principal.email, details={"records_removed": len(event_ids), "cutoff": cutoff.isoformat()}, source_ip=request.client.host if request.client else None); db.commit()
    return {"records_removed": len(event_ids), "cutoff": cutoff.isoformat(), "remaining_old_records_may_exist": len(event_ids) == 10000}
