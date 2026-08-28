import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from api.attacks import filtered_attack_query
from api.dashboard import _serialize
from database import get_db
from models import Detection, NetworkEvent

router = APIRouter(prefix="/api/export", tags=["Export"])
HEADERS = ["id", "timestamp", "src_ip", "dst_ip", "method", "host", "uri", "attack_type", "confidence", "severity", "attack_status", "status_code"]


def export_rows(db, **filters):
    return [{key: _serialize(event, detection).get(key) for key in HEADERS} for event, detection in filtered_attack_query(db, **filters).order_by(NetworkEvent.timestamp.desc()).all()]


def export_filters(attack_type=None, src_ip=None, dst_ip=None, severity=None, attack_status=None, host=None, start_time=None, end_time=None, min_confidence=0):
    return {"attack_type": attack_type, "src_ip": src_ip, "dst_ip": dst_ip, "severity": severity, "attack_status": attack_status, "host": host, "start_time": start_time, "end_time": end_time, "min_confidence": min_confidence}


@router.get("/csv")
def export_csv(attack_type: str | None = None, src_ip: str | None = None, dst_ip: str | None = None, severity: str | None = None, attack_status: str | None = None, host: str | None = None, start_time: datetime | None = None, end_time: datetime | None = None, min_confidence: float = Query(0, ge=0, le=100), db: Session = Depends(get_db)):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=HEADERS)
    writer.writeheader(); writer.writerows(export_rows(db, **export_filters(attack_type, src_ip, dst_ip, severity, attack_status, host, start_time, end_time, min_confidence)))
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=byteforce-export.csv"})


@router.get("/json")
def export_json(attack_type: str | None = None, src_ip: str | None = None, dst_ip: str | None = None, severity: str | None = None, attack_status: str | None = None, host: str | None = None, start_time: datetime | None = None, end_time: datetime | None = None, min_confidence: float = Query(0, ge=0, le=100), db: Session = Depends(get_db)):
    return Response(json.dumps(export_rows(db, **export_filters(attack_type, src_ip, dst_ip, severity, attack_status, host, start_time, end_time, min_confidence)), indent=2), media_type="application/json", headers={"Content-Disposition": "attachment; filename=byteforce-export.json"})
