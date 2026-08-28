from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import Detection, NetworkEvent

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    total = db.query(NetworkEvent).count()
    threats = db.query(Detection).filter(Detection.attack_type != "BENIGN").count()
    attempts = db.query(Detection).filter(Detection.attack_status == "ATTEMPT").count()
    probable = db.query(Detection).filter(Detection.attack_status.in_(["PROBABLE_SUCCESS", "CONFIRMED_SUCCESS"])).count()
    critical = db.query(Detection).filter(Detection.severity == "CRITICAL").count()
    unique_sources = db.query(func.count(func.distinct(NetworkEvent.src_ip))).scalar() or 0
    recent_rows = (
        db.query(NetworkEvent, Detection).join(Detection).filter(Detection.attack_type != "BENIGN")
        .order_by(NetworkEvent.timestamp.desc()).limit(8).all()
    )
    return {
        "total_requests": total, "threats_detected": threats, "attack_attempts": attempts,
        "probable_successes": probable, "critical_alerts": critical, "unique_source_ips": unique_sources,
        "recent_threats": [_serialize(event, detection) for event, detection in recent_rows],
    }


def _serialize(event, detection):
    return {
        "id": detection.id, "event_id": event.id, "timestamp": event.timestamp.isoformat(), "src_ip": event.src_ip,
        "dst_ip": event.dst_ip, "method": event.method, "host": event.host, "uri": event.uri,
        "attack_type": detection.attack_type, "confidence": detection.confidence, "severity": detection.severity,
        "attack_status": detection.attack_status, "status_code": event.status_code,
    }
