from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from models import Detection, NetworkEvent

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


def _rows(db):
    return db.query(NetworkEvent, Detection).join(Detection).all()


@router.get("/timeline")
def timeline(days: int = Query(7, ge=1, le=90), db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    rows = db.query(NetworkEvent, Detection).join(Detection).filter(NetworkEvent.timestamp >= cutoff).all()
    counts = Counter(event.timestamp.strftime("%Y-%m-%d") for event, detection in rows if detection.attack_type != "BENIGN")
    attempts = Counter(event.timestamp.strftime("%Y-%m-%d") for event, detection in rows if detection.attack_status == "ATTEMPT")
    probable = Counter(event.timestamp.strftime("%Y-%m-%d") for event, detection in rows if detection.attack_status in {"PROBABLE_SUCCESS", "CONFIRMED_SUCCESS"})
    return [{"date": (cutoff + timedelta(days=i)).strftime("%Y-%m-%d"), "threats": counts[(cutoff + timedelta(days=i)).strftime("%Y-%m-%d")], "attempts": attempts[(cutoff + timedelta(days=i)).strftime("%Y-%m-%d")], "probable": probable[(cutoff + timedelta(days=i)).strftime("%Y-%m-%d")]} for i in range(days + 1)]


@router.get("/types")
def types(db: Session = Depends(get_db)):
    counts = Counter(d.attack_type for _, d in _rows(db) if d.attack_type != "BENIGN")
    return [{"name": key, "value": value} for key, value in counts.most_common()]


@router.get("/severity")
def severity(db: Session = Depends(get_db)):
    counts = Counter(d.severity for _, d in _rows(db) if d.attack_type != "BENIGN")
    return [{"name": key, "value": counts[key]} for key in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    rows = _rows(db)
    threats = [(e, d) for e, d in rows if d.attack_type != "BENIGN"]
    def count(field): return [{"name": key, "value": value} for key, value in Counter(field(e, d) for e, d in threats).most_common(10)]
    return {
        "top_sources": count(lambda e, d: e.src_ip), "top_hosts": count(lambda e, d: e.host),
        "statuses": count(lambda e, d: str(e.status_code or "Unknown")), "outcomes": count(lambda e, d: d.attack_status),
    }
