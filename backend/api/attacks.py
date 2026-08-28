import ipaddress
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from api.dashboard import _serialize
from database import get_db
from models import Detection, NetworkEvent

router = APIRouter(tags=["Threat Explorer"])


def _filters(query, attack_type=None, src_ip=None, dst_ip=None, severity=None, attack_status=None, host=None, start_time=None, end_time=None, min_confidence=0):
    if attack_type:
        query = query.filter(Detection.attack_type == attack_type)
    if severity:
        query = query.filter(Detection.severity == severity)
    if attack_status:
        query = query.filter(Detection.attack_status == attack_status)
    if host:
        query = query.filter(NetworkEvent.host.ilike(f"%{host}%"))
    if src_ip:
        query = _apply_ip(query, NetworkEvent.src_ip, src_ip)
    if dst_ip:
        query = _apply_ip(query, NetworkEvent.dst_ip, dst_ip)
    if start_time:
        query = query.filter(NetworkEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(NetworkEvent.timestamp <= end_time)
    return query.filter(Detection.confidence >= min_confidence)


def filtered_attack_query(db, **filters):
    query = db.query(NetworkEvent, Detection).join(Detection).filter(Detection.attack_type != "BENIGN")
    return _filters(query, **filters)


def _apply_ip(query, column, value):
    if "/" not in value:
        return query.filter(column == value)
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise HTTPException(422, "Invalid IP or CIDR filter.") from exc
    # SQLite has no native INET type; a bounded Python expansion is acceptable for demo ranges.
    if network.num_addresses > 4096:
        raise HTTPException(422, "CIDR filter is too broad for demo mode (maximum 4096 addresses).")
    return query.filter(column.in_([str(address) for address in network]))


@router.get("/api/attacks")
def list_attacks(
    attack_type: str | None = None, src_ip: str | None = None, dst_ip: str | None = None,
    severity: str | None = None, attack_status: str | None = None, host: str | None = None,
    start_time: datetime | None = None, end_time: datetime | None = None, min_confidence: float = 0,
    page: int = Query(1, ge=1), limit: int = Query(25, ge=1, le=200), db: Session = Depends(get_db),
):
    query = filtered_attack_query(db, attack_type=attack_type, src_ip=src_ip, dst_ip=dst_ip, severity=severity, attack_status=attack_status, host=host, start_time=start_time, end_time=end_time, min_confidence=min_confidence)
    total = query.count()
    rows = query.order_by(NetworkEvent.timestamp.desc()).offset((page - 1) * limit).limit(limit).all()
    return {"items": [_serialize(event, detection) for event, detection in rows], "total": total, "page": page, "limit": limit, "pages": (total + limit - 1) // limit}


@router.get("/api/attacks/{detection_id}")
def attack_detail(detection_id: int, db: Session = Depends(get_db)):
    row = db.query(NetworkEvent, Detection).join(Detection).filter(Detection.id == detection_id).first()
    if not row:
        raise HTTPException(404, "Threat record not found.")
    event, detection = row
    evidence = json.loads(detection.evidence or "{}")
    data = _serialize(event, detection)
    data.update({
        "src_port": event.src_port, "dst_port": event.dst_port, "protocol": event.protocol,
        "original_url": event.uri, "normalized_url": event.normalized_url, "response_size": event.response_size,
        "user_agent": event.user_agent, "scores": {"rule_score": detection.rule_score, "ml_score": detection.ml_score, "behavior_score": detection.behavior_score},
        "evidence": evidence.get("items", []), "status_reason": evidence.get("status_reason", ""), "metadata": evidence.get("metadata", {}),
    })
    return data


@router.get("/api/ip/{ip_value}")
def ip_analysis(ip_value: str, db: Session = Depends(get_db)):
    try:
        ipaddress.ip_address(ip_value)
    except ValueError as exc:
        raise HTTPException(422, "Enter a valid IPv4 or IPv6 address.") from exc
    rows = db.query(NetworkEvent, Detection).join(Detection).filter(NetworkEvent.src_ip == ip_value).order_by(NetworkEvent.timestamp.desc()).all()
    if not rows:
        return {"ip": ip_value, "risk_score": 0, "risk_level": "LOW", "total_requests": 0, "detected_threats": 0, "unique_targets": 0, "critical_alerts": 0, "first_seen": None, "last_seen": None, "attack_distribution": [], "recent_activity": []}
    threats = [(event, detection) for event, detection in rows if detection.attack_type != "BENIGN"]
    risk = round(sum(d.confidence for _, d in threats) / max(len(rows), 1), 1)
    level = "CRITICAL" if risk > 70 else "HIGH" if risk > 50 else "MEDIUM" if risk > 30 else "LOW"
    counts = {}
    for _, detection in threats:
        counts[detection.attack_type] = counts.get(detection.attack_type, 0) + 1
    return {
        "ip": ip_value, "risk_score": risk, "risk_level": level, "first_seen": rows[-1][0].timestamp.isoformat(), "last_seen": rows[0][0].timestamp.isoformat(),
        "total_requests": len(rows), "detected_threats": len(threats), "unique_targets": len({event.dst_ip for event, _ in rows}),
        "critical_alerts": sum(d.severity == "CRITICAL" for _, d in threats), "attack_distribution": [{"name": key, "value": value} for key, value in counts.items()],
        "recent_activity": [_serialize(event, detection) for event, detection in rows[:12]],
    }
