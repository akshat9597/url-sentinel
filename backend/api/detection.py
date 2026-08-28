import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from detection.service import detect_record, store_record
from schemas import DetectionResponse, URLDetectionRequest

router = APIRouter(prefix="/api/detect", tags=["Detection"])


@router.post("/url", response_model=DetectionResponse)
def detect_url(payload: URLDetectionRequest, db: Session = Depends(get_db)):
    for label, value in (("source", payload.src_ip), ("destination", payload.dst_ip)):
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise HTTPException(422, f"The {label} IP address is invalid.") from exc
    record = payload.model_dump()
    record["uri"] = record.pop("url")
    result = detect_record(record)
    store_record(db, record, result)
    db.commit()
    return result
