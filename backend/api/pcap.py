from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from database import get_db
from detection.service import detect_record, store_record
from pcap.processor import process_pcap

router = APIRouter(prefix="/api/pcap", tags=["PCAP"])


@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    result = process_pcap(file.filename or "capture", await file.read())
    if not result["ok"]:
        if result["code"] == "ZEEK_MISSING":
            return {**result, "demo_available": True}
        raise HTTPException(400, result["message"])
    threats = critical = 0
    sources = set()
    for record in result["events"]:
        detection = detect_record(record)
        store_record(db, record, detection)
        sources.add(record["src_ip"])
        threats += detection["malicious"]
        critical += detection["severity"] == "CRITICAL"
    db.commit()
    return {"ok": True, "records_processed": len(result["events"]), "http_events_extracted": len(result["events"]), "threats_detected": threats, "critical_alerts": critical, "unique_source_ips": len(sources)}
