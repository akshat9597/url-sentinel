import csv
import io
import json
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from database import get_db
from config import settings
from detection.behavior_engine import analyze_behavior
from detection.service import detect_record, store_record
from models import Detection, NetworkEvent

router = APIRouter(prefix="/api/dataset", tags=["Datasets"])
REQUIRED = {"src_ip", "dst_ip", "uri"}
BASE_DIR = Path(__file__).resolve().parents[1]


def ingest(db: Session, records: list[dict], max_records: int = 20000) -> dict:
    if not records:
        raise HTTPException(400, "The dataset contains no records.")
    missing = REQUIRED - set(records[0])
    if missing:
        raise HTTPException(422, f"Missing required columns: {', '.join(sorted(missing))}. Required: src_ip, dst_ip, uri.")
    # Normalize primitive CSV values before behavior analysis so numeric status
    # codes and false ground-truth strings are interpreted correctly.
    for record in records[:max_records]:
        for numeric_field in ("status_code", "response_size", "src_port", "dst_port", "request_count"):
            if record.get(numeric_field) not in (None, ""):
                try:
                    record[numeric_field] = int(float(record[numeric_field]))
                except (TypeError, ValueError):
                    record[numeric_field] = None
        record["ground_truth_success"] = str(record.get("ground_truth_success", "false")).strip().lower() in {"true", "1", "yes"}
    groups = {}
    for record in records[:max_records]:
        groups.setdefault(record.get("src_ip") or "0.0.0.0", []).append(record)
    behavior = {source: analyze_behavior(source_records) for source, source_records in groups.items()}
    attacks = 0
    critical = 0
    processed = 0
    for record in records[:max_records]:
        try:
            source_behavior = behavior.get(record.get("src_ip") or "0.0.0.0", {})
            result = detect_record(record, source_behavior.get("score", 0), source_behavior.get("type"), source_behavior.get("evidence", []))
            store_record(db, record, result)
            attacks += result["malicious"]
            critical += result["severity"] == "CRITICAL"
            processed += 1
        except (ValueError, TypeError):
            continue
    db.commit()
    return {"records_processed": processed, "attacks_detected": attacks, "benign": processed - attacks, "critical_alerts": critical}


@router.post("/upload")
async def upload_dataset(file: UploadFile = File(...), db: Session = Depends(get_db)):
    suffix = Path(file.filename or "").suffix.lower()
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, f"Dataset exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit.")
    try:
        text = content.decode("utf-8-sig")
        if suffix == ".csv":
            records = list(csv.DictReader(io.StringIO(text)))
        elif suffix == ".json":
            decoded = json.loads(text)
            records = decoded if isinstance(decoded, list) else decoded.get("records", [])
        else:
            raise HTTPException(400, "Upload a CSV or JSON dataset.")
    except (UnicodeDecodeError, json.JSONDecodeError, csv.Error) as exc:
        raise HTTPException(400, "The uploaded dataset is malformed or not UTF-8 encoded.") from exc
    return ingest(db, records)


@router.post("/demo/load")
def load_demo_dataset(limit: int = 1200, db: Session = Depends(get_db)):
    path = BASE_DIR / "data" / "demo_traffic.csv"
    if not path.exists():
        raise HTTPException(404, "Demo data has not been generated. Run python scripts/generate_demo_data.py.")
    if db.query(NetworkEvent).count() > 0:
        return {"message": "Demo database already contains records.", "records_processed": 0, "attacks_detected": db.query(Detection).filter(Detection.attack_type != "BENIGN").count(), "benign": db.query(Detection).filter(Detection.attack_type == "BENIGN").count()}
    with path.open(newline="") as handle:
        all_records = list(csv.DictReader(handle))
    requested = min(limit, 10000)
    benign_count = int(requested * .65)
    benign = [row for row in all_records if row.get("label") == "BENIGN"][:benign_count]
    suspicious = [row for row in all_records if row.get("label") != "BENIGN"][:requested - benign_count]
    records = benign + suspicious
    result = ingest(db, records)
    result["message"] = "Safe synthetic demo data loaded."
    return result


@router.post("/demo/reset")
def reset_demo_database(db: Session = Depends(get_db)):
    db.query(Detection).delete()
    db.query(NetworkEvent).delete()
    db.commit()
    return {"message": "Demo database reset.", "records_removed": True}


@router.post("/demo/pcap")
def load_demo_pcap(db: Session = Depends(get_db)):
    path = BASE_DIR / "data" / "demo_traffic.csv"
    with path.open(newline="") as handle:
        suspicious = [row for row in csv.DictReader(handle) if row.get("label") != "BENIGN"][:180]
    summary = ingest(db, suspicious)
    return {"ok": True, "mode": "safe_demo", "records_processed": summary["records_processed"], "http_events_extracted": summary["records_processed"], "threats_detected": summary["attacks_detected"], "critical_alerts": summary["critical_alerts"], "unique_source_ips": len({row["src_ip"] for row in suspicious})}
