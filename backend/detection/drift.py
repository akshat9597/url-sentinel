import json
from pathlib import Path

from sqlalchemy.orm import Session

from models import Detection, NetworkEvent

REGISTRY = Path(__file__).resolve().parents[1] / "data" / "models" / "registry.json"


def drift_report(db: Session, sample_size: int = 1000) -> dict:
    rows = db.query(NetworkEvent, Detection).join(Detection).order_by(NetworkEvent.timestamp.desc()).limit(sample_size).all()
    if not rows:
        return {"status": "NO_DATA", "sample_size": 0, "message": "No telemetry is available for drift analysis."}
    average_length = sum(len(event.normalized_url or event.uri or "") for event, _ in rows) / len(rows)
    threat_rate = sum(detection.attack_type != "BENIGN" for _, detection in rows) / len(rows)
    baseline = None
    if REGISTRY.exists():
        try:
            registry = json.loads(REGISTRY.read_text())
            active = next((item for item in registry.get("models", []) if item["version"] == registry.get("active")), None)
            baseline = active.get("baseline") if active else None
        except (json.JSONDecodeError, OSError):
            baseline = None
    if not baseline:
        return {"status": "BASELINE_REQUIRED", "sample_size": len(rows), "average_url_length": round(average_length, 2), "threat_rate": round(threat_rate, 4), "message": "Train and activate a versioned model to establish a baseline."}
    length_change = abs(average_length - baseline["average_url_length"]) / max(baseline["average_url_length"], 1)
    rate_change = abs(threat_rate - baseline["threat_rate"])
    drifted = length_change > .30 or rate_change > .20
    return {"status": "DRIFT_DETECTED" if drifted else "STABLE", "sample_size": len(rows), "average_url_length": round(average_length, 2), "threat_rate": round(threat_rate, 4), "length_change": round(length_change, 4), "threat_rate_change": round(rate_change, 4), "message": "Review and retrain with recent analyst-labelled data." if drifted else "Recent telemetry remains within the configured baseline tolerance."}
