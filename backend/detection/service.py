import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from detection.ml_engine import predict
from detection.normalizer import normalize_url
from detection.rule_engine import analyze
from detection.scoring import combine_scores
from detection.success_classifier import classify_success
from models import Detection, NetworkEvent
from security import redact_url


def detect_record(record: dict, behavior_score: float = 0, behavior_type: str | None = None, behavior_evidence: list[str] | None = None) -> dict:
    uri = str(record.get("uri") or record.get("url") or "")
    host = str(record.get("host") or "")
    full_url = uri if "://" in uri else f"http://{host or 'example.test'}{uri if uri.startswith('/') else '/' + uri}"
    normalized = normalize_url(full_url)
    rule = analyze(normalized, record.get("method", "GET"), record.get("content_type", ""), record.get("file_name", ""), record.get("request_body", ""))
    ml = predict(normalized["normalized"])
    response_score = 25 if record.get("status_code") in {200, 201} and (record.get("response_size") or 0) > 75000 else 0
    score = combine_scores(rule["score"], ml["ml_score"], behavior_score, response_score)
    truth_value = record.get("ground_truth_success", False)
    explicit_ground_truth = truth_value is True or str(truth_value).strip().lower() in {"1", "true", "yes"}
    status, status_reason = classify_success(
        score["malicious"], record.get("status_code"), record.get("response_size"), explicit_ground_truth,
        record.get("response_body"), record.get("follow_up_evidence"),
    )
    evidence = list(rule["evidence"]) + list(behavior_evidence or [])
    if status_reason:
        evidence.append(status_reason)
    return {
        "malicious": score["malicious"], "attack_type": (rule["attack_type"] if rule["attack_type"] != "BENIGN" else behavior_type or "UNKNOWN_SUSPICIOUS") if score["malicious"] else "BENIGN",
        "severity": score["severity"], "confidence": score["confidence"], "attack_status": status,
        "original_url": full_url, "normalized_url": normalized["normalized"],
        "scores": {"rule_score": rule["score"], "ml_score": ml["ml_score"], "behavior_score": behavior_score},
        "evidence": evidence if score["malicious"] else [], "status_reason": status_reason,
        "metadata": {**rule.get("metadata", {}), "matched_rules": rule.get("all_hits", []), "ml_class": ml["predicted_class"], "model_version": ml.get("model_version")},
        "normalization": normalized,
    }


def store_record(db: Session, record: dict, result: dict | None = None) -> tuple[NetworkEvent, Detection]:
    result = result or detect_record(record)
    timestamp = record.get("timestamp") or datetime.now(timezone.utc)
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    host = record.get("host") or result["normalization"].get("hostname") or urlsplit(result["original_url"]).hostname or "unknown"
    safe_uri = redact_url(record.get("uri") or record.get("url") or "/")
    safe_normalized = redact_url(result["normalized_url"])
    event = NetworkEvent(
        timestamp=timestamp, src_ip=record.get("src_ip") or "0.0.0.0", src_port=record.get("src_port"),
        dst_ip=record.get("dst_ip") or "0.0.0.0", dst_port=record.get("dst_port"), protocol=record.get("protocol", "HTTP"),
        method=record.get("method", "GET").upper(), host=host, uri=safe_uri,
        normalized_url=safe_normalized, status_code=record.get("status_code"), response_size=record.get("response_size"),
        user_agent=str(record.get("user_agent") or "")[:1024] or None, request_count=int(record.get("request_count") or 1),
    )
    db.add(event)
    db.flush()
    detection = Detection(
        event_id=event.id, attack_type=result["attack_type"], severity=result["severity"], confidence=result["confidence"],
        rule_score=result["scores"]["rule_score"], ml_score=result["scores"]["ml_score"], behavior_score=result["scores"]["behavior_score"],
        attack_status=result["attack_status"], evidence=json.dumps({"items": result["evidence"], "status_reason": result["status_reason"], "metadata": result["metadata"]}),
    )
    db.add(detection)
    return event, detection
