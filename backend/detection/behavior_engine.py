"""Small-window behavior heuristics. These complement, not replace, URL rules."""
from collections import Counter
from dataclasses import dataclass


@dataclass
class BehaviorThresholds:
    authentication_requests: int = 12
    high_failure_ratio: float = 0.70
    scanner_unique_paths: int = 15
    scanner_not_found_ratio: float = 0.55


def analyze_behavior(events: list[dict], thresholds: BehaviorThresholds | None = None) -> dict:
    thresholds = thresholds or BehaviorThresholds()
    if not events:
        return {"score": 0, "type": None, "evidence": []}

    paths = [str(event.get("uri", "")).split("?", 1)[0] for event in events]
    statuses = Counter(event.get("status_code") for event in events)
    auth_events = [event for event in events if any(word in str(event.get("uri", "")).lower() for word in ("login", "signin", "auth"))]
    auth_failures = sum(event.get("status_code") in {401, 403, 429} for event in auth_events)
    auth_ratio = auth_failures / len(auth_events) if auth_events else 0
    not_found_ratio = statuses[404] / len(events)

    if len(auth_events) >= thresholds.authentication_requests and auth_ratio >= thresholds.high_failure_ratio:
        return {"score": 82, "type": "BRUTE_FORCE", "evidence": ["One source made many authentication requests with a high failure ratio."]}
    if len(set(paths)) >= thresholds.scanner_unique_paths and not_found_ratio >= thresholds.scanner_not_found_ratio:
        return {"score": 75, "type": "SCANNER_ACTIVITY", "evidence": ["One source rapidly requested many unique paths and received mostly 404 responses."]}
    if len(set(paths)) >= thresholds.scanner_unique_paths:
        return {"score": 58, "type": "RECONNAISSANCE_PATTERN", "evidence": ["A single source explored an unusually broad set of paths."]}
    return {"score": 0, "type": None, "evidence": []}
