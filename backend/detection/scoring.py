DEFAULT_WEIGHTS = {"rule": 0.45, "ml": 0.25, "behavior": 0.20, "response": 0.10}


def severity_for(score: float, malicious: bool) -> str:
    if not malicious:
        return "LOW"
    if score <= 30:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 70:
        return "HIGH"
    return "CRITICAL"


def combine_scores(rule_score: float | None, ml_score: float | None, behavior_score: float | None, response_score: float | None = 0) -> dict:
    components = {"rule": rule_score, "ml": ml_score, "behavior": behavior_score, "response": response_score}
    available = {name: value for name, value in components.items() if value is not None}
    weight_total = sum(DEFAULT_WEIGHTS[name] for name in available)
    confidence = sum(float(value) * DEFAULT_WEIGHTS[name] for name, value in available.items()) / weight_total if weight_total else 0
    # A strong single engine should remain visible even when other available
    # engines correctly return zero. Correlation still raises it further.
    strongest = max((float(value) for value in available.values()), default=0)
    confidence = max(confidence, strongest * 0.82)
    malicious = max(rule_score or 0, ml_score or 0, behavior_score or 0) >= 45
    if not malicious:
        confidence = min(confidence, 30)
    return {"confidence": round(max(0, min(100, confidence)), 1), "severity": severity_for(confidence, malicious), "malicious": malicious}
