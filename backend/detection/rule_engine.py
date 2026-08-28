"""Explainable, signature-oriented URL detection for safe telemetry analysis."""
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parents[1]
RULES = json.loads((BASE_DIR / "rules" / "attack_rules.json").read_text())
PROTECTED_DOMAINS = json.loads((BASE_DIR / "data" / "protected_domains.json").read_text())
SSRF_NAMES = {"url", "uri", "endpoint", "callback", "redirect", "host", "target", "proxy", "destination"}


def _edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def _registered_like(host: str, protected: str) -> bool:
    return host == protected or host.endswith("." + protected)


def detect_typosquatting(host: str) -> dict | None:
    if not host:
        return None
    if host.startswith("xn--") or ".xn--" in host:
        return {"matched_brand": "punycode", "similarity_score": 90, "evidence": "Punycode hostname warrants brand-spoofing review."}
    for protected in PROTECTED_DOMAINS:
        if _registered_like(host, protected):
            continue  # Legitimate subdomains are not typosquatting.
        distance = _edit_distance(host, protected)
        similarity = round(100 * (1 - distance / max(len(host), len(protected), 1)), 1)
        if distance <= 2 and similarity >= 78:
            return {
                "matched_brand": protected,
                "similarity_score": similarity,
                "evidence": f"Hostname closely resembles protected domain {protected} but is not its subdomain.",
            }
    return None


def _internal_target(value: str) -> bool:
    candidate = value.strip().strip("[]")
    try:
        parsed = urlsplit(candidate if "://" in candidate else "//" + candidate)
        host = parsed.hostname or candidate.split(":", 1)[0]
    except ValueError:
        return False
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith((".local", ".internal", ".localhost")):
        return True
    try:
        address = ipaddress.ip_address(lowered)
        return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved
    except ValueError:
        return False


def _subtype(attack_type: str, searchable: str, status_code: int | None = None) -> str | None:
    value = searchable.lower()
    if attack_type == "SQL_INJECTION":
        if "union" in value and "select" in value:
            return "UNION_BASED"
        if "sleep(" in value or "benchmark(" in value or "waitfor" in value:
            return "BLIND_TIME_BASED"
        if "select" in value or "from" in value or "--" in value:
            return "ERROR_OR_BOOLEAN_BASED"
    if attack_type == "XSS":
        if "javascript:" in value or "onerror" in value or "onload" in value:
            return "DOM_OR_EVENT_HANDLER"
        return "REFLECTED_OR_STORED"
    return None


def analyze(normalized: dict, method: str = "GET", content_type: str = "", file_name: str = "", request_body: str = "") -> dict:
    comparison = normalized.get("comparison", "")
    searchable = " ".join([comparison, normalized.get("path", "").lower(), content_type.lower(), file_name.lower(), str(request_body).lower()])
    hits: list[dict] = []

    for attack_type, rule in RULES.items():
        matched = [pattern for pattern in rule["patterns"] if re.search(pattern, searchable, re.IGNORECASE)]
        if matched:
            hits.append({"attack_type": attack_type, "score": rule["score"], "evidence": [rule["evidence"]]})

    parameters = normalized.get("parameters", {})
    for name, values in parameters.items():
        if len(values) > 1 and len(set(values)) > 1:
            hits.append({
                "attack_type": "HTTP_PARAMETER_POLLUTION",
                "score": 72,
                "evidence": [f"Duplicate parameter '{name}' contains conflicting values."],
            })
        if name.lower() in SSRF_NAMES and any(_internal_target(value) for value in values):
            hits.append({
                "attack_type": "SSRF",
                "score": 89,
                "evidence": ["URL parameter points to a private, loopback, link-local, or internal destination."],
            })

    executable_suffix = re.search(r"\.(?:php|php[0-9]|phtml|jsp|jspx|asp|aspx)(?:$|[\s\"']|[?;])", file_name.lower())
    if "multipart/form-data" in content_type.lower() and executable_suffix:
        hits.append({
            "attack_type": "WEB_SHELL_UPLOAD", "score": 94,
            "evidence": ["A multipart upload references a server-executable script filename."],
        })
    typo = detect_typosquatting(normalized.get("hostname", ""))
    if typo:
        hits.append({"attack_type": "TYPOSQUATTING", "score": typo["similarity_score"], "evidence": [typo["evidence"]], "metadata": typo})

    if not hits:
        return {"attack_type": "BENIGN", "score": 0, "evidence": [], "all_hits": [], "metadata": {}}
    winner = max(hits, key=lambda hit: hit["score"])
    evidence = []
    for hit in hits:
        evidence.extend(hit["evidence"])
    if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        evidence.append("An uncommon HTTP method was observed and should be reviewed.")
    return {
        "attack_type": winner["attack_type"],
        "score": min(100, winner["score"]),
        "evidence": list(dict.fromkeys(evidence)),
        "all_hits": [hit["attack_type"] for hit in hits],
        "metadata": {**winner.get("metadata", {}), **({"subtype": _subtype(winner["attack_type"], searchable)} if _subtype(winner["attack_type"], searchable) else {})},
    }
