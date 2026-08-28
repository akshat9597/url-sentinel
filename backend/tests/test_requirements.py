from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.attacks import filtered_attack_query
from api.export import export_rows
from database import Base
from detection.behavior_engine import analyze_behavior
from detection.rule_engine import analyze
from detection.normalizer import normalize_url
from detection.service import detect_record
from detection.success_classifier import classify_success
from models import Detection, NetworkEvent
from pcap.zeek_parser import parse_http_log


def detect(url, **record):
    return detect_record({"uri": url, "host": "authorized-site.local", **record})


def test_required_attack_families():
    cases = {
        "SQL_INJECTION": "/search?q=1%27%20union%20select%20password%20from%20users",
        "XSS": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "DIRECTORY_TRAVERSAL": "/download?f=../../../../etc/passwd",
        "COMMAND_INJECTION": "/lookup?host=x%3Bwhoami",
        "SSRF": "/preview?url=http://127.0.0.1/admin",
        "LFI": "/view?page=../../../etc/passwd",
        "RFI": "/view?include=https://example.test/file.txt",
        "HTTP_PARAMETER_POLLUTION": "/profile?role=user&role=admin",
    }
    for expected, url in cases.items():
        result = analyze(normalize_url(url))
        assert result["attack_type"] == expected, expected
    assert analyze(normalize_url("https://githab.com/signin"))["attack_type"] == "TYPOSQUATTING"
    assert analyze(normalize_url("/upload"), content_type="multipart/form-data", file_name="avatar.php")["attack_type"] == "WEB_SHELL_UPLOAD"
    assert analyze(normalize_url("/upload"), content_type="multipart/form-data", file_name="avatar.jpg")["attack_type"] == "BENIGN"
    assert analyze(normalize_url("/submit"), content_type="application/xml", request_body="<!DOCTYPE x [<!ENTITY file SYSTEM 'file:///etc/passwd'>]")["attack_type"] == "XXE_INDICATOR"


def test_brute_force_behavior():
    events = [{"uri": "/login?user=user-{n}".format(n=index), "status_code": 401} for index in range(12)]
    result = analyze_behavior(events)
    assert result["type"] == "BRUTE_FORCE"


def test_success_requires_correlated_evidence():
    assert classify_success(True, 200, 1000) == ("ATTEMPT", "Suspicious traffic was detected, but the response does not prove that exploitation succeeded.")
    status, reason = classify_success(True, 200, 1000, response_body="root:x:0:0:root:/root:/bin/bash")
    assert status == "CONFIRMED_SUCCESS"
    assert "root:x:" in reason
    status, _ = classify_success(True, 200, 1000, follow_up_evidence=["A protected file was read in the next request."])
    assert status == "CONFIRMED_SUCCESS"
    assert classify_success(True, 403, 1000)[0] == "ATTEMPT"
    assert classify_success(True, 200, 80000)[0] == "PROBABLE_SUCCESS"


def test_zeek_http_parser(tmp_path):
    path = tmp_path / "http.log"
    path.write_text('{"ts": 1720000000, "id.orig_h": "192.0.2.5", "id.resp_h": "198.51.100.5", "method": "GET", "host": "lab.test", "uri": "/x", "status_code": 403}\n')
    records = parse_http_log(path)
    assert len(records) == 1
    assert records[0]["src_ip"] == "192.0.2.5"
    assert records[0]["status_code"] == 403


def test_filters_and_exports_apply_same_query():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    for index, attack_type in enumerate(("SQL_INJECTION", "XSS")):
        event = NetworkEvent(timestamp=datetime.now(timezone.utc), src_ip=f"192.0.2.{index + 1}", dst_ip="198.51.100.1", host="lab.test", uri="/x", normalized_url="http://lab.test/x")
        session.add(event)
        session.flush()
        session.add(Detection(event_id=event.id, attack_type=attack_type, confidence=90, severity="HIGH", attack_status="ATTEMPT"))
    session.commit()
    query = filtered_attack_query(session, attack_type="SQL_INJECTION")
    assert query.count() == 1
    rows = export_rows(session, attack_type="SQL_INJECTION")
    assert len(rows) == 1
    assert rows[0]["attack_type"] == "SQL_INJECTION"
