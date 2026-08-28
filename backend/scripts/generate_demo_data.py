"""Generate safe, labelled telemetry locally. No network connection is made."""
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(2908)
OUTPUT = Path(__file__).resolve().parents[1] / "data" / "demo_traffic.csv"
FIELDS = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "method", "host", "uri", "status_code", "response_size", "user_agent", "request_count", "label", "ground_truth_success", "content_type", "file_name", "request_body", "response_body"]

BENIGN = [
    ("portal.example.test", "/"), ("portal.example.test", "/search?q=annual+report"),
    ("services.example.test", "/api/notices?page=2"), ("citizen.example.test", "/profile/settings"),
    ("docs.example.test", "/guides/network-safety"), ("payments.example.test", "/receipt?id=INV-2048"),
]
SUSPICIOUS = {
    "SQL_INJECTION": ("portal.example.test", "/search?q=%27+OR+%271%27%3D%271"),
    "XSS": ("portal.example.test", "/feedback?message=%3Cscript%3Ealert(1)%3C/script%3E"),
    "DIRECTORY_TRAVERSAL": ("files.example.test", "/download?name=../../../../etc/passwd"),
    "COMMAND_INJECTION": ("tools.example.test", "/lookup?host=sample.test%3Bwhoami"),
    "SSRF": ("gateway.example.test", "/preview?url=http://127.0.0.1/admin"),
    "LFI": ("portal.example.test", "/view?page=../../../etc/passwd"),
    "RFI": ("portal.example.test", "/view?include=https://assets.example.test/sample.txt"),
    "HTTP_PARAMETER_POLLUTION": ("accounts.example.test", "/profile?role=user&role=admin"),
    "TYPOSQUATTING": ("githab.com", "/signin"),
    "SCANNER_ACTIVITY": ("portal.example.test", "/.env"),
    "WEB_SHELL_REFERENCE": ("portal.example.test", "/uploads/shell-demo.php?view=1"),
    "XXE_INDICATOR": ("portal.example.test", "/xml/import"),
    "WEB_SHELL_UPLOAD": ("portal.example.test", "/upload"),
}
AGENTS = ["Mozilla/5.0 ByteForce-Demo", "DemoMobile/1.0", "SyntheticMonitor/2.1", "TelemetryLab/1.2"]


def ip_in_documentation_range(prefix: str) -> str:
    return f"{prefix}.{random.randint(1, 254)}"


def row(index: int, start: datetime, suspicious: bool) -> dict:
    timestamp = start + timedelta(seconds=index * 5 + random.randint(0, 3))
    label = random.choice(list(SUSPICIOUS)) if suspicious else "BENIGN"
    host, uri = SUSPICIOUS[label] if suspicious else random.choice(BENIGN)
    blocked = suspicious and random.random() < 0.72
    status = random.choice([401, 403, 404, 429]) if blocked else random.choice([200, 200, 201, 302])
    response_size = random.randint(180, 7000)
    # Some suspicious responses are unusually large (probable, not proof). An
    # even smaller subset carries explicit synthetic ground truth.
    unusual_response = suspicious and not blocked and random.random() < 0.10
    ground_truth = unusual_response and random.random() < 0.25
    if unusual_response:
        response_size = random.randint(80000, 130000)
    record = {
        "timestamp": timestamp.isoformat(), "src_ip": ip_in_documentation_range(random.choice(["192.0.2", "198.51.100", "203.0.113"])),
        "src_port": random.randint(1024, 65535), "dst_ip": ip_in_documentation_range("198.51.100"), "dst_port": 443 if random.random() < .75 else 80,
        "protocol": "HTTP", "method": random.choice(["GET", "GET", "POST"]), "host": host, "uri": uri,
        "status_code": status, "response_size": response_size, "user_agent": random.choice(AGENTS), "request_count": 1,
        "label": label, "ground_truth_success": str(ground_truth).lower(), "content_type": "", "file_name": "", "request_body": "", "response_body": "",
    }
    if label == "XXE_INDICATOR":
        record.update({"content_type": "application/xml", "request_body": "<!DOCTYPE x [<!ENTITY file SYSTEM 'file:///etc/passwd'>]"})
    if label == "WEB_SHELL_UPLOAD":
        record.update({"content_type": "multipart/form-data; boundary=demo", "file_name": "avatar.php"})
    return record


def main(count: int = 10000):
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now(timezone.utc) - timedelta(days=7)
    records = [row(index, start, index >= int(count * .70)) for index in range(count)]

    # Add clustered authentication and scan traffic so behavior analytics can be demonstrated.
    for index in range(100, 145):
        records[index].update({"src_ip": "192.0.2.250", "host": "accounts.example.test", "uri": "/login?user=demo", "status_code": 401, "label": "BRUTE_FORCE"})
    for index in range(300, 345):
        records[index].update({"src_ip": "203.0.113.240", "uri": f"/probe-{index}?check=1", "status_code": 404, "label": "SCANNER_ACTIVITY"})
    # Deterministic examples keep the judging dashboard repeatable: one
    # probable outcome and one explicitly confirmed synthetic ground truth.
    records[7000].update({"status_code": 200, "response_size": 92000, "ground_truth_success": "true"})
    records[7001].update({"status_code": 200, "response_size": 88000, "ground_truth_success": "false"})

    with OUTPUT.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader(); writer.writerows(records)
    print(f"Generated {len(records):,} safe synthetic events at {OUTPUT}")


if __name__ == "__main__":
    main()
