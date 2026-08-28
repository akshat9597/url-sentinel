"""Parse Zeek JSON logs into the small NetworkEvent shape used by ByteForce."""
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_http_log(path: Path) -> list[dict]:
    events = []
    if not path.exists():
        return events
    for line in path.read_text(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = row.get("host") or "unknown"
        uri = row.get("uri") or "/"
        events.append({
            "timestamp": datetime.fromtimestamp(float(row.get("ts", 0)), tz=timezone.utc).isoformat(),
            "src_ip": row.get("id.orig_h", "0.0.0.0"), "src_port": row.get("id.orig_p"),
            "dst_ip": row.get("id.resp_h", "0.0.0.0"), "dst_port": row.get("id.resp_p"),
            "protocol": "HTTP", "method": row.get("method", "GET"), "host": host, "uri": uri,
            "status_code": row.get("status_code"), "response_size": row.get("response_body_len"),
            "user_agent": row.get("user_agent"),
        })
    return events
