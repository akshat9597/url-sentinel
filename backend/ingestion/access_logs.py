"""Parsers for common Nginx/Apache combined logs and JSON-lines telemetry."""
import ipaddress
import json
import re
from datetime import datetime

COMBINED = re.compile(
    r'^(?P<src>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)


def _valid_ip(value: str, fallback: str = "0.0.0.0") -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return fallback


def _json_record(row: dict, default_host: str, default_dst_ip: str) -> dict | None:
    uri = row.get("uri") or row.get("request_uri") or row.get("url") or row.get("path")
    if not uri:
        return None
    timestamp = row.get("timestamp") or row.get("time_iso8601") or row.get("@timestamp")
    return {
        "timestamp": timestamp, "src_ip": _valid_ip(str(row.get("src_ip") or row.get("remote_addr") or "")),
        "src_port": row.get("src_port"), "dst_ip": _valid_ip(str(row.get("dst_ip") or default_dst_ip), default_dst_ip),
        "dst_port": row.get("dst_port") or 443, "protocol": row.get("protocol") or "HTTP",
        "method": row.get("method") or row.get("request_method") or "GET", "host": row.get("host") or row.get("http_host") or default_host,
        "uri": str(uri), "status_code": row.get("status_code") or row.get("status"),
        "response_size": row.get("response_size") or row.get("body_bytes_sent") or row.get("bytes"),
        "user_agent": row.get("user_agent") or row.get("http_user_agent"),
        "request_body": row.get("request_body") or "", "response_body": row.get("response_body") or "",
        "follow_up_evidence": row.get("follow_up_evidence") or [], "content_type": row.get("content_type") or "",
        "file_name": row.get("file_name") or "",
    }


def parse_access_logs(text: str, log_format: str = "auto", default_host: str = "authorized-site.local", default_dst_ip: str = "127.0.0.1") -> tuple[list[dict], list[str]]:
    events, errors = [], []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            if log_format == "json" or (log_format == "auto" and line.lstrip().startswith("{")):
                event = _json_record(json.loads(line), default_host, default_dst_ip)
            else:
                match = COMBINED.match(line)
                if not match:
                    raise ValueError("line does not match combined access-log format")
                values = match.groupdict()
                timestamp = datetime.strptime(values["time"], "%d/%b/%Y:%H:%M:%S %z").isoformat()
                event = {
                    "timestamp": timestamp, "src_ip": _valid_ip(values["src"]), "dst_ip": default_dst_ip,
                    "dst_port": 443, "protocol": values["protocol"].split("/")[0], "method": values["method"],
                    "host": default_host, "uri": values["uri"], "status_code": int(values["status"]),
                    "response_size": 0 if values["size"] == "-" else int(values["size"]), "user_agent": values["agent"],
                }
            if event:
                events.append(event)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            if len(errors) < 20:
                errors.append(f"Line {line_number}: {exc}")
    return events, errors
