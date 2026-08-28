import shutil
import subprocess
import tempfile
from pathlib import Path

from pcap.zeek_parser import parse_http_log

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024


def zeek_available() -> bool:
    return shutil.which("zeek") is not None


def process_pcap(file_name: str, content: bytes) -> dict:
    suffix = Path(file_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        return {"ok": False, "code": "UNSUPPORTED_FILE", "message": "Upload a .pcap or .pcapng file."}
    if len(content) > MAX_UPLOAD_BYTES:
        return {"ok": False, "code": "TOO_LARGE", "message": "Capture exceeds the 50 MB demo limit."}
    if not zeek_available():
        return {"ok": False, "code": "ZEEK_MISSING", "message": "Zeek is not installed. Demo mode is available."}

    with tempfile.TemporaryDirectory(prefix="urlsentinel-") as temp_dir:
        capture = Path(temp_dir) / f"capture{suffix}"
        capture.write_bytes(content)
        try:
            # An argument array prevents the filename from being interpreted by a shell.
            subprocess.run(
                ["zeek", "-Cr", str(capture), "LogAscii::use_json=T"], cwd=temp_dir,
                check=True, capture_output=True, text=True, timeout=120,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "code": "ZEEK_ERROR", "message": "Zeek could not extract HTTP records from this capture."}
        events = parse_http_log(Path(temp_dir) / "http.log")
        return {"ok": True, "events": events, "records_extracted": len(events)}
