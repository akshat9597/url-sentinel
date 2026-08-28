"""Optional polling watcher for an explicitly configured local access-log path."""
import threading
from pathlib import Path

from config import settings
from database import SessionLocal
from ingestion.jobs import process_log_job
from models import IngestionJob


class AccessLogWatcher:
    def __init__(self):
        self.path = Path(settings.log_watch_path).expanduser() if settings.log_watch_path else None
        self.offset = 0
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        if not self.path:
            return
        self.thread = threading.Thread(target=self._run, name="byteforce-log-watcher", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)

    def scan_once(self) -> int | None:
        if not self.path or not self.path.is_file():
            return None
        size = self.path.stat().st_size
        if size < self.offset:
            self.offset = 0
        with self.path.open("rb") as handle:
            handle.seek(self.offset)
            content = handle.read(settings.max_upload_bytes)
            self.offset = handle.tell()
        if not content:
            return None
        db = SessionLocal()
        job = IngestionJob(source_name=str(self.path), log_format=settings.log_format, status="QUEUED")
        db.add(job); db.commit(); db.refresh(job); job_id = job.id; db.close()
        process_log_job(job_id, content, settings.log_format, settings.default_host, settings.default_dst_ip)
        return job_id

    def _run(self):
        while not self.stop_event.wait(5):
            try:
                self.scan_once()
            except OSError:
                continue


watcher = AccessLogWatcher()
