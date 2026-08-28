import json

from sqlalchemy.orm import Session

from models import AuditLog


def write_audit(db: Session, action: str, actor: str = "system", resource: str | None = None, details: dict | None = None, source_ip: str | None = None) -> None:
    db.add(AuditLog(actor=actor, action=action, resource=resource, details=json.dumps(details or {}), source_ip=source_ip))
