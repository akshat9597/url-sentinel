from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    src_ip = Column(String(64), index=True)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String(64), index=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), default="HTTP")
    method = Column(String(16), default="GET")
    host = Column(String(255), index=True)
    uri = Column(Text)
    normalized_url = Column(Text)
    status_code = Column(Integer, nullable=True)
    response_size = Column(Integer, nullable=True)
    user_agent = Column(Text, nullable=True)
    request_count = Column(Integer, default=1)

    detection = relationship("Detection", back_populates="event", uselist=False, cascade="all, delete-orphan")


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("network_events.id"), unique=True, index=True)
    attack_type = Column(String(64), index=True, default="BENIGN")
    severity = Column(String(16), index=True, default="LOW")
    confidence = Column(Float, default=0)
    rule_score = Column(Float, default=0)
    ml_score = Column(Float, nullable=True)
    behavior_score = Column(Float, default=0)
    attack_status = Column(String(32), index=True, default="BENIGN")
    evidence = Column(Text, default="[]")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    event = relationship("NetworkEvent", back_populates="detection")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(32), default="ANALYST", nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    actor = Column(String(255), default="system", index=True)
    action = Column(String(128), index=True, nullable=False)
    resource = Column(String(255), nullable=True)
    details = Column(Text, default="{}")
    source_ip = Column(String(64), nullable=True)


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    id = Column(Integer, primary_key=True)
    source_name = Column(String(255), nullable=False)
    log_format = Column(String(32), default="auto")
    status = Column(String(32), default="QUEUED", index=True)
    records_processed = Column(Integer, default=0)
    attacks_detected = Column(Integer, default=0)
    errors = Column(Integer, default=0)
    message = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = Column(DateTime, nullable=True)


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    id = Column(Integer, primary_key=True)
    detection_id = Column(Integer, ForeignKey("detections.id"), index=True, nullable=False)
    analyst_email = Column(String(255), index=True)
    reviewed_label = Column(String(64), nullable=False)
    outcome_label = Column(String(32), nullable=True)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class ModelVersion(Base):
    __tablename__ = "model_versions"
    id = Column(Integer, primary_key=True)
    version = Column(String(64), unique=True, nullable=False, index=True)
    path = Column(Text, nullable=False)
    status = Column(String(32), default="INACTIVE", index=True)
    metrics = Column(Text, default="{}")
    training_source = Column(String(255), default="synthetic")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    activated_at = Column(DateTime, nullable=True)
