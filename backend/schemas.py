from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class URLDetectionRequest(BaseModel):
    url: str = Field(..., max_length=8192)
    src_ip: Optional[str] = "192.0.2.10"
    dst_ip: Optional[str] = "198.51.100.20"
    method: str = "GET"
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    ground_truth_success: bool = False
    content_type: str = ""
    file_name: str = ""
    request_body: str = ""
    response_body: str = ""
    follow_up_evidence: list[str] = []

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("URL cannot be empty.")
        return value.strip()


class NetworkEventInput(BaseModel):
    timestamp: Optional[datetime] = None
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    protocol: str = "HTTP"
    method: str = "GET"
    host: Optional[str] = None
    uri: str
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    user_agent: Optional[str] = None
    request_count: int = 1
    ground_truth_success: bool = False
    content_type: str = ""
    file_name: str = ""
    request_body: str = ""
    response_body: str = ""
    follow_up_evidence: list[str] = []


class DetectionResponse(BaseModel):
    malicious: bool
    attack_type: str
    severity: str
    confidence: float
    attack_status: str
    original_url: str
    normalized_url: str
    scores: dict[str, Optional[float]]
    evidence: list[str]
    status_reason: str
    metadata: dict[str, Any] = {}
