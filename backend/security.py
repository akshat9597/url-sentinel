"""Authentication primitives and secret-safe telemetry storage helpers."""
import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_PARAMETERS = {
    "password", "passwd", "pwd", "token", "access_token", "refresh_token", "api_key",
    "apikey", "secret", "authorization", "session", "sessionid", "cookie", "otp", "credit_card",
}


def redact_url(value: object) -> str:
    """Remove common credentials before telemetry is persisted or exported."""
    raw = "" if value is None else str(value)
    try:
        parts = urlsplit(raw)
        redacted = [(name, "[REDACTED]" if name.lower() in SENSITIVE_PARAMETERS else item) for name, item in parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted, doseq=True), parts.fragment))
    except ValueError:
        return raw[:8192]


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, rounds, salt_value, expected_value = encoded.split("$", 3)
        salt = base64.urlsafe_b64decode(salt_value)
        expected = base64.urlsafe_b64decode(expected_value)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_token(subject: str, role: str, secret: str, expires_seconds: int = 8 * 3600) -> str:
    payload = _b64(json.dumps({"sub": subject, "role": role, "exp": int(time.time()) + expires_seconds}, separators=(",", ":")).encode())
    signature = _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def decode_token(token: str, secret: str) -> dict | None:
    try:
        payload, signature = token.split(".", 1)
        expected = _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        decoded = json.loads(_decode(payload))
        return decoded if int(decoded["exp"]) >= int(time.time()) else None
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
