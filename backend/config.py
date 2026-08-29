"""Environment-driven settings for local demos and production-oriented pilots."""
import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("BYTEFORCE_ENV", "demo")
    observation_mode: bool = _bool("BYTEFORCE_OBSERVATION_MODE", True)
    auth_enabled: bool = _bool("BYTEFORCE_AUTH_ENABLED", False)
    secret_key: str = os.getenv("BYTEFORCE_SECRET_KEY", "")
    admin_email: str = os.getenv("BYTEFORCE_ADMIN_EMAIL", "admin@byteforce.local")
    admin_password: str = os.getenv("BYTEFORCE_ADMIN_PASSWORD", "")
    auto_seed: bool = _bool("BYTEFORCE_AUTO_SEED", os.getenv("BYTEFORCE_ENV", "demo") != "production")
    https_redirect: bool = _bool("BYTEFORCE_HTTPS_REDIRECT", False)
    allowed_origins: list[str] = field(default_factory=lambda: [item.strip() for item in os.getenv(
        "BYTEFORCE_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",") if item.strip()])
    trusted_hosts: list[str] = field(default_factory=lambda: [item.strip() for item in os.getenv(
        "BYTEFORCE_TRUSTED_HOSTS", "localhost,127.0.0.1,testserver"
    ).split(",") if item.strip()])
    max_upload_bytes: int = int(os.getenv("BYTEFORCE_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
    retention_days: int = int(os.getenv("BYTEFORCE_RETENTION_DAYS", "90"))
    rate_limit_per_minute: int = int(os.getenv("BYTEFORCE_RATE_LIMIT_PER_MINUTE", "120"))
    log_watch_path: str = os.getenv("BYTEFORCE_LOG_WATCH_PATH", "")
    log_format: str = os.getenv("BYTEFORCE_LOG_FORMAT", "auto")
    default_host: str = os.getenv("BYTEFORCE_DEFAULT_HOST", "authorized-site.local")
    default_dst_ip: str = os.getenv("BYTEFORCE_DEFAULT_DST_IP", "127.0.0.1")


settings = Settings()


def validate_production_settings() -> None:
    if settings.environment == "production":
        # Hackathon/demo deployments may be intentionally public so judges can
        # explore dashboards without credentials. When auth is enabled, keep the
        # stronger secret checks.
        if settings.auth_enabled:
            if len(settings.secret_key) < 32:
                raise RuntimeError("BYTEFORCE_SECRET_KEY must contain at least 32 characters in production.")
            if not settings.admin_password:
                raise RuntimeError("BYTEFORCE_ADMIN_PASSWORD is required when production authentication is enabled.")
