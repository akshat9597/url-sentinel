from contextlib import asynccontextmanager
import csv
from pathlib import Path
from collections import defaultdict, deque
import time

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from api import analytics, attacks, authentication, dashboard, datasets, detection, export, operations, pcap
from auth import bootstrap_admin, current_principal
from config import settings, validate_production_settings
from database import Base, SessionLocal, engine
from ingestion.watcher import watcher
from models import NetworkEvent


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app); self.requests = defaultdict(deque)

    async def dispatch(self, request, call_next):
        if request.method != "GET" and request.url.path.startswith("/api/"):
            client = request.client.host if request.client else "unknown"; now = time.monotonic(); bucket = self.requests[client]
            while bucket and bucket[0] < now - 60:
                bucket.popleft()
            if len(bucket) >= settings.rate_limit_per_minute:
                return JSONResponse({"detail": "Rate limit exceeded. Try again shortly."}, status_code=429)
            bucket.append(now)
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_production_settings()
    Base.metadata.create_all(bind=engine)
    # Seed a modest subset on first start so the dashboard is immediately useful.
    # The full 10,000-row CSV remains available for upload and repeatable demos.
    db = SessionLocal()
    try:
        bootstrap_admin(db)
        if settings.auto_seed and db.query(NetworkEvent).count() == 0:
            demo_path = Path(__file__).resolve().parent / "data" / "demo_traffic.csv"
            if demo_path.exists():
                with demo_path.open(newline="") as handle:
                    all_records = list(csv.DictReader(handle))
                # Use a representative slice so every dashboard is populated
                # with both ordinary traffic and varied threat categories.
                records = [row for row in all_records if row.get("label") == "BENIGN"][:390]
                records += [row for row in all_records if row.get("label") != "BENIGN"][:210]
                datasets.ingest(db, records)
    finally:
        db.close()
    watcher.start()
    yield
    watcher.stop()


app = FastAPI(
    title="ByteForce API", version="1.0.0",
    description="Explainable, observation-only URL-centric defensive threat detection for authorized telemetry.",
    lifespan=lifespan,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
if settings.https_redirect:
    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

app.include_router(authentication.router)
for router in (dashboard.router, detection.router, attacks.router, datasets.router, analytics.router, export.router, pcap.router):
    # In demo mode this dependency returns a local observer. In production it
    # protects telemetry, detections, analytics, and exports with a signed
    # HttpOnly session.
    app.include_router(router, dependencies=[Depends(current_principal)])
app.include_router(operations.router)


@app.get("/api/health", tags=["System"])
def health():
    from detection.ml_engine import active_model_info
    from pcap.processor import zeek_available
    model = active_model_info()
    return {"status": "online", "database": engine.url.get_backend_name(), "ml_model": model is not None, "model_version": model.get("version") if model else None, "zeek": zeek_available(), "environment": settings.environment, "mode": "OBSERVATION" if settings.observation_mode else "ACTIVE_RESPONSE", "auth_enabled": settings.auth_enabled}


@app.get("/", include_in_schema=False)
def root():
    return {"name": "ByteForce", "status": "online", "dashboard": "http://localhost:5173", "documentation": "/docs"}
