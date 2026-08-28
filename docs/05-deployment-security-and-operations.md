# ByteForce Deployment, Security, and Operations

## Deployment modes

### Demo mode

SQLite, synthetic telemetry, optional demo model, and no login. Use this mode for a quick local demonstration.

### Authorized pilot

Local or controlled deployment using access logs, reviewed datasets, or PCAP from infrastructure the operator owns or administers. The system remains observation-only.

### Production-oriented deployment

PostgreSQL, Alembic migrations, authenticated signed cookies, TLS, retention, audit logs, model governance, and controlled operational access.

## Local startup

```bash
cd "/Users/cyph3rrr/Documents/PROJECT 2908/url-sentinel/backend"
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/generate_demo_data.py
python scripts/train_model.py --version local-demo-baseline
python -m uvicorn main:app --reload
```

In another terminal:

```bash
cd "/Users/cyph3rrr/Documents/PROJECT 2908/url-sentinel/frontend"
npm install
npm run dev
```

## Docker deployment

```bash
docker compose up --build
```

The compose file provides PostgreSQL, backend, frontend, and an optional Nginx gateway profile. For internet-facing use, place services behind TLS, do not expose ports 5173 or 8000 publicly, restrict firewall access, and replace all example credentials and secrets.

## Production settings

Use `.env.example` as the starting point. Required production controls include:

```text
BYTEFORCE_ENV=production
BYTEFORCE_AUTH_ENABLED=true
BYTEFORCE_OBSERVATION_MODE=true
BYTEFORCE_AUTO_SEED=false
BYTEFORCE_BOOTSTRAP_MODEL=false
```

Set a random `BYTEFORCE_SECRET_KEY` of at least 32 characters, a strong administrator password, real trusted hosts, allowed origins, database credentials, and TLS configuration.

## Security controls

- Signed HttpOnly authentication cookies.
- SameSite Strict and Secure cookies in production.
- Passwords hashed with salted PBKDF2-SHA256.
- CORS and trusted hosts controlled by environment settings.
- Common secret query values redacted before storage.
- Upload extension and byte limits.
- Bounded mutation rate limiting.
- Audit records for login, ingestion, feedback, model activation, and retention operations.
- Bounded retention cleanup.
- Security headers including content-type sniffing, frame, referrer, permissions, and content-security policies.

For multiple backend replicas, replace process-local rate limiting, background jobs, and watcher offsets with shared infrastructure and durable checkpoints. Store secrets in a platform secret manager, not committed `.env` files.

## Migrations and data

```bash
cd backend
source .venv/bin/activate
alembic upgrade head
```

Use a clean external PostgreSQL database for migrations. Older local SQLite tables created before Alembic should continue using local automatic table creation or be replaced with a clean database.

## Verification

```bash
cd backend
source .venv/bin/activate
python -m compileall -q .
python -m pytest -q
```

```bash
cd frontend
npm run build
```

Optional:

```bash
docker compose config
```

## Operational limitations

The project does not include backups, certificate renewal, high availability, external reputation feeds, alert delivery, automatic blocking, WAF/SIEM connectors, or production infrastructure monitoring. These remain deployment responsibilities.
