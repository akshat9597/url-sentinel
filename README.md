# ByteForce

**Explainable URL-Centric Cyber Threat Detection & Network Traffic Analysis**

> A defensive analysis platform for authorized URL, HTTP access-log, dataset, and PCAP telemetry.

## Product status

| Area | Status |
|---|---|
| URL and HTTP telemetry analysis | Available |
| Rule-based detection | Available |
| Optional ML classification | Available |
| Attempt/probable/confirmed outcome labels | Available with supplied evidence |
| Dashboard, investigation, filtering, and exports | Available |
| Access-log ingestion | Available |
| PCAP ingestion through Zeek | Optional; requires Zeek |
| Browser extension for visited-site checks | **Future update; not included in this release** |

ByteForce is a defensive SIH cybersecurity system that converts supplied URL/HTTP telemetry into explainable alerts. It can run as a reproducible hackathon demo or as an **observation-only production pilot** using access logs from websites and APIs you own or are authorized to monitor.

ByteForce does not visit submitted URLs, scan websites, exploit vulnerabilities, block traffic, or execute payloads. “Real website monitoring” means analyzing authorized reverse-proxy, application, WAF, dataset, or PCAP telemetry—not attacking a public URL.

## What is included

- Manual URL analysis without contacting the URL.
- Safe URL normalization with original and normalized values preserved.
- Explainable rule detection for SQL injection, XSS, traversal, command injection, SSRF, LFI/RFI, parameter pollution, typosquatting, scanner activity, XXE indicators, redirects, and related URL indicators.
- Behavior correlation for brute-force, credential-stuffing-like, scanner, and reconnaissance patterns.
- Versioned character TF-IDF + logistic-regression model with evaluation metrics, activation, rollback, and drift monitoring.
- CSV/JSON telemetry import and Nginx/Apache combined or JSON Lines access-log ingestion.
- Optional watched-log ingestion from one administrator-configured local path.
- PCAP/PCAPNG ingestion through Zeek, with graceful safe-demo fallback.
- SQLite local mode and PostgreSQL deployment mode through SQLAlchemy and Alembic.
- Optional signed HttpOnly-cookie authentication, administrator role, audit log, upload limits, rate limiting, secret redaction, trusted hosts, CORS controls, retention cleanup, and reverse-proxy security headers.
- Analyst feedback export for controlled retraining on reviewed, authorized examples.
- React SOC dashboard, Threat Explorer, details, IP intelligence, analytics, Operations, filters, and CSV/JSON export.

## What is not included in this release

- No browser extension is currently shipped. A future extension will read navigation URLs, submit them to the same `/api/detect/url` service, and display a risk badge or warning without visiting URLs on the user's behalf.
- No automatic browsing, crawling, exploitation, blocking, or active response is performed.
- A URL alert does not prove that a server was compromised. Confirmed outcomes require trustworthy response, application, WAF, or follow-up evidence.

The browser extension is intentionally planned as a separate client of the existing detection API. The planned scope is documented in [Browser extension roadmap](#browser-extension-roadmap).

## Documentation

The project documentation is separated by audience and purpose:

- [Requirements and compliance review](docs/01-requirements-and-compliance.md)
- [Product and user guide](docs/02-product-and-user-guide.md)
- [Detection, ML, and outcomes](docs/03-detection-ml-and-outcomes.md)
- [Data, PCAP, and controlled-lab workflow](docs/04-data-ingestion-pcap-and-dataset.md)
- [Deployment, security, and operations](docs/05-deployment-security-and-operations.md)
- [Browser extension roadmap](docs/06-browser-extension-roadmap.md)
- [Supporting material and visual assets](docs/07-supporting-material-and-visual-assets.md)
- [Presentation: capability, reality alignment, and roadmap](docs/08-presentation-capability-and-roadmap.md)

## Architecture

```mermaid
flowchart TD
    A["Authorized telemetry"] --> B["Dataset / access log / PCAP"]
    B --> C["Traffic extraction and validation"]
    C --> D["Secret redaction and URL normalization"]
    D --> E["Rule engine"]
    D --> F["Versioned ML engine"]
    C --> G["Behaviour engine"]
    E --> H["Threat correlation"]
    F --> H
    G --> H
    H --> I["Confidence and severity"]
    I --> J["Attempt / probable success / confirmed ground truth"]
    J --> K["SQLite or PostgreSQL"]
    K --> L["Dashboard / analyst review / export"]
```

The base application is intentionally a single FastAPI service plus a React interface. This is easier to understand and demonstrate than unnecessary microservices.

## Operating modes

### 1. Demo mode

Uses SQLite, synthetic telemetry, optional demo model, and no login. This is the quickest judging setup.

### 2. Authorized real-log pilot

Runs locally but ingests Nginx, Apache, application JSON Lines, datasets, or PCAP from infrastructure you control. Open **Operations → Ingest real access logs**. The detection pipeline and stored alerts are real; the system remains observation-only.

### 3. Production-oriented deployment

Uses PostgreSQL, Alembic migrations, authentication, strong environment secrets, TLS reverse proxy, retention, audit records, and a model trained from analyst-reviewed organizational telemetry.

This repository supplies the application controls. You must supply the server, owned domain, certificates, backups, monitoring, authorized telemetry, and reviewed labels.

## Primary workflows

### Analyze one URL

Use the Dashboard URL analyzer or call `POST /api/detect/url`. ByteForce normalizes and inspects the supplied value locally; it never sends a request to that URL. The result includes the classification, confidence, severity, matched evidence, model contribution, and outcome status.

### Investigate stored traffic

Open Threat Explorer to filter detections by attack type, source or destination IP/CIDR, host, severity, confidence, and outcome. Open any row to inspect the captured event, normalized URL, engine scores, evidence, and status reason. CSV and JSON exports use the active Threat Explorer filters.

### Ingest authorized telemetry

Use Operations for Nginx, Apache, or JSON Lines access logs. Use PCAP Analyzer for `.pcap` or `.pcapng` files when Zeek is installed. Both paths feed the same normalization and detection pipeline.

## Technology stack

- Frontend: React, Vite, Tailwind CSS, Recharts, Lucide React, Axios
- Backend: Python 3.12, FastAPI, Uvicorn, Pydantic, SQLAlchemy, Alembic
- Data: SQLite locally; PostgreSQL 16 in Docker/production mode
- Detection: `urllib.parse`, `re`, `html`, `unicodedata`, `ipaddress`, Pandas, scikit-learn
- Optional extraction: Zeek
- Edge: Nginx static frontend and reverse proxy

## Directory structure

```text
url-sentinel/
├── backend/
│   ├── api/                 # API route groups, auth, operations
│   ├── data/                # synthetic data, safe access-log example, models
│   ├── detection/           # normalization, rules, ML, scoring, drift
│   ├── ingestion/           # Nginx/Apache parsers, jobs, watched log
│   ├── migrations/          # Alembic schema
│   ├── pcap/                # Zeek runner and parser
│   ├── rules/               # editable JSON detection indicators
│   ├── scripts/             # generation, training, container start
│   └── tests/               # detection, parser, and security tests
├── frontend/
│   ├── nginx.conf           # production static server/API proxy
│   └── src/                 # React components and pages
├── deploy/                  # HTTP and TLS gateway examples
├── .env.example             # deployment settings template
└── docker-compose.yml       # PostgreSQL + backend + frontend
```

## How detection works

### URL normalization

`backend/detection/normalizer.py` keeps the captured value unchanged and creates a comparison value using HTML decoding, limited percent decoding, Unicode NFKC, lowercased comparison fields, safe hostname/path extraction, and duplicate-preserving query parsing. Malformed input returns a parse error instead of crashing.

Before persistence, common secret parameters such as `password`, `token`, `api_key`, `session`, and `otp` are replaced with `[REDACTED]`.

### Rule engine

Most signatures are readable JSON in `backend/rules/attack_rules.json`. Python semantic checks add private/loopback/link-local SSRF detection using `ipaddress`, conflicting duplicate-parameter detection, and protected-domain similarity without treating legitimate subdomains as typosquatting.

### ML engine

The model is character-level TF-IDF plus logistic regression. It is multiclass and uses the strongest malicious-class probability as its cautious score. If no model exists or a model cannot load, `ml_score` becomes `null` and the other engines continue working.

The bundled/synthetic baseline is for pipeline demonstration only. Its high synthetic test accuracy is **not evidence of real-world accuracy**. A real model requires reviewed, representative traffic from the environment where it will operate.

### Behaviour engine

Events are grouped by source IP. Configurable thresholds evaluate authentication failures, request rate, unique paths, repeated 404s, and sensitive-looking paths. These conclusions require a batch of requests and are not fabricated from one URL.

### Threat scoring

Default weights are rules 45%, ML 25%, behavior 20%, and response context 10%. Missing engines are removed and available weights are normalized. A strong engine can still raise an alert, while benign traffic is capped so it cannot become critical from response context alone.

### Attempt versus success

- `ATTEMPT`: suspicious input exists, but a rejection or normal response does not prove exploitation.
- `PROBABLE_SUCCESS`: suspicious input plus unusual successful-response evidence is suggestive, not proof.
- `CONFIRMED_SUCCESS`: only explicit trustworthy imported ground truth.
- `BENIGN`: no sufficiently strong suspicious indicators.

HTTP 200 alone never means an attack succeeded.

## Quick local start

Python 3.10–3.13 and Node.js 20–22 are recommended. Python 3.14 and very new Node releases may lack compatible package wheels or tooling.

### Backend terminal

```bash
cd "/Users/cyph3rrr/Documents/PROJECT 2908/url-sentinel/backend"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python scripts/generate_demo_data.py
python scripts/train_model.py --version local-demo-baseline
python -m uvicorn main:app --reload
```

### Frontend terminal

```bash
cd "/Users/cyph3rrr/Documents/PROJECT 2908/url-sentinel/frontend"
npm install
npm run dev
```

Open:

- Frontend: [http://localhost:5173](http://localhost:5173)
- Backend health: [http://localhost:8000/api/health](http://localhost:8000/api/health)
- Swagger API: [http://localhost:8000/docs](http://localhost:8000/docs)

The backend root returning JSON is normal. The dashboard is on port 5173; `/docs` is the API interface.

## Use real website telemetry safely

Do not type a public site into ByteForce expecting it to scan that site. Instead, export access logs from an owned reverse proxy/application and upload them on the Operations page.

Supported Nginx/Apache combined example:

```text
192.0.2.21 - - [28/Aug/2026:22:00:01 +0530] "GET /products?page=2 HTTP/1.1" 200 4821 "-" "Mozilla/5.0"
```

Supported JSON Lines fields include:

```json
{"time_iso8601":"2026-08-28T22:00:01+05:30","remote_addr":"192.0.2.21","request_method":"GET","host":"shop.example.test","request_uri":"/products?page=2","status":200,"body_bytes_sent":4821}
```

Configure the default host and protected destination for combined logs:

```bash
export BYTEFORCE_DEFAULT_HOST=portal.your-owned-domain.example
export BYTEFORCE_DEFAULT_DST_IP=10.20.0.15
python -m uvicorn main:app --reload
```

Then open **Operations**, choose the log, select Auto/Nginx/Apache/JSON, and click **Analyze logs**. The job runs in the background and appears in Ingestion Jobs.

The bundled `backend/data/demo_access.log` is a safe format example:

```bash
curl -X POST -F "file=@data/demo_access.log" \
  "http://localhost:8000/api/operations/logs/upload?log_format=nginx"
```

### Optional watched-log mode

For one local log file readable by the backend process:

```bash
export BYTEFORCE_LOG_WATCH_PATH=/var/log/nginx/access.log
export BYTEFORCE_LOG_FORMAT=nginx
export BYTEFORCE_DEFAULT_HOST=portal.your-owned-domain.example
python -m uvicorn main:app
```

The file path is administrator configuration, never a user-supplied shell argument. New bytes are checked every five seconds. This simple single-process watcher is suitable for a pilot; use a durable collector/queue for multiple production replicas.

## Train with reviewed real data

1. Analysts investigate detections and submit a corrected label in **Operations → Analyst feedback**.
2. Export `byteforce-reviewed-training.csv`.
3. Collect at least 100 reviewed records and at least 10 examples per class.
4. Train and validate a new inactive version first:

```bash
cd backend
source .venv/bin/activate
python scripts/train_model.py \
  --dataset /absolute/path/to/authorized-reviewed-training.csv \
  --version organization-v1 \
  --no-activate
```

The command prints accuracy, weighted precision/recall/F1, per-class metrics, and confusion-matrix data. When timestamps exist, a time-ordered holdout is used to reduce leakage.

After human review, activate it from Operations or:

```bash
curl -X POST http://localhost:8000/api/operations/models/organization-v1/activate
```

Rollback is the same operation with an earlier version. The ML loader notices the registry change without stopping the rules engine. Drift compares recent URL length and threat rate with the active version’s training baseline; it is a warning to investigate, not automatic retraining.

Never train directly on unreviewed detector output. That would reinforce false positives.

## PostgreSQL + authenticated deployment

Create deployment settings and replace every example secret:

```bash
cd "/Users/cyph3rrr/Documents/PROJECT 2908/url-sentinel"
cp .env.example .env
openssl rand -hex 32
```

Paste the generated value into `BYTEFORCE_SECRET_KEY`. Set strong unique PostgreSQL and administrator passwords, your real allowed origin, trusted host, default protected host/IP, and keep:

```text
BYTEFORCE_ENV=production
BYTEFORCE_AUTH_ENABLED=true
BYTEFORCE_OBSERVATION_MODE=true
BYTEFORCE_AUTO_SEED=false
BYTEFORCE_BOOTSTRAP_MODEL=false
```

Start PostgreSQL, backend, and optimized frontend:

```bash
docker compose up --build
```

Open [http://localhost:5173/operations](http://localhost:5173/operations) for a local deployment test. Sign in with `BYTEFORCE_ADMIN_EMAIL` and `BYTEFORCE_ADMIN_PASSWORD`.

For an internet-facing deployment, do not expose ports 5173 or 8000 publicly. Put the containers behind the example TLS gateway in `deploy/nginx-tls.conf.example`, mount certificates for a domain you control, restrict firewall ingress, and set `BYTEFORCE_HTTPS_REDIRECT=true`. The production login cookie is `Secure`, so HTTPS is required.

### Database migrations

Containers execute this automatically:

```bash
alembic upgrade head
```

For a clean external PostgreSQL database:

```bash
export DATABASE_URL='postgresql+psycopg://USER:PASSWORD@HOST:5432/byteforce'
cd backend
source .venv/bin/activate
alembic upgrade head
```

Do not run the initial migration against the older local SQLite file whose tables were created before Alembic; continue using automatic `create_all` locally or start a clean database.

## Authentication and security controls

- Production startup fails if authentication is disabled, the secret is shorter than 32 characters, or the admin password is absent.
- Telemetry, detection, analytics, PCAP, datasets, and exports require a signed HttpOnly session when auth is enabled.
- Cookie is SameSite Strict and Secure in production.
- CORS and trusted-host values come from environment variables.
- Common secret query values are redacted before persistence.
- Mutation APIs have a bounded per-process rate limit.
- Upload extensions and byte limits are checked.
- Login, ingestion, analyst feedback, model activation, and retention actions are audited.
- Retention cleanup removes a bounded batch older than `BYTEFORCE_RETENTION_DAYS`.
- Passwords use salted PBKDF2-SHA256 hashes.

For multiple backend replicas, replace the in-memory rate limiter and background jobs with shared infrastructure such as a managed gateway and durable queue. Store secrets in a platform secret manager, not `.env` committed to Git.

## PCAP processing and HTTPS limitation

```mermaid
flowchart TD
    A["Upload .pcap / .pcapng"] --> B["Validate extension and size"]
    B --> C{"Zeek installed?"}
    C -- Yes --> D["Run Zeek locally with argument array"]
    D --> E["Parse HTTP/connection logs"]
    E --> F["Normalize, detect, store"]
    C -- No --> G["Offer bundled safe demo results"]
```

On macOS, optional Zeek installation:

```bash
brew install zeek
zeek --version
```

Encrypted HTTPS normally hides paths, query strings, and bodies from passive PCAP inspection. Use reverse-proxy/application logs or traffic decrypted by infrastructure you own. ByteForce never pretends it can decrypt arbitrary HTTPS.

## Main API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Engine/database/model/Zeek status |
| POST | `/api/auth/login` | Authenticated deployment login |
| GET | `/api/dashboard/stats` | Dashboard counters |
| POST | `/api/detect/url` | Analyze and store a URL event |
| GET | `/api/attacks` | Paginated and filterable detections |
| GET | `/api/attacks/{id}` | Event, scores, evidence, status reason |
| GET | `/api/ip/{ip}` | Local IP telemetry intelligence |
| GET | `/api/analytics/*` | Timelines and distributions |
| POST | `/api/dataset/upload` | CSV/JSON ingestion |
| POST | `/api/pcap/upload` | Optional Zeek processing |
| GET | `/api/export/csv` | CSV evidence export |
| GET | `/api/export/json` | JSON evidence export |
| POST | `/api/operations/logs/upload` | Nginx/Apache/JSON Lines ingestion |
| GET | `/api/operations/jobs` | Background job status |
| POST | `/api/operations/detections/{id}/feedback` | Analyst review |
| GET | `/api/operations/models` | Model registry |
| POST | `/api/operations/models/{version}/activate` | Activate/rollback model |
| GET | `/api/operations/drift` | Active-baseline drift report |
| GET | `/api/operations/audit` | Administrator audit records |
| POST | `/api/operations/retention/run` | Administrator retention batch |

Swagger documents all fields and filters at `/docs`.

## Tests and verification

```bash
cd backend
source .venv/bin/activate
python -m compileall -q .
python -m pytest
```

```bash
cd frontend
npm run build
```

Optional Docker configuration check:

```bash
docker compose config
```

## Three-minute hackathon demo

1. Start backend and frontend; open the populated Dashboard.
2. Analyze the normal pre-filled URL, then a safe SQL-like artificial URL. Explain normalization, rules, ML score, severity, evidence, and why HTTP 403 means `ATTEMPT`.
3. Filter Threat Explorer by SQL Injection and open a detail row.
4. Show IP Intelligence and Analytics.
5. Open Operations and upload `backend/data/demo_access.log`; show that five real-format log records produce two benign results and three threats.
6. Show active model, drift state, analyst feedback, and version rollback.
7. Export CSV, then show PCAP Analyzer and its honest HTTPS/Zeek fallback message.
8. Close with **How ByteForce Works**.

## Troubleshooting

### `{"detail":"Not Found"}` at port 8000

The backend is running, but the dashboard is a separate frontend. Open port 5173. API documentation is at `http://localhost:8000/docs`.

### `uvicorn: command not found` or SciPy/Fortran build errors

The dependency install did not complete, commonly because Python is too new. Use Python 3.12, activate `.venv`, install requirements, and start with `python -m uvicorn main:app --reload`.

### macOS `EPERM`, `uv_cwd`, or “operation not permitted”

Give Terminal access to Documents in **System Settings → Privacy & Security → Files & Folders**, close all old terminal tabs, open a new tab, and `cd` into the project again. Moving the project to a developer folder outside Documents is another clean option.

### Dashboard receives 401

Authentication is enabled. Open Operations, sign in, then refresh the dashboard. In production the cookie requires HTTPS.

### ML says not trained

Run `python scripts/train_model.py --version local-demo-baseline`. The rule and behavior engines work without it.

### Zeek missing or zero HTTP records

Use Load Demo Results. A capture may be encrypted HTTPS or contain no recognized HTTP. Prefer proxy/application logs for complete URLs.

### Drift detected

This does not prove model failure. Review a recent representative sample, label errors, compare per-class metrics, train a new inactive version, and activate only after validation.

## Known limitations

- The included ML baseline is synthetic and deliberately not claimed as a production security model.
- Rules and ML can produce false positives and false negatives.
- Drift monitoring uses simple global statistics, not per-application feature distributions.
- Background jobs and watched-log offsets are process-local; use a durable queue/checkpoint store for horizontal scaling.
- The local rate limiter is not shared across replicas.
- No external reputation feed or paid API is used.
- No automatic blocking or active response is included.
- PCAP cannot generally reveal encrypted HTTPS URLs.
- Operational backups, alert delivery, certificate renewal, high availability, SIEM/WAF integration, and infrastructure monitoring remain deployment responsibilities.

## Future improvements

- Calibrated per-application models and realistic time-based evaluation.
- Rule/model approval workflow and signed model artifacts.
- Durable Kafka/queue or collector ingestion and saved checkpoints.
- OIDC/SSO and finer RBAC.
- PostgreSQL native network types and partitions.
- Prometheus/OpenTelemetry metrics and alert delivery.
- Object storage for authorized raw evidence with strict retention.
- WAF/SIEM connectors for approved response workflows.

## Browser extension roadmap

The browser extension is a planned future update, not a current feature. It will be designed as a Manifest V3 client for Chromium-based browsers, with the following guarded workflow:

1. Observe a tab navigation event.
2. Send the URL to a configured ByteForce server over HTTPS.
3. Display a compact safe/suspicious/malicious badge with attack type, confidence, and explanation.
4. Optionally warn before high-risk navigation, subject to user or organization policy.

The extension will not collect passwords, cookies, page contents, form values, or session tokens. It will use an allow-list, local result caching, an enable/disable control, narrow browser permissions, and an administrator-configured backend. Browser results will represent URL risk only; server-side success classification will continue to require authorized telemetry.

For intentionally vulnerable-application experiments, use an isolated local lab you own. Never test third-party systems without explicit written authorization.
