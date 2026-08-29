ByteForce

Explainable URL-Centric Cyber Threat Detection & Network Traffic Analysis






A defensive analysis platform for authorized URL, HTTP access-log, dataset, and PCAP telemetry.

🚀 Live Demo

ByteForce Web App: https://byteforce-frontend.vercel.app

GitHub Repository: https://github.com/akshat9597/url-sentinel

🧩 SIH Problem Statement

Problem Statement ID: 25229

Problem Statement: Identification of URL Based Attacks from IP Data

Theme: Cyber Security

Category: Software

Team: ByteForce

💡 What is ByteForce?

ByteForce is an explainable cyber-threat detection platform designed to analyze authorized URL and HTTP telemetry and identify suspicious or malicious activity.

It combines:

Rule-based attack detection

Behavioral correlation

Optional machine-learning classification

URL normalization and decoding

Evidence-aware outcome classification

PCAP analysis through Zeek

Investigation dashboards and filtered exports

ByteForce is observation-only. It does not automatically browse submitted URLs, exploit websites, execute payloads, block traffic, or prove server compromise from a URL alone.

🛡️ Attacks Detected

ByteForce supports indicators and behavioral detection for:

SQL Injection

Cross-Site Scripting (XSS)

Directory / Path Traversal

Command Injection

Typosquatting / URL Spoofing

Server-Side Request Forgery (SSRF)

Local / Remote File Inclusion (LFI/RFI)

HTTP Parameter Pollution

XXE indicators

Web-shell upload indicators

Brute-force / Credential-stuffing-like behavior

Scanner and reconnaissance patterns

✨ Key Features

Explainable Detection — readable evidence for matched rules

Hybrid Detection — rules + optional ML + behavior correlation

URL Normalization — percent decoding, HTML decoding, Unicode normalization and safe parsing

Attack Subtype Identification

Severity & Confidence Scoring

Outcome Classification: BENIGN, ATTEMPT, PROBABLE_SUCCESS, CONFIRMED_SUCCESS

Threat Explorer with attack, IP, host, severity and confidence filters

IP Intelligence & Analytics

CSV / JSON Dataset Ingestion

Nginx / Apache / JSON Lines Log Analysis

PCAP / PCAPNG Analysis via Zeek

CSV / JSON Export

Analyst Feedback, Model Versioning & Drift Monitoring

🧠 Detection Pipeline

flowchart TD
    A[Authorized URL / HTTP Telemetry] --> B[Validation & Secret Redaction]
    B --> C[URL Normalization]
    C --> D[Rule Engine]
    C --> E[Optional ML Model]
    A --> F[Behavior Correlation]
    D --> G[Weighted Threat Score]
    E --> G
    F --> G
    G --> H[Severity & Confidence]
    H --> I[Outcome Classification]
    I --> J[Evidence Store & Dashboard]

🧰 Technology Stack

Frontend

React

Vite

Tailwind CSS

Recharts

Lucide React

Axios

Backend

Python

FastAPI

Uvicorn

Pydantic

SQLAlchemy

Alembic

Detection & ML

urllib.parse

re

html

unicodedata

ipaddress

Pandas

Scikit-learn

Character-level TF-IDF

Logistic Regression

Data & Network

SQLite — local/demo mode

PostgreSQL — deployment mode

Zeek — optional PCAP/PCAPNG extraction

📥 Supported Inputs

Manual URL strings

CSV datasets

JSON datasets

Nginx access logs

Apache access logs

JSON Lines application/proxy logs

.pcap

.pcapng

Telemetry should only come from systems you own or are authorized to monitor.

🔍 Analyzed Fields

Source IP

Destination IP

Timestamp

HTTP Method

Host / Domain

URL / URI Path

Query Parameters

HTTP Status Code

Response Size

User-Agent

Optional request / response evidence

🤖 Machine Learning

The optional ML engine uses:

Character-level TF-IDF

Logistic Regression

Multiclass URL labels

Versioned model artifacts

Accuracy, Precision, Recall and F1

Per-class metrics and confusion matrix

Model activation / rollback

Drift monitoring

The bundled synthetic model is intended for pipeline demonstration, not as evidence of production-level detection accuracy.

📡 PCAP Processing

flowchart LR
    A[Upload PCAP / PCAPNG] --> B[Validate File]
    B --> C[Zeek]
    C --> D[Extract HTTP Records]
    D --> E[Normalize URLs]
    E --> F[Run Detection Pipeline]
    F --> G[Dashboard Results]

HTTPS Limitation

Encrypted HTTPS traffic normally hides full paths, query strings and request bodies from passive PCAP inspection.

For stronger evidence, use authorized reverse-proxy logs, application logs, WAF logs, controlled TLS decryption, or response telemetry.

⚙️ Quick Local Setup

1. Clone

git clone https://github.com/akshat9597/url-sentinel.git
cd url-sentinel

2. Backend

cd backend

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python scripts/generate_demo_data.py
python scripts/train_model.py --version local-demo-baseline

python -m uvicorn main:app --reload

Backend: http://localhost:8000
Swagger API: http://localhost:8000/docs

3. Frontend

cd frontend
npm install
npm run dev

Frontend: http://localhost:5173

🧪 Hackathon Demo Workflow

Open the Dashboard.

Analyze a benign URL.

Analyze a safe artificial malicious-looking URL string.

Show normalization, matched evidence, severity and confidence.

Filter Threat Explorer by attack type.

Show IP Intelligence and Analytics.

Upload demo access-log telemetry.

Show model health / analyst feedback.

Export filtered detections.

Open PCAP Analyzer and explain Zeek + HTTPS visibility limitations.

🌐 Main API Endpoints

Method

Endpoint

Purpose

GET

/api/health

Engine, DB, ML and Zeek health

POST

/api/detect/url

Analyze one URL event

GET

/api/attacks

Filter and paginate detections

GET

/api/attacks/{id}

Detection evidence details

GET

/api/ip/{ip}

IP telemetry intelligence

GET

/api/analytics/*

Analytics and distributions

POST

/api/dataset/upload

CSV / JSON ingestion

POST

/api/pcap/upload

PCAP processing through Zeek

GET

/api/export/csv

Export filtered detections

GET

/api/export/json

Export filtered detections

POST

/api/operations/logs/upload

Access-log ingestion

🔐 Security Principles

Secret query values are redacted before persistence.

Production deployments can use signed HttpOnly authentication cookies.

CORS and trusted hosts are configurable.

Upload types and sizes are restricted.

Administrative actions can be audited.

Production deployments should use TLS and strong secrets.

Public websites must not be tested without explicit authorization.

⚠️ Important Accuracy Boundary

A malicious-looking URL indicates suspicious input or an attack attempt. It does not automatically prove successful exploitation.

HTTP 200 OK alone is not proof of compromise.

Stored XSS needs application context.

Successful command execution requires trustworthy response/server evidence.

Successful SSRF requires supporting telemetry.

Web-shell execution requires post-upload evidence.

🗺️ Future Roadmap

Browser extension for navigation URL risk checks

Improved per-application ML models

More realistic time-based model evaluation

SIEM / WAF integrations

Durable queue-based ingestion

Fine-grained RBAC / SSO

OpenTelemetry / Prometheus monitoring

Improved alerting and analyst workflows

The browser extension is planned future work and is not part of the current release.

👥 Team ByteForce

Built for Smart India Hackathon 2026 under the Cyber Security theme.

Problem Statement ID: 25229
Problem Statement: Identification of URL Based Attacks from IP Data

🔗 Links

Live Demo: https://byteforce-frontend.vercel.app

GitHub: https://github.com/akshat9597/url-sentinel

OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/

Zeek: https://docs.zeek.org/

FastAPI: https://fastapi.tiangolo.com/

Scikit-learn: https://scikit-learn.org/

📌 Disclaimer

This project is intended for defensive cybersecurity research, education, authorized monitoring and controlled security testing. Only analyze systems, logs, datasets and network traffic that you own or are explicitly authorized to inspect.
