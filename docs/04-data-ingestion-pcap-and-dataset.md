# ByteForce Data, PCAP, and Controlled-Lab Workflow

## Data sources

ByteForce accepts:

- Manual URL analysis.
- CSV and JSON datasets.
- Nginx and Apache combined access logs.
- JSON Lines application or proxy logs.
- Optional `.pcap` and `.pcapng` files processed by Zeek.
- Analyst-reviewed labels for future model training.

All data must come from systems the operator owns or is authorized to monitor.

## Demo dataset

`backend/scripts/generate_demo_data.py` creates a deterministic 10,000-record dataset at `backend/data/demo_traffic.csv` without making a network connection. It includes benign traffic, all required attack labels, brute-force clusters, XXE indicators, web-upload indicators, and explicit ground-truth outcome examples.

The dataset demonstrates ingestion and UI behavior. It is not captured attack traffic and cannot establish real-world precision or recall.

Regenerate it with:

```bash
cd backend
python scripts/generate_demo_data.py
```

## Authorized controlled-lab captures

Use an isolated vulnerable application lab owned by the project team. Capture traffic using Zeek or another approved tool, review and label the records, then prepare them for training:

```bash
cd backend
python scripts/prepare_captured_dataset.py \
  input.csv \
  data/captured/reviewed.csv \
  --capture-name lab-run-001
```

The utility requires `timestamp`, `src_ip`, `dst_ip`, `uri`, `label`, and `ground_truth_success`. It adds `capture_name` and `provenance=authorized-controlled-lab`.

Do not include passwords, cookies, session tokens, private data, or captures from third-party systems. Keep raw captures under strict retention and access controls.

## Access-log ingestion

Operations accepts `.log`, `.txt`, `.json`, and `.jsonl` files. Supported formats are auto, Nginx combined, Apache combined, and JSON Lines.

Example combined record:

```text
192.0.2.21 - - [28/Aug/2026:22:00:01 +0530] "GET /products?page=2 HTTP/1.1" 200 4821 "-" "Mozilla/5.0"
```

Example JSON Lines record:

```json
{"time_iso8601":"2026-08-28T22:00:01+05:30","remote_addr":"192.0.2.21","request_method":"GET","host":"shop.example.test","request_uri":"/products?page=2","status":200,"body_bytes_sent":4821}
```

Optional evidence fields supported by JSON telemetry include `request_body`, `response_body`, `follow_up_evidence`, `content_type`, and `file_name`.

## PCAP processing

The PCAP pipeline validates the extension and size, writes the upload to a temporary directory, invokes Zeek with an argument array, parses `http.log`, and feeds extracted events into the common detector. Temporary capture files are removed after processing.

Install Zeek on macOS when needed:

```bash
brew install zeek
zeek --version
```

PCAP limitations:

- Encrypted HTTPS normally hides URL paths, query strings, and request bodies.
- Captures without recognizable HTTP may produce zero extracted events.
- Zeek is an optional external dependency.
- Application/proxy logs may provide better evidence for outcomes.

## Dataset upload contract

Required dataset fields are `src_ip`, `dst_ip`, and `uri`. Optional fields include timestamps, ports, method, host, status code, response size, user agent, request count, labels, ground truth, request/response bodies, content type, and filename.

CSV and JSON uploads are size-limited and primitive numeric fields are normalized before analysis. Secret values are redacted before persistence.
