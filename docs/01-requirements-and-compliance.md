# ByteForce Requirements and Compliance Review

## Purpose

This document maps the supplied problem statement to the current ByteForce implementation. It distinguishes implemented behavior, partial support, evidence requirements, and future work.

## Executive assessment

ByteForce satisfies the core MVP shape: it accepts URL/HTTP telemetry, identifies suspicious requests, assigns attack categories, correlates behavior, provides attempt/probable/confirmed outcome labels, supports dashboard investigation, imports logs and datasets, exports CSV/JSON, and can process raw PCAP through Zeek.

It is an observation-only defensive analysis platform. It does not visit URLs, exploit targets, block traffic, or prove server compromise from a URL alone.

## Requirement matrix

| Requirement | Current status | Implementation and qualification |
|---|---|---|
| URL/HTTP attack detection | Available | Rule, behavior, and optional ML engines analyze supplied telemetry. |
| Typosquatting / URL spoofing | Available | Protected-domain similarity, punycode review, and legitimate-subdomain exclusion. |
| SQL injection | Available | Generic, union, error/boolean, and time-based indicators are supported. Subtype metadata is returned when recognized. |
| XSS | Available | Script, JavaScript URL, event-handler, image, SVG, and iframe indicators are supported. Reflected/stored and DOM/event-handler metadata is approximate and requires application context for proof. |
| Directory traversal | Available | Encoded and common path traversal indicators are normalized and inspected. |
| Command injection | Available | Shell separators, command substitution, and common command indicators are detected. |
| SSRF | Available | URL parameters targeting private, loopback, link-local, reserved, or internal destinations are detected. |
| LFI/RFI | Available | Local file and remote include indicators are supported. Overlapping traversal payloads are classified using include-parameter context. |
| Credential stuffing / brute force | Available with telemetry batch | Repeated authentication requests and high failure ratios are correlated by source IP. Varying credential values should be supplied by real telemetry. |
| HTTP parameter pollution | Available | Duplicate conflicting parameter values are detected. |
| XXE | Available as an indicator | XML request bodies containing external entity declarations are analyzed when request body and content type are supplied. It does not execute XML or prove entity resolution. |
| Web-shell uploads | Available as an upload indicator | Multipart telemetry with executable server-side filenames is detected. File-content scanning and post-upload execution correlation remain future improvements. |
| Attempt vs. successful attack | Partial but evidence-aware | `ATTEMPT`, `PROBABLE_SUCCESS`, and `CONFIRMED_SUCCESS` are supported. Confirmed status requires explicit ground truth, response markers, or follow-up evidence. HTTP 200 alone is never proof. |
| Self-generated dataset | Available for demo | A deterministic 10,000-record synthetic dataset is generated locally. It is not a substitute for real controlled-lab captures. |
| Real captured ground truth | Workflow available | Reviewed authorized capture preparation is documented in `backend/data/captured/README.md` and implemented by `backend/scripts/prepare_captured_dataset.py`. Actual captures must be supplied by the operator. |
| Dashboard and charts | Available | Dashboard, analytics, threat explorer, details, and source-IP investigation are included. |
| Filtering | Available | Attack type, source/destination IP or CIDR, host, severity, outcome status, time, and confidence are supported. |
| CSV/JSON export | Available | Export endpoints accept the same filters as Threat Explorer and export the filtered result set. |
| Raw PCAP ingestion | Available with Zeek | `.pcap` and `.pcapng` files are passed to Zeek, HTTP records are parsed, and the same detector is used. Zeek must be installed. |
| HTTPS visibility | Limited by design | Encrypted PCAP normally cannot expose complete paths, query strings, or bodies. Use authorized proxy/application logs or controlled TLS decryption. |
| Browser extension | Future update | Planned as a separate Manifest V3 client of `/api/detect/url`; it is not shipped in this release. |

## Evaluation risks

1. Synthetic data can demonstrate the pipeline but cannot establish real-world detection accuracy.
2. URL indicators alone cannot establish successful exploitation.
3. Attack subtypes such as stored XSS, blind SQL injection, and successful web-shell execution require application or response context.
4. The optional ML model is trained on synthetic or reviewed data and must be evaluated on representative held-out traffic.
5. PCAP extraction depends on Zeek and visibility of unencrypted HTTP.

## Recommended evidence for a final evaluation

- A controlled vulnerable application lab owned by the project team.
- Labeled request, response, application-log, and outcome records.
- Per-class precision, recall, F1, confusion matrix, and false-positive review.
- A demonstration of filtered exports matching the visible Threat Explorer result count.
- A PCAP processed through Zeek with extracted HTTP records shown in the UI.
- A clear statement that the browser extension is planned, not currently delivered.
