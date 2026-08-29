# ByteForce Presentation: Capability, Reality Alignment, and Roadmap

## Positioning statement

> ByteForce is an observation-only network threat analysis platform. It accepts URL and HTTP telemetry, access logs, datasets, and optional PCAP files through Zeek; detects specialized web attack indicators offline using explainable rules, behavior analysis, and an optional ML model; supports IP/CIDR investigation and filtered exports; and separates attack attempts from probable or confirmed outcomes when authorized response evidence is available.

ByteForce is not a URL reputation script, active scanner, crawler, exploit tool, WAF, or automatic blocking system.

## Capability and reality alignment

| Aspect | What ByteForce does not claim | Actual current capability |
|---|---|---|
| PCAP ingestion | Native C/C++ packet reassembly or raw socket sniffing | Delegates `.pcap`/`.pcapng` processing to Zeek through `backend/pcap/processor.py`, parses structured HTTP records, and feeds them into the common detector. |
| Exploit verification | 100% automated proof of systemic compromise | Performs outcome triage using explicit ground truth, response-body markers, response status/size context, and supplied follow-up evidence. |
| Payload evasion | Complete decoding of every Base64, hex, Unicode, or nested evasion technique | Performs safe normalization and limited repeated percent decoding, HTML decoding, and Unicode normalization. Advanced multi-layer decoding remains roadmap work. |
| Attack scope | Generic phishing-only URL matching | Provides targeted indicators for SQL injection, XSS, traversal, command injection, SSRF, LFI/RFI, HPP, XXE indicators, web-shell upload indicators, typosquatting, scanning, and brute-force behavior. |
| Dataset and ML | Production-trained AI on live exploited networks | Provides a local optional character TF-IDF plus Logistic Regression baseline evaluated on generated synthetic data; reviewed authorized captures can be prepared for training. |
| External dependencies | Self-contained native parsing and zero dependencies | Detection rules and ML run locally; Zeek is an optional dependency for raw PCAP extraction, and PostgreSQL is optional for deployment. |
| Browser monitoring | A browser extension is already available | Browser extension support is a future update. The planned extension will use the existing API and will not collect secrets or page contents. |

## Current implementation

- **Ingestion:** PCAP/PCAPNG through Zeek, access logs, JSON Lines, CSV, JSON, and manual URL input.
- **Detection engine:** Offline explainable rules, semantic checks, behavior heuristics, and optional local ML.
- **Outcome triage:** `ATTEMPT`, `PROBABLE_SUCCESS`, and `CONFIRMED_SUCCESS` based on available evidence.
- **Vector coverage:** SSRF, XXE indicators, HPP, LFI/RFI, web-shell upload indicators, SQL injection, XSS, traversal, command injection, typosquatting, scanner activity, and brute-force behavior.
- **Investigation:** Dashboard, analytics, threat details, source-IP analysis, attack-type filters, IP/CIDR filters, host filters, severity, outcome, confidence, and filtered CSV/JSON exports.
- **Data governance:** Secret redaction, upload limits, authentication option, audit records, retention controls, model registry, rollback, and drift reporting.

## Acknowledged constraints and roadmap

| Current constraint | Planned enhancement |
|---|---|
| PCAP extraction uses Zeek | Native stream parser or deeper protocol integration where justified by performance and coverage requirements |
| Safe normalization handles common encoding and obfuscation | Multi-layer Base64, hex, Unicode, compression, and context-aware canonicalization |
| Web-shell detection is currently indicator and upload-metadata based | File-content scanning, quarantine integration, and post-upload execution correlation |
| URL-only analysis cannot prove server-side impact | Stronger correlation with application, WAF, database, identity, and endpoint telemetry |
| Passive PCAP cannot normally expose encrypted HTTPS contents | Integration with authorized TLS-terminating proxies, decrypted logs, or endpoint telemetry |
| Synthetic demo data is not real-world accuracy evidence | Reviewed, representative controlled-lab captures and time-separated evaluation |
| Browser extension is not shipped | Manifest V3 client with privacy controls, badge status, caching, allow-list, and optional warning policy |

## Questions evaluators may ask

### Why use Zeek instead of writing a native C or Python PCAP parser?

> Writing a custom packet parser in a hackathon setting introduces avoidable risks around TCP stream reassembly, protocol edge cases, memory use, and dropped packets. ByteForce delegates packet and protocol extraction to Zeek and focuses project engineering on L7 normalization, detection, explainability, and outcome correlation. This is an explicit engineering trade-off, not a claim of native packet parsing.

### How do you distinguish an attempt from a confirmed exploit without executing payloads?

> ByteForce is strictly observation-only. It never executes the supplied payload. It labels suspicious input as an attempt when there is no corroborating evidence, uses probable success for suggestive response context such as an unusually large successful response, and uses confirmed success only when explicit reviewed ground truth, recognized response-body evidence, or supplied follow-up evidence supports it. HTTP 200 alone is never treated as proof.

### How do you handle encrypted HTTPS traffic in PCAPs?

> Passive inspection cannot normally reveal encrypted paths, query strings, or bodies. ByteForce therefore supports clear HTTP extracted by Zeek and recommends authorized reverse-proxy, application, WAF, or decrypted TLS telemetry when full request and response context is required. TLS visibility through a controlled proxy is a roadmap integration, not a claim that arbitrary HTTPS can be decrypted.

### Is the ML model the only detector?

> No. The platform is designed with graceful degradation. Explainable rules and behavior analysis continue to work when no model is trained. The ML score is one contribution to the combined score, and its model version and evaluation metrics are retained for review.

### Is the demo dataset real attack traffic?

> No. The bundled 10,000-record dataset is deterministic synthetic telemetry intended to demonstrate the pipeline and interface. Real accuracy claims require analyst-reviewed traffic captured from an authorized, isolated controlled lab or an owned production environment.

## Slide-ready summary

```text
================================================================================
BYTEFORCE: OBSERVATION-ONLY NETWORK THREAT ANALYSIS PLATFORM
================================================================================

[ CURRENT IMPLEMENTATION ]
- Ingestion: PCAP / PCAPNG through Zeek + access logs + telemetry datasets
- Detection: Offline explainable rules + behavior heuristics + baseline local ML
- Outcome triage: Attempted vs. Probable vs. Confirmed with available evidence
- Vector coverage: SSRF, XXE, HPP, LFI/RFI, web-shell indicators, brute force,
  SQL injection, XSS, traversal, command injection, typosquatting, and scanning
- Investigation: IP/CIDR filters, evidence details, CSV and JSON exports

-------------------------------------------------------------------------------

[ ACKNOWLEDGED CONSTRAINTS AND ROADMAP ]
- Packet parsing: Zeek pipeline          -> deeper/native stream integration
- Evasion handling: limited normalization -> multi-layer Base64/hex/Unicode
- Upload detection: metadata indicators  -> content and execution correlation
- Encryption: clear HTTP and logs         -> authorized TLS proxy integration
- Dataset: synthetic baseline              -> reviewed controlled-lab captures
- Browser monitoring: not shipped          -> privacy-preserving Manifest V3 client
================================================================================
```

## Claims to avoid

Do not state that ByteForce currently:

- Natively reassembles raw TCP streams without Zeek.
- Decrypts arbitrary HTTPS PCAPs.
- Automatically proves a vulnerability or systemic compromise from a URL.
- Fully unwraps Base64, hex, Unicode, or every nested encoding.
- Detects complete web-shell execution from a filename alone.
- Uses a production-trained ML model.
- Includes a working browser extension.

These limitations strengthen the technical credibility of the presentation because they clearly separate delivered engineering from planned work.
