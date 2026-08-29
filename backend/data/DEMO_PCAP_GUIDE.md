# ByteForce demo PCAP test map

`byteforce_demo.pcap` is a deterministic, local-only capture. It contains 15
synthetic HTTP conversations and does not contact any external system. All IP
addresses come from RFC 5737 documentation ranges.

| Source IP | Expected category |
|---|---|
| `192.0.2.10` | Benign home request |
| `192.0.2.11` | Benign search request |
| `192.0.2.21` | SQL injection indicator |
| `192.0.2.22` | Cross-site scripting indicator |
| `192.0.2.23` | Directory traversal indicator |
| `192.0.2.24` | Command injection indicator |
| `192.0.2.25` | SSRF indicator referencing loopback |
| `192.0.2.26` | Local file inclusion indicator |
| `192.0.2.27` | Remote file inclusion indicator |
| `192.0.2.28` | HTTP parameter pollution |
| `192.0.2.29` | Punycode/typosquatting review indicator |
| `192.0.2.30` | Scanner-path indicator |
| `192.0.2.31` | Web-shell filename reference |
| `192.0.2.32` | XML external-entity indicator |
| `192.0.2.33` | Open-redirect indicator |

Destination IPs are `198.51.100.20` and `203.0.113.80`. These are also
documentation-only addresses.

Regenerate the file from `backend/` with:

```bash
python scripts/generate_demo_pcap.py
```

Upload `data/byteforce_demo.pcap` on the ByteForce **PCAP Analyzer** page. Zeek
must be installed for packet extraction; otherwise ByteForce will offer its
bundled demo-results fallback.
