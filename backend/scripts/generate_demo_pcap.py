#!/usr/bin/env python3
"""Create a deterministic, safe PCAP for the ByteForce demonstration.

The script writes Ethernet/IPv4/TCP packets directly with Python's standard
library. It never opens a socket and therefore never contacts a website.
All network endpoints use RFC 5737 documentation address ranges, while HTTP
hostnames use reserved .test/.example names.
"""

from __future__ import annotations

import argparse
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data" / "byteforce_demo.pcap"


@dataclass(frozen=True)
class DemoFlow:
    label: str
    src_ip: str
    dst_ip: str
    host: str
    uri: str
    status: int
    response_body: str
    method: str = "GET"


# The values resemble security telemetry but are inert strings carried inside
# a local file. Nothing in this script sends or executes them.
DEMO_FLOWS = [
    DemoFlow("BENIGN_HOME", "192.0.2.10", "198.51.100.20", "portal.example.test", "/", 200, "ByteForce demo home"),
    DemoFlow("BENIGN_SEARCH", "192.0.2.11", "198.51.100.20", "portal.example.test", "/search?q=cybersecurity", 200, "Safe search result"),
    DemoFlow("SQL_INJECTION", "192.0.2.21", "198.51.100.20", "portal.example.test", "/item?id=1%27%20OR%20%271%27=%271", 403, "Blocked synthetic request"),
    DemoFlow("XSS", "192.0.2.22", "198.51.100.20", "portal.example.test", "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", 403, "Blocked synthetic request"),
    DemoFlow("DIRECTORY_TRAVERSAL", "192.0.2.23", "203.0.113.80", "files.example.test", "/download%2F..%2F..%2Fdemo.txt", 403, "Blocked synthetic request"),
    DemoFlow("COMMAND_INJECTION", "192.0.2.24", "198.51.100.20", "portal.example.test", "/tools?name=demo%3Becho%20test-marker", 403, "Blocked synthetic request"),
    DemoFlow("SSRF", "192.0.2.25", "198.51.100.20", "gateway.example.test", "/preview?url=http%3A%2F%2F127.0.0.1%2Fadmin", 403, "Blocked loopback reference"),
    DemoFlow("LFI", "192.0.2.26", "203.0.113.80", "files.example.test", "/view?page=..%2F..%2Fetc%2Fpasswd", 403, "Blocked synthetic request"),
    DemoFlow("RFI", "192.0.2.27", "203.0.113.80", "files.example.test", "/view?page=https%3A%2F%2Fassets.example%2Fdemo.txt", 403, "Blocked synthetic request"),
    DemoFlow("HTTP_PARAMETER_POLLUTION", "192.0.2.28", "198.51.100.20", "portal.example.test", "/account?role=user&role=admin", 400, "Conflicting parameters"),
    DemoFlow("TYPOSQUATTING", "192.0.2.29", "198.51.100.20", "xn--byteforce-demo.example", "/login", 404, "Synthetic reserved hostname"),
    DemoFlow("SCANNER_ACTIVITY", "192.0.2.30", "198.51.100.20", "portal.example.test", "/wp-admin/", 404, "Not found"),
    DemoFlow("WEB_SHELL_REFERENCE", "192.0.2.31", "203.0.113.80", "files.example.test", "/shell-demo.php?source=pcap", 404, "Not found"),
    DemoFlow("XXE_INDICATOR", "192.0.2.32", "198.51.100.20", "api.example.test", "/xml?doc=%3C%21DOCTYPE%20demo%20%5B%3C%21ENTITY%20marker%20SYSTEM%20%22file%3A%2F%2F%2Fdemo%22%3E%5D%3E", 403, "Blocked synthetic request"),
    DemoFlow("OPEN_REDIRECT", "192.0.2.33", "198.51.100.20", "portal.example.test", "/leave?next=https%3A%2F%2Fsafe.example%2Fwelcome", 302, "Redirect reviewed"),
]


def checksum(data: bytes) -> int:
    """Return the Internet checksum used by IPv4 and TCP headers."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    packet_id: int,
) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    tcp_header = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo_header = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_header) + len(payload))
    tcp_sum = checksum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack("!HHLLBBH", src_port, dst_port, seq, ack, 5 << 4, flags, 64240) + struct.pack("!HH", tcp_sum, 0)

    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, packet_id, 0x4000, 64, socket.IPPROTO_TCP, 0, src, dst)
    ip_sum = checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, packet_id, 0x4000, 64, socket.IPPROTO_TCP, ip_sum, src, dst)

    client_mac = bytes.fromhex("020000000001")
    server_mac = bytes.fromhex("020000000002")
    client_to_server = src_ip.startswith("192.0.2.")
    ethernet = (
        server_mac + client_mac if client_to_server else client_mac + server_mac
    ) + struct.pack("!H", 0x0800)
    return ethernet + ip_header + tcp_header + payload


def http_request(flow: DemoFlow) -> bytes:
    return (
        f"{flow.method} {flow.uri} HTTP/1.1\r\n"
        f"Host: {flow.host}\r\n"
        "User-Agent: ByteForce-Safe-PCAP/1.0\r\n"
        "Accept: text/html,application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def http_response(flow: DemoFlow) -> bytes:
    reasons = {200: "OK", 302: "Found", 400: "Bad Request", 403: "Forbidden", 404: "Not Found"}
    body = flow.response_body.encode("utf-8")
    return (
        f"HTTP/1.1 {flow.status} {reasons.get(flow.status, 'Response')}\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body


def build_packets() -> list[tuple[float, bytes]]:
    packets: list[tuple[float, bytes]] = []
    base_time = datetime(2025, 1, 15, 10, 0, tzinfo=timezone.utc).timestamp()
    packet_id = 1

    for index, flow in enumerate(DEMO_FLOWS):
        src_port = 41000 + index
        client_seq = 100_000 + index * 10_000
        server_seq = 700_000 + index * 10_000
        request = http_request(flow)
        response = http_response(flow)
        timestamp = base_time + index * 0.75

        def add(offset: float, src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> None:
            nonlocal packet_id
            packets.append((timestamp + offset, ipv4_tcp_packet(src, dst, sport, dport, seq, ack, flags, payload, packet_id)))
            packet_id += 1

        # Complete handshake and request/response exchange make the capture easy
        # for Zeek and Wireshark to reconstruct during a live demonstration.
        add(0.00, flow.src_ip, flow.dst_ip, src_port, 80, client_seq, 0, 0x02)  # SYN
        add(0.01, flow.dst_ip, flow.src_ip, 80, src_port, server_seq, client_seq + 1, 0x12)  # SYN/ACK
        add(0.02, flow.src_ip, flow.dst_ip, src_port, 80, client_seq + 1, server_seq + 1, 0x10)  # ACK
        add(0.03, flow.src_ip, flow.dst_ip, src_port, 80, client_seq + 1, server_seq + 1, 0x18, request)
        add(0.04, flow.dst_ip, flow.src_ip, 80, src_port, server_seq + 1, client_seq + 1 + len(request), 0x10)
        add(0.05, flow.dst_ip, flow.src_ip, 80, src_port, server_seq + 1, client_seq + 1 + len(request), 0x18, response)
        add(0.06, flow.src_ip, flow.dst_ip, src_port, 80, client_seq + 1 + len(request), server_seq + 1 + len(response), 0x11)
        add(0.07, flow.dst_ip, flow.src_ip, 80, src_port, server_seq + 1 + len(response), client_seq + 2 + len(request), 0x11)
        add(0.08, flow.src_ip, flow.dst_ip, src_port, 80, client_seq + 2 + len(request), server_seq + 2 + len(response), 0x10)

    return packets


def write_pcap(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        # Classic little-endian PCAP, Ethernet link type, 65,535-byte snapshot.
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, packet in build_packets():
            seconds = int(timestamp)
            microseconds = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
            handle.write(packet)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Destination .pcap path")
    args = parser.parse_args()
    if args.output.suffix.lower() != ".pcap":
        parser.error("The output filename must end in .pcap")
    write_pcap(args.output)
    print(f"Created {args.output} with {len(DEMO_FLOWS)} synthetic HTTP conversations and {len(build_packets())} packets.")


if __name__ == "__main__":
    main()
