"""Validate and normalize labeled traffic captured from an authorized local lab.

This utility never generates or replays attacks. It prepares analyst-reviewed
CSV exports from Zeek/access logs for model training and preserves provenance.
"""
import argparse
import csv
from pathlib import Path

REQUIRED = {"timestamp", "src_ip", "dst_ip", "uri", "label", "ground_truth_success"}


def prepare(source: Path, destination: Path, capture_name: str) -> int:
    with source.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("The capture export is empty.")
    missing = REQUIRED - set(rows[0])
    if missing:
        raise ValueError(f"Missing required reviewed-capture columns: {', '.join(sorted(missing))}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0])
    for field in ("capture_name", "provenance"):
        if field not in fields:
            fields.append(field)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            row["capture_name"] = capture_name
            row["provenance"] = "authorized-controlled-lab"
            writer.writerow(row)
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare reviewed authorized capture data for training.")
    parser.add_argument("source", type=Path, help="CSV exported from Zeek or an authorized access-log review")
    parser.add_argument("destination", type=Path, help="Normalized labeled CSV output")
    parser.add_argument("--capture-name", required=True, help="PCAP or lab run identifier")
    args = parser.parse_args()
    print(f"Prepared {prepare(args.source, args.destination, args.capture_name):,} reviewed records.")


if __name__ == "__main__":
    main()
