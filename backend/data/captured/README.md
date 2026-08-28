# Authorized captured datasets

Place reviewed HTTP records captured from an isolated vulnerable-application lab in this directory. Do not commit credentials, session tokens, or captures from systems you do not own or administer.

Recommended flow:

1. Capture traffic with Zeek from the controlled lab PCAP.
2. Export HTTP records and add analyst-reviewed `label` and `ground_truth_success` columns.
3. Run `python scripts/prepare_captured_dataset.py input.csv data/captured/reviewed.csv --capture-name lab-run-001`.
4. Upload the resulting CSV through Dataset Upload or train with `python scripts/train_model.py --dataset data/captured/reviewed.csv`.

Required columns are `timestamp`, `src_ip`, `dst_ip`, `uri`, `label`, and `ground_truth_success`. The utility adds `capture_name` and `provenance=authorized-controlled-lab` so evaluation data is distinguishable from `demo_traffic.csv`.
