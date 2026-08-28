#!/bin/sh
set -eu
if [ "${BYTEFORCE_BOOTSTRAP_MODEL:-false}" = "true" ] && [ ! -f data/models/registry.json ]; then
  python scripts/train_model.py --version demo-baseline
fi
alembic upgrade head
exec uvicorn main:app --host 0.0.0.0 --port 8000
