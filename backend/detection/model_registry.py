"""Small filesystem model registry with explicit activation and rollback."""
import json
from datetime import datetime, timezone
from pathlib import Path

MODELS_DIR = Path(__file__).resolve().parents[1] / "data" / "models"
REGISTRY_PATH = MODELS_DIR / "registry.json"


def read_registry() -> dict:
    if not REGISTRY_PATH.exists():
        return {"active": None, "models": []}
    try:
        return json.loads(REGISTRY_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {"active": None, "models": []}


def write_registry(registry: dict) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    temporary = REGISTRY_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(registry, indent=2))
    temporary.replace(REGISTRY_PATH)


def _resolved_entry(entry: dict | None) -> dict | None:
    if not entry:
        return None
    resolved = dict(entry)
    value = Path(str(entry.get("path", "")))
    if value.is_absolute() and not value.exists():
        value = MODELS_DIR / value.name
    resolved["path"] = str(value if value.is_absolute() else MODELS_DIR / value)
    return resolved


def register_model(version: str, path: Path, metrics: dict, training_source: str, baseline: dict, activate: bool = True) -> dict:
    registry = read_registry()
    entry = {"version": version, "path": path.name, "metrics": metrics, "training_source": training_source, "baseline": baseline, "created_at": datetime.now(timezone.utc).isoformat()}
    registry["models"] = [item for item in registry["models"] if item["version"] != version] + [entry]
    if activate:
        registry["active"] = version
    write_registry(registry)
    return _resolved_entry(entry)


def activate_model(version: str) -> dict | None:
    registry = read_registry()
    entry = next((item for item in registry["models"] if item["version"] == version), None)
    resolved = _resolved_entry(entry)
    if not resolved or not Path(resolved["path"]).exists():
        return None
    registry["active"] = version
    write_registry(registry)
    return resolved


def active_model() -> dict | None:
    registry = read_registry()
    return _resolved_entry(next((item for item in registry["models"] if item["version"] == registry.get("active")), None))
