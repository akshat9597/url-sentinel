"""Version-aware optional ML inference; failures never stop rule detection."""
from pathlib import Path

from detection.model_registry import active_model

LEGACY_MODEL_PATH = Path(__file__).resolve().parents[1] / "data" / "url_model.joblib"
MODEL_PATH = LEGACY_MODEL_PATH
_model = None
_loaded_path = None
_loaded_mtime = None


def active_model_info() -> dict | None:
    entry = active_model()
    if entry and Path(entry["path"]).exists():
        return entry
    if LEGACY_MODEL_PATH.exists():
        return {"version": "legacy", "path": str(LEGACY_MODEL_PATH), "training_source": "prototype"}
    return None


def _load_model():
    global _model, _loaded_path, _loaded_mtime
    info = active_model_info()
    if not info:
        return None, None
    path = Path(info["path"]); mtime = path.stat().st_mtime
    if _model is not None and _loaded_path == path and _loaded_mtime == mtime:
        return _model, info
    try:
        import joblib
        _model = joblib.load(path); _loaded_path, _loaded_mtime = path, mtime
        return _model, info
    except Exception:
        return None, None


def predict(url: str) -> dict:
    model, info = _load_model()
    if model is None:
        return {"ml_score": None, "predicted_class": None, "model_version": None}
    try:
        probabilities = model.predict_proba([url])[0]
        classes = list(model.classes_)
        # This is a multiclass model. Adding every non-benign probability can
        # make ordinary URLs look dangerous simply because probability mass is
        # spread across many attack classes. Use the strongest malicious class
        # as the cautious ML signal instead.
        malicious_probabilities = [probability for label, probability in zip(classes, probabilities) if label != "BENIGN"]
        score = 100 * max(malicious_probabilities, default=0)
        return {"ml_score": round(float(score), 1), "predicted_class": classes[int(probabilities.argmax())], "model_version": info["version"]}
    except Exception:
        return {"ml_score": None, "predicted_class": None, "model_version": None}
