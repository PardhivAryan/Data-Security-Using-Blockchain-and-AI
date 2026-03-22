import os
import pickle
from dataclasses import dataclass
from app.core.config import settings


@dataclass
class RiskResult:
    score: float
    severity: str
    reason: str


def _severity(score: float) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def predict_risk(features: dict) -> RiskResult:
    model_path = settings.risk_model_path
    if os.path.exists(model_path):
        with open(model_path, "rb") as f:
            pack = pickle.load(f)
        model = pack["model"]
        cols = pack["columns"]
        x = [[float(features.get(c, 0.0)) for c in cols]]
        prob = float(model.predict_proba(x)[0][1])
        score = prob * 100.0
        return RiskResult(score=score, severity=_severity(score), reason="ML risk score")

    score = 0.0
    score += min(60.0, float(features.get("failed_auth_10m", 0)) * 15.0)
    score += min(60.0, float(features.get("password_failed_10m", 0)) * 15.0)
    score += min(40.0, float(features.get("tamper_24h", 0)) * 40.0)
    score += min(30.0, float(features.get("denied_access_1h", 0)) * 10.0)
    score = min(100.0, score)
    reason = "Heuristic risk score (train ML later)"
    return RiskResult(score=score, severity=_severity(score), reason=reason)