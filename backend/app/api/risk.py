from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.rbac import require_roles
from app.models import User, Role
from app.services import compute_user_features
from app.ml.inference import predict_risk

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/me")
def my_risk(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    feats = compute_user_features(db, user.id)
    rr = predict_risk(feats)
    return {"features": feats, "score": rr.score, "severity": rr.severity, "reason": rr.reason}


@router.get("/user/{user_id}")
def user_risk(user_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_roles(user, {Role.ADMIN})
    feats = compute_user_features(db, user_id)
    rr = predict_risk(feats)
    return {"features": feats, "score": rr.score, "severity": rr.severity, "reason": rr.reason}