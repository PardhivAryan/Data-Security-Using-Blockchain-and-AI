from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.rbac import require_roles
from app.models import User, Role, RiskAlert, AuditEvent

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/risk-alerts")
def list_risk_alerts(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_roles(user, {Role.ADMIN})
    alerts = db.execute(select(RiskAlert).order_by(desc(RiskAlert.id)).limit(200)).scalars().all()
    return [
        {"id": a.id, "user_id": a.user_id, "severity": a.severity.value, "score": a.score, "reason": a.reason, "created_at": a.created_at, "related_event_id": a.related_event_id}
        for a in alerts
    ]


@router.get("/audit")
def list_audit(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_roles(user, {Role.ADMIN})
    events = db.execute(select(AuditEvent).order_by(desc(AuditEvent.id)).limit(200)).scalars().all()
    return [
        {"id": e.id, "user_id": e.user_id, "event_type": e.event_type, "severity": e.severity, "meta": e.meta, "created_at": e.created_at}
        for e in events
    ]