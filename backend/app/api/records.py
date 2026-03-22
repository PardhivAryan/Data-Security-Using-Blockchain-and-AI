from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.session import get_db
from app.api.deps import get_current_user
from app.models import User, Role, MedicalRecord, AccessRequest, AccessRequestStatus
from app.core.rbac import require_roles
from app.schemas import UploadRecordOut, AccessRequestIn, DecideAccessIn
from app.services import (
    create_record, read_record_verified,
    request_access, decide_access,
    doctor_has_permission, log_event
)

router = APIRouter(prefix="/records", tags=["records"])


@router.post("/upload", response_model=UploadRecordOut)
async def upload_record(
    patient_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_roles(user, {Role.PATIENT, Role.DOCTOR, Role.LAB})

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")

    rec = create_record(db, patient_id=patient_id, uploaded_by_id=user.id, filename=file.filename, plaintext=data, ip=None, ua=None)
    return {"record_id": rec.id, "status": rec.status.value}


@router.get("/{record_id}/download")
def download_record(
    record_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rec = db.execute(select(MedicalRecord).where(MedicalRecord.id == record_id)).scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Record not found")

    if user.role == Role.PATIENT and user.id != rec.patient_id:
        log_event(db, user.id, "ACCESS_DENIED", "HIGH", None, None, {"record_id": record_id})
        raise HTTPException(status_code=403, detail="Forbidden")

    if user.role == Role.DOCTOR and not doctor_has_permission(db, rec.patient_id, user.id):
        log_event(db, user.id, "ACCESS_DENIED", "HIGH", None, None, {"record_id": record_id})
        raise HTTPException(status_code=403, detail="No permission from patient")

    data = read_record_verified(db, rec, user.id, None, None)
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{rec.filename}"'},
    )


@router.post("/access/request")
def doctor_request_access(
    payload: AccessRequestIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_roles(user, {Role.DOCTOR})
    req = request_access(db, patient_id=payload.patient_id, doctor_id=user.id)
    return {"request_id": req.id, "status": req.status.value}


@router.get("/access/pending")
def patient_pending_requests(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_roles(user, {Role.PATIENT})
    reqs = db.execute(
        select(AccessRequest).where(AccessRequest.patient_id == user.id, AccessRequest.status == AccessRequestStatus.PENDING)
    ).scalars().all()
    return [{"id": r.id, "doctor_id": r.doctor_id, "status": r.status.value} for r in reqs]


@router.post("/access/decide")
def patient_decide_access(
    payload: DecideAccessIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_roles(user, {Role.PATIENT})
    r = decide_access(db, payload.request_id, payload.approve, actor_patient_id=user.id)
    return {"request_id": r.id, "status": r.status.value}