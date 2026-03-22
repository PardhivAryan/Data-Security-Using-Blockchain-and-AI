import base64
import enum
import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, List

from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, func, inspect as sa_inspect

from app.core.config import settings
from app.core.webauthn_core import (
    start_registration_options,
    finish_registration,
    start_authentication_options,
    finish_authentication,
    b64e,
    b64d,
)
from app.core.security import hash_password, verify_password
from app.models import (
    User, Role, WebAuthnCredential, WebAuthnChallenge,
    AuditEvent, LedgerBlock, MedicalRecord, MedicalRecordStatus,
    AccessRequest, AccessRequestStatus, RecordPermission,
    RiskAlert, RiskSeverity
)
from app.ml.inference import predict_risk

# Optional models (some project versions may not have these yet)
try:
    from app.models import VideoSession  # type: ignore
except Exception:
    VideoSession = None  # type: ignore


# -----------------------------
# Helpers
# -----------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def ensure_dirs() -> None:
    os.makedirs(settings.storage_dir, exist_ok=True)
    os.makedirs(settings.encrypted_dir, exist_ok=True)
    os.makedirs(settings.quarantined_dir, exist_ok=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fernet() -> Fernet:
    try:
        key = settings.fernet_key.encode()
        return Fernet(key)
    except Exception:
        raise RuntimeError("Invalid fernet_key. Generate one and set it in .env")


def encrypt_bytes(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    return _fernet().decrypt(token)


def _id_str(x: Any) -> Optional[str]:
    if x is None:
        return None
    return str(x)


def admin_user_exists(db: Session, exclude_user_id: Any | None = None) -> bool:
    stmt = select(User.id).where(User.role == Role.ADMIN)
    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)
    return db.execute(stmt.limit(1)).first() is not None


def ensure_single_admin_role(db: Session, role: Optional[Role], exclude_user_id: Any | None = None) -> None:
    # Business rule: only one admin account may exist in the system.
    if role == Role.ADMIN and admin_user_exists(db, exclude_user_id=exclude_user_id):
        raise HTTPException(status_code=400, detail="Admin account already exists. Only one admin is allowed.")


def _jsonable(obj: Any) -> Any:
    """Convert non-JSON types to JSON-safe values."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    if isinstance(obj, uuid.UUID):
        return str(obj)

    if isinstance(obj, datetime):
        return obj.isoformat()

    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("utf-8")

    if isinstance(obj, enum.Enum):
        return obj.value

    if isinstance(obj, dict):
        return {str(_jsonable(k)): _jsonable(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(x) for x in obj]

    return str(obj)


def _model_kwargs(model: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Filter kwargs so we only pass real mapped columns."""
    cols = {attr.key for attr in sa_inspect(model).mapper.column_attrs}
    return {k: v for k, v in payload.items() if k in cols}


# -----------------------------
# Audit + Blockchain
# -----------------------------

def log_event(
    db: Session,
    user_id: Any,
    event_type: str,
    severity: str = "INFO",
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    meta: Optional[dict] = None,
) -> AuditEvent:
    meta_safe = _jsonable(meta or {})
    if not isinstance(meta_safe, dict):
        meta_safe = {"meta": meta_safe}

    ev = AuditEvent(
        user_id=_id_str(user_id),
        event_type=event_type,
        severity=severity,
        ip=ip,
        user_agent=user_agent,
        meta=meta_safe,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


def create_block(db: Session, data: dict) -> LedgerBlock:
    """
    Fix: ledger_blocks.data must be JSON-safe.
    Prevents: TypeError: Object of type UUID is not JSON serializable
    """
    last = db.execute(select(LedgerBlock).order_by(desc(LedgerBlock.id)).limit(1)).scalar_one_or_none()
    prev_hash = last.curr_hash if last else "0" * 64

    data_safe = _jsonable(data)
    if not isinstance(data_safe, dict):
        data_safe = {"data": data_safe}

    # IMPORTANT: default=str guarantees no UUID crash
    payload = json.dumps(
        {"prev": prev_hash, "data": data_safe},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    curr_hash = sha256_hex(payload)

    blk = LedgerBlock(prev_hash=prev_hash, curr_hash=curr_hash, data=data_safe)
    db.add(blk)
    db.commit()
    db.refresh(blk)
    return blk


def create_risk_alert(
    db: Session,
    user_id: Any,
    score: float,
    reason: str,
    related_event_id: Optional[int] = None,
) -> RiskAlert:
    if score >= 80:
        sev = RiskSeverity.HIGH
    elif score >= 40:
        sev = RiskSeverity.MEDIUM
    else:
        sev = RiskSeverity.LOW

    ra = RiskAlert(
        user_id=_id_str(user_id),
        severity=sev,
        score=int(score),
        reason=reason,
        related_event_id=related_event_id,
    )
    db.add(ra)
    db.commit()
    db.refresh(ra)
    return ra


def compute_user_features(db: Session, user_id: Optional[str]) -> dict:
    now = now_utc()
    f_10m = now - timedelta(minutes=10)
    f_1h = now - timedelta(hours=1)
    f_24h = now - timedelta(hours=24)

    def count(event_type: str, since: datetime) -> int:
        q = select(func.count(AuditEvent.id)).where(AuditEvent.event_type == event_type, AuditEvent.created_at >= since)
        if user_id:
            q = q.where(AuditEvent.user_id == user_id)
        return int(db.execute(q).scalar_one())

    return {
        "failed_auth_10m": count("AUTH_WEBAUTHN_FAILED", f_10m),
        "password_failed_10m": count("PASSWORD_FAILED", f_10m),
        "denied_access_1h": count("ACCESS_DENIED", f_1h),
        "tamper_24h": count("FILE_TAMPER_DETECTED", f_24h),
        "new_device_24h": count("NEW_DEVICE_DETECTED", f_24h),
    }


def log_password_fail(db: Session, user_id: Any, ip: Optional[str], ua: Optional[str], email: str) -> None:
    ev = log_event(db, user_id, "PASSWORD_FAILED", "HIGH", ip, ua, {"email": email})
    feats = compute_user_features(db, _id_str(user_id))
    rr = predict_risk(feats)
    create_risk_alert(db, user_id, max(rr.score, 80.0), "Password failed", ev.id)


# -----------------------------
# WebAuthn Registration / Login
# -----------------------------

def get_or_create_user(db: Session, email: str, full_name: str, role: Role) -> User:
    u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    ensure_single_admin_role(db, role, exclude_user_id=u.id if u else None)
    if u:
        return u

    handle_bytes = uuid.uuid4().bytes
    u = User(
        email=email,
        full_name=full_name,
        role=role,
        is_active=True,
        password_hash=None,
        webauthn_user_handle_b64=b64e(handle_bytes),
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def start_register(db: Session, email: str, full_name: str, role: Role) -> dict:
    u = get_or_create_user(db, email, full_name, role)

    existing = db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == u.id)).scalars().all()
    exclude = [b64d(c.credential_id_b64) for c in existing]

    options_json, challenge_bytes = start_registration_options(
        user_id_bytes=b64d(u.webauthn_user_handle_b64),
        user_name=u.email,
        exclude_cred_ids=exclude,
    )

    ch = WebAuthnChallenge(
        user_id=u.id,
        purpose="REG",
        challenge_b64=b64e(challenge_bytes),
        expires_at=now_utc() + timedelta(minutes=5),
    )
    db.add(ch)
    db.commit()

    return json.loads(options_json)


def finish_register(
    db: Session,
    email: str,
    password: str,
    full_name: Optional[str],
    role: Optional[Role],
    credential: dict,
    ip: Optional[str],
    ua: Optional[str],
) -> None:
    u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    ensure_single_admin_role(db, role, exclude_user_id=u.id)

    if not u.password_hash:
        u.password_hash = hash_password(password)
        if full_name:
            u.full_name = full_name
        if role:
            u.role = role
        db.commit()

    ch = db.execute(
        select(WebAuthnChallenge)
        .where(WebAuthnChallenge.user_id == u.id, WebAuthnChallenge.purpose == "REG")
        .order_by(desc(WebAuthnChallenge.id))
        .limit(1)
    ).scalar_one_or_none()

    if not ch or ch.expires_at < now_utc():
        raise HTTPException(status_code=400, detail="Registration challenge expired")

    try:
        verified = finish_registration(credential=credential, expected_challenge_b64=ch.challenge_b64)
    except Exception as e:
        ev = log_event(db, u.id, "AUTH_WEBAUTHN_FAILED", "HIGH", ip, ua, {"stage": "REG", "error": str(e)})
        feats = compute_user_features(db, _id_str(u.id))
        rr = predict_risk(feats)
        create_risk_alert(db, u.id, max(rr.score, 80.0), "Fingerprint registration failed", ev.id)
        raise HTTPException(status_code=400, detail="Fingerprint registration failed")

    cred = WebAuthnCredential(
        user_id=u.id,
        credential_id_b64=b64e(verified.credential_id),
        public_key_b64=b64e(verified.credential_public_key),
        sign_count=0,
        transports=credential.get("response", {}).get("transports"),
    )
    db.add(cred)
    db.commit()

    log_event(db, u.id, "AUTH_WEBAUTHN_REGISTERED", "INFO", ip, ua, {})
    create_block(db, {"event": "AUTH_WEBAUTHN_REGISTERED", "user_id": _id_str(u.id)})


def start_login(db: Session, email: str, password: str, ip: Optional[str] = None, ua: Optional[str] = None) -> dict:
    u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not u:
        log_password_fail(db, None, ip, ua, email)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not u.password_hash or not verify_password(password, u.password_hash):
        log_password_fail(db, u.id, ip, ua, email)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    creds = db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == u.id)).scalars().all()
    if not creds:
        raise HTTPException(status_code=400, detail="No fingerprint/passkey registered for this user")

    allow = [b64d(c.credential_id_b64) for c in creds]
    options_json, challenge_bytes = start_authentication_options(allow_cred_ids=allow)

    ch = WebAuthnChallenge(
        user_id=u.id,
        purpose="AUTH",
        challenge_b64=b64e(challenge_bytes),
        expires_at=now_utc() + timedelta(minutes=5),
    )
    db.add(ch)
    db.commit()
    return json.loads(options_json)


def finish_login(db: Session, email: str, password: str, credential: dict, ip: Optional[str], ua: Optional[str]) -> User:
    u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not u or not u.password_hash or not verify_password(password, u.password_hash):
        log_password_fail(db, u.id if u else None, ip, ua, email)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    ch = db.execute(
        select(WebAuthnChallenge)
        .where(WebAuthnChallenge.user_id == u.id, WebAuthnChallenge.purpose == "AUTH")
        .order_by(desc(WebAuthnChallenge.id))
        .limit(1)
    ).scalar_one_or_none()

    if not ch or ch.expires_at < now_utc():
        raise HTTPException(status_code=400, detail="Login challenge expired")

    cred_id = credential.get("id")
    if not cred_id:
        raise HTTPException(status_code=400, detail="Missing credential id")

    stored = db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == u.id,
            WebAuthnCredential.credential_id_b64 == cred_id
        )
    ).scalar_one_or_none()

    if not stored:
        ev = log_event(db, u.id, "AUTH_WEBAUTHN_FAILED", "HIGH", ip, ua, {"stage": "AUTH", "reason": "Unknown credential"})
        create_risk_alert(db, u.id, 85.0, "Unknown credential used", ev.id)
        raise HTTPException(status_code=401, detail="Fingerprint verification failed")

    try:
        verified = finish_authentication(
            credential=credential,
            expected_challenge_b64=ch.challenge_b64,
            credential_public_key_b64=stored.public_key_b64,
            credential_current_sign_count=stored.sign_count,
        )
    except Exception as e:
        ev = log_event(db, u.id, "AUTH_WEBAUTHN_FAILED", "HIGH", ip, ua, {"stage": "AUTH", "error": str(e)})
        feats = compute_user_features(db, _id_str(u.id))
        rr = predict_risk(feats)
        create_risk_alert(db, u.id, max(rr.score, 80.0), "Fingerprint verification failed", ev.id)
        raise HTTPException(status_code=401, detail="Fingerprint verification failed")

    stored.sign_count = int(getattr(verified, "new_sign_count", stored.sign_count + 1))
    u.last_login_at = now_utc()
    db.commit()

    log_event(db, u.id, "AUTH_WEBAUTHN_SUCCESS", "INFO", ip, ua, {})
    create_block(db, {"event": "AUTH_WEBAUTHN_SUCCESS", "user_id": _id_str(u.id)})
    return u


def record_webauthn_fail(db: Session, email: Optional[str], stage: str, reason: str, ip: Optional[str], ua: Optional[str]) -> None:
    user_id = None
    if email:
        u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        user_id = u.id if u else None

    ev = log_event(db, user_id, "AUTH_WEBAUTHN_FAILED", "HIGH", ip, ua, {"stage": stage, "reason": reason})
    feats = compute_user_features(db, _id_str(user_id))
    rr = predict_risk(feats)
    create_risk_alert(db, user_id, max(rr.score, 80.0), "WebAuthn failed", ev.id)


# -----------------------------
# Medical Records (encrypt + hash + quarantine)
# -----------------------------

def create_record(
    db: Session,
    patient_id: Any,
    uploaded_by_id: Any,
    filename: str,
    plaintext: bytes,
    ip: Optional[str],
    ua: Optional[str],
) -> MedicalRecord:
    ensure_dirs()

    patient_id_s = _id_str(patient_id)
    uploaded_by_s = _id_str(uploaded_by_id)

    h = sha256_hex(plaintext)
    enc = encrypt_bytes(plaintext)

    rec_id = str(uuid.uuid4())
    path = os.path.join(settings.encrypted_dir, f"{rec_id}.bin")
    with open(path, "wb") as f:
        f.write(enc)

    payload = {
        "id": rec_id,
        "patient_id": patient_id_s,
        "uploaded_by_user_id": uploaded_by_s,
        "filename": filename,
        "stored_path": path,
        "sha256": h,
        "status": MedicalRecordStatus.ACTIVE,
    }
    rec = MedicalRecord(**_model_kwargs(MedicalRecord, payload))
    db.add(rec)
    db.commit()
    db.refresh(rec)

    create_block(db, {
        "event": "RECORD_UPLOADED",
        "record_id": _id_str(getattr(rec, "id", rec_id)),
        "sha256": h,
        "patient_id": patient_id_s,
        "filename": filename,
    })
    return rec


def _quarantine_record(
    db: Session,
    rec: MedicalRecord,
    actor_user_id: Any,
    ip: Optional[str],
    ua: Optional[str],
    reason: str,
) -> None:
    ensure_dirs()

    if getattr(rec, "status", None) != MedicalRecordStatus.QUARANTINED:
        current_path = getattr(rec, "stored_path", None)
        if current_path:
            dest = os.path.join(settings.quarantined_dir, os.path.basename(current_path))
            try:
                shutil.move(current_path, dest)
                current_path = dest
            except Exception:
                pass

            if hasattr(rec, "stored_path"):
                rec.stored_path = current_path

        if hasattr(rec, "status"):
            rec.status = MedicalRecordStatus.QUARANTINED
        if hasattr(rec, "updated_at"):
            rec.updated_at = now_utc()

        db.commit()

    ev = log_event(
        db,
        actor_user_id,
        "FILE_TAMPER_DETECTED",
        "HIGH",
        ip,
        ua,
        {"record_id": _id_str(getattr(rec, "id", None)), "filename": getattr(rec, "filename", ""), "reason": reason},
    )
    create_block(db, {
        "event": "FILE_TAMPER_DETECTED",
        "record_id": _id_str(getattr(rec, "id", None)),
        "filename": getattr(rec, "filename", ""),
        "reason": reason
    })

    feats = compute_user_features(db, _id_str(actor_user_id))
    rr = predict_risk(feats)
    create_risk_alert(db, actor_user_id, max(rr.score, 90.0), "Tamper detected, record quarantined", ev.id)


def read_record_verified(
    db: Session,
    rec: MedicalRecord,
    actor_user_id: Any,
    ip: Optional[str],
    ua: Optional[str],
) -> bytes:
    if getattr(rec, "status", None) == MedicalRecordStatus.QUARANTINED:
        log_event(db, actor_user_id, "ACCESS_DENIED", "HIGH", ip, ua, {"record_id": _id_str(getattr(rec, "id", None)), "reason": "QUARANTINED"})
        raise HTTPException(status_code=423, detail="Record is quarantined/blocked")

    current_path = getattr(rec, "stored_path", None)
    if not current_path:
        _quarantine_record(db, rec, actor_user_id, ip, ua, "Missing stored_path")
        raise HTTPException(status_code=423, detail="Record is quarantined/blocked")

    try:
        with open(current_path, "rb") as f:
            enc = f.read()
        pt = decrypt_bytes(enc)
    except Exception as e:
        _quarantine_record(db, rec, actor_user_id, ip, ua, f"Decrypt/read error: {e}")
        raise HTTPException(status_code=423, detail="Record is quarantined/blocked")

    expected_hash = getattr(rec, "sha256", None)
    if expected_hash and sha256_hex(pt) != expected_hash:
        _quarantine_record(db, rec, actor_user_id, ip, ua, "Hash mismatch")
        raise HTTPException(status_code=423, detail="Record is quarantined/blocked")

    return pt


# -----------------------------
# Access Requests
# -----------------------------

def doctor_has_permission(db: Session, patient_id: Any, doctor_id: Any) -> bool:
    perm = db.execute(
        select(RecordPermission).where(
            RecordPermission.patient_id == _id_str(patient_id),
            RecordPermission.doctor_id == _id_str(doctor_id)
        )
    ).scalar_one_or_none()
    return perm is not None


def request_access(db: Session, patient_id: Any, doctor_id: Any) -> AccessRequest:
    req = AccessRequest(
        patient_id=_id_str(patient_id),
        doctor_id=_id_str(doctor_id),
        status=AccessRequestStatus.PENDING
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    create_block(db, {"event": "ACCESS_REQUESTED", "patient_id": _id_str(patient_id), "doctor_id": _id_str(doctor_id), "request_id": req.id})
    return req


def decide_access(db: Session, request_id: int, approve: bool, actor_patient_id: Any) -> AccessRequest:
    req = db.execute(select(AccessRequest).where(AccessRequest.id == request_id)).scalar_one_or_none()
    if not req or _id_str(req.patient_id) != _id_str(actor_patient_id):
        raise HTTPException(status_code=404, detail="Access request not found")

    req.status = AccessRequestStatus.APPROVED if approve else AccessRequestStatus.REJECTED
    req.decided_at = now_utc()
    db.commit()

    if approve:
        perm = db.execute(
            select(RecordPermission).where(
                RecordPermission.patient_id == _id_str(req.patient_id),
                RecordPermission.doctor_id == _id_str(req.doctor_id)
            )
        ).scalar_one_or_none()
        if not perm:
            db.add(RecordPermission(patient_id=_id_str(req.patient_id), doctor_id=_id_str(req.doctor_id)))
            db.commit()

    create_block(db, {"event": "ACCESS_DECIDED", "request_id": req.id, "approve": approve})
    return req


# -----------------------------
# UI helpers
# -----------------------------

def ui_role_from_api(role: Role) -> str:
    if role == Role.ADMIN:
        return "Admin"
    if role == Role.DOCTOR:
        return "Doctor"
    if role == Role.LAB:
        return "Lab Assistant"
    return "Patient"


def api_role_from_ui(ui_role: str) -> Role:
    r = (ui_role or "").strip().lower()
    if r == "admin":
        return Role.ADMIN
    if r == "doctor":
        return Role.DOCTOR
    if r in ("lab assistant", "labassistant", "lab"):
        return Role.LAB
    return Role.PATIENT


# -----------------------------
# Blockchain verification + file integrity registry
# -----------------------------

def verify_ledger(db: Session) -> Tuple[bool, int, str, Optional[dict]]:
    blocks = db.execute(select(LedgerBlock).order_by(LedgerBlock.id.asc())).scalars().all()
    prev = "0" * 64
    for b in blocks:
        payload = json.dumps(
            {"prev": prev, "data": b.data},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        expected = sha256_hex(payload)
        if b.prev_hash != prev or b.curr_hash != expected:
            last_hash = blocks[-1].curr_hash if blocks else "0" * 64
            last_block = blocks[-1].data if blocks else None
            return False, len(blocks), last_hash, last_block
        prev = b.curr_hash

    last_hash = blocks[-1].curr_hash if blocks else "0" * 64
    last_block = blocks[-1].data if blocks else None
    return True, len(blocks), last_hash, last_block


def file_hash_registry(db: Session) -> List[dict]:
    recs = db.execute(select(MedicalRecord).order_by(desc(MedicalRecord.created_at))).scalars().all()
    out: List[dict] = []
    for r in recs:
        status = "Valid"
        current_hash = None

        if getattr(r, "status", None) == MedicalRecordStatus.QUARANTINED:
            status = "Quarantined"

        current_path = getattr(r, "stored_path", None)
        expected_hash = getattr(r, "sha256", None)

        try:
            if current_path:
                with open(current_path, "rb") as f:
                    enc = f.read()
                pt = decrypt_bytes(enc)
                current_hash = sha256_hex(pt)
                if expected_hash and current_hash != expected_hash:
                    status = "Tampered"
            else:
                status = "Tampered"
        except Exception:
            status = "Tampered"

        out.append({
            "filename": getattr(r, "filename", ""),
            "stored_hash": expected_hash,
            "current_hash": current_hash,
            "status": status,
        })
    return out


# -----------------------------
# Video call session helper
# -----------------------------

def create_video_session(db: Session, patient_id: Any, doctor_id: Any) -> str:
    if VideoSession is None:
        raise HTTPException(status_code=500, detail="VideoSession model not available in this build")

    room_id = uuid.uuid4().hex

    p = db.execute(select(User).where(User.id == _id_str(patient_id))).scalar_one_or_none()
    if not p or p.role != Role.PATIENT:
        raise HTTPException(status_code=400, detail="Invalid patient_id")

    vs = VideoSession(room_id=room_id, patient_id=_id_str(patient_id), doctor_id=_id_str(doctor_id))
    db.add(vs)
    db.commit()
    db.refresh(vs)

    create_block(db, {"event": "VIDEO_SESSION_CREATED", "room_id": room_id, "patient_id": _id_str(patient_id), "doctor_id": _id_str(doctor_id)})
    return room_id
