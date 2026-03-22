import os
import json
import mimetypes
from urllib.parse import quote
from datetime import datetime, timezone
from typing import Optional, Any

from fastapi import FastAPI, Request, Depends, Form, UploadFile, File, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from sqlalchemy.orm import Session
from sqlalchemy import select, desc, cast, String

from app.core.config import settings
from app.api.router import router as api_router
from app.db.session import get_db
from app.core.security import decode_access_token

from app.models import (
    User, Role,
    Appointment, AppointmentStatus,
    MedicalRecord,
    LabRequest, LabRequestStatus,
    Prescription,
    RiskAlert, AuditEvent,
)

from app.services import (
    admin_user_exists,
    ensure_dirs,
    ui_role_from_api,
    verify_ledger,
    file_hash_registry,
    create_record,
    read_record_verified,
)


# ---------- Paths ----------

def project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def templates_dir() -> str:
    root = project_root()
    lower = os.path.join(root, "templates")
    upper = os.path.join(root, "Templates")
    if os.path.isdir(lower):
        return lower
    if os.path.isdir(upper):
        return upper
    return lower


def static_dir() -> str:
    return os.path.join(project_root(), "static")


templates = Jinja2Templates(directory=templates_dir())


# ---------- Small helpers ----------

def render(req: Request, name: str, ctx: dict | None = None):
    data = {"request": req, "session": req.session}
    if ctx:
        data.update(ctx)
    return templates.TemplateResponse(name, data)


def must_role(req: Request, role: str) -> bool:
    return req.session.get("role") == role


def _attr(obj: Any, *names: str, default=None):
    for n in names:
        if hasattr(obj, n):
            v = getattr(obj, n)
            if v is not None:
                return v
    return default


def _user_display(u: Optional[User]) -> str:
    if not u:
        return "Unknown"
    return u.full_name or u.email or str(u.id)


def _safe_filename(filename: str) -> str:
    """
    Make filename safe for headers and downloads.
    Keeps the original visible name as much as possible,
    but strips path fragments that can break browsers/headers.
    """
    if not filename:
        return "record.bin"

    # Handle Windows and Unix style paths safely
    filename = filename.replace("\\", "/")
    filename = filename.split("/")[-1].strip()

    if not filename:
        return "record.bin"

    return filename


def _guess_media_type(filename: str) -> str:
    guessed, _ = mimetypes.guess_type(filename or "")
    return guessed or "application/octet-stream"


def _build_download_headers(filename: str) -> dict[str, str]:
    """
    Robust Content-Disposition header.
    This fixes image download failures caused by unsafe/non-ascii filenames.
    """
    safe_name = _safe_filename(filename)

    # ASCII fallback for old header handling
    ascii_name = safe_name.encode("ascii", "ignore").decode("ascii").strip()
    if not ascii_name:
        _, ext = os.path.splitext(safe_name)
        ascii_name = f"download{ext or '.bin'}"

    ascii_name = ascii_name.replace('"', "").replace("\n", "").replace("\r", "")

    # RFC 5987 UTF-8 filename support
    utf8_name = quote(safe_name)

    return {
        "Content-Disposition": f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{utf8_name}'
    }


def _approved_patient_ids_for_doctor(db: Session, doctor_id: str) -> list[str]:
    appts = db.execute(
        select(Appointment)
        .where(cast(Appointment.doctor_id, String) == doctor_id)
        .where(Appointment.status == AppointmentStatus.APPROVED)
    ).scalars().all()
    return sorted({str(a.patient_id) for a in appts})


def _prescription_preview(p: Prescription) -> str:
    medicine = (_attr(p, "medicine", default="") or "").strip()
    dosage = (_attr(p, "dosage", default="") or "").strip()
    notes = (_attr(p, "notes", default="") or "").strip()

    preview = medicine
    if dosage:
        preview = f"{preview} - {dosage}" if preview else dosage
    if not preview:
        preview = notes or "Prescription"
    return preview


def _prescription_file_bytes(p: Prescription, patient_name: str, doctor_name: str) -> bytes:
    lines = [
        "MEDICAL PRESCRIPTION",
        "",
        f"Patient: {patient_name}",
        f"Doctor: {doctor_name}",
        f"Date: {p.created_at.strftime('%Y-%m-%d %H:%M') if getattr(p, 'created_at', None) else ''}",
        "",
        f"Medicine: {_attr(p, 'medicine', default='')}",
        f"Dosage: {_attr(p, 'dosage', default='')}",
        f"Notes: {_attr(p, 'notes', default='') or ''}",
    ]
    return "\n".join(lines).encode("utf-8")


def _parse_prescription_form(
    medicine: Optional[str],
    dosage: Optional[str],
    notes: Optional[str],
    text: Optional[str],
) -> tuple[str, str, Optional[str]]:
    med = (medicine or "").strip()
    dose = (dosage or "").strip()
    note = (notes or "").strip() or None
    raw_text = (text or "").strip()

    if med and dose:
        if raw_text:
            note = f"{raw_text}\n\n{note}" if note else raw_text
        return med, dose, note

    if raw_text:
        first_line = raw_text.splitlines()[0].strip()
        med = med or first_line or "Prescription"
        dose = dose or "As directed"
        note = note or raw_text
        return med, dose, note

    raise HTTPException(status_code=400, detail="Prescription text is missing")


# ---------- Video Message Helpers ----------

def _ensure_video_message_state(app: FastAPI) -> None:
    if not hasattr(app.state, "video_patient_requests"):
        app.state.video_patient_requests = []
    if not hasattr(app.state, "video_room_notifications"):
        app.state.video_room_notifications = []


def _upsert_video_patient_request(
    app: FastAPI,
    *,
    doctor_email: str,
    patient_id: str,
    patient_name: str,
    patient_email: str,
) -> None:
    _ensure_video_message_state(app)
    now = datetime.now(timezone.utc)

    app.state.video_patient_requests = [
        item
        for item in app.state.video_patient_requests
        if not (item["doctor_email"] == doctor_email and item["patient_id"] == patient_id)
    ]

    app.state.video_patient_requests.append(
        {
            "doctor_email": doctor_email,
            "patient_id": patient_id,
            "patient_name": patient_name,
            "patient_email": patient_email,
            "sent_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "sent_at_ts": now.timestamp(),
        }
    )


def _get_video_patient_requests_for_doctor(app: FastAPI, doctor_email: str) -> list[dict[str, Any]]:
    _ensure_video_message_state(app)
    items = [
        item for item in app.state.video_patient_requests
        if item["doctor_email"] == doctor_email
    ]
    return sorted(items, key=lambda x: x["sent_at_ts"], reverse=True)


def _remove_video_patient_request(app: FastAPI, *, doctor_email: str, patient_id: str) -> None:
    _ensure_video_message_state(app)
    app.state.video_patient_requests = [
        item
        for item in app.state.video_patient_requests
        if not (item["doctor_email"] == doctor_email and item["patient_id"] == patient_id)
    ]


def _upsert_video_room_notification(
    app: FastAPI,
    *,
    patient_id: str,
    doctor_name: str,
    room_id: str,
) -> None:
    _ensure_video_message_state(app)
    now = datetime.now(timezone.utc)

    app.state.video_room_notifications = [
        item
        for item in app.state.video_room_notifications
        if not (item["patient_id"] == patient_id and item["doctor_name"] == doctor_name)
    ]

    app.state.video_room_notifications.append(
        {
            "patient_id": patient_id,
            "doctor_name": doctor_name,
            "room_id": room_id,
            "sent_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "sent_at_ts": now.timestamp(),
        }
    )


def _get_video_room_notifications_for_patient(app: FastAPI, patient_id: str) -> list[dict[str, Any]]:
    _ensure_video_message_state(app)
    items = [
        item for item in app.state.video_room_notifications
        if item["patient_id"] == patient_id
    ]
    return sorted(items, key=lambda x: x["sent_at_ts"], reverse=True)


# ---------- App ----------

def create_app() -> FastAPI:
    ensure_dirs()

    app = FastAPI(title=settings.app_name, debug=settings.debug)
    _ensure_video_message_state(app)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(SessionMiddleware, secret_key=settings.jwt_secret)

    # API under /api
    app.include_router(api_router, prefix=settings.api_prefix)

    # Static assets
    app.mount("/static", StaticFiles(directory=static_dir()), name="static")

    # ---------- Public pages ----------

    @app.get("/", response_class=HTMLResponse, name="home")
    def home(req: Request):
        if not req.session.get("user"):
            return RedirectResponse("/login", status_code=303)

        role = req.session.get("role", "Patient")
        if role == "Admin":
            return RedirectResponse("/admin", status_code=303)
        if role == "Doctor":
            return RedirectResponse("/doctor", status_code=303)
        if role == "Lab Assistant":
            return RedirectResponse("/labassistant", status_code=303)
        return RedirectResponse("/patient", status_code=303)

    @app.get("/login", response_class=HTMLResponse, name="login_page")
    def login_page(req: Request):
        return render(req, "login.html")

    @app.get("/register", response_class=HTMLResponse, name="register_page")
    def register_page(req: Request, db: Session = Depends(get_db)):
        return render(req, "register.html", {"admin_exists": admin_user_exists(db)})

    @app.get("/logout", name="logout")
    def logout(req: Request):
        req.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.post("/ui/session")
    async def set_ui_session(req: Request, db: Session = Depends(get_db)):
        payload = await req.json()
        token = payload.get("token")
        data = decode_access_token(token) if token else None
        if not data:
            return {"ok": False}

        user_id = data.get("sub")
        if not user_id:
            return {"ok": False}

        u = db.execute(select(User).where(cast(User.id, String) == str(user_id))).scalar_one_or_none()
        if not u:
            return {"ok": False}

        req.session["user"] = u.email
        req.session["user_id"] = str(u.id)
        req.session["role"] = ui_role_from_api(u.role)
        return {"ok": True}

    # ---------- Admin Dashboard ----------

    @app.get("/admin", response_class=HTMLResponse, name="admin")
    def admin(req: Request, db: Session = Depends(get_db)):
        if not must_role(req, "Admin"):
            return RedirectResponse("/login", status_code=303)

        users = db.execute(select(User).order_by(User.created_at.asc())).scalars().all()
        users_out = [{"name": u.full_name, "email": u.email, "role": ui_role_from_api(u.role)} for u in users]

        alerts = db.execute(select(RiskAlert).order_by(desc(RiskAlert.id)).limit(200)).scalars().all()
        anomalies = []
        for a in alerts:
            who = "Unknown"
            r = "Unknown"
            if a.user_id:
                u2 = db.execute(select(User).where(cast(User.id, String) == str(a.user_id))).scalar_one_or_none()
                if u2:
                    who = u2.email
                    r = ui_role_from_api(u2.role)

            action = "RISK_ALERT"
            if a.related_event_id:
                ev = db.execute(select(AuditEvent).where(AuditEvent.id == a.related_event_id)).scalar_one_or_none()
                if ev:
                    action = ev.event_type

            anomalies.append(
                {
                    "timestamp": a.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "user": who,
                    "role": r,
                    "action": action,
                    "risk": a.severity.value,
                }
            )

        return render(req, "admin_dashboard.html", {"users": users_out, "anomalies": anomalies})

    # ---------- Patient Dashboard ----------

    @app.get("/patient", response_class=HTMLResponse, name="patient")
    def patient(req: Request, db: Session = Depends(get_db)):
        if not must_role(req, "Patient"):
            return RedirectResponse("/login", status_code=303)

        my_id = str(req.session.get("user_id"))
        me = db.execute(select(User).where(cast(User.id, String) == my_id)).scalar_one_or_none()
        if not me:
            return RedirectResponse("/login", status_code=303)

        doctors = db.execute(select(User).where(User.role == Role.DOCTOR)).scalars().all()
        doctors_out = [{"name": d.full_name, "email": d.email} for d in doctors]

        appts = db.execute(
            select(Appointment)
            .where(cast(Appointment.patient_id, String) == my_id)
            .order_by(desc(Appointment.scheduled_for))
        ).scalars().all()

        appt_out = []
        for a in appts:
            d = db.execute(select(User).where(cast(User.id, String) == str(a.doctor_id))).scalar_one_or_none()
            appt_out.append({
                "id": a.id,
                "patient": _user_display(me),
                "patient_email": me.email,
                "doctor": _user_display(d),
                "doctor_email": (d.email if d else "Unknown"),
                "date": a.scheduled_for.date().isoformat(),
                "status": a.status.value.title() if hasattr(a.status, "value") else str(a.status),
            })

        recs = db.execute(
            select(MedicalRecord)
            .where(cast(MedicalRecord.patient_id, String) == my_id)
            .order_by(desc(MedicalRecord.created_at))
        ).scalars().all()

        records_out = []
        record_map: dict[str, dict[str, Any]] = {}
        for r in recs:
            item = {
                "id": str(r.id),
                "record_id": str(r.id),
                "name": _attr(r, "filename", "name", default="record"),
                "filename": _attr(r, "filename", "name", default="record"),
                "date": r.created_at.date().isoformat() if getattr(r, "created_at", None) else "",
                "hash": _attr(r, "sha256", "sha256_hex", "hash", default=""),
            }
            records_out.append(item)
            record_map[str(r.id)] = item

        lab_reqs = db.execute(
            select(LabRequest)
            .where(cast(LabRequest.patient_id, String) == my_id)
            .order_by(desc(LabRequest.created_at))
        ).scalars().all()

        lab_out = []
        scans_out = []
        for lr in lab_reqs:
            report_record_id = (_attr(lr, "report_file", "report_filename", default=None) or "").strip() or None
            report_record = record_map.get(report_record_id) if report_record_id else None

            lab_item = {
                "id": lr.id,
                "patient": _user_display(me),
                "patient_email": me.email,
                "test_type": _attr(lr, "test_type", "scan_type", default=""),
                "status": lr.status.value.title() if hasattr(lr.status, "value") else str(lr.status),
                "report_file": report_record_id,
                "report": bool(report_record_id),
                "report_id": report_record_id,
            }
            lab_out.append(lab_item)

            if report_record:
                scans_out.append({
                    "id": report_record["id"],
                    "filename": report_record["filename"],
                    "date": report_record["date"],
                    "hash": report_record["hash"],
                })

        pres = db.execute(
            select(Prescription)
            .where(cast(Prescription.patient_id, String) == my_id)
            .order_by(desc(Prescription.created_at))
        ).scalars().all()

        pres_out = []
        for p in pres:
            d = db.execute(select(User).where(cast(User.id, String) == str(p.doctor_id))).scalar_one_or_none()
            pres_out.append({
                "id": p.id,
                "patient": _user_display(me),
                "patient_email": me.email,
                "doctor": _user_display(d),
                "doctor_name": (d.full_name if d else "Doctor"),
                "medicine": _attr(p, "medicine", default=""),
                "dosage": _attr(p, "dosage", default=""),
                "notes": _attr(p, "notes", default=""),
                "preview": _prescription_preview(p),
                "date": p.created_at.strftime("%Y-%m-%d %H:%M") if getattr(p, "created_at", None) else "",
            })

        incoming_room_ids = _get_video_room_notifications_for_patient(req.app, str(me.id))

        return render(req, "patient_dashboard.html", {
            "patient_id": str(me.id),
            "patient_uuid": str(me.id),
            "user_id": str(me.id),
            "doctors": doctors_out,
            "appointments": appt_out,
            "records": records_out,
            "lab_requests": lab_out,
            "scans": scans_out,
            "prescriptions": pres_out,
            "incoming_room_ids": incoming_room_ids,
        })

    @app.post("/patient", include_in_schema=False)
    def book_appointment_compat(
        req: Request,
        doctor_email: str = Form(...),
        date: str = Form(...),
        db: Session = Depends(get_db),
    ):
        return book_appointment(req, doctor_email, date, db)

    @app.post("/patient/book", name="book_appointment")
    def book_appointment(
        req: Request,
        doctor_email: str = Form(...),
        date: str = Form(...),
        db: Session = Depends(get_db),
    ):
        if not must_role(req, "Patient"):
            return RedirectResponse("/login", status_code=303)

        patient_id = str(req.session.get("user_id"))

        doctor = db.execute(
            select(User).where(User.email == doctor_email, User.role == Role.DOCTOR)
        ).scalar_one_or_none()
        if not doctor:
            return RedirectResponse("/patient", status_code=303)

        scheduled_for = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)

        appt = Appointment(
            patient_id=patient_id,
            doctor_id=str(doctor.id),
            scheduled_for=scheduled_for,
            status=AppointmentStatus.PENDING,
        )
        db.add(appt)
        db.commit()
        return RedirectResponse("/patient", status_code=303)

    @app.post("/patient/upload", name="upload_record")
    async def upload_record(
        req: Request,
        file: UploadFile = File(...),
        db: Session = Depends(get_db),
    ):
        if not must_role(req, "Patient"):
            return RedirectResponse("/login", status_code=303)

        patient_id = str(req.session.get("user_id"))
        raw = await file.read()
        filename = _safe_filename(file.filename or "record.bin")

        create_record(
            db=db,
            patient_id=patient_id,
            uploaded_by_id=patient_id,
            filename=filename,
            plaintext=raw,
            ip=req.client.host if req.client else None,
            ua=req.headers.get("user-agent"),
        )
        return RedirectResponse("/patient", status_code=303)

    @app.post("/patient/video/send-id", name="send_patient_id_to_doctor")
    def send_patient_id_to_doctor(
        req: Request,
        doctor_email: str = Form(...),
        db: Session = Depends(get_db),
    ):
        if not must_role(req, "Patient"):
            return RedirectResponse("/login", status_code=303)

        patient_id = str(req.session.get("user_id"))
        me = db.execute(select(User).where(cast(User.id, String) == patient_id)).scalar_one_or_none()
        doctor = db.execute(
            select(User).where(User.email == doctor_email, User.role == Role.DOCTOR)
        ).scalar_one_or_none()

        if not me or not doctor:
            return RedirectResponse("/patient", status_code=303)

        _upsert_video_patient_request(
            req.app,
            doctor_email=doctor.email,
            patient_id=str(me.id),
            patient_name=_user_display(me),
            patient_email=me.email,
        )

        return RedirectResponse("/patient", status_code=303)

    # ---------- Doctor Dashboard ----------

    @app.get("/doctor", response_class=HTMLResponse, name="doctor")
    def doctor(req: Request, db: Session = Depends(get_db)):
        if not must_role(req, "Doctor"):
            return RedirectResponse("/login", status_code=303)

        doctor_id = str(req.session.get("user_id"))
        doctor_user = db.execute(select(User).where(cast(User.id, String) == doctor_id)).scalar_one_or_none()

        appts = db.execute(
            select(Appointment)
            .where(cast(Appointment.doctor_id, String) == doctor_id)
            .order_by(desc(Appointment.scheduled_for))
        ).scalars().all()

        approved_patient_ids: list[str] = []
        appt_out = []
        for a in appts:
            pid = str(a.patient_id)
            p = db.execute(select(User).where(cast(User.id, String) == pid)).scalar_one_or_none()
            if a.status == AppointmentStatus.APPROVED:
                approved_patient_ids.append(pid)

            patient_display = _user_display(p)
            appt_out.append({
                "id": a.id,
                "patient": patient_display,
                "patient_name": patient_display,
                "patient_email": (p.email if p else ""),
                "date": a.scheduled_for.date().isoformat(),
                "status": a.status.value.title() if hasattr(a.status, "value") else str(a.status),
                "approved": (a.status == AppointmentStatus.APPROVED),
            })

        medical_records_out = []
        if approved_patient_ids:
            recs = db.execute(
                select(MedicalRecord)
                .where(cast(MedicalRecord.patient_id, String).in_(approved_patient_ids))
                .order_by(desc(MedicalRecord.created_at))
            ).scalars().all()

            for r in recs:
                p = db.execute(select(User).where(cast(User.id, String) == str(r.patient_id))).scalar_one_or_none()
                patient_display = _user_display(p)
                medical_records_out.append({
                    "id": str(r.id),
                    "record_id": str(r.id),
                    "patient": patient_display,
                    "patient_name": patient_display,
                    "patient_email": (p.email if p else ""),
                    "record": _attr(r, "filename", "name", default="record"),
                    "filename": _attr(r, "filename", "name", default="record"),
                    "date": r.created_at.date().isoformat() if getattr(r, "created_at", None) else "",
                    "hash": _attr(r, "sha256", "sha256_hex", "hash", default=""),
                })

        patients_dropdown = []
        for pid in sorted(set(approved_patient_ids)):
            p = db.execute(select(User).where(cast(User.id, String) == pid)).scalar_one_or_none()
            if p:
                label = f"{(p.full_name or p.email)} ({p.email})"
                patients_dropdown.append({
                    "id": str(p.id),
                    "email": p.email,
                    "name": p.full_name or p.email,
                    "label": label,
                })

        lab_reqs = db.execute(
            select(LabRequest)
            .where(cast(LabRequest.doctor_id, String) == doctor_id)
            .order_by(desc(LabRequest.created_at))
        ).scalars().all()

        lab_out = []
        for lr in lab_reqs:
            p = db.execute(select(User).where(cast(User.id, String) == str(lr.patient_id))).scalar_one_or_none()
            report_record_id = (_attr(lr, "report_file", "report_filename", default=None) or "").strip() or None
            lab_out.append({
                "id": lr.id,
                "patient": _user_display(p),
                "patient_name": _user_display(p),
                "patient_email": (p.email if p else ""),
                "test_type": _attr(lr, "test_type", "scan_type", default=""),
                "status": lr.status.value.title() if hasattr(lr.status, "value") else str(lr.status),
                "report_file": report_record_id,
                "report": bool(report_record_id),
                "report_id": report_record_id,
            })

        pres = db.execute(
            select(Prescription)
            .where(cast(Prescription.doctor_id, String) == doctor_id)
            .order_by(desc(Prescription.created_at))
        ).scalars().all()

        pres_out = []
        for p in pres:
            pu = db.execute(select(User).where(cast(User.id, String) == str(p.patient_id))).scalar_one_or_none()
            pres_out.append({
                "id": p.id,
                "patient": _user_display(pu),
                "patient_name": _user_display(pu),
                "patient_email": (pu.email if pu else ""),
                "medicine": _attr(p, "medicine", default=""),
                "dosage": _attr(p, "dosage", default=""),
                "notes": _attr(p, "notes", default=""),
                "preview": _prescription_preview(p),
                "date": p.created_at.strftime("%Y-%m-%d %H:%M") if getattr(p, "created_at", None) else "",
            })

        video_patient_requests = _get_video_patient_requests_for_doctor(
            req.app,
            doctor_user.email if doctor_user else "",
        )

        return render(req, "doctor_dashboard.html", {
            "appointments": appt_out,
            "doctor_email": (doctor_user.email if doctor_user else ""),
            "medical_records": medical_records_out,
            "patients": patients_dropdown,
            "lab_requests": lab_out,
            "prescriptions": pres_out,
            "video_patient_requests": video_patient_requests,
        })

    @app.get("/doctor/appointments/{appointment_id}/approve", name="approve_appointment")
    def approve_appointment(req: Request, appointment_id: int, db: Session = Depends(get_db)):
        if not must_role(req, "Doctor"):
            return RedirectResponse("/login", status_code=303)

        doctor_id = str(req.session.get("user_id"))
        appt = db.execute(
            select(Appointment).where(Appointment.id == appointment_id, cast(Appointment.doctor_id, String) == doctor_id)
        ).scalar_one_or_none()

        if appt and appt.status == AppointmentStatus.PENDING:
            appt.status = AppointmentStatus.APPROVED
            db.commit()

        return RedirectResponse("/doctor", status_code=303)

    @app.post("/doctor/video/send-room", name="send_room_to_patient")
    def send_room_to_patient(
        req: Request,
        patient_id: str = Form(...),
        room_id: str = Form(...),
        db: Session = Depends(get_db),
    ):
        if not must_role(req, "Doctor"):
            return RedirectResponse("/login", status_code=303)

        doctor_id = str(req.session.get("user_id"))
        doctor_user = db.execute(select(User).where(cast(User.id, String) == doctor_id)).scalar_one_or_none()
        patient = db.execute(
            select(User).where(cast(User.id, String) == str(patient_id), User.role == Role.PATIENT)
        ).scalar_one_or_none()

        approved_patient_ids = _approved_patient_ids_for_doctor(db, doctor_id)
        clean_room_id = (room_id or "").strip()

        if not doctor_user or not patient or str(patient.id) not in approved_patient_ids or not clean_room_id:
            return RedirectResponse("/doctor", status_code=303)

        _upsert_video_room_notification(
            req.app,
            patient_id=str(patient.id),
            doctor_name=_user_display(doctor_user),
            room_id=clean_room_id,
        )

        _remove_video_patient_request(
            req.app,
            doctor_email=doctor_user.email,
            patient_id=str(patient.id),
        )

        return RedirectResponse("/doctor", status_code=303)

    @app.post("/doctor/labrequest", include_in_schema=False)
    def create_lab_request_alias(
        req: Request,
        patient_email: Optional[str] = Form(None),
        patient_id: Optional[str] = Form(None),
        test_type: str = Form(...),
        db: Session = Depends(get_db),
    ):
        return create_lab_request(req, patient_email, patient_id, test_type, db)

    @app.post("/doctor/lab", name="create_lab_request")
    def create_lab_request(
        req: Request,
        patient_email: Optional[str] = Form(None),
        patient_id: Optional[str] = Form(None),
        test_type: str = Form(...),
        db: Session = Depends(get_db),
    ):
        if not must_role(req, "Doctor"):
            return RedirectResponse("/login", status_code=303)

        doctor_id = str(req.session.get("user_id"))
        approved_patient_ids = _approved_patient_ids_for_doctor(db, doctor_id)

        patient = None
        if patient_id:
            patient = db.execute(select(User).where(cast(User.id, String) == str(patient_id))).scalar_one_or_none()
        if not patient and patient_email:
            patient = db.execute(select(User).where(User.email == patient_email)).scalar_one_or_none()

        if not patient or str(patient.id) not in approved_patient_ids:
            return RedirectResponse("/doctor", status_code=303)

        lr = LabRequest(
            patient_id=str(patient.id),
            doctor_id=str(doctor_id),
            test_type=test_type.strip(),
            status=LabRequestStatus.PENDING,
        )
        db.add(lr)
        db.commit()
        return RedirectResponse("/doctor", status_code=303)

    @app.post("/doctor/prescribe", include_in_schema=False)
    def write_prescription_alias(
        req: Request,
        patient_email: Optional[str] = Form(None),
        patient_id: Optional[str] = Form(None),
        medicine: Optional[str] = Form(None),
        dosage: Optional[str] = Form(None),
        notes: Optional[str] = Form(None),
        text: Optional[str] = Form(None),
        db: Session = Depends(get_db),
    ):
        return write_prescription(req, patient_email, patient_id, medicine, dosage, notes, text, db)

    @app.post("/doctor/prescription", name="write_prescription")
    def write_prescription(
        req: Request,
        patient_email: Optional[str] = Form(None),
        patient_id: Optional[str] = Form(None),
        medicine: Optional[str] = Form(None),
        dosage: Optional[str] = Form(None),
        notes: Optional[str] = Form(None),
        text: Optional[str] = Form(None),
        db: Session = Depends(get_db),
    ):
        if not must_role(req, "Doctor"):
            return RedirectResponse("/login", status_code=303)

        doctor_id = str(req.session.get("user_id"))
        approved_patient_ids = _approved_patient_ids_for_doctor(db, doctor_id)

        patient = None
        if patient_id:
            patient = db.execute(select(User).where(cast(User.id, String) == str(patient_id))).scalar_one_or_none()
        if not patient and patient_email:
            patient = db.execute(select(User).where(User.email == patient_email)).scalar_one_or_none()
        if not patient or str(patient.id) not in approved_patient_ids:
            return RedirectResponse("/doctor", status_code=303)

        med, dose, note = _parse_prescription_form(medicine, dosage, notes, text)

        p = Prescription(
            patient_id=str(patient.id),
            doctor_id=str(doctor_id),
            medicine=med,
            dosage=dose,
            notes=note,
        )
        db.add(p)
        db.commit()
        return RedirectResponse("/doctor", status_code=303)

    @app.get("/prescriptions/{prescription_id}/download", name="download_prescription")
    def download_prescription(prescription_id: int, req: Request, db: Session = Depends(get_db)):
        if not req.session.get("user_id"):
            return RedirectResponse("/login", status_code=303)

        actor_id = str(req.session.get("user_id"))
        actor_role = req.session.get("role")

        p = db.execute(select(Prescription).where(Prescription.id == prescription_id)).scalar_one_or_none()
        if not p:
            return Response(content=b"Not found", status_code=404)

        if actor_role == "Patient" and str(p.patient_id) != actor_id:
            raise HTTPException(status_code=403, detail="Forbidden")
        if actor_role == "Doctor" and str(p.doctor_id) != actor_id:
            raise HTTPException(status_code=403, detail="Forbidden")
        if actor_role not in {"Patient", "Doctor", "Admin"}:
            raise HTTPException(status_code=403, detail="Forbidden")

        patient_user = db.execute(select(User).where(cast(User.id, String) == str(p.patient_id))).scalar_one_or_none()
        doctor_user = db.execute(select(User).where(cast(User.id, String) == str(p.doctor_id))).scalar_one_or_none()

        filename = f"prescription_{prescription_id}.txt"
        data = _prescription_file_bytes(
            p,
            patient_name=_user_display(patient_user),
            doctor_name=_user_display(doctor_user),
        )
        return Response(
            content=data,
            media_type="text/plain; charset=utf-8",
            headers=_build_download_headers(filename),
        )

    # ---------- Lab Assistant Dashboard ----------

    @app.get("/labassistant", response_class=HTMLResponse, name="labassistant")
    def labassistant(req: Request, db: Session = Depends(get_db)):
        if not must_role(req, "Lab Assistant"):
            return RedirectResponse("/login", status_code=303)

        lab_reqs = db.execute(select(LabRequest).order_by(desc(LabRequest.created_at))).scalars().all()
        out = []
        for lr in lab_reqs:
            p = db.execute(select(User).where(cast(User.id, String) == str(lr.patient_id))).scalar_one_or_none()
            d = db.execute(select(User).where(cast(User.id, String) == str(lr.doctor_id))).scalar_one_or_none()
            report_record_id = (_attr(lr, "report_file", default=None) or "").strip() or None
            out.append({
                "id": lr.id,
                "patient": _user_display(p),
                "patient_email": (p.email if p else "Unknown"),
                "doctor": _user_display(d),
                "doctor_email": (d.email if d else "Unknown"),
                "test_type": _attr(lr, "test_type", "scan_type", default=""),
                "status": lr.status.value.title() if hasattr(lr.status, "value") else str(lr.status),
                "report_file": report_record_id,
                "report": bool(report_record_id),
                "report_id": report_record_id,
            })

        return render(req, "lab_dashboard.html", {
            "lab_requests": out,
            "requests": out,
        })

    @app.post("/labassistant/complete", name="complete_lab")
    async def complete_lab(
        req: Request,
        patient_email: Optional[str] = Form(None),
        request_id: Optional[int] = Form(None),
        report_file: UploadFile = File(...),
        db: Session = Depends(get_db),
    ):
        if not must_role(req, "Lab Assistant"):
            return RedirectResponse("/login", status_code=303)

        lab_id = str(req.session.get("user_id"))

        lr = None
        if request_id is not None:
            lr = db.execute(select(LabRequest).where(LabRequest.id == request_id)).scalar_one_or_none()
        elif patient_email:
            patient = db.execute(select(User).where(User.email == patient_email)).scalar_one_or_none()
            if patient:
                lr = db.execute(
                    select(LabRequest)
                    .where(cast(LabRequest.patient_id, String) == str(patient.id), LabRequest.status == LabRequestStatus.PENDING)
                    .order_by(desc(LabRequest.created_at))
                ).scalar_one_or_none()

        if not lr:
            return RedirectResponse("/labassistant", status_code=303)

        raw = await report_file.read()
        created_report = create_record(
            db=db,
            patient_id=str(lr.patient_id),
            uploaded_by_id=lab_id,
            filename=_safe_filename(report_file.filename or f"lab_report_{lr.id}.bin"),
            plaintext=raw,
            ip=req.client.host if req.client else None,
            ua=req.headers.get("user-agent"),
        )

        lr.status = LabRequestStatus.COMPLETED
        lr.report_file = str(created_report.id)
        lr.completed_at = datetime.now(timezone.utc)
        lr.lab_assistant_id = lab_id
        db.commit()

        return RedirectResponse("/labassistant", status_code=303)

    @app.post("/labassistant/requests/{request_id}/upload", include_in_schema=False)
    async def upload_lab_request_report(
        request_id: int,
        req: Request,
        file: UploadFile = File(...),
        db: Session = Depends(get_db),
    ):
        return await complete_lab(req=req, patient_email=None, request_id=request_id, report_file=file, db=db)

    # ---------- Verify Blockchain (Admin) ----------

    @app.get("/verify_blockchain", response_class=HTMLResponse, name="verify_blockchain")
    def verify_blockchain_page(req: Request, db: Session = Depends(get_db)):
        if not must_role(req, "Admin"):
            return RedirectResponse("/login", status_code=303)

        ok, total, last_hash, last_block = verify_ledger(db)
        details = {
            "status": "Valid" if ok else "Tampered",
            "total_blocks": total,
            "last_hash": last_hash,
            "last_block": json.dumps(last_block, indent=2, sort_keys=True, default=str) if last_block else "{}",
            "files": file_hash_registry(db),
        }
        return render(req, "blockchain_status.html", {"details": details})

    # ---------- Download Medical Record ----------

    @app.get("/download/{record_id}", name="download_record")
    def download_record(record_id: str, req: Request, db: Session = Depends(get_db)):
        if not req.session.get("user_id"):
            return RedirectResponse("/login", status_code=303)

        rid = str(record_id)
        rec = db.execute(select(MedicalRecord).where(cast(MedicalRecord.id, String) == rid)).scalar_one_or_none()
        if not rec:
            return Response(content=b"Not found", status_code=404)

        actor_id = str(req.session.get("user_id"))
        actor_role = req.session.get("role")
        rec_patient_id = str(_attr(rec, "patient_id", default=""))

        if actor_role == "Patient" and rec_patient_id != actor_id:
            raise HTTPException(status_code=403, detail="Forbidden")
        if actor_role == "Doctor":
            ok = db.execute(
                select(Appointment)
                .where(cast(Appointment.doctor_id, String) == actor_id)
                .where(cast(Appointment.patient_id, String) == rec_patient_id)
                .where(Appointment.status == AppointmentStatus.APPROVED)
                .limit(1)
            ).scalar_one_or_none()
            if not ok:
                raise HTTPException(status_code=403, detail="Forbidden")
        if actor_role == "Lab Assistant":
            related_request = db.execute(
                select(LabRequest)
                .where(cast(LabRequest.lab_assistant_id, String) == actor_id)
                .where(LabRequest.report_file == rid)
                .limit(1)
            ).scalar_one_or_none()
            if not related_request:
                raise HTTPException(status_code=403, detail="Forbidden")

        try:
            data = read_record_verified(
                db=db,
                rec=rec,
                actor_user_id=actor_id,
                ip=req.client.host if req.client else None,
                ua=req.headers.get("user-agent"),
            )
        except Exception:
            db.rollback()
            raise

        filename = _safe_filename(_attr(rec, "filename", default="record.bin"))
        media_type = _guess_media_type(filename)

        return Response(
            content=data,
            media_type=media_type,
            headers=_build_download_headers(filename),
        )

    return app


app = create_app()
