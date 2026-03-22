import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sqlalchemy import (
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Enum as SAEnum,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from app.db.base import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------- Enums ----------

class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    DOCTOR = "DOCTOR"
    PATIENT = "PATIENT"
    LAB = "LAB"


class MedicalRecordStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"


class AccessRequestStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AppointmentStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    CANCELLED = "CANCELLED"


class RiskSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class VideoSessionStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    ENDED = "ENDED"


class RecordType(str, enum.Enum):
    MEDICAL = "MEDICAL"
    SCAN = "SCAN"


class LabRequestStatus(str, enum.Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"


# ---------- Tables ----------

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[Role] = mapped_column(SAEnum(Role, name="role"), nullable=False, default=Role.PATIENT)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # webauthn
    webauthn_user_handle_b64: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    credentials = relationship("WebAuthnCredential", back_populates="user", cascade="all, delete-orphan")
    challenges = relationship("WebAuthnChallenge", back_populates="user", cascade="all, delete-orphan")


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    credential_id_b64: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False)
    public_key_b64: Mapped[str] = mapped_column(String(4096), nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    user = relationship("User", back_populates="credentials")


class WebAuthnChallenge(Base):
    __tablename__ = "webauthn_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    purpose: Mapped[str] = mapped_column(String(20), nullable=False)  # REG / AUTH
    challenge_b64: Mapped[str] = mapped_column(String(2048), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    user = relationship("User", back_populates="challenges")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="INFO", nullable=False)

    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    meta: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class LedgerBlock(Base):
    __tablename__ = "ledger_blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    curr_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class MedicalRecord(Base):
    __tablename__ = "medical_records"

    # Keep as STRING UUID so your services.py can pass str(uuid4()) safely
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    patient_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    uploaded_by_user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(500), nullable=False)

    sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    record_type: Mapped[RecordType] = mapped_column(SAEnum(RecordType, name="recordtype"), default=RecordType.MEDICAL, nullable=False)
    status: Mapped[MedicalRecordStatus] = mapped_column(SAEnum(MedicalRecordStatus, name="medicalrecordstatus"), default=MedicalRecordStatus.ACTIVE, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    # ✅ These aliases FIX your RecursionError (no custom @property nonsense)
    uploaded_by_id = synonym("uploaded_by_user_id")
    storage_path = synonym("stored_path")
    sha256_hex = synonym("sha256")


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    patient_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    doctor_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    status: Mapped[AccessRequestStatus] = mapped_column(SAEnum(AccessRequestStatus, name="accessrequeststatus"), default=AccessRequestStatus.PENDING, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RecordPermission(Base):
    __tablename__ = "record_permissions"
    __table_args__ = (UniqueConstraint("patient_id", "doctor_id", name="uq_patient_doctor_perm"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    patient_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    doctor_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Appointment(Base):
    __tablename__ = "appointments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    patient_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    doctor_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[AppointmentStatus] = mapped_column(SAEnum(AppointmentStatus, name="appointmentstatus"), default=AppointmentStatus.PENDING, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class VideoSession(Base):
    __tablename__ = "video_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    room_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)

    patient_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    doctor_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    status: Mapped[VideoSessionStatus] = mapped_column(SAEnum(VideoSessionStatus, name="videosessionstatus"), default=VideoSessionStatus.ACTIVE, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RiskAlert(Base):
    __tablename__ = "risk_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    severity: Mapped[RiskSeverity] = mapped_column(SAEnum(RiskSeverity, name="riskseverity"), nullable=False, default=RiskSeverity.LOW)
    score: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)

    related_event_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("audit_events.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class LabRequest(Base):
    __tablename__ = "lab_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    patient_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    doctor_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    lab_assistant_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    test_type: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[LabRequestStatus] = mapped_column(SAEnum(LabRequestStatus, name="labrequeststatus"), default=LabRequestStatus.PENDING, nullable=False)

    report_file: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Prescription(Base):
    __tablename__ = "prescriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    patient_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    doctor_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    medicine: Mapped[str] = mapped_column(String(120), nullable=False)
    dosage: Mapped[str] = mapped_column(String(120), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)