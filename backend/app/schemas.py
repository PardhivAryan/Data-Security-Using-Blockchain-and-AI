from pydantic import BaseModel, EmailStr
from app.models import Role, RiskSeverity


class RegisterStartIn(BaseModel):
    email: EmailStr
    full_name: str
    role: Role


class RegisterStartOut(BaseModel):
    publicKey: dict


class RegisterFinishIn(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None
    role: Role | None = None
    credential: dict


class LoginStartIn(BaseModel):
    email: EmailStr
    password: str


class LoginStartOut(BaseModel):
    publicKey: dict


class LoginFinishIn(BaseModel):
    email: EmailStr
    password: str
    credential: dict


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role


class WebAuthnFailIn(BaseModel):
    email: EmailStr | None = None
    stage: str
    reason: str


class UploadRecordOut(BaseModel):
    record_id: str
    status: str


class AccessRequestIn(BaseModel):
    patient_id: str


class DecideAccessIn(BaseModel):
    request_id: int
    approve: bool


class RiskAlertOut(BaseModel):
    id: int
    user_id: str | None
    severity: RiskSeverity
    score: float
    reason: str


class CreateVideoSessionIn(BaseModel):
    patient_id: str


class CreateVideoSessionOut(BaseModel):
    room_id: str