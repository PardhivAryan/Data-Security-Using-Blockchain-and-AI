from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas import (
    RegisterStartIn, RegisterStartOut, RegisterFinishIn,
    LoginStartIn, LoginStartOut, LoginFinishIn,
    TokenOut, WebAuthnFailIn
)
from app.services import start_register, finish_register, start_login, finish_login, record_webauthn_fail
from app.core.security import create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])


def _ip_ua(req: Request):
    ip = req.client.host if req.client else None
    ua = req.headers.get("user-agent")
    return ip, ua


@router.post("/register/options", response_model=RegisterStartOut)
def register_options(payload: RegisterStartIn, db: Session = Depends(get_db)):
    publicKey = start_register(db, payload.email, payload.full_name, payload.role)
    return {"publicKey": publicKey}


@router.post("/register/verify")
def register_verify(payload: RegisterFinishIn, req: Request, db: Session = Depends(get_db)):
    ip, ua = _ip_ua(req)
    finish_register(db, payload.email, payload.password, payload.full_name, payload.role, payload.credential, ip, ua)
    return {"status": "registered"}


@router.post("/login/options", response_model=LoginStartOut)
def login_options(payload: LoginStartIn, req: Request, db: Session = Depends(get_db)):
    ip, ua = _ip_ua(req)
    publicKey = start_login(db, payload.email, payload.password, ip, ua)
    return {"publicKey": publicKey}


@router.post("/login/verify", response_model=TokenOut)
def login_verify(payload: LoginFinishIn, req: Request, db: Session = Depends(get_db)):
    ip, ua = _ip_ua(req)
    user = finish_login(db, payload.email, payload.password, payload.credential, ip, ua)
    token = create_access_token(user.id, {"role": user.role})
    return {"access_token": token, "role": user.role}


@router.post("/webauthn/fail")
def webauthn_fail(payload: WebAuthnFailIn, req: Request, db: Session = Depends(get_db)):
    ip, ua = _ip_ua(req)
    record_webauthn_fail(db, payload.email, payload.stage, payload.reason, ip, ua)
    return {"status": "logged"}