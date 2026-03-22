import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings


def _normalize_password(password: str) -> bytes:
    """
    Always hash to fixed 32 bytes using SHA-256 so bcrypt never sees long input.
    """
    if password is None:
        password = ""
    return hashlib.sha256(password.encode("utf-8")).digest()


def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(_normalize_password(password), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_normalize_password(plain_password), password_hash.encode("utf-8"))
    except Exception:
        return False


def create_access_token(
    sub: str,
    claims: Optional[Dict[str, Any]] = None,
    expires_minutes: Optional[int] = None,
) -> str:
    now = datetime.now(timezone.utc)
    exp_min = expires_minutes if expires_minutes is not None else int(settings.jwt_exp_minutes)
    expire = now + timedelta(minutes=exp_min)

    payload: Dict[str, Any] = {"sub": str(sub), "exp": expire}
    if claims:
        payload.update(claims)

    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_alg)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
    except JWTError:
        return None