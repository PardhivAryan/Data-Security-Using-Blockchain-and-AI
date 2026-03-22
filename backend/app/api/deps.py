from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.session import get_db
from app.core.security import decode_access_token
from app.models import User

bearer = HTTPBearer(auto_error=False)


def get_current_user(
    db: Session = Depends(get_db),
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> User:
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")

    payload = decode_access_token(creds.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user_id = payload["sub"]
    u = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not u.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User inactive")
    return u