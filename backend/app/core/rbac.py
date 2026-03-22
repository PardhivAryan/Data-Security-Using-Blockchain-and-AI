from fastapi import HTTPException, status
from app.models import Role, User


def require_roles(user: User, allowed: set[Role]) -> None:
    if user.role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden for this role",
        )