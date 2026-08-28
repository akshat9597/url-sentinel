"""Optional cookie authentication. Disabled by default for local hackathon use."""
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import User
from security import decode_token, hash_password


@dataclass
class Principal:
    email: str
    role: str


def bootstrap_admin(db: Session) -> None:
    if not settings.auth_enabled or not settings.admin_password:
        return
    user = db.query(User).filter(User.email == settings.admin_email.lower()).first()
    if not user:
        db.add(User(email=settings.admin_email.lower(), password_hash=hash_password(settings.admin_password), role="ADMIN"))
        db.commit()


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    if not settings.auth_enabled:
        return Principal("local-observer@byteforce.local", "ADMIN")
    token = request.cookies.get("byteforce_session")
    payload = decode_token(token or "", settings.secret_key)
    if not payload:
        raise HTTPException(401, "Sign in is required for this operation.")
    user = db.query(User).filter(User.email == payload.get("sub"), User.active.is_(True)).first()
    if not user:
        raise HTTPException(401, "The account is unavailable.")
    return Principal(user.email, user.role)


def require_admin(principal: Principal = Depends(current_principal)) -> Principal:
    if principal.role != "ADMIN":
        raise HTTPException(403, "Administrator access is required.")
    return principal
