from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from audit import write_audit
from auth import Principal, current_principal
from config import settings
from database import get_db
from models import User
from security import create_token, verify_password

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    # Reserved local/test domains are useful for private deployments, so keep
    # validation structural rather than requiring public DNS-style domains.
    email: str = Field(min_length=3, max_length=255, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=8, max_length=256)


@router.post("/login")
def login(payload: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    if not settings.auth_enabled:
        return {"authenticated": True, "email": "local-observer@byteforce.local", "role": "ADMIN", "auth_enabled": False}
    user = db.query(User).filter(User.email == payload.email.lower(), User.active.is_(True)).first()
    if not user or not verify_password(payload.password, user.password_hash):
        write_audit(db, "AUTH_LOGIN_FAILED", payload.email.lower(), source_ip=request.client.host if request.client else None)
        db.commit()
        raise HTTPException(401, "Email or password is incorrect.")
    token = create_token(user.email, user.role, settings.secret_key)
    response.set_cookie("byteforce_session", token, httponly=True, secure=settings.environment == "production", samesite="strict", max_age=8 * 3600)
    write_audit(db, "AUTH_LOGIN", user.email, source_ip=request.client.host if request.client else None)
    db.commit()
    return {"authenticated": True, "email": user.email, "role": user.role, "auth_enabled": True}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("byteforce_session")
    return {"authenticated": False}


@router.get("/me")
def me(principal: Principal = Depends(current_principal)):
    return {"authenticated": True, "email": principal.email, "role": principal.role, "auth_enabled": settings.auth_enabled}
