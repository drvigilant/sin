"""
sin.api.auth
════════════
JWT authentication, password hashing, role enforcement.
"""
import os
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from sin.storage.database import SessionLocal
from sin.storage import models
from sin.utils.logger import get_logger

logger = get_logger("sin.api.auth")

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY        = os.getenv("SIN_JWT_SECRET", "change-me-in-production-use-32-chars-min")
ALGORITHM         = "HS256"
ACCESS_EXPIRE_MIN = int(os.getenv("SIN_JWT_ACCESS_EXPIRE_MIN", "30"))
REFRESH_EXPIRE_DAYS = int(os.getenv("SIN_JWT_REFRESH_EXPIRE_DAYS", "7"))

pwd_ctx  = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer   = HTTPBearer(auto_error=False)

# ── Password ──────────────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

# ── JWT ───────────────────────────────────────────────────────────────────────
def create_access_token(user_id: int, username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_EXPIRE_MIN)
    return jwt.encode(
        {"sub": str(user_id), "username": username, "role": role, "exp": expire, "type": "access"},
        SECRET_KEY, algorithm=ALGORITHM
    )

def create_refresh_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRE_DAYS)
    return jwt.encode(
        {"sub": str(user_id), "exp": expire, "type": "refresh"},
        SECRET_KEY, algorithm=ALGORITHM
    )

def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.username == username).first()

def get_user_by_id(db: Session, user_id: int) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.id == user_id).first()

# ── FastAPI dependency ────────────────────────────────────────────────────────
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db)
) -> models.User:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not credentials:
        raise exc
    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise exc
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise exc

    user = get_user_by_id(db, user_id)
    if not user or user.is_active != "true":
        raise exc

    # Update last_login
    user.last_login = datetime.utcnow()
    db.commit()
    return user

def require_role(*roles: str):
    """Dependency factory — raises 403 if user role not in roles."""
    def _check(user: models.User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail=f"Role '{user.role}' not permitted")
        return user
    return _check

# Convenience shortcuts
require_admin   = require_role("admin")
require_analyst = require_role("admin", "analyst")
require_viewer  = require_role("admin", "analyst", "viewer")
