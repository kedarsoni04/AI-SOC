"""
Authentication API Routes
POST /auth/login
POST /auth/logout
POST /auth/refresh
GET  /auth/me
"""
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import (
    verify_password, hash_password, create_access_token,
    create_refresh_token, decode_token
)
from app.models import User, AuditLog
from app.schemas import LoginRequest, TokenResponse, UserResponse, UserCreate

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ── Dependency: get current user ───────────────────────────────────────────────
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise credentials_exc
    
    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exc
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise credentials_exc
    
    return user


def require_role(*roles: str):
    """Role-based access control dependency factory."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {list(roles)}",
            )
        return current_user
    return role_checker


# ── Routes ─────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user and return JWT tokens."""
    # Find user by username or email
    result = await db.execute(
        select(User).where(
            (User.username == form_data.username) | (User.email == form_data.username)
        )
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        # Log failed attempt
        await _log_audit(
            db, None, "login_failed",
            resource_type="auth",
            details={"username": form_data.username},
            ip_address=request.client.host if request.client else None,
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
    
    # Update last login
    user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add(user)
    
    # Log successful login
    await _log_audit(
        db, user.id, "login_success",
        resource_type="auth",
        ip_address=request.client.host if request.client else None,
    )
    
    access_token = create_access_token(subject=user.id, role=user.role)
    refresh_token = create_refresh_token(subject=user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Log out the current user (client should discard the token)."""
    await _log_audit(
        db, current_user.id, "logout",
        resource_type="auth",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Return current user profile."""
    return UserResponse.model_validate(current_user)


@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new user (admin only)."""
    # Check uniqueness
    existing = await db.execute(
        select(User).where(
            (User.username == user_data.username) | (User.email == user_data.email)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role,
    )
    db.add(user)
    await db.flush()
    return UserResponse.model_validate(user)


async def _log_audit(
    db: AsyncSession,
    user_id: Optional[str],
    action: str,
    resource_type: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
    success: bool = True,
):
    """Create an audit log entry."""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        details=details,
        ip_address=ip_address,
        success=success,
    )
    db.add(log)
