"""
Authentication & User Management Endpoints.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.core.security import create_access_token, get_password_hash, verify_password
from app.models.models import Tenant, User
from app.schemas.schemas import TenantCreate, TenantRead, Token, UserCreate, UserLogin, UserRead

router = APIRouter()


@router.post("/register-tenant", response_model=TenantRead, status_code=status.HTTP_201_CREATED)
async def register_tenant(
    tenant_in: TenantCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Tenant:
    """Registers a new tenant workspace."""
    existing = await db.execute(select(Tenant).where(Tenant.slug == tenant_in.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant slug '{tenant_in.slug}' already exists.",
        )

    tenant = Tenant(name=tenant_in.name, slug=tenant_in.slug)
    db.add(tenant)
    await db.flush()
    await db.refresh(tenant)
    return tenant


@router.post("/register-user", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Creates a new user account."""
    existing = await db.execute(select(User).where(User.email == user_in.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email '{user_in.email}' is already registered.",
        )

    tenant_res = await db.execute(select(Tenant).where(Tenant.id == user_in.tenant_id))
    if not tenant_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant ID '{user_in.tenant_id}' does not exist.",
        )

    user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        tenant_id=user_in.tenant_id,
        role=user_in.role,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.post("/login", response_model=Token)
async def login(
    login_in: UserLogin,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Token:
    """Authenticates user and returns JWT Bearer token."""
    result = await db.execute(select(User).where(User.email == login_in.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(login_in.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    access_token = create_access_token(
        subject=user.id,
        tenant_id=user.tenant_id,
        role=user.role.value,
    )
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserRead)
async def get_me(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Gets currently authenticated user details."""
    return current_user
